"""Triskel-backed layout: SESE decomposition, in character cells.

`triskel <https://github.com/triskellib/triskel>`_ lays a CFG out by splitting it
into Single-Entry Single-Exit regions first, laying each region out on its own,
and pasting the results back as super-nodes. On our corpus that takes functions
that our own layered engine draws with up to 41 edge crossings down to 0 or 1,
and it routes loop edges around the side of the graph the way IDA does instead
of straight back up the middle.

This module owns the whole impedance mismatch between a float/pixel layout
engine and a grid of character cells. Three things make that mismatch small:

1. **We work in cells, not pixels.** Our fork exposes ``set_spacing()``, so the
   gutters and the edge-lane pitch are set in cells (3 / 1 / 1) and node sizes
   are handed over in cells. Upstream's constants are pixels (50 / 40 / 30);
   feeding those a 32px-tall cell rounds two adjacent edge lanes onto the same
   row, which in a terminal means two differently-coloured edges fighting over
   one cell. In cell units the output is integral and lanes never collide.
2. **Triskel's routes are already orthogonal.** Zero diagonal segments out of
   2471 on the corpus, so every segment is a run of ``─`` or ``│``.
3. **Ports already land on the box border**, spread along it by degree, which is
   exactly what our own ``_ports`` does.

What it does NOT do is trust the library with degenerate input. Self-loops and
disconnected graphs make it throw, an empty graph used to segfault, and a
segfault takes the TUI down with it. Both are handled here, before the call.
"""

from __future__ import annotations

import os

from . import graph as G

# Spacing, in cells. X_GUTTER is the gap between boxes in a layer, Y_GUTTER the
# gap between a box and the first edge lane, EDGE_HEIGHT the pitch between
# stacked horizontal edge runs -- so EDGE_HEIGHT >= 1 is what guarantees two
# lanes never share a row.
HGAP = 3
VGAP = 1
LANE = 1

_mod: object | None = None
_tried = False


def module():
    """The ``pytriskel`` extension, or None. Imported lazily and cached.

    ``$IDATUI_TRISKEL_PATH`` points at a build tree (our fork's
    ``build/bindings/python``) for development installs.
    """
    global _mod, _tried
    if _tried:
        return _mod
    _tried = True
    path = os.environ.get("IDATUI_TRISKEL_PATH")
    if path:
        import sys

        if path not in sys.path:
            sys.path.insert(0, path)
    try:
        import pytriskel  # noqa: PLC0415
    except ImportError:
        return None
    # Upstream ships wheels whose get_waypoints() always throws (a missing
    # <pybind11/stl.h>), and without waypoints there are no edges to draw. Fail
    # the availability check rather than dying mid-layout.
    if not hasattr(pytriskel, "set_spacing"):
        return None
    _mod = pytriskel
    return _mod


def available() -> bool:
    return module() is not None


def _reachable(succ: dict[int, list[int]], root: int) -> set[int]:
    seen = {root}
    stack = [root]
    while stack:
        for j in succ.get(stack.pop(), ()):
            if j not in seen:
                seen.add(j)
                stack.append(j)
    return seen


def _phantom_edges(g: G._Graph, root: int) -> list[tuple[int, int]]:
    """Extra root->node edges that make every node reachable from ``root``.

    **This is a hard precondition, not a nicety.** Triskel's root is whichever
    node was created first, and every analysis walks out from it; hand it a node
    the root cannot reach and it either throws ``EMPTY BL`` from the SESE
    bracket lists or -- with an entry block that has no successors at all --
    dereferences its way straight off the end and SEGFAULTS. A segfault cannot
    be caught and fallen back from; it takes the TUI with it.

    Real CFGs hit this in two ways, both routine: IDA flowcharts contain blocks
    unreachable from the entry (dead code, a jump table entry it could not
    resolve), and a function whose entry is a bare `jmp` thunk can leave the
    rest of the chunk weakly connected but not reachable.

    The edges are handed to the layout but never drawn. They cost a little
    reserved space and, in exchange, triskel positions the orphans sensibly
    (under the entry) instead of us stacking them beside the graph and hoping.
    Attachment points are chosen at the natural entry of each orphan subgraph --
    a node no other orphan reaches -- so one phantom edge usually covers many
    blocks.
    """
    succ: dict[int, list[int]] = {i: [] for i in g.nodes}
    preds: dict[int, list[int]] = {i: [] for i in g.nodes}
    for e in g.edges:
        succ[e.src].append(e.dst)
        preds[e.dst].append(e.src)

    reach = _reachable(succ, root)
    phantom: list[tuple[int, int]] = []
    while len(reach) < len(g.nodes):
        rest = [i for i in g.nodes if i not in reach]
        rest_set = set(rest)
        head = next(
            (i for i in rest if not any(p in rest_set for p in preds[i])), rest[0]
        )
        phantom.append((root, head))
        reach |= _reachable(succ, head)
    return phantom


def _edge_type(pt, kind: str):
    if kind == G.E_TRUE:
        return pt.EdgeType.T
    if kind == G.E_FALSE:
        return pt.EdgeType.F
    return pt.EdgeType.Default


def _clean(pts: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Drop duplicate and collinear waypoints.

    Triskel emits doubled points where it stitches region layouts together (a
    back edge came back with 20 waypoints, 6 of them duplicates). A doubled
    point is a zero-length segment, which would make the corner-glyph pass read
    a direction of "nowhere".
    """
    out: list[tuple[int, int]] = []
    for p in pts:
        if out and out[-1] == p:
            continue
        out.append(p)
    i = 1
    while i < len(out) - 1:
        a, b, c = out[i - 1], out[i], out[i + 1]
        if (a[0] == b[0] == c[0]) or (a[1] == b[1] == c[1]):
            del out[i]
        else:
            i += 1
    return out


def run(g: G._Graph, root: int) -> tuple[list[G.Route], int]:
    """Position every node in ``g`` and return (routes, layer count).

    Mirrors the contract of ``graph._native_engine``: nodes come back with
    ``x``/``y``/``rank``/``order`` set, edges keep their real direction (triskel
    handles cycles internally, so nothing is flipped), and routes are cell
    polylines.
    """
    pt = module()
    if pt is None:
        raise RuntimeError("pytriskel is not available")
    pt.set_spacing(x_gutter=float(HGAP), y_gutter=float(VGAP), edge_height=float(LANE))

    routes: list[G.Route] = []
    if g.nodes:
        phantom = _phantom_edges(g, root)
        _layout_graph(pt, g, root, g.edges, phantom, routes)

    # The native engine learns which edges are back edges from its DFS, because
    # it has to reverse them to get a DAG. Triskel handles cycles internally and
    # tells us nothing, so recover it from the drawing: an edge that does not
    # descend is one control flow comes back along. This is style only (purple,
    # and the `loop:` reading in the RPC surface) -- the direction is untouched,
    # which is why ``flipped`` stays False on every triskel route.
    for e in g.edges:
        e.back = g.nodes[e.dst].y <= g.nodes[e.src].y

    # Ranks are a layout concept the rest of the app navigates by (`w`/`b`, the
    # RPC surface). Triskel doesn't expose them -- it has regions, not layers --
    # so recover bands from the y coordinates the boxes actually landed on.
    real = [n for n in g.nodes.values() if not n.dummy]
    bands = sorted({n.y for n in real})
    rank_of = {y: r for r, y in enumerate(bands)}
    for n in real:
        n.rank = rank_of[n.y]
    for y in bands:
        row = sorted((n for n in real if n.y == y), key=lambda n: n.x)
        for k, n in enumerate(row):
            n.order = k

    _repair_boxes(g, routes)
    _verify(g, routes)
    return routes, len(bands)


def _layout_graph(
    pt,
    g: G._Graph,
    root: int,
    edges: list[G.Edge],
    phantom: list[tuple[int, int]],
    routes: list[G.Route],
) -> None:
    """Lay the whole graph out and append its routes."""
    order = [root] + [i for i in g.nodes if i != root]
    succ: dict[int, list[int]] = {i: [] for i in g.nodes}
    for e in edges:
        succ[e.src].append(e.dst)
    for a, b in phantom:
        succ[a].append(b)
    unreachable = set(g.nodes) - _reachable(succ, root)
    if unreachable:
        # Belt and braces: _phantom_edges is supposed to have made this
        # impossible, and the consequence of being wrong is a SIGSEGV rather
        # than an exception, so check before crossing into C++ rather than
        # after. RuntimeError here means a fallback to native; a segfault means
        # the user loses the session.
        raise RuntimeError(
            f"{len(unreachable)} blocks unreachable from the "
            f"layout root {root}: {sorted(unreachable)[:8]}"
        )

    builder = pt.make_layout_builder()
    tid = {}
    # The root MUST be created first: triskel takes its graph root to be
    # whichever node was made first, and every one of its analyses walks out
    # from there.
    for nid in order:
        n = g.nodes[nid]
        # NOTE the argument order: make_node(height, width). Upstream's Python
        # docstring says "width and height", which is the other way round; our
        # fork makes them keyword arguments so it cannot be got wrong silently.
        tid[nid] = builder.make_node(height=float(n.h), width=float(n.w))
    teid = [
        (builder.make_edge(tid[e.src], tid[e.dst], _edge_type(pt, e.kind)), e)
        for e in edges
    ]
    for a, b in phantom:
        builder.make_edge(tid[a], tid[b], _edge_type(pt, G.E_UNCOND))
    lay = builder.build()

    polys: list[tuple[G.Edge, list[tuple[float, float]]]] = []
    for eid, e in teid:
        polys.append((e, [(p.x, p.y) for p in lay.get_waypoints(eid)]))

    # Triskel's origin is not its bounding box: a loop edge routed around the
    # side runs to y = -1, above every node. Normalise on everything drawn, not
    # just the boxes, or the canvas clips its own edges.
    xs = [lay.get_coords(tid[i]).x for i in g.nodes]
    ys = [lay.get_coords(tid[i]).y for i in g.nodes]
    xs += [x for _, wps in polys for x, _ in wps]
    ys += [y for _, wps in polys for _, y in wps]
    min_x, min_y = min(xs, default=0.0), min(ys, default=0.0)

    def cell(x: float, y: float) -> tuple[int, int]:
        return int(round(y - min_y)), int(round(x - min_x))

    for nid in g.nodes:
        n = g.nodes[nid]
        p = lay.get_coords(tid[nid])
        n.y, n.x = cell(p.x, p.y)

    for e, wps in polys:
        pts = _clean([cell(x, y) for x, y in wps])
        if len(pts) < 2:
            continue
        _snap_ports(g, e, pts)
        routes.append(
            G.Route(edge=e, pts=_clean(pts), head=True, tail=True, flipped=False)
        )


def _box_index(g: G._Graph) -> tuple[dict[int, list[G.Node]], dict[int, list[G.Node]]]:
    """(boxes strictly covering each column, boxes strictly covering each row).

    "Strictly" because a cell ON the border is where ports, arrowheads and tees
    legitimately live; only the interior is off limits.
    """
    by_col: dict[int, list[G.Node]] = {}
    by_row: dict[int, list[G.Node]] = {}
    for n in g.nodes.values():
        if n.dummy:
            continue
        for c in range(n.x + 1, n.right):
            by_col.setdefault(c, []).append(n)
        for r in range(n.y + 1, n.bottom):
            by_row.setdefault(r, []).append(n)
    return by_col, by_row


def _hits(by_col, by_row, p: tuple[int, int], q: tuple[int, int]) -> list[G.Node]:
    """Boxes whose interior a straight segment from ``p`` to ``q`` runs into."""
    (r0, c0), (r1, c1) = p, q
    if c0 == c1:
        lo, hi = (r0, r1) if r0 <= r1 else (r1, r0)
        return [n for n in by_col.get(c0, ()) if n.y < hi and lo < n.bottom]
    lo, hi = (c0, c1) if c0 <= c1 else (c1, c0)
    return [n for n in by_row.get(r0, ()) if n.x < hi and lo < n.right]


def _free_line(
    blocked: list[tuple[int, int]], want: int, allow: tuple[int, int] | None = None
) -> int | None:
    """The coordinate nearest ``want`` that is in none of ``blocked``.

    ``blocked`` is a list of inclusive intervals. Jumping to the near side of
    the *first* box in the way is not enough in a dense layout -- that column is
    very often inside the next box along -- so consider every box the run
    passes and step out of each interval in turn.

    ``allow`` constrains the result to an inclusive range, which is how a port
    stays on its own box's border: everything outside becomes blocked.
    """
    if allow is not None:
        lo, hi = allow
        if lo > hi:
            return None
        blocked = list(blocked) + [(hi + 1, hi + 1 + 10**6)]
        if lo > 0:
            blocked.append((0, lo - 1))
    if not blocked:
        return want
    merged: list[list[int]] = []
    for lo, hi in sorted(blocked):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])

    def inside(v: int) -> list[int] | None:
        for iv in merged:
            if iv[0] <= v <= iv[1]:
                return iv
        return None

    if inside(want) is None:
        return want
    low = want
    while (iv := inside(low)) is not None:
        low = iv[0] - 1
        if low < 0:
            low = None
            break
    high = want
    while (iv := inside(high)) is not None:
        high = iv[1] + 1
    if low is None:
        return high
    return low if want - low <= high - want else high


def _repair_boxes(g: G._Graph, routes: list[G.Route]) -> int:
    """Detour any segment that runs through a box. Returns the number moved.

    Triskel does not actually guarantee this. On the corpus one edge in 128
    functions comes back drawn through a block (``sub_69C0``: a vertical at
    x=235 crossing a box spanning x=222.5..236.5, in float space -- so it is the
    library's own layout, not our rounding). Two cells is nothing in a PNG,
    where the box is opaque and painted last. In a terminal the box is mostly
    holes: the edge appears *inside* the disassembly text, and ``edge_at``
    happily reports an edge under a cell the user reads as code.

    ``docs/GRAPH_VIEW.md`` states that no edge ever crosses a box and
    ``tests/test_graph.py`` counts it across the corpus, so rather than weaken
    the claim we push the offending run out to the nearest side of the box it
    hits. Only interior segments are moved -- the first and last carry the port
    and the arrowhead, and those belong on the border.
    """
    by_col, by_row = _box_index(g)
    real = [n for n in g.nodes.values() if not n.dummy]
    moved = 0
    for rt in routes:
        # Moving one segment stretches the two beside it, which can push THEM
        # into a box, so sweep until the route stops changing. Three passes is
        # plenty in practice and bounds the work on a pathological route.
        for _ in range(3):
            dirty = False
            last = len(rt.pts) - 2
            for i in range(0, len(rt.pts) - 1):
                p, q = rt.pts[i], rt.pts[i + 1]
                if not _hits(by_col, by_row, p, q):
                    continue
                if p[1] == q[1]:  # vertical: shift column
                    lo, hi = sorted((p[0], q[0]))
                    blocked = [
                        (n.x + 1, n.right - 1)
                        for n in real
                        if n.y < hi and lo < n.bottom
                    ]
                    # The first and last segments carry the port and the
                    # arrowhead, so they may only move ALONG their own box's
                    # border -- but move they must: triskel is happy to park a
                    # block directly above its successor and drive the final
                    # approach straight through it. Another port on the same
                    # border is almost always free.
                    allow = None
                    if i == 0 or i == last:
                        ends = []
                        if i == 0:
                            ends.append(g.nodes[rt.edge.src])
                        if i == last:
                            ends.append(g.nodes[rt.edge.dst])
                        allow = (
                            max(n.x + 1 for n in ends),
                            min(n.right - 1 for n in ends),
                        )
                    col = _free_line(blocked, p[1], allow)
                    if col is None:
                        continue
                    rt.pts[i], rt.pts[i + 1] = (p[0], col), (q[0], col)
                elif i not in (0, last):  # horizontal: shift row
                    lo, hi = sorted((p[1], q[1]))
                    blocked = [
                        (n.y + 1, n.bottom - 1)
                        for n in real
                        if n.x < hi and lo < n.right
                    ]
                    row = _free_line(blocked, p[0])
                    if row is None:
                        continue
                    rt.pts[i], rt.pts[i + 1] = (row, p[1]), (row, q[1])
                else:
                    continue
                moved += 1
                dirty = True
            if not dirty:
                break
    return moved


def _verify(g: G._Graph, routes: list[G.Route]) -> None:
    """Raise if the drawing breaks an invariant, so ``layout()`` falls back.

    The invariants are worth more than the engine: a layout with more crossings
    beats one that draws edges through the code, or one block over another.

    Overlapping boxes are triskel's, not ours -- it superimposes independently
    laid out SESE regions, and on 2 of `ls`'s 400 functions two blocks end up a
    couple of columns into each other in float space, before any rounding. In a
    PNG that is a cosmetic nick on a border. Here the boxes are made of text, so
    one block's disassembly overwrites another's.
    """
    rows: dict[int, list[G.Node]] = {}
    for n in g.nodes.values():
        if n.dummy:
            continue
        for r in range(n.y, n.y + n.h):
            rows.setdefault(r, []).append(n)
    for r, boxes in rows.items():
        boxes.sort(key=lambda n: n.x)
        for a, b in zip(boxes, boxes[1:]):
            if b.x <= a.right:
                raise RuntimeError(
                    f"blocks {a.id} and {b.id} overlap on row {r} "
                    f"(x[{a.x},{a.right}] vs x[{b.x},{b.right}])"
                )

    by_col, by_row = _box_index(g)
    for rt in routes:
        for p, q in zip(rt.pts, rt.pts[1:]):
            hit = _hits(by_col, by_row, p, q)
            if hit:
                raise RuntimeError(
                    f"edge {rt.edge.src}->{rt.edge.dst} crosses block "
                    f"{hit[0].id} at {p}-{q} and could not be detoured"
                )


def _snap_ports(g: G._Graph, e: G.Edge, pts: list[tuple[int, int]]) -> None:
    """Pull the polyline's ends onto the box borders, in place.

    Triskel leaves a node at ``y + height`` -- the first row *below* the box,
    because it thinks in half-open pixel rectangles while our boxes own rows
    ``y .. y+h-1`` inclusive and draw a border on the last one. Landing the end
    points on the border row is what lets the arrowhead and the port tee replace
    a border character instead of floating one cell off it.
    """
    src, dst = g.nodes[e.src], g.nodes[e.dst]

    def clamp(n: G.Node, col: int) -> int:
        return max(n.x + 1, min(col, n.x + n.w - 2))

    if len(pts) == 2:
        # A straight drop between two boxes: one column has to satisfy both, or
        # the "line" acquires a kink with no corner glyph to explain it.
        col = clamp(dst, clamp(src, pts[0][1]))
        down = pts[1][0] >= pts[0][0]
        pts[0] = (src.bottom if down else src.y, col)
        pts[1] = (dst.y if down else dst.bottom, col)
        return

    # tail: src's bottom border if the edge leaves downward, its top if not
    old_r, old_c = pts[0]
    col = clamp(src, old_c)
    pts[0] = (src.bottom if pts[1][0] >= old_r else src.y, col)
    if pts[1][1] == old_c:  # the first segment was vertical: keep it
        pts[1] = (pts[1][0], col)

    # head: dst's top border if the edge arrives downward, its bottom if not
    old_r, old_c = pts[-1]
    col = clamp(dst, old_c)
    pts[-1] = (dst.y if pts[-2][0] <= old_r else dst.bottom, col)
    if pts[-2][1] == old_c:
        pts[-2] = (pts[-2][0], col)
