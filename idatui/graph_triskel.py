"""Triskel-backed layout: SESE decomposition, in character cells.

`triskel <https://github.com/triskellib/triskel>`_ lays a CFG out by splitting it
into Single-Entry Single-Exit regions first, laying each region out on its own,
and pasting the results back as super-nodes. On our corpus that takes functions
that our own layered engine draws with up to 41 edge crossings down to 0 or 1,
and it routes loop edges around the side of the graph the way IDA does instead
of straight back up the middle. ``docs/TRISKEL_EVAL.md`` has the measurements.

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

#: Columns between two weakly-connected components laid out side by side.
COMPONENT_GAP = 4

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
        import pytriskel                                    # noqa: PLC0415
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


def _components(g: G._Graph) -> list[list[int]]:
    """Weakly-connected components, entry's component first.

    Triskel raises ``EMPTY BL`` on a disconnected graph (its cycle-equivalence
    bracket lists run dry), and IDA flowcharts do contain unreachable blocks --
    ``tests/test_graph.py:t_unreachable`` is exactly that shape. So we split the
    work ourselves and stack the pieces side by side, which is also what the
    native engine effectively does.
    """
    adj: dict[int, set[int]] = {i: set() for i in g.nodes}
    for e in g.edges:
        adj[e.src].add(e.dst)
        adj[e.dst].add(e.src)
    seen: set[int] = set()
    comps: list[list[int]] = []
    for start in g.nodes:
        if start in seen:
            continue
        stack, comp = [start], []
        seen.add(start)
        while stack:
            i = stack.pop()
            comp.append(i)
            for j in adj[i]:
                if j not in seen:
                    seen.add(j)
                    stack.append(j)
        comps.append(sorted(comp))
    return comps


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
    pt.set_spacing(x_gutter=float(HGAP), y_gutter=float(VGAP),
                   edge_height=float(LANE))

    by_src: dict[int, list[G.Edge]] = {}
    for e in g.edges:
        by_src.setdefault(e.src, []).append(e)

    routes: list[G.Route] = []
    x_off = 0
    for comp in _components(g):
        members = set(comp)
        edges = [e for i in comp for e in by_src.get(i, []) if e.dst in members]
        x_off = _layout_component(pt, g, comp, edges, routes, x_off)

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


def _layout_component(pt, g: G._Graph, comp: list[int], edges: list[G.Edge],
                      routes: list[G.Route], x_off: int) -> int:
    """Lay one component out, shifted right by ``x_off``. Returns the next x."""
    builder = pt.make_layout_builder()
    tid = {}
    for nid in comp:
        n = g.nodes[nid]
        # NOTE the argument order: make_node(height, width). Upstream's Python
        # docstring says "width and height", which is the other way round; our
        # fork makes them keyword arguments so it cannot be got wrong silently.
        tid[nid] = builder.make_node(height=float(n.h), width=float(n.w))
    teid = [(builder.make_edge(tid[e.src], tid[e.dst], _edge_type(pt, e.kind)), e)
            for e in edges]
    lay = builder.build()

    polys: list[tuple[G.Edge, list[tuple[float, float]]]] = []
    for eid, e in teid:
        polys.append((e, [(p.x, p.y) for p in lay.get_waypoints(eid)]))

    # Triskel's origin is not its bounding box: a loop edge routed around the
    # side runs to y = -1, above every node. Normalise on everything drawn, not
    # just the boxes, or the canvas clips its own edges.
    xs = [lay.get_coords(tid[i]).x for i in comp]
    ys = [lay.get_coords(tid[i]).y for i in comp]
    xs += [x for _, wps in polys for x, _ in wps]
    ys += [y for _, wps in polys for _, y in wps]
    min_x, min_y = min(xs, default=0.0), min(ys, default=0.0)

    def cell(x: float, y: float) -> tuple[int, int]:
        return int(round(y - min_y)), int(round(x - min_x)) + x_off

    for nid in comp:
        n = g.nodes[nid]
        p = lay.get_coords(tid[nid])
        n.y, n.x = cell(p.x, p.y)

    right = max((g.nodes[i].x + g.nodes[i].w for i in comp), default=x_off)
    for e, wps in polys:
        pts = _clean([cell(x, y) for x, y in wps])
        if len(pts) < 2:
            continue
        _snap_ports(g, e, pts)
        pts = _clean(pts)
        routes.append(G.Route(edge=e, pts=pts, head=True, tail=True,
                              flipped=False))
        right = max(right, max(c for _, c in pts) + 1)
    return right + COMPONENT_GAP


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
        return [n for n in by_col.get(c0, ())
                if n.y < hi and lo < n.bottom]
    lo, hi = (c0, c1) if c0 <= c1 else (c1, c0)
    return [n for n in by_row.get(r0, ())
            if n.x < hi and lo < n.right]


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
    moved = 0
    for rt in routes:
        for i in range(1, len(rt.pts) - 2):
            p, q = rt.pts[i], rt.pts[i + 1]
            for _ in range(4):
                hit = _hits(by_col, by_row, p, q)
                if not hit:
                    break
                n = hit[0]
                if p[1] == q[1]:                       # vertical: shift column
                    col = p[1]
                    out = n.x - 1                      # nearest side of the box
                    if col - n.x > n.right - col or out < 0:
                        out = n.right + 1              # never detour off-canvas
                    p, q = (p[0], out), (q[0], out)
                else:                                  # horizontal: shift row
                    row = p[0]
                    out = n.y - 1
                    if row - n.y > n.bottom - row or out < 0:
                        out = n.bottom + 1
                    p, q = (out, p[1]), (out, q[1])
                rt.pts[i], rt.pts[i + 1] = p, q
                moved += 1
    return moved


def _verify(g: G._Graph, routes: list[G.Route]) -> None:
    """Raise if any segment still crosses a box, so ``layout()`` falls back.

    The invariant is worth more than the engine: a layout with more crossings
    beats one that draws edges through the code.
    """
    by_col, by_row = _box_index(g)
    for rt in routes:
        for p, q in zip(rt.pts, rt.pts[1:]):
            hit = _hits(by_col, by_row, p, q)
            if hit:
                raise RuntimeError(
                    f"edge {rt.edge.src}->{rt.edge.dst} crosses block "
                    f"{hit[0].id} at {p}-{q} and could not be detoured")


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
    if pts[1][1] == old_c:            # the first segment was vertical: keep it
        pts[1] = (pts[1][0], col)

    # head: dst's top border if the edge arrives downward, its bottom if not
    old_r, old_c = pts[-1]
    col = clamp(dst, old_c)
    pts[-1] = (dst.y if pts[-2][0] <= old_r else dst.bottom, col)
    if pts[-2][1] == old_c:
        pts[-2] = (pts[-2][0], col)
