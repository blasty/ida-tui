"""Layered control-flow-graph layout, in character cells.

Pure python: no IDA, no Textual, no I/O. That is deliberate — it means the whole
layout can be unit-tested offline in milliseconds (``tests/test_graph.py``) and
iterated without an idalib worker, and it keeps the hard algorithmic part away
from the UI.

The pipeline is textbook Sugiyama, the same shape IDA's own graph uses:

  1. break cycles   DFS gray-set; back edges are reversed for layout only
  2. layer          longest-path ranking on the resulting DAG
  3. dummies        an edge spanning k layers becomes a chain of k-1 dummy
                    nodes, so every segment is between ADJACENT layers and long
                    edges reserve real horizontal space (this is what makes it
                    impossible for an edge to need to cross a box)
  4. order          median sweeps + adjacent transposition, to cut crossings
  5. x-coords       priority/median sweeps, variable node widths
  6. route          ports on node borders, one lane-packed channel per layer gap

Sizing is injected (``sizer``) rather than computed here, so the caller decides
how wide a block is at the current zoom level without this module knowing
anything about text.

The result is NOT a painted canvas. A big function lays out to millions of
cells, so ``Painting`` is an *index* — per-row horizontal runs, a bucketed
interval index of vertical runs, and point marks — and the view asks it for one
row at a time (``cells_at_row``), exactly like the listing's ``render_line``.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

_LOG = logging.getLogger(__name__)

# Terminal cells are about twice as tall as they are wide, so horizontal gaps
# need roughly 2x the cell count of vertical gaps to look square.
HGAP = 3  # min columns between two boxes in a layer
VGAP = 1  # min rows between a layer band and the channel below it

# Edge classes, used as style keys by the renderer.
E_UNCOND = "uncond"
E_TRUE = "jump"
E_FALSE = "fall"
E_SWITCH = "switch"
E_BACK = "back"


@dataclass
class Block:
    """One basic block, as the backend reports it."""

    id: int
    start: int
    end: int
    succs: list[tuple[int, str]] = field(default_factory=list)
    selfloop: bool = False


@dataclass
class Node:
    """A laid-out box (``block`` set) or a routing dummy (``block`` None)."""

    id: int
    block: Block | None = None
    label: str = ""
    rank: int = 0
    order: int = 0
    x: int = 0  # left column
    y: int = 0  # top row
    w: int = 1
    h: int = 1

    @property
    def dummy(self) -> bool:
        return self.block is None

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def bottom(self) -> int:
        return self.y + self.h - 1

    @property
    def right(self) -> int:
        return self.x + self.w - 1

    def contains(self, row: int, col: int) -> bool:
        return self.y <= row <= self.bottom and self.x <= col <= self.right

    def inside(self, row: int, col: int) -> bool:
        """Strictly inside the border (where text lives)."""
        return (self.y < row < self.bottom) and (self.x < col < self.right)


@dataclass
class Edge:
    src: int
    dst: int
    kind: str = E_UNCOND
    back: bool = False
    chain: list[int] = field(default_factory=list)
    #: ``src``/``dst`` are swapped relative to control flow. The native engine
    #: reverses back edges so layering sees a DAG; the triskel engine handles
    #: cycles itself and leaves them alone. Everything downstream that has to
    #: recover the real direction (succ/pred, arrowheads) reads THIS, not
    #: ``back`` -- which is now purely a style bit.
    flipped: bool = False

    @property
    def style(self) -> str:
        return E_BACK if self.back else self.kind


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[int, Node] = {}
        self.edges: list[Edge] = []
        self._next = 0

    def add(self, n: Node) -> Node:
        self.nodes[n.id] = n
        self._next = max(self._next, n.id + 1)
        return n

    def new_dummy(self) -> Node:
        n = Node(id=self._next, w=1, h=1)
        return self.add(n)


# ------------------------------------------------------------ 1. cycles


def _break_cycles(g: _Graph, root: int) -> None:
    """Reverse back edges (DFS gray-set) so layering sees a DAG."""
    color: dict[int, int] = {}
    adj: dict[int, list[Edge]] = {i: [] for i in g.nodes}
    for e in g.edges:
        adj[e.src].append(e)
    for start in [root] + [i for i in g.nodes if i != root]:
        if color.get(start):
            continue
        color[start] = 1
        stack = [(start, iter(adj[start]))]
        while stack:
            node, it = stack[-1]
            for e in it:
                c = color.get(e.dst, 0)
                if c == 1:
                    e.back = True
                elif c == 0:
                    color[e.dst] = 1
                    stack.append((e.dst, iter(adj[e.dst])))
                    break
            else:
                color[node] = 2
                stack.pop()
    for e in g.edges:
        if e.back:
            e.src, e.dst = e.dst, e.src
            e.flipped = True


# --------------------------------------------------------- 2. layering


def _assign_ranks(g: _Graph, root: int) -> None:
    """Longest-path layering: rank(v) = 1 + max(rank(preds)).

    Kahn, but it never trusts that ``_break_cycles`` left a perfect DAG: if the
    ready queue drains with nodes left over (a residual cycle, or a block only
    reachable through a reversed edge) it force-releases the most-constrained
    survivor instead of stranding it at rank 0. Getting this wrong collapses the
    whole graph into three layers and looks like a layout bug, not a ranking one.
    """
    indeg = {i: 0 for i in g.nodes}
    adj: dict[int, list[int]] = {i: [] for i in g.nodes}
    for e in g.edges:
        indeg[e.dst] += 1
        adj[e.src].append(e.dst)

    rank = {i: 0 for i in g.nodes}
    done: set[int] = set()
    ready = [i for i in g.nodes if indeg[i] == 0] or [root]
    pending = dict(indeg)
    while len(done) < len(g.nodes):
        if not ready:
            left = [i for i in g.nodes if i not in done]
            ready = [min(left, key=lambda i: (pending[i], rank[i], i))]
        i = ready.pop(0)
        if i in done:
            continue
        done.add(i)
        for j in adj[i]:
            if rank[j] < rank[i] + 1:
                rank[j] = rank[i] + 1
            pending[j] -= 1
            if pending[j] <= 0 and j not in done:
                ready.append(j)
    for i, n in g.nodes.items():
        n.rank = rank[i]


# ---------------------------------------------------------- 3. dummies


def _add_dummies(g: _Graph) -> None:
    for e in list(g.edges):
        span = g.nodes[e.dst].rank - g.nodes[e.src].rank
        if span <= 0:
            e.back = True  # residual cycle: colour it, route it flat
        chain = [e.src]
        if span > 1:
            for r in range(g.nodes[e.src].rank + 1, g.nodes[e.dst].rank):
                d = g.new_dummy()
                d.rank = r
                chain.append(d.id)
        chain.append(e.dst)
        e.chain = chain


def _layers_of(g: _Graph) -> list[list[int]]:
    top = max((n.rank for n in g.nodes.values()), default=0)
    layers: list[list[int]] = [[] for _ in range(top + 1)]
    for i, n in g.nodes.items():
        layers[n.rank].append(i)
    return layers


def _segments(g: _Graph) -> list[tuple[int, int, Edge]]:
    out = []
    for e in g.edges:
        for a, b in zip(e.chain, e.chain[1:]):
            out.append((a, b, e))
    return out


# ---------------------------------------------------------- 4. ordering


def _neighbors(g: _Graph) -> tuple[dict[int, list[int]], dict[int, list[int]]]:
    down: dict[int, list[int]] = {i: [] for i in g.nodes}
    up: dict[int, list[int]] = {i: [] for i in g.nodes}
    for a, b, _ in _segments(g):
        down[a].append(b)
        up[b].append(a)
    return down, up


def _cross_below(
    layer: list[int], down: dict[int, list[int]], pos: dict[int, int]
) -> int:
    """Crossings between this layer and the one below, counted as inversions
    with a Fenwick tree: O(E log E). The naive O(E^2) version is the entire
    runtime on a 400-block function (20s vs 150ms), so it is not an option."""
    pairs = []
    for u in layer:
        for v in down[u]:
            pairs.append((pos[u], pos[v]))
    if not pairs:
        return 0
    pairs.sort()
    size = max(p[1] for p in pairs) + 2
    tree = [0] * (size + 1)
    total = seen = 0
    for _, v in pairs:
        i = v + 1
        acc, j = 0, i
        while j > 0:
            acc += tree[j]
            j -= j & -j
        total += seen - acc
        seen += 1
        j = i
        while j <= size:
            tree[j] += 1
            j += j & -j
    return total


def _pair_cross(a: int, b: int, side: dict[int, list[int]], pos: dict[int, int]) -> int:
    """Crossings from a's and b's edges to one neighbouring layer given a sits
    immediately LEFT of b. Local — O(deg(a)*deg(b)) — so the transposition pass
    never has to recount the whole graph per candidate swap."""
    n = 0
    for u in side[a]:
        pu = pos[u]
        for v in side[b]:
            if pu > pos[v]:
                n += 1
    return n


def _swap_delta(
    a: int,
    b: int,
    down: dict[int, list[int]],
    up: dict[int, list[int]],
    pos: dict[int, int],
) -> tuple[int, int]:
    """``(keep, swap)`` for the adjacent pair (a, b), both sides, in one pass.

    The same as calling :func:`_pair_cross` four times, which is what the
    transposition loop used to do: every neighbour pair was visited twice (once
    per direction) and each visit was a python call. Counting both outcomes
    while the pair is in hand halves the comparisons and removes three calls per
    candidate swap — and this runs a third of a million times over a corpus.
    """
    keep = swap = 0
    for side in (down, up):
        va = side[a]
        vb = side[b]
        if not va or not vb:
            continue
        pbs = [pos[v] for v in vb]
        for u in va:
            pu = pos[u]
            for pv in pbs:
                if pu > pv:
                    keep += 1
                elif pu < pv:
                    swap += 1
    return keep, swap


def crossings(
    layers: list[list[int]], down: dict[int, list[int]], pos: dict[int, int]
) -> int:
    return sum(_cross_below(l, down, pos) for l in layers)


def _order_layers(g: _Graph, root: int, sweeps: int = 6) -> list[list[int]]:
    layers = _layers_of(g)
    down, up = _neighbors(g)

    # Seed with a DFS preorder so the picture already resembles control flow
    # (fallthrough-first); barycenter alone does not recover that.
    seed: dict[int, int] = {}
    stack, seen, tick = [root], {root}, 0
    while stack:
        i = stack.pop()
        seed[i] = tick
        tick += 1
        for j in reversed(down.get(i, [])):
            if j not in seen:
                seen.add(j)
                stack.append(j)
    for layer in layers:
        layer.sort(key=lambda i: seed.get(i, 10**9))
    pos = {i: k for layer in layers for k, i in enumerate(layer)}

    def median(i: int, side: dict[int, list[int]]) -> float:
        # Almost every node in a control-flow graph has one or two neighbours
        # on a given side, so answer those without building and sorting a list:
        # this runs tens of thousands of times per corpus layout.
        js = side[i]
        n = len(js)
        if n == 1:
            return float(pos[js[0]])
        if n == 2:
            return (pos[js[0]] + pos[js[1]]) / 2
        if not n:
            return -1.0
        ps = sorted(pos[j] for j in js)
        m = n // 2
        return float(ps[m]) if n % 2 else (ps[m - 1] + ps[m]) / 2

    best, best_x = [list(l) for l in layers], crossings(layers, down, pos)
    for s in range(sweeps):
        rng = range(1, len(layers)) if s % 2 == 0 else range(len(layers) - 2, -1, -1)
        side = up if s % 2 == 0 else down
        for r in rng:
            layer = layers[r]
            keys = {i: median(i, side) for i in layer}
            layer.sort(key=lambda i: (keys[i] if keys[i] >= 0 else pos[i], pos[i]))
            for k, i in enumerate(layer):
                pos[i] = k
        for _ in range(4):
            improved = False
            for layer in layers:
                for k in range(len(layer) - 1):
                    a, b = layer[k], layer[k + 1]
                    keep, swap = _swap_delta(a, b, down, up, pos)
                    if swap < keep:
                        layer[k], layer[k + 1] = b, a
                        pos[a], pos[b] = k + 1, k
                        improved = True
            if not improved:
                break
        x = crossings(layers, down, pos)
        if x < best_x:
            best, best_x = [list(l) for l in layers], x

    layers = best
    for layer in layers:
        for k, i in enumerate(layer):
            g.nodes[i].order = k
    return layers


# --------------------------------------------------------- 5. x coords


def _assign_x(g: _Graph, layers: list[list[int]], sweeps: int = 8) -> None:
    down, up = _neighbors(g)
    for layer in layers:
        x = 0
        for i in layer:
            g.nodes[i].x = x
            x += g.nodes[i].w + HGAP

    def pack(layer: list[int]) -> None:
        for k in range(1, len(layer)):
            a, b = g.nodes[layer[k - 1]], g.nodes[layer[k]]
            if b.x < a.x + a.w + HGAP:
                b.x = a.x + a.w + HGAP
        for k in range(len(layer) - 2, -1, -1):
            a, b = g.nodes[layer[k]], g.nodes[layer[k + 1]]
            if a.x + a.w + HGAP > b.x:
                a.x = b.x - HGAP - a.w

    for s in range(sweeps):
        rng = range(1, len(layers)) if s % 2 == 0 else range(len(layers) - 2, -1, -1)
        side = up if s % 2 == 0 else down
        for r in rng:
            layer = layers[r]
            # dummies first: keeping long edges straight matters most
            order = sorted(
                layer, key=lambda i: (not g.nodes[i].dummy, g.nodes[i].order)
            )
            for i in order:
                nb = side[i]
                if not nb:
                    continue
                cs = sorted(g.nodes[j].cx for j in nb)
                m = len(cs) // 2
                target = cs[m] if len(cs) % 2 else (cs[m - 1] + cs[m]) / 2
                g.nodes[i].x = int(round(target - g.nodes[i].w / 2))
            pack(layer)

    lo = min((g.nodes[i].x for layer in layers for i in layer), default=0)
    for n in g.nodes.values():
        n.x -= lo


# ------------------------------------------------------------ 6. route


def _ports(g: _Graph) -> tuple[dict, dict]:
    """Spread a node's out-edges along its bottom border and its in-edges along
    its top, each ordered by the other end's x so they don't cross at the node."""
    out_port: dict[tuple, int] = {}
    in_port: dict[tuple, int] = {}
    by_src: dict[int, list] = {}
    by_dst: dict[int, list] = {}
    for a, b, e in _segments(g):
        by_src.setdefault(a, []).append((a, b, e))
        by_dst.setdefault(b, []).append((a, b, e))

    def spread(n: Node, k: int, count: int) -> int:
        if n.dummy or count <= 1:
            return int(n.cx)
        usable = max(n.w - 4, 1)
        step = usable / (count + 1)
        return int(n.x + 2 + step * (k + 1))

    for i, lst in by_src.items():
        lst.sort(key=lambda t: g.nodes[t[1]].cx)
        for k, (a, b, e) in enumerate(lst):
            out_port[(a, b, id(e))] = spread(g.nodes[i], k, len(lst))
    for i, lst in by_dst.items():
        lst.sort(key=lambda t: g.nodes[t[0]].cx)
        for k, (a, b, e) in enumerate(lst):
            in_port[(a, b, id(e))] = spread(g.nodes[i], k, len(lst))
    return out_port, in_port


@dataclass
class Route:
    edge: Edge
    pts: list[tuple[int, int]]
    head: bool = True  # arrowhead (target is a real block)
    tail: bool = True  # port tee (source is a real block)
    #: the polyline is drawn against control flow (a reversed back edge), so the
    #: arrowhead belongs at ``pts[0]`` and the port tee at ``pts[-1]``.
    flipped: bool = False


def _route(g: _Graph, layers: list[list[int]]) -> list[Route]:
    out_port, in_port = _ports(g)
    segs = _segments(g)
    by_rank: dict[int, list] = {}
    for a, b, e in segs:
        by_rank.setdefault(g.nodes[a].rank, []).append((a, b, e))

    lanes: dict[tuple, int] = {}
    channels = [1] * len(layers)
    for r, lst in by_rank.items():
        runs = []
        for a, b, e in lst:
            x0, x1 = out_port[(a, b, id(e))], in_port[(a, b, id(e))]
            if x0 != x1:  # a straight drop needs no lane
                runs.append((min(x0, x1), max(x0, x1), (a, b, id(e))))
        runs.sort(key=lambda t: (t[1] - t[0], t[0]))
        occupied: list[list[tuple[int, int]]] = []
        for lo, hi, key in runs:
            for li, used in enumerate(occupied):
                if all(hi < u_lo or lo > u_hi for u_lo, u_hi in used):
                    used.append((lo, hi))
                    lanes[key] = li
                    break
            else:
                occupied.append([(lo, hi)])
                lanes[key] = len(occupied) - 1
        channels[r] = max(len(occupied), 1)

    # y: a band per layer, then the routing channel underneath it. Horizontal
    # runs live in the channel BELOW A WHOLE LAYER, never at a per-node offset
    # -- that is what stops an edge sawing through a taller neighbour.
    chan_y = []
    y = 0
    for r, layer in enumerate(layers):
        h = max((g.nodes[i].h for i in layer if not g.nodes[i].dummy), default=1)
        for i in layer:
            n = g.nodes[i]
            n.y = y
            if n.dummy:
                n.h = h  # the band is its pass-through
        chan_y.append(y + h - 1 + VGAP)
        y += h - 1 + VGAP + channels[r] + VGAP + 1

    def exit_y(n: Node) -> int:
        # a dummy leaves from the TOP of its band: its own outgoing segment
        # draws the vertical that passes through the band.
        return n.y if n.dummy else n.bottom

    routes = []
    for a, b, e in segs:
        na, nb = g.nodes[a], g.nodes[b]
        x0, x1 = out_port[(a, b, id(e))], in_port[(a, b, id(e))]
        y0, y1 = exit_y(na), nb.y
        if x0 == x1:
            pts = [(y0, x0), (y1, x1)]
        else:
            ych = chan_y[na.rank] + lanes.get((a, b, id(e)), 0)
            pts = [(y0, x0), (ych, x0), (ych, x1), (y1, x1)]
        routes.append(
            Route(
                edge=e, pts=pts, head=not nb.dummy, tail=not na.dummy, flipped=e.flipped
            )
        )
    return routes


# ------------------------------------------------------------ painting

BOX = {
    "tl": "\u250c",
    "tr": "\u2510",
    "bl": "\u2514",
    "br": "\u2518",
    "h": "\u2500",
    "v": "\u2502",
}
LINE_CHARS = set(
    "\u2502\u2500\u250c\u2510\u2514\u2518\u251c\u2524\u252c\u2534"
    "\u253c\u256d\u256e\u2570\u256f"
)
MERGE = {
    frozenset("\u2502\u2500"): "\u253c",
    frozenset("\u2502\u250c"): "\u251c",
    frozenset("\u2502\u2510"): "\u2524",
    frozenset("\u2502\u2514"): "\u251c",
    frozenset("\u2502\u2518"): "\u2524",
    frozenset("\u2500\u250c"): "\u252c",
    frozenset("\u2500\u2510"): "\u252c",
    frozenset("\u2500\u2514"): "\u2534",
    frozenset("\u2500\u2518"): "\u2534",
    frozenset("\u2502\u256d"): "\u251c",
    frozenset("\u2502\u256e"): "\u2524",
    frozenset("\u2502\u2570"): "\u251c",
    frozenset("\u2502\u256f"): "\u2524",
    frozenset("\u2500\u256d"): "\u252c",
    frozenset("\u2500\u256e"): "\u252c",
    frozenset("\u2500\u2570"): "\u2534",
    frozenset("\u2500\u256f"): "\u2534",
}
CORNER = {
    ("D", "R"): "\u2570",
    ("D", "L"): "\u256f",
    ("R", "D"): "\u256e",
    ("L", "D"): "\u256d",
    ("R", "U"): "\u256f",
    ("L", "U"): "\u2570",
    ("U", "R"): "\u256d",
    ("U", "L"): "\u256e",
}
BUCKET = 32  # rows per vertical-run index bucket


def _dir(p: tuple[int, int], q: tuple[int, int]) -> str:
    if p[0] == q[0]:
        return "R" if q[1] > p[1] else "L"
    return "D" if q[0] > p[0] else "U"


class Painting:
    """A queryable drawing of the edges. Never a full canvas: a 400-block
    function is ~13M cells, so runs are stored as intervals and asked for one
    row at a time."""

    def __init__(self) -> None:
        self.hruns: dict[int, list[tuple[int, int, str, int]]] = {}
        self.vruns: list[tuple[int, int, int, str, int]] = []
        self.vindex: dict[int, list[int]] = {}
        self.marks: dict[int, list[tuple[int, str, str, int]]] = {}

    def add_h(self, row: int, c0: int, c1: int, style: str, eid: int) -> None:
        self.hruns.setdefault(row, []).append((min(c0, c1), max(c0, c1), style, eid))

    def add_v(self, r0: int, r1: int, col: int, style: str, eid: int) -> None:
        lo, hi = (r0, r1) if r0 <= r1 else (r1, r0)
        idx = len(self.vruns)
        self.vruns.append((lo, hi, col, style, eid))
        for b in range(lo // BUCKET, hi // BUCKET + 1):
            self.vindex.setdefault(b, []).append(idx)

    def add_mark(self, row: int, col: int, ch: str, style: str, eid: int) -> None:
        self.marks.setdefault(row, []).append((col, ch, style, eid))

    def cells_at_row(
        self, row: int, c0: int, c1: int
    ) -> dict[int, tuple[str, str, int]]:
        """{col: (char, style, edge_id)} for ``row`` within [c0, c1)."""
        out: dict[int, tuple[str, str, int]] = {}

        def put(col: int, ch: str, style: str, eid: int, force: bool = False) -> None:
            if col < c0 or col >= c1:
                return
            old = out.get(col)
            if (
                old
                and not force
                and old[0] != ch
                and old[0] in LINE_CHARS
                and ch in LINE_CHARS
            ):
                ch = MERGE.get(frozenset((old[0], ch)), ch)
            out[col] = (ch, style, eid)

        for lo, hi, style, eid in self.hruns.get(row, ()):
            for c in range(max(lo, c0), min(hi + 1, c1)):
                put(c, BOX["h"], style, eid)
        for i in self.vindex.get(row // BUCKET, ()):
            lo, hi, col, style, eid = self.vruns[i]
            if lo <= row <= hi:
                put(col, BOX["v"], style, eid)
        for col, ch, style, eid in self.marks.get(row, ()):
            put(col, ch, style, eid, force=True)
        return out


@dataclass
class Layout:
    """The finished drawing: boxes, an edge index, and enough structure for the
    view to hit-test, navigate and highlight."""

    nodes: list[Node]  # real blocks only, layout order
    by_id: dict[int, Node]
    edges: list[Edge]
    painting: Painting
    width: int
    height: int
    entry: int
    rows: dict[int, list[int]]  # row -> real node ids covering it
    incident: dict[int, set[int]]  # node id -> edge ids touching it
    succ: dict[int, list[tuple[int, str]]]  # node id -> [(node id, style)]
    pred: dict[int, list[tuple[int, str]]]
    stats: dict

    def node_at(self, row: int, col: int) -> Node | None:
        for nid in self.rows.get(row, ()):
            n = self.by_id[nid]
            if n.x <= col <= n.right:
                return n
        return None

    def nodes_at_row(self, row: int) -> list[Node]:
        return [self.by_id[i] for i in self.rows.get(row, ())]

    def edge_at(self, row: int, col: int) -> Edge | None:
        cells = self.painting.cells_at_row(row, col, col + 1)
        hit = cells.get(col)
        if hit is None:
            return None
        for e in self.edges:
            if id(e) == hit[2]:
                return e
        return None


def _build(blocks: list[Block], sizer, entry: int | None) -> tuple[_Graph, int]:
    """The block list as a layout graph, plus the entry node id.

    Shared by both engines, and re-run from scratch if one of them has to fall
    back, because an engine positions nodes in place.
    """
    g = _Graph()
    for b in blocks:
        w, h = sizer(b)
        b.selfloop = False
        g.add(
            Node(
                id=b.id,
                block=b,
                label=f"loc_{b.start:X}",
                w=max(int(w), 4),
                h=max(int(h), 3),
            )
        )
    for b in blocks:
        outs = [(d, k) for d, k in b.succs if d in g.nodes]
        for dst, kind in outs:
            if dst == b.id:
                # A self-loop constrains nothing, deadlocks the Kahn ranking
                # (its own in-degree never drains) and makes triskel throw
                # "EMPTY BL" from its bracket lists. Drawn as a marker instead.
                b.selfloop = True
                continue
            if len(outs) == 1:
                kind = E_UNCOND
            g.edges.append(Edge(src=b.id, dst=dst, kind=kind))

    root = entry if entry in g.nodes else (min(g.nodes) if g.nodes else 0)
    return g, root


def _native_engine(g: _Graph, root: int) -> tuple[list[Route], int]:
    """Layered Sugiyama in cells: the pipeline documented at the top."""
    _break_cycles(g, root)
    _assign_ranks(g, root)
    _add_dummies(g)
    layers = _order_layers(g, root)
    _assign_x(g, layers)
    return _route(g, layers), len(layers)


#: Engine names accepted by ``layout(engine=...)`` and ``IDATUI_GRAPH_ENGINE``.
ENGINES = ("auto", "native", "triskel")

#: Above this many blocks ``auto`` stays native. Layout runs on every open and
#: every zoom keypress, so this is an interactivity budget, not a correctness
#: one. Triskel's cost knees hard (measured on `ls`, 400 functions):
#:
#:     blocks   174    233    256    329    424    495
#:     native    25     72     23     93    144    203  ms
#:     triskel   66    489    266    555   1501   1968  ms
#:
#: 180 keeps the worst auto-triskel layout in the tens of milliseconds. Raising
#: it buys prettier pictures of graphs nobody can read anyway -- the view
#: refuses to draw past 400 blocks at all.
AUTO_TRISKEL_MAX_BLOCKS = 180


def _pick_engine(engine: str | None, nblocks: int) -> str:
    want = (engine or os.environ.get("IDATUI_GRAPH_ENGINE") or "auto").lower()
    if want not in ENGINES:
        want = "auto"
    if want == "auto":
        from . import graph_triskel

        if nblocks <= AUTO_TRISKEL_MAX_BLOCKS and graph_triskel.available():
            return "triskel"
        return "native"
    return want


def layout(
    blocks: list[Block], sizer, entry: int | None = None, engine: str | None = None
) -> Layout:
    """Lay out ``blocks``. ``sizer(block) -> (width, height)`` in cells.

    ``engine`` picks the layout backend: ``native`` (pure python, always
    available), ``triskel`` (SESE decomposition via the C++ library, far fewer
    crossings) or ``auto``. Defaults to ``$IDATUI_GRAPH_ENGINE`` or ``auto``.
    A triskel failure is never fatal: it falls back to native.
    """
    t0 = time.perf_counter()
    name = _pick_engine(engine, len(blocks))
    g, root = _build(blocks, sizer, entry)

    layers = 0
    err = None
    if not g.nodes:
        routes = []
    elif name == "triskel":
        from . import graph_triskel

        try:
            routes, layers = graph_triskel.run(g, root)
        except Exception as exc:  # noqa: BLE001
            # Native code with a history of throwing on degenerate CFGs. The
            # graph view is a convenience; losing it beats losing the session.
            # Keep the REASON: a fallback the user can see but not explain is
            # only marginally better than a crash.
            _LOG.warning("triskel layout failed (%s), falling back", exc)
            name, err = "native (triskel failed)", f"{type(exc).__name__}: {exc}"
            g, root = _build(blocks, sizer, entry)
            routes, layers = _native_engine(g, root)
    else:
        routes, layers = _native_engine(g, root)

    # ---- paint into the index -----------------------------------------
    p = Painting()
    real = [n for n in g.nodes.values() if not n.dummy]
    rows: dict[int, list[int]] = {}
    for n in real:
        for r in range(n.y, n.y + n.h):
            rows.setdefault(r, []).append(n.id)
    for lst in rows.values():
        lst.sort(key=lambda i: g.nodes[i].x)

    def blocked(row: int, col: int) -> bool:
        for nid in rows.get(row, ()):
            if g.nodes[nid].inside(row, col):
                return True
        return False

    incident: dict[int, set[int]] = {n.id: set() for n in real}
    for rt in routes:
        e, style, eid = rt.edge, rt.edge.style, id(rt.edge)
        incident.setdefault(e.src, set()).add(eid)
        incident.setdefault(e.dst, set()).add(eid)
        for (r0, c0), (r1, c1) in zip(rt.pts, rt.pts[1:]):
            if r0 == r1:
                p.add_h(r0, c0, c1, style, eid)
            else:
                p.add_v(r0, r1, c0, style, eid)
        for k in range(1, len(rt.pts) - 1):
            a, b, c = rt.pts[k - 1], rt.pts[k], rt.pts[k + 1]
            ch = CORNER.get((_dir(a, b), _dir(b, c)))
            if ch and not blocked(*b):
                p.add_mark(b[0], b[1], ch, style, eid)
        # Where the arrowhead goes is a question about CONTROL FLOW, not about
        # geometry. The native engine reverses back edges for layering, so their
        # polyline runs from the loop HEAD down to the tail and the arrow
        # belongs at the start, pointing up into the block control returns to.
        # The triskel engine keeps the real direction and routes the loop around
        # the side of the graph, so the arrow is at the end like any other edge.
        # ``rt.flipped`` is the only thing that distinguishes the two.
        first, last = rt.pts[0], rt.pts[-1]
        down_first = rt.pts[1][0] > first[0] if len(rt.pts) > 1 else True
        down_last = last[0] > rt.pts[-2][0] if len(rt.pts) > 1 else True
        if rt.flipped:
            if rt.tail:
                p.add_mark(
                    first[0], first[1], "\u25b2" if down_first else "\u25bc", style, eid
                )
            if rt.head:
                p.add_mark(
                    last[0], last[1], "\u2534" if down_last else "\u252c", style, eid
                )
        else:
            if rt.tail:
                p.add_mark(
                    first[0], first[1], "\u252c" if down_first else "\u2534", style, eid
                )
            if rt.head:
                p.add_mark(
                    last[0], last[1], "\u25bc" if down_last else "\u25b2", style, eid
                )

    succ: dict[int, list[tuple[int, str]]] = {n.id: [] for n in real}
    pred: dict[int, list[tuple[int, str]]] = {n.id: [] for n in real}
    for e in g.edges:
        a, b = (e.dst, e.src) if e.flipped else (e.src, e.dst)  # undo reversal
        if a in succ:
            succ[a].append((b, e.style))
        if b in pred:
            pred[b].append((a, e.style))

    # The canvas has to cover the EDGES too, not just the boxes. Under the
    # native engine that is the same thing -- dummy nodes reserve space, so no
    # edge is ever outside the boxes' bounding box. Triskel routes a loop around
    # the side of the graph, past every node, and sizing on boxes alone clipped
    # exactly the edges that make its layouts worth having.
    width = max((n.right + 1 for n in real), default=1)
    height = max((n.y + n.h for n in real), default=1)
    for rt in routes:
        for r, c in rt.pts:
            width = max(width, c + 1)
            height = max(height, r + 1)
    order = sorted(real, key=lambda n: (n.rank, n.order))
    stats = {
        "blocks": len(blocks),
        "nodes": len(g.nodes),
        "dummies": len(g.nodes) - len(real),
        "layers": layers,
        "edges": len(g.edges),
        "back": sum(1 for e in g.edges if e.back),
        "engine": name,
        "engine_error": err,
        "ms": (time.perf_counter() - t0) * 1000,
    }
    return Layout(
        nodes=order,
        by_id={n.id: n for n in g.nodes.values()},
        edges=g.edges,
        painting=p,
        width=width,
        height=height,
        entry=root,
        rows=rows,
        incident=incident,
        succ=succ,
        pred=pred,
        stats=stats,
    )
