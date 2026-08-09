# Triskel for graph layout — evaluated, forked, integrated

> **Outcome.** Shipped as the `triskel` engine behind `graph.layout(engine=...)`,
> preferred by `auto` up to 250 blocks, off a local fork
> (`~/dev/triskel`, branch `idatui`, see its `PATCHES.md`). The library needed
> six fixes before it could be used from Python at all — including a segfault
> and a binding bug that made edge routes unreachable. Everything below is the
> evaluation that led there; `docs/GRAPH_VIEW.md` documents what shipped.


[triskel](https://github.com/triskellib/triskel) (MPL-2.0, C++23, 126★) is a CFG
layout engine from Inria, the implementation of *[Towards better CFG
layouts](https://hal.science/hal-04996939)*. Its idea is genuinely better than
ours: before running Sugiyama, split the CFG into **Single-Entry Single-Exit
(SESE) regions**, lay each region out on its own, then paste the region layouts
back in as single super-nodes. Divide and conquer, so crossings stay local.

This is what happened when we actually ran it against `idatui.graph` on the
128-function corpus in `.auto/cfg-corpus.json`.

**Verdict as first written: don't link the library, port the idea.** That was
reversed after the blockers turned out to be six small, independent patches
rather than algorithm work — and one of them (settable spacing) removed the
quantisation problem entirely instead of managing it. Reimplementing 350 lines
of cycle-equivalence C++ in Python to avoid a `#include` would have been a poor
trade. The licensing note at the end is why the fork stays a fork: MPL-2.0 is
file-level copyleft, so linking it costs us nothing, and our changes to *their*
files stay in *their* repo.

## The quality gap is real

Both engines fed identical blocks and identical cell sizes (triskel gets them as
"pixels" at 16×32 per cell). Crossings are proper segment intersections counted
on each engine's own edge polylines; `X` is that count, `None` = above the
counting cap.

```
 blk  edge |  ours ms     ours WxH      X |   tk ms  tk WxH(cells)      X | name
   9    14 |      0.5        89x62      5 |     0.3          81x71      1 | sub_61D0
  10    41 |      1.3        99x80     10 |     0.5         86x105      0 | sub_3500
  17    44 |      1.4      213x144      6 |     0.6        159x171      0 | sub_2FF0
  21    33 |      1.2      724x105     41 |     0.5        782x119      0 | sub_5CA0
  38   150 |      4.7      325x305     32 |     2.8        202x392      1 | sub_2C90
  87   428 |     14.8     1202x444   None |    30.3        850x775   None | main
 109   647 |     25.9      793x476   None |    53.6        363x970   None | sub_69C0
 424  3340 |    145.7    9222x1386   None |  1534.3      1872x3883   None | sub_3720
total ours 207 ms  triskel 1626 ms   (full corpus in /tmp/tk_cmp.py)
```

Two things to take from that table:

- **Crossings collapse to ~0.** Every function under 40 blocks lays out with 0
  or 1 crossing, where ours has up to 41. That is the SESE decomposition doing
  exactly what the paper claims.
- **Canvases get narrow and tall.** `sub_69C0`: 793×476 → 363×970. `sub_3720`:
  9222×1386 → 1872×3883. For a terminal that is the right trade — vertical
  scrolling is free, horizontal panning is the thing that makes our graph view
  feel like peering through a letterbox.

And it costs us on speed above ~40 blocks: 2× slower at 87–109 blocks, **10×
slower at 424** (1.5 s vs 145 ms). So it would not let us raise the 400-block
cap; it would argue for lowering it.

## The output *is* renderable in character cells

This was the thing that could have killed the idea outright, and it doesn't:

- **Every segment is axis-aligned.** 0 diagonal segments out of 1708 (`main`)
  and 2471 (`sub_69C0`). Box-drawing characters map straight onto it.
- **No edge is routed through a box.** The "edge cells inside a box" count comes
  out at exactly ~1 per edge — that is the polyline's first waypoint, which sits
  at the source node's *centre*. Clip the first and last segment to the border
  and it is clean.
- **Quantisation is a knob, not a wall.** Triskel packs edges in continuous
  space, so rounding to cells can drop two edges into one column. How often
  depends entirely on the px-per-cell we feed it (`main`, 140 edges):

  | px/cell | edge cells | cells shared by >1 edge |
  |---|---|---|
  | 8×16 | 50418 | 73 (0.1%) |
  | 12×24 | 41536 | 69 (0.2%) |
  | 16×32 | 36071 | 1026 (2.8%) |
  | 24×48 | 28113 | 4525 (16.1%) |

  The gutters are hardcoded constants (`X_GUTTER=50`, `Y_GUTTER=40`,
  `EDGE_HEIGHT=30`), so px-per-cell is really "how many cells of gutter do I
  buy". Cheap cells → wider canvas, unambiguous edges. This matters more for us
  than for a pixel renderer: an ambiguous cell isn't just ugly, it breaks
  click-to-select-edge and the incident-edge highlight, which assume a cell
  belongs to one edge. Our lane-packed channels exist to make that impossible.

## Why we can't just `pip install pytriskel` (all fixed in the fork)

1. **No wheel we can use.** All ten releases ship `manylinux_2_34_x86_64` wheels
   for cp37–cp313 and **no sdist**. Our venv is Python 3.14 → `pip install`
   finds nothing. It is also x86_64-Linux only: no macOS, no arm64, no Windows.
2. **The Python bindings can't return edge routes at all.** `pytriskel.cpp`
   never includes `<pybind11/stl.h>`, so `get_waypoints()` raises
   `Unable to convert function return value to a Python type` on every published
   version. The `.pyi` stub gives it away: `get_waypoints(self, arg0: int) -> ...`.
   From the shipped wheel you can get node coordinates and save a PNG — that is
   it. A one-line patch fixes it (verified locally).
3. **Building from source works but is heavy.** Verified here: clone, `cmake
   -DENABLE_CAIRO=ON -DBUILD_BINDINGS=ON`, ~2 minutes, produces a working
   `pytriskel.cpython-314-*.so`. But `BUILD_BINDINGS` is gated on
   `ENABLE_CAIRO`, so a user installing a *TUI* would need cmake, a C++23
   compiler, fmt and cairo dev headers to draw boxes made of `─`.
4. **It crashes the process on degenerate input.**
   - empty graph → **segfault** (not an exception — it takes the interpreter with
     it, and with it your session)
   - disconnected graph → `RuntimeError: EMPTY BL`, an internal bracket-list
     assertion leaking out. IDA flowcharts do contain unreachable blocks.

   Self-loops, parallel edges and 2-cycles are all handled fine.
5. **Rough edges in the API.** `make_node(float height, float width)` is
   documented in the Python stub as "with a width and height" — the arguments
   are the other way round (this cost us a benchmark run). `get_height` is bound
   twice, once over `get_width`, so graph width is unreachable from Python.
   Node sizes can't be read back, and the SESE tree isn't exposed.

## What we'd also lose

`graph.py` doesn't just return coordinates. It returns ranks and per-layer
order, which `w`/`b` navigation, the minimap and the RPC `graph show` verb all
read. Triskel exposes neither — we'd re-derive ordering from y coordinates.
And the whole engine is currently pure Python with no I/O, which is why
`tests/test_graph.py` runs offline in milliseconds against a 128-function
corpus. Linking a native layout engine costs us that property.

## What integration actually cost

Six patches to the fork (`~/dev/triskel/PATCHES.md`) and one new module,
`idatui/graph_triskel.py`. The patch that mattered most was making `X_GUTTER` /
`Y_GUTTER` / `EDGE_HEIGHT` settable: feeding the engine **cells instead of
pixels** (3 / 1 / 1) makes its output integral, so the whole quantisation
section above stops applying. Measured after the fact on the real pipeline, the
fear was backwards — cells claimed by more than one edge across the small-corpus
functions: **native 131, triskel 35**.

Three things stayed on our side of the boundary because they are the caller's
job, not the library's: self-loops (never passed — they throw), disconnected
components (laid out separately and stacked — they throw), and the one corpus
edge triskel routes through a block (detoured, then re-verified, else the whole
layout falls back to native).

The canvas also had to learn that edges can live outside the boxes' bounding
box: triskel routes a loop around the side of the graph, and sizing the canvas
on nodes alone — which is exact for the native engine, since its dummy nodes
reserve the space — clipped exactly the edges that make its layouts worth having.

## The road not taken: port the idea, not the code

The win is the SESE decomposition, and that is ~350 lines of C++
(`lib/src/analysis/sese.cpp`, cycle equivalence / program structure tree, plus
`udfs.cpp`) and the region orchestration in `layout.cpp`. In Python, on top of
the pipeline we already have, that is roughly:

1. undirected DFS + cycle equivalence → the program structure tree (~200 lines)
2. per-region layout: run our existing steps 2–5 on the region subgraph
3. collapse each region into a super-node in its parent, then translate

Steps 2 and 3 reuse `_assign_ranks` / `_order_layers` / `_assign_x` unchanged,
and — this is the point — **our cell-native router and lane packing survive**, so
we keep the 0-edge-cells-inside-a-box guarantee and unambiguous edge ownership
instead of inheriting a quantisation problem.

On licensing: MPL-2.0 is file-level copyleft. Linking the library unmodified
imposes nothing on our code; copying their source into `graph.py` would arguably
make that file MPL. Implementing from the paper and citing it keeps this clean.

Worth doing regardless, as upstream is friendly and we may want the library
later: file the missing `<pybind11/stl.h>`, the empty-graph segfault, and the
`make_node` docstring order.

## Reproducing

The throwaway scripts that produced the tables above (`/tmp/tk_*.py`, driving
pytriskel directly) have been replaced by one that drives the shipping pipeline:

```bash
python3 experiments/graph_compare.py .auto/cfg-corpus.json --real-sizer
```

and the engines are exercised side by side, on every invariant, by
`tests/test_graph.py` — which runs its whole suite once per available engine, so
"triskel draws no edge through a box" is checked on 128 real functions rather
than asserted here.
