# Graph view — the function's control flow, in character cells

**Space** swaps the code view for an IDA-style basic-block graph of the current
function. Space again returns to the text. It is opt-in, off by default, and
lives in its own module: with graph mode off nothing else in the app does any
extra work.

```
                    ┌─ sub_61D0 ──────────────────────┐
                    │ 000061D0  sub_61D0  endbr64     │        ┌─ 9 blocks ──────┐
                    │ 000061D4  push rbp              │        │    █████████    │
                    │ ...                             │        │   ·███████████  │
                    │ 00006200  jmp short loc_622C    │        │  ████·███████   │
                    └─────────────────┬───────────────┘        └─────────────────┘
                                      │
                   ┌─ loc_622C ───────▼─────────────────┐
                   │ 0000622C  loc_622C  mov eax, [rcx] │
                   │ 00006231  jbe short loc_6208       │
                   └──────────┬─────────────┬───────────┘
                    ╭─────────╯             ╰──────────╮
```

## Keys

| key | |
|---|---|
| `Space` | graph ⇄ text |
| `j` `k` | line up/down, crossing into the next/previous block |
| `h` `l` | column left / right |
| `J` `K` | follow an edge to a successor / predecessor block |
| `w` `b` | next / previous block in layout order |
| `0` | jump to the entry block |
| `z` | zoom: full → compact → collapsed |
| `m` | show / hide the minimap |
| `e` | layout engine: auto → native → triskel |
| `f` | centre on the current block |
| `Enter` | follow — stays in the graph when the target is a block of this function |
| `x` `n` `y` `;` | xrefs / rename / retype / comment, exactly as in the listing |
| `Tab` | leave for the pseudocode of the block you're on |
| mouse | drag to pan, click to place the cursor, double-click to follow |
| minimap | click to jump the view there, drag to scrub |

Graph mode is **sticky**: following a call from the graph lands in the callee's
graph rather than dumping you back in the listing.

## Why the boxes are cheap

A node's body is **the same `Head` rows the listing renders** — fetched with the
same `heads` tool, carrying IDA's own colour tags, names and operand text. That
is the whole reason this feature is a few hundred lines instead of a rewrite:
syntax highlighting, the word-under-cursor highlight, the execution trail and
every editing verb work inside a box because they are working on listing rows.
Growing a second disassembly renderer for graph mode would have been the real
cost.

The backend adds exactly one operation, `flowchart(addr)` in
`idatui/codemode_client.py`, which returns block ranges and typed edges — **not**
text.

## Two layout engines

`graph.layout(blocks, sizer, engine=...)` takes `auto` (the default, also
`$IDATUI_GRAPH_ENGINE`), `native` or `triskel`, and `e` cycles them in the view.
`auto` prefers **triskel** where it is installed and the function is at most 180
blocks, and falls back to **native** otherwise — including if triskel raises,
which is never fatal, and the status line then says why.

The 180 is an interactivity budget: layout runs on every open and every zoom
keypress, and triskel's cost knees hard just past it (174 blocks: 66 ms;
233 blocks: 489 ms; 329: 555 ms; 424: 1.5 s, against native's 25/72/93/144).

| | native | triskel |
|---|---|---|
| algorithm | layered Sugiyama, below | SESE decomposition ([paper](https://hal.science/hal-04996939)) |
| ships with | always, pure python | needs `pytriskel` (our fork) |
| shape | wide and short | narrow and tall |
| crossings | more | far fewer |
| 87-block `main` | 15 ms, 1202×444 | 37 ms, 845×789 |
| 424-block `sub_3720` | 145 ms | 1.5 s (so `auto` won't) |

On the 128-function corpus with realistic box sizes, triskel draws fewer
crossings on 12 functions, the same on 9, more on 3 — and the wins are where it
matters: `sub_5CA0` 41 → 6, `sub_2C90` 32 → 7, `sub_2C00` 12 → 0. It also routes
loop edges around the side of the graph the way IDA does, instead of straight
back up the middle. It is not a clean sweep: on `sub_69C0` (109 blocks) its
narrower canvas packs edges tighter and it ends up with *more* cells shared
between edges than native (1280 vs 935).

`experiments/graph_compare.py` regenerates all of those numbers, and
`docs/TRISKEL_EVAL.md` is the full evaluation, including what had to be fixed in
triskel to make it usable at all.

### The triskel path (`idatui/graph_triskel.py`)

The whole impedance mismatch lives in that one module. Three things keep it
small: triskel's routes are already orthogonal (0 diagonal segments in 2471), its
ports already land spread along the box border, and — because our fork made the
spacing settable — **we hand it cell counts rather than pixels**, so nothing is
ever rounded and two edge lanes can never land on the same row.

What it does not do is trust the library with degenerate input, all of which is
handled before the call: self-loops (drawn as `↺`, and they make triskel throw),
disconnected components (laid out separately and stacked; IDA flowcharts do have
unreachable blocks), and the one edge in the corpus that triskel routes *through*
a block, which is detoured and then re-verified — if the detour fails the whole
layout falls back to native rather than draw an edge through the disassembly.

## Layout (`idatui/graph.py`, the native engine)

Pure python: no IDA, no Textual, no I/O, so it is unit-tested offline in
milliseconds (`tests/test_graph.py`, which needs no worker). Textbook Sugiyama,
the same shape IDA's own graph uses:

| step | what | notes |
|---|---|---|
| 1 | break cycles | DFS gray-set; back edges reversed for layout only |
| 2 | layer | longest-path ranking |
| 3 | dummies | a k-layer edge becomes k−1 dummy nodes |
| 4 | order | median sweeps + adjacent transposition |
| 5 | x-coords | priority/median sweeps, variable node widths |
| 6 | route | ports per border, one lane-packed channel per layer gap |

Step 3 is what makes step 6 tractable: because every long edge occupies real
horizontal space as dummy nodes, **no edge ever has to cross a box**. That is
measured, not hoped — `tests/test_graph.py` counts edge cells landing inside a
box across a 128-function corpus and requires 0.

Edges are coloured by IDA's convention: green = branch taken, red = falls
through, blue = the block's only successor, purple = loops back, amber = one arm
of an n-way switch. The edges touching the block under the cursor are brightened.
A self-loop is a `↺` on the block's top border rather than an edge.

### Two traps worth remembering

- **Self-loops deadlock the Kahn ranking.** A block that jumps to itself never
  drains its own in-degree, so ranking stalls and every downstream block stays at
  rank 0 — the graph collapses into three layers and comes out 280 columns wide.
  They are dropped from the layout graph and drawn as a marker. `_assign_ranks`
  also force-releases the most-constrained survivor if the queue ever drains
  early, so a residual cycle degrades instead of exploding.
- **Crossing minimisation is where the time goes.** The naive transposition pass
  recounts crossings globally per candidate swap: O(n³), which made a 424-block
  function take **20.4 seconds**. Counting inversions with a Fenwick tree and
  computing only the local `O(deg(a)·deg(b))` delta per swap took the same
  function to **152 ms**, and the whole 128-function corpus from 21 s to 224 ms.

## Rendering

Nothing is pre-painted. A 424-block function lays out to ~13M cells, so
`graph.Painting` is an *index* — per-row horizontal runs, a bucketed interval
index of vertical runs, and point marks — and `GraphView.render_line(y)` asks it
for one row at a time, exactly like `ListingView`. Cost per frame is proportional
to the viewport, not the graph.

Three zoom levels (`z`) trade detail for shape: **full** (address gutter +
instructions), **compact** (instructions only), **collapsed** (one summary row
per block). On `main` (87 blocks) that is a 1378×518 canvas down to 545×289.

The **minimap** (`m`) is a coarse occupancy grid of the whole graph with the
viewport marked, drawn top-right and inset two columns — a `ScrollView` paints
its scrollbar over the last column, which otherwise eats the minimap's border.
Clicking it **snaps to the nearest block** and takes the cursor with it;
dragging scrubs from block to block. It deliberately does not scroll to the
coordinate you clicked: blocks cover only a few percent of a laid-out graph
(4.6% on an 87-block function, under 1% on a 424-block one) and the rest is the
padding that keeps edges apart, so a coordinate-accurate jump parks you in empty
space with the cursor left behind. For the same reason, a drag-pan or a
`ctrl+d`/`pageup` that ends with **no block on screen at all** eases to the
nearest one — only when nothing is visible, so it never fights a deliberate pan. Because it floats over the canvas rather than living in it,
`on_click` has to test the minimap's hit-box **before** translating the click
into canvas coordinates — otherwise a click on the overview reads as a click on
whatever block happens to lie underneath it. `_minimap_rect()` is the single
source of truth for both the drawing and the hit-test.

## Limits

Above **400 blocks** the graph is refused with a message and you stay in the
listing. A CFG that size is not a picture anyone can read — IDA's own is a
hairball there too (1853 crossings on the worst function in `targets/echo`).
This is a feature, not a shortcoming.

Known cosmetic gap **of the native engine**: a back edge leaves its tail's *top*
border (`┴`) and arrows up into the head's *bottom* (`▲`). Correct and readable,
but IDA runs loop edges around the side of the graph — which is exactly what the
triskel engine does, so `e` is the workaround.

That difference is why an edge's arrowhead is decided by `Route.flipped` and not
by geometry. The native engine reverses back edges to get a DAG, so its polyline
runs *against* control flow and the arrow belongs at the start; triskel keeps the
real direction. Reading the direction off the drawing would silently reverse
every loop edge on one of the two engines.

## Driving it

`graph` is an RPC verb (see `docs/RPC.md`), and it reports **structure**, not box
drawing characters — a driver wants blocks and edges, not glyphs:

```bash
drive raw graph action=open              # Space
drive raw graph action=show              # blocks, edges, ranks, cursor
drive raw graph action=block target=0x6250
drive raw graph action=succ              # J
drive raw graph action=zoom
```

## Offline tools

- `experiments/cfg_dump.py` — freeze real CFGs from a binary to JSON.
- `experiments/graph_spike.py` — lay out and render a corpus function to stdout,
  or `--stats` the whole corpus; `--engine` picks the backend. Uses
  `idatui.graph`, so it exercises the shipping engine with no worker in the loop.
- `experiments/graph_compare.py` — both engines over a corpus: crossings, canvas,
  ambiguous cells, cost. `--real-sizer` sizes boxes from the disassembly text,
  which is the only comparison worth reading.
- `experiments/graph_smoke.py` — end-to-end: tool → domain → layout.
- `experiments/graph_shot.py` — render the real view headless at a chosen size
  (the pane you are in is usually too narrow to judge it); takes an engine as
  its fifth argument.

## Installing the triskel engine

It is optional; without it everything works and `auto` means `native`.

**Install it into the interpreter the launcher actually runs**, which is
`$IDATUI_PYTHON` and defaults to `~/ida-venv/bin/python` — *not* the repo's
`.venv`, which is only what the tests use. Getting this wrong is the one way to
see `no pytriskel in ...` in the status bar while `tests/test_graph.py` happily
exercises both engines; the message names the interpreter for that reason.

```bash
~/ida-venv/bin/python -m pip install ~/dev/triskel/bindings/python
.venv/bin/python   -m pip install ~/dev/triskel/bindings/python   # for the tests
```

Needs cmake, ninja and a C++23 compiler at install time; the wheel is built from
source for whichever interpreter runs pip.

That is **our fork**, not PyPI. Upstream's wheels stop at cp313 with no sdist
(so there is nothing to install on 3.14), and on any version their
`get_waypoints()` raises, which means no edge routes at all. `~/dev/triskel/PATCHES.md`
lists every change. `$IDATUI_TRISKEL_PATH` can point at a build tree instead.
