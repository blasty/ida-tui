#!/usr/bin/env python3
"""Layout tests for idatui.graph — pure, offline, no IDA and no Textual.

    python3 tests/test_graph.py                     # synthetic shapes
    python3 tests/test_graph.py /tmp/cfg-echo.json  # + a real CFG corpus

The corpus file is what ``experiments/cfg_dump.py`` writes. It's optional so the
suite runs anywhere, but when present it is the interesting half: real functions
are where the degenerate shapes (switch fan-out, irreducible loops, 400-block
monsters) actually live.
"""

from __future__ import annotations

#: the layout engine is pure: no IDA, no Textual.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui import graph as G  # noqa: E402

FAILED: list[str] = []
CHECKS = 0


def check(cond: bool, what: str) -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILED.append(what)
        print(f"  FAIL: {what}")


def sizer(b: G.Block) -> tuple[int, int]:
    """Stand-in for the view's real sizer: width from the address text."""
    return (len(f"loc_{b.start:X}") + 6, 4)


#: Which layout engine the current pass is exercising. Every invariant here is
#: a claim about the DRAWING, not about how it was arrived at, so the whole
#: suite runs once per available engine (see main()).
ENGINE = "native"


def layout(blocks, sz=None, entry=None) -> G.Layout:
    return G.layout(blocks, sz or sizer, entry=entry, engine=ENGINE)


def mk(edges: dict[int, list[tuple[int, str]]], n: int | None = None) -> list[G.Block]:
    ids = set(edges) | {d for v in edges.values() for d, _ in v}
    if n:
        ids |= set(range(n))
    return [
        G.Block(
            id=i,
            start=0x1000 + i * 0x10,
            end=0x1000 + i * 0x10 + 8,
            succs=list(edges.get(i, [])),
        )
        for i in sorted(ids)
    ]


# ------------------------------------------------------------ invariants


def no_box_overlap(lay: G.Layout) -> bool:
    for i, a in enumerate(lay.nodes):
        for b in lay.nodes[i + 1 :]:
            if (
                a.x <= b.right
                and b.x <= a.right
                and a.y <= b.y + b.h - 1
                and b.y <= a.y + a.h - 1
            ):
                return False
    return True


def no_edge_through_box(lay: G.Layout) -> int:
    """Count edge cells landing strictly inside a box. Must be 0: this is the
    property the dummy-node machinery exists to guarantee."""
    bad = 0
    for row in range(lay.height):
        cells = lay.painting.cells_at_row(row, 0, lay.width)
        if not cells:
            continue
        for n in lay.nodes_at_row(row):
            for col in list(cells):
                if n.inside(row, col):
                    bad += 1
    return bad


def all_edges_drawn(lay: G.Layout) -> bool:
    """Every edge must contribute at least one painted cell."""
    seen = set()
    for row in range(lay.height):
        for _, (_, _, eid) in lay.painting.cells_at_row(row, 0, lay.width).items():
            seen.add(eid)
    return all(id(e) in seen for e in lay.edges)


def invariants(lay: G.Layout, name: str) -> None:
    check(no_box_overlap(lay), f"{name}: boxes must not overlap")
    check(no_edge_through_box(lay) == 0, f"{name}: no edge may cross a box")
    check(
        all(n.x >= 0 and n.y >= 0 for n in lay.nodes),
        f"{name}: no negative coordinates",
    )
    check(lay.width > 0 and lay.height > 0, f"{name}: canvas has extent")


# ---------------------------------------------------------------- cases


def t_linear() -> None:
    lay = layout(mk({0: [(1, "uncond")], 1: [(2, "uncond")]}), sizer)
    invariants(lay, "linear")
    ranks = [lay.by_id[i].rank for i in (0, 1, 2)]
    check(ranks == [0, 1, 2], f"linear: ranks stack ({ranks})")
    check(all_edges_drawn(lay), "linear: every edge is drawn")


def t_diamond() -> None:
    lay = layout(
        mk({0: [(1, "jump"), (2, "fall")], 1: [(3, "uncond")], 2: [(3, "uncond")]}),
        sizer,
    )
    invariants(lay, "diamond")
    check(lay.by_id[3].rank == 2, "diamond: join sits below both arms")
    check(lay.by_id[1].rank == lay.by_id[2].rank, "diamond: arms share a rank")
    check(len(lay.succ[0]) == 2, "diamond: entry has two successors")
    check(sorted(a for a, _ in lay.pred[3]) == [1, 2], "diamond: join has two preds")


def t_selfloop() -> None:
    """A self-loop must not stall the ranking — the bug that collapsed a whole
    function into three layers and made the graph 280 columns wide."""
    lay = layout(
        mk({0: [(1, "uncond")], 1: [(1, "jump"), (2, "fall")], 2: [(3, "uncond")]}),
        sizer,
    )
    invariants(lay, "selfloop")
    ranks = [lay.by_id[i].rank for i in (0, 1, 2, 3)]
    check(ranks == [0, 1, 2, 3], f"selfloop: ranking still stacks ({ranks})")
    check(lay.by_id[1].block.selfloop, "selfloop: the block is marked")


def t_loop() -> None:
    lay = layout(
        mk({0: [(1, "uncond")], 1: [(2, "jump"), (3, "fall")], 2: [(1, "uncond")]}),
        sizer,
    )
    invariants(lay, "loop")
    check(any(e.back for e in lay.edges), "loop: a back edge is detected")
    check(lay.by_id[1].rank < lay.by_id[2].rank, "loop: header above the body")
    back = [e for e in lay.edges if e.back][0]
    check(
        (2, G.E_BACK) in [(a, s) for a, s in lay.pred[1]]
        or (1, G.E_BACK) in [(a, s) for a, s in lay.succ[2]],
        "loop: the back edge reads 2 -> 1 despite being reversed for layout",
    )


def t_switch() -> None:
    lay = layout(
        mk(
            {
                0: [(i, "switch") for i in range(1, 9)],
                **{i: [(9, "uncond")] for i in range(1, 9)},
            }
        ),
        sizer,
    )
    invariants(lay, "switch")
    check(
        len({lay.by_id[i].rank for i in range(1, 9)}) == 1,
        "switch: all cases share a rank",
    )
    check(lay.by_id[9].rank == 2, "switch: the join is below the cases")


def t_unreachable() -> None:
    """A block reachable only through a reversed edge must still get a rank."""
    lay = layout(mk({0: [(1, "uncond")], 2: [(2, "jump")]}, n=3), sizer)
    invariants(lay, "unreachable")
    check(len(lay.nodes) == 3, "unreachable: every block is placed")


def t_unreachable_entry() -> None:
    """Blocks the entry cannot reach, including an entry with no successors.

    IDA hands these out routinely -- dead code, an unresolved jump table -- and
    triskel's root is whichever node was created first, with every analysis
    walking out from there. Anything it cannot reach is undefined behaviour:
    this exact 7-block shape SEGFAULTED the interpreter, and lesser versions
    threw "EMPTY BL" from its SESE bracket lists. A crash cannot be fallen back
    from, so the engine must never be handed one.
    """
    # entry 0 is a sink; 2 and 3 jump INTO it; 1 and 6 self-loop.
    lay = layout(
        mk(
            {
                0: [],
                1: [(5, "switch"), (1, "fall"), (4, "switch")],
                2: [(5, "jump"), (0, "uncond")],
                3: [(0, "switch")],
                4: [],
                5: [(4, "jump")],
                6: [(2, "jump"), (6, "switch"), (3, "jump")],
            }
        ),
        entry=0,
    )
    invariants(lay, "unreachable_entry")
    check(len(lay.nodes) == 7, "unreachable_entry: every block is placed")
    check(
        lay.stats.get("engine_error") is None,
        f"unreachable_entry: no fallback ({lay.stats.get('engine_error')})",
    )

    # An entry that reaches nothing at all, with everything hanging off nodes
    # it cannot see, is the degenerate version of the same thing.
    lay = layout(mk({0: [], 1: [(2, "jump")], 2: [(1, "jump")]}), entry=0)
    invariants(lay, "orphan_pair")
    check(len(lay.nodes) == 3, "orphan_pair: every block is placed")


def t_long_edge() -> None:
    """An edge spanning many layers gets dummies, so it reserves real space."""
    chain = {i: [(i + 1, "uncond")] for i in range(6)}
    chain[0] = [(1, "fall"), (6, "jump")]
    lay = layout(mk(chain), sizer)
    invariants(lay, "long_edge")
    # Dummy nodes are how the NATIVE engine reserves horizontal space for a
    # long edge. Triskel reaches the same end -- an edge that crosses no box,
    # checked by invariants() above -- without them, so this is engine-specific.
    if ENGINE == "native":
        check(
            lay.stats["dummies"] >= 4,
            f"long_edge: the skip edge is padded ({lay.stats['dummies']} dummies)",
        )
    check(all_edges_drawn(lay), "long_edge: the long edge is drawn")


def t_empty() -> None:
    lay = layout([], sizer)
    check(lay.nodes == [], "empty: no nodes")
    check(lay.width >= 1 and lay.height >= 1, "empty: canvas is still sane")


def t_row_query() -> None:
    """cells_at_row must be windowed: asking for a slice returns only that
    slice, which is what keeps a 13M-cell graph renderable."""
    lay = layout(
        mk({0: [(1, "jump"), (2, "fall")], 1: [(3, "uncond")], 2: [(3, "uncond")]}),
        sizer,
    )
    for row in range(lay.height):
        full = lay.painting.cells_at_row(row, 0, lay.width)
        part = lay.painting.cells_at_row(row, 5, 12)
        check(all(5 <= c < 12 for c in part), f"row {row}: window respected")
        check(
            all(full.get(c) == v for c, v in part.items()),
            f"row {row}: window agrees with the full row",
        )


def t_hit_test() -> None:
    lay = layout(mk({0: [(1, "jump"), (2, "fall")]}), sizer)
    n = lay.nodes[0]
    check(lay.node_at(n.y, n.x) is n, "hit: top-left corner hits the node")
    check(lay.node_at(n.y + 1, n.x + 1) is n, "hit: interior hits the node")
    check(lay.node_at(n.y - 1, n.x) is None, "hit: above the node is empty")
    check(lay.node_at(n.y, n.right + 1) is None, "hit: right of the node is empty")


# ---------------------------------------------------------------- corpus


def t_corpus(path: str) -> None:
    recs = json.load(open(path))
    print(f"\ncorpus: {len(recs)} functions from {path}")
    worst_ms = 0.0
    worst_name = ""
    fellback: list[tuple[str, str | None]] = []
    worst_any_ms = 0.0
    worst_any_name = ""
    t0 = time.perf_counter()
    for rec in recs:
        blocks = [
            G.Block(
                id=b["id"],
                start=b["start"],
                end=b["end"],
                succs=[(d, k) for d, k in b["succs"]],
            )
            for b in rec["blocks"]
        ]
        lay = layout(blocks, sizer)
        # A SILENT fallback is the failure mode that matters here: the engine
        # under test quietly stops being the engine under test, and every
        # invariant below then passes for the wrong reason. `ls` main (329
        # blocks) used to fall back on all three zoom levels because a final
        # approach was routed through the block above its target.
        #
        # Falling back is legitimate -- it is how an upstream layout defect is
        # kept off the screen -- so this asserts it is rare and explained,
        # not that it never happens.
        if ENGINE != "auto" and lay.stats["engine"] != ENGINE:
            fellback.append((rec["name"], lay.stats.get("engine_error")))
            check(
                bool(lay.stats.get("engine_error")),
                f"corpus {rec['name']}: a fallback must record its reason",
            )
        # Time the engine only on the functions it would actually be ASKED for.
        # `auto` hands anything over AUTO_TRISKEL_MAX_BLOCKS to native, and the
        # view refuses to draw past 400 blocks at all, so a forced triskel run
        # on a 495-block monster times a call the app cannot make.
        reachable = ENGINE != "triskel" or len(blocks) <= G.AUTO_TRISKEL_MAX_BLOCKS
        if reachable and lay.stats["ms"] > worst_ms:
            worst_ms, worst_name = lay.stats["ms"], rec["name"]
        if lay.stats["ms"] > worst_any_ms:
            worst_any_ms, worst_any_name = lay.stats["ms"], rec["name"]
        check(no_box_overlap(lay), f"corpus {rec['name']}: boxes must not overlap")
        check(
            len(lay.nodes) == len(blocks),
            f"corpus {rec['name']}: every block is placed",
        )
        # The full cell sweep is O(canvas); only affordable on the small ones,
        # but that is where a routing bug would show up anyway.
        if lay.width * lay.height < 400_000:
            check(
                no_edge_through_box(lay) == 0,
                f"corpus {rec['name']}: no edge may cross a box",
            )
    total = (time.perf_counter() - t0) * 1000
    print(
        f"  laid out {len(recs)} functions in {total:.0f} ms "
        f"(worst {worst_ms:.0f} ms: {worst_name})"
    )
    if fellback:
        print(f"  {len(fellback)} fell back to native:")
        for name, why in fellback:
            print(f"    {name}: {why}")
    check(
        len(fellback) <= max(2, len(recs) // 20),
        f"corpus: {ENGINE} fell back on {len(fellback)}/{len(recs)} functions",
    )
    check(
        worst_ms < 2000,
        f"corpus: worst REACHABLE layout under 2s ({worst_ms:.0f} ms: {worst_name})",
    )
    # Nothing may blow up quadratically even when forced past its own limits.
    check(
        worst_any_ms < 5000,
        f"corpus: worst layout at any size under 5s "
        f"({worst_any_ms:.0f} ms: {worst_any_name})",
    )


def main() -> int:
    global ENGINE
    print("idatui.graph layout tests")
    from idatui import graph_triskel

    engines = ["native"]
    if graph_triskel.available():
        engines.append("triskel")
    else:
        print("  (pytriskel not importable: skipping the triskel engine)")
    for engine in engines:
        ENGINE = engine
        print(f"\nengine: {engine}")
        for fn in (
            t_linear,
            t_diamond,
            t_selfloop,
            t_loop,
            t_switch,
            t_unreachable,
            t_unreachable_entry,
            t_long_edge,
            t_empty,
            t_row_query,
            t_hit_test,
        ):
            print(f"  {fn.__name__}")
            fn()
        for path in sys.argv[1:]:
            if os.path.exists(path):
                t_corpus(path)
    print(f"\n{CHECKS} checks, {len(FAILED)} failed")
    for f in FAILED:
        print(f"  - {f}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
