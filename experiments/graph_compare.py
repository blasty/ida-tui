#!/usr/bin/env python3
"""Compare the layout engines on a corpus: crossings, canvas, ambiguity, cost.

    python3 experiments/graph_compare.py .auto/cfg-corpus.json
    python3 experiments/graph_compare.py .auto/cfg-corpus.json --max-blocks 40

Every number comes out of the shipping pipeline (``idatui.graph``), not out of a
side channel, so it measures what the view will actually draw.

The columns that matter:

``X``    proper segment crossings -- what the SESE decomposition is for.
``amb``  cells claimed by more than one edge. In a pixel renderer overlapping
         lines are invisible; in a terminal one cell holds one character, so an
         ambiguous cell is an edge the user cannot follow and ``edge_at`` gets
         wrong under the cursor.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui import graph as G  # noqa: E402


def sizer(b: G.Block) -> tuple[int, int]:
    return (len(f"loc_{b.start:X}") + 6, 4)


def real_sizer(rec: dict, max_lines: int):
    """Box sizes from the actual disassembly text, like the view's own sizer.

    Box shape is not a detail here: it decides how much horizontal room a layer
    needs, and therefore how far edges travel sideways. Comparing engines on
    uniform 20-column stubs measures the wrong graph.
    """
    texts = {}
    for b in rec["blocks"]:
        lines = list(b["lines"])
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines - 1] + [f"... {len(b['lines']) - max_lines + 1} more"]
        texts[b["id"]] = lines

    def size(b: G.Block) -> tuple[int, int]:
        lines = texts[b.id]
        return max((len(line) for line in lines), default=8) + 4, len(lines) + 2
    return size


def segments(lay: G.Layout) -> dict[int, list[tuple[int, int, int, int]]]:
    """Per-edge segments as (x0, y0, x1, y1), rebuilt from the painting."""
    segs: dict[int, list] = defaultdict(list)
    for row, runs in lay.painting.hruns.items():
        for lo, hi, _style, eid in runs:
            segs[eid].append((lo, row, hi, row))
    for lo, hi, col, _style, eid in lay.painting.vruns:
        segs[eid].append((col, lo, col, hi))
    return segs


def crossings(segs: dict[int, list], cap: int = 400_000) -> int | None:
    def orient(px, py, qx, qy, rx, ry):
        v = (qx - px) * (ry - py) - (qy - py) * (rx - px)
        return (v > 0) - (v < 0)

    keys = list(segs)
    n = pairs = 0
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            for ax, ay, bx, by in segs[a]:
                for cx, cy, dx, dy in segs[b]:
                    pairs += 1
                    if pairs > cap:
                        return None
                    o1 = orient(ax, ay, bx, by, cx, cy)
                    o2 = orient(ax, ay, bx, by, dx, dy)
                    o3 = orient(cx, cy, dx, dy, ax, ay)
                    o4 = orient(cx, cy, dx, dy, bx, by)
                    if o1 != o2 and o3 != o4:
                        n += 1
    return n


def ambiguous(lay: G.Layout) -> tuple[int, int]:
    """(cells claimed by >1 edge, total edge cells)."""
    owners: dict[tuple[int, int], set[int]] = defaultdict(set)
    for row, runs in lay.painting.hruns.items():
        for lo, hi, _s, eid in runs:
            for c in range(lo, hi + 1):
                owners[(row, c)].add(eid)
    for lo, hi, col, _s, eid in lay.painting.vruns:
        for r in range(lo, hi + 1):
            owners[(r, col)].add(eid)
    return sum(1 for v in owners.values() if len(v) > 1), len(owners)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--max-blocks", type=int, default=10 ** 9)
    ap.add_argument("--min-blocks", type=int, default=6)
    ap.add_argument("--real-sizer", action="store_true",
                    help="size boxes from the disassembly text, as the view does")
    ap.add_argument("--max-lines", type=int, default=8)
    args = ap.parse_args()

    from idatui import graph_triskel
    if not graph_triskel.available():
        print("pytriskel not importable; set IDATUI_TRISKEL_PATH", file=sys.stderr)
        return 2

    recs = json.load(open(args.corpus))
    recs = [r for r in recs
            if args.min_blocks <= len(r["blocks"]) <= args.max_blocks]
    recs.sort(key=lambda r: len(r["blocks"]))

    print(f"{'blk':>4} | {'native ms':>9} {'canvas':>11} {'X':>5} {'amb':>5} | "
          f"{'tk ms':>7} {'canvas':>11} {'X':>5} {'amb':>5} | name")
    tot = {"native": 0.0, "triskel": 0.0}
    won = tied = lost = 0
    amb_tot = {"native": 0, "triskel": 0}
    for rec in recs:
        row = {}
        for engine in ("native", "triskel"):
            blocks = [G.Block(id=b["id"], start=b["start"], end=b["end"],
                              succs=[(d, k) for d, k in b["succs"]])
                      for b in rec["blocks"]]
            size = real_sizer(rec, args.max_lines) if args.real_sizer else sizer
            t0 = time.perf_counter()
            lay = G.layout(blocks, size, engine=engine)
            ms = (time.perf_counter() - t0) * 1000
            tot[engine] += ms
            amb, _cells = ambiguous(lay)
            amb_tot[engine] += amb
            row[engine] = (ms, lay.width, lay.height, crossings(segments(lay)), amb)
        (nm, nw, nh, nx, na) = row["native"]
        (tm, tw, th, tx, ta) = row["triskel"]
        if nx is not None and tx is not None:
            won += tx < nx
            tied += tx == nx
            lost += tx > nx
        print(f"{len(rec['blocks']):>4} | {nm:>9.1f} {f'{nw}x{nh}':>11} "
              f"{str(nx):>5} {na:>5} | {tm:>7.1f} {f'{tw}x{th}':>11} "
              f"{str(tx):>5} {ta:>5} | {rec['name']}")
    print(f"\ntotal: native {tot['native']:.0f} ms, triskel {tot['triskel']:.0f} ms")
    print(f"crossings: triskel better on {won}, equal on {tied}, worse on {lost}")
    print(f"ambiguous cells: native {amb_tot['native']}, triskel {amb_tot['triskel']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
