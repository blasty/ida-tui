#!/usr/bin/env python3
"""Render a CFG with idatui.graph, offline, to stdout.

The layout engine now lives in ``idatui/graph.py`` (this started life as the
spike that proved it). What survives here is the offline harness: feed it a
corpus from ``cfg_dump.py`` and look at a function, or lay out the whole corpus
and check the cost. No IDA, no Textual, no worker -- so it iterates in
milliseconds when you're changing layout heuristics.

    /usr/bin/python3 experiments/cfg_dump.py targets/echo -o /tmp/cfg-echo.json
    python3 experiments/graph_spike.py /tmp/cfg-echo.json --func sub_61D0
    python3 experiments/graph_spike.py /tmp/cfg-echo.json --stats
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui import graph as G  # noqa: E402

COLOR = {
    G.E_UNCOND: "\033[38;5;39m", G.E_TRUE: "\033[38;5;40m",
    G.E_FALSE: "\033[38;5;203m", G.E_SWITCH: "\033[38;5;178m",
    G.E_BACK: "\033[38;5;135m",
}
DIM, RESET = "\033[38;5;244m", "\033[0m"
PAD = 1


def build(rec: dict, max_lines: int):
    """(blocks, sizer, texts) for one cfg_dump record."""
    texts: dict[int, list[str]] = {}
    for b in rec["blocks"]:
        lines = list(b["lines"])
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines - 1] + [f"... {len(b['lines']) - max_lines + 1} more"]
        texts[b["id"]] = lines
    blocks = [G.Block(id=b["id"], start=b["start"], end=b["end"],
                      succs=[(d, k) for d, k in b["succs"]])
              for b in rec["blocks"]]

    def sizer(b: G.Block) -> tuple[int, int]:
        lines = texts[b.id]
        label = f"loc_{b.start:X}"
        widest = max([len(label) + 4] + [len(l) for l in lines] or [4])
        return (widest + 2 * PAD + 2, max(len(lines), 1) + 2)

    return blocks, sizer, texts


def render(lay: G.Layout, texts: dict[int, list[str]], color: bool) -> str:
    rows = []
    for row in range(lay.height):
        cells: dict[int, tuple[str, str]] = {}
        for col, (ch, kind, _eid) in lay.painting.cells_at_row(
                row, 0, lay.width).items():
            cells[col] = (ch, COLOR.get(kind, ""))
        for n in lay.nodes_at_row(row):
            label = f"loc_{n.block.start:X}" if n.block else ""
            if row == n.y:
                cells[n.x] = (G.BOX["tl"], DIM)
                for i in range(1, n.w - 1):
                    cells[n.x + i] = (G.BOX["h"], DIM)
                cells[n.x + n.w - 1] = (G.BOX["tr"], DIM)
                tag = f" {label} "
                if len(tag) <= n.w - 4:
                    for k, c in enumerate(tag):
                        cells[n.x + 2 + k] = (c, DIM)
                if n.block is not None and n.block.selfloop:
                    cells[n.x + n.w - 2] = ("\u21ba", COLOR[G.E_BACK])
            elif row == n.y + n.h - 1:
                cells[n.x] = (G.BOX["bl"], DIM)
                for i in range(1, n.w - 1):
                    cells[n.x + i] = (G.BOX["h"], DIM)
                cells[n.x + n.w - 1] = (G.BOX["br"], DIM)
            else:
                cells[n.x] = (G.BOX["v"], DIM)
                cells[n.x + n.w - 1] = (G.BOX["v"], DIM)
                for i in range(1, n.w - 1):
                    cells[n.x + i] = (" ", "")
                lines = texts.get(n.id, [])
                i = row - n.y - 1
                if 0 <= i < len(lines):
                    for k, c in enumerate(lines[i]):
                        cells[n.x + 1 + PAD + k] = (c, "")
        line, cur, last = [], "", -1
        for col in sorted(cells):
            ch, st = cells[col]
            line.append(" " * (col - last - 1))
            if color and st != cur:
                line.append(st or RESET)
                cur = st
            line.append(ch)
            last = col
        if color and cur:
            line.append(RESET)
        rows.append("".join(line))
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--func", help="function name (default: the smallest)")
    ap.add_argument("--stats", action="store_true", help="lay out the whole corpus")
    ap.add_argument("--max-lines", type=int, default=8,
                    help="collapse blocks longer than this (0 = never)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--engine", choices=G.ENGINES, default=None,
                    help="layout backend (default: $IDATUI_GRAPH_ENGINE or auto)")
    args = ap.parse_args()

    recs = json.load(open(args.corpus))
    if args.stats:
        print(f"{'blocks':>7} {'nodes':>6} {'dummy':>6} {'layer':>6} "
              f"{'canvas':>12} {'ms':>8}  name")
        tot = 0.0
        for r in sorted(recs, key=lambda r: len(r["blocks"])):
            blocks, sizer, _ = build(r, args.max_lines)
            lay = G.layout(blocks, sizer, engine=args.engine)
            s = lay.stats
            tot += s["ms"]
            print(f"{s['blocks']:>7} {s['nodes']:>6} {s['dummies']:>6} "
                  f"{s['layers']:>6} {lay.width:>5}x{lay.height:<6} "
                  f"{s['ms']:>8.1f}  {r['name']}")
        print(f"total {tot:.0f} ms over {len(recs)} functions")
        return 0

    if args.func:
        rec = next((r for r in recs if r["name"] == args.func), None)
        if rec is None:
            print("no such function; have: "
                  f"{', '.join(r['name'] for r in recs[:20])}", file=sys.stderr)
            return 1
    else:
        rec = min(recs, key=lambda r: len(r["blocks"]))

    blocks, sizer, texts = build(rec, args.max_lines)
    lay = G.layout(blocks, sizer, engine=args.engine)
    print(render(lay, texts, color=not args.no_color))
    print(f"\n{rec['name']}: {lay.stats}  canvas {lay.width}x{lay.height}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
