#!/usr/bin/env python3
"""Dump real basic-block CFGs to JSON, so graph-layout work can be done offline.

Run with a python that has ``idapro`` (i.e. the worker python, /usr/bin/python3):

    /usr/bin/python3 experiments/cfg_dump.py targets/echo -o /tmp/cfg-echo.json

Copies the binary to a scratch dir first (never touches the tracked .i64), opens
it with idalib, and writes one record per function:

    {"name","ea","blocks":[{"id","start","end","lines":[str],"succs":[[id,kind]]}]}

``kind`` is "fall" (falls through to the next address), "jump" (unconditional or
taken branch) or "switch" (n-way). That is exactly the input a graph view needs;
everything after this point (layering, ordering, routing, rendering) is pure
python and needs no IDA at all.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile


def dump(path: str, want: list[str], max_blocks: int) -> list[dict]:
    import idapro

    scratch = tempfile.mkdtemp(prefix="cfgdump-")
    local = os.path.join(scratch, os.path.basename(path))
    shutil.copy2(path, local)
    if idapro.open_database(local, run_auto_analysis=True) != 0:
        raise SystemExit(f"failed to open {local}")

    import ida_bytes
    import ida_funcs
    import ida_gdl
    import ida_lines
    import idaapi
    import idautils

    out = []
    try:
        for fea in idautils.Functions():
            fn = ida_funcs.get_func(fea)
            if not fn:
                continue
            name = ida_funcs.get_func_name(fea)
            if want and not any(w in name for w in want):
                continue
            fc = ida_gdl.FlowChart(fn, flags=ida_gdl.FC_PREDS)
            blocks = []
            index = {}
            for i, bb in enumerate(fc):
                index[bb.start_ea] = i
            for bb in fc:
                lines = []
                ea = bb.start_ea
                while ea < bb.end_ea and ea != idaapi.BADADDR:
                    txt = ida_lines.tag_remove(
                        ida_lines.generate_disasm_line(ea, 0) or ""
                    )
                    lines.append(txt.rstrip())
                    nxt = ida_bytes.next_head(ea, bb.end_ea)
                    if nxt <= ea:
                        break
                    ea = nxt
                succs = []
                sl = list(bb.succs())
                for s in sl:
                    if s.start_ea not in index:
                        continue
                    if len(sl) > 2:
                        kind = "switch"
                    elif s.start_ea == bb.end_ea:
                        kind = "fall"
                    else:
                        kind = "jump"
                    succs.append([index[s.start_ea], kind])
                blocks.append(
                    {
                        "id": index[bb.start_ea],
                        "start": bb.start_ea,
                        "end": bb.end_ea,
                        "lines": lines,
                        "succs": succs,
                    }
                )
            if max_blocks and len(blocks) > max_blocks:
                continue
            out.append({"name": name, "ea": fea, "blocks": blocks})
    finally:
        idapro.close_database(save=False)
        shutil.rmtree(scratch, ignore_errors=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("-o", "--out", default="/tmp/cfg.json")
    ap.add_argument(
        "-f",
        "--func",
        action="append",
        default=[],
        help="only functions whose name contains this (repeatable)",
    )
    ap.add_argument(
        "--max-blocks",
        type=int,
        default=0,
        help="skip functions with more blocks than this",
    )
    args = ap.parse_args()

    recs = dump(os.path.abspath(args.binary), args.func, args.max_blocks)
    recs.sort(key=lambda r: len(r["blocks"]), reverse=True)
    with open(args.out, "w") as f:
        json.dump(recs, f)
    tot = sum(len(r["blocks"]) for r in recs)
    print(f"{len(recs)} functions, {tot} blocks -> {args.out}")
    for r in recs[:12]:
        print(f"  {len(r['blocks']):4d} blocks  {r['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
