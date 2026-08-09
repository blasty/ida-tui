"""Measure ``_PACK_EPILOGUE`` against the live ida-codemode runtime.

Our snippets return one pre-serialised JSON STRING instead of a structure, to
dodge to_jsonable()'s Python-level walk of the result (a 200-row listing page
is ~10k small objects). ida-codemode 0.3.2 gave that path a C fast path --
``serialization.dumps_json`` hands the structure straight to ``json.dumps`` and
only falls back to the walker for values the encoder rejects -- so the packing
now costs a double encode (escaping the whole payload as a string literal) to
avoid a walk that may no longer happen.

This script answers whether packing still pays. Its sibling question, the
``sys.settrace`` strip, is settled: 0.3.2 deleted the trace hook, the workaround
measured 0.99x, and it has been removed.

Usage::

    PYTHONPATH=. ~/ida-venv/bin/python experiments/bench_pack_trace.py [FILE]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time

from idatui import codemode_client as cc
from idatui.codemode_client import CodeModeClient


def _time(fn, reps: int) -> tuple[float, float]:
    """Best-of and median wall time in ms; best-of resists co-tenant noise."""
    samples = []
    for _ in range(reps):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000.0)
    return min(samples), statistics.median(samples)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default="targets/bash")
    ap.add_argument("--reps", type=int, default=25)
    ap.add_argument("--rows", type=int, default=200)
    args = ap.parse_args()

    target = os.path.abspath(args.target)
    client = CodeModeClient(target)
    client.connect()

    # A real listing page: the flow the workaround was tuned for.
    # list_funcs answers {"result": [{"data": [...], "total": N}]}.
    index = client.invoke("list_funcs", queries=[{"offset": 0, "count": 40}])
    funcs = (index.get("result") or [{}])[0].get("data") or []
    biggest = max(funcs, key=lambda f: f.get("size") or 0, default=None)
    if not biggest:
        print("VERDICT: FAIL - no functions")
        return 1
    addr = biggest["addr"]
    if isinstance(addr, int):
        addr = hex(addr)

    page = lambda: client.invoke(  # noqa: E731
        "heads", addr=addr, count=args.rows, annotate=True)

    # _script() reads _PACK_EPILOGUE at CALL time, so both variants share one
    # process -- one lease, one warm database, one fair baseline. _unpack()
    # passes an unpacked answer through untouched, so plain `result` works.
    packed_epilogue = cc._PACK_EPILOGUE
    results = {}
    for packing in (True, False):
        cc._PACK_EPILOGUE = packed_epilogue if packing else "\nresult\n"
        payload = page()
        rows = len(payload.get("heads", []))
        for _ in range(3):  # warm caches; the first sample is always an outlier
            page()
        results[packing] = (rows, *_time(page, args.reps))
    cc._PACK_EPILOGUE = packed_epilogue

    size = len(json.dumps(payload, separators=(",", ":"), default=str)) / 1024
    print(f"target        {os.path.basename(target)}  backend={client.backend}")
    print(f"listing page  func {addr}, {results[True][0]} rows, "
          f"{size:.1f} KiB of JSON, {args.reps} reps")
    for packing, label in ((True, "packed string (current)"),
                           (False, "plain structure")):
        rows, best, med = results[packing]
        print(f"  {label:<26} best {best:7.2f}ms   median {med:7.2f}ms"
              f"   rows={rows}")
    print(f"  packing buys               "
          f"{results[False][1] / results[True][1]:.2f}x")
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
