"""Measure cold installation versus warm calls for typed remote modules.

Historical note: this file used to benchmark ``_PACK_EPILOGUE``. Application
scripts are no longer strings and packing is gone; the relevant design cost is
now the one-time content-addressed module installation versus steady-state calls.

Usage::

    PYTHONPATH=. python experiments/bench_pack_trace.py [FILE]
"""

from __future__ import annotations

import argparse
import os
import statistics
import time

from idatui import remote_ops
from idatui.codemode_client import CodeModeClient


def timed(function, reps: int = 1) -> tuple[object, float]:
    samples = []
    result = None
    for _ in range(reps):
        started = time.perf_counter()
        result = function()
        samples.append((time.perf_counter() - started) * 1000.0)
    return result, statistics.median(samples)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", default="targets/bash")
    parser.add_argument("--reps", type=int, default=25)
    parser.add_argument("--rows", type=int, default=200)
    args = parser.parse_args()

    client = CodeModeClient(os.path.abspath(args.target)).connect()

    index, operations_cold = timed(
        lambda: client.call(remote_ops.list_funcs, queries=[{"offset": 0, "count": 40}])
    )
    funcs = (index.get("result") or [{}])[0].get("data") or []
    biggest = max(funcs, key=lambda function: function.get("size") or 0, default=None)
    if not biggest:
        print("VERDICT: FAIL - no functions")
        return 1
    addr = biggest["addr"]
    if isinstance(addr, int):
        addr = hex(addr)

    _, operations_warm = timed(
        lambda: client.call(
            remote_ops.list_funcs, queries=[{"offset": 0, "count": 40}]
        ),
        args.reps,
    )
    page = lambda: client.call(  # noqa: E731
        remote_ops.heads, addr=addr, count=args.rows, annotate=True
    )
    payload, tools_cold = timed(page)
    _, tools_warm = timed(page, args.reps)

    print(f"target          {os.path.basename(args.target)}  backend={client.backend}")
    print(f"function        {addr}")
    print(f"listing rows    {len(payload.get('heads', []))}")
    print(
        f"operations.py   cold {operations_cold:8.3f}ms  warm {operations_warm:8.3f}ms"
    )
    print(f"remote_tools.py cold {tools_cold:8.3f}ms  warm {tools_warm:8.3f}ms")
    print(f"tools install overhead {tools_cold / max(tools_warm, 0.001):.2f}x one time")
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
