"""Profile persistent ida-tui operations inside the IDA process.

The profiler itself is a typed ``RemoteModule`` function in ``remote_tools.py``;
this file contains no generated Python source or knowledge of remote module names.

Usage::

    PYTHONPATH=. python experiments/profile_remote.py [BINARY]
    PYTHONPATH=. python experiments/profile_remote.py --op decompile
"""

from __future__ import annotations

import argparse
import os

from idatui import remote_ops
from idatui.codemode_client import CodeModeClient

CALLS = {
    "heads": ("heads", {"count": 500, "annotate": True}),
    "heads_plain": ("heads", {"count": 500, "annotate": False}),
    "heads_skeleton": (
        "heads",
        {"count": 500, "annotate": True, "text": False},
    ),
    "decompile": ("decompile", {}),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default="targets/bash")
    parser.add_argument("--op", default="heads", choices=sorted(CALLS))
    parser.add_argument("--reps", type=int, default=20)
    parser.add_argument("--addr", default=None, help="default: the .text start")
    args = parser.parse_args()

    client = CodeModeClient(os.path.abspath(args.binary)).connect()
    addr = args.addr
    if addr is None:
        regions = client.call(remote_ops.file_regions)
        rows = regions.get("regions") or regions.get("result") or []
        text = next(
            (row for row in rows if ".text" in str(row.get("name", ""))),
            None,
        )
        addr = (text or rows[0])["start"] if rows else "0x0"

    operation, call_args = CALLS[args.op]
    call_args = {"addr": addr, **call_args}
    print(
        f"# {os.path.basename(args.binary)}  op={args.op}  "
        f"addr={addr}  reps={args.reps}"
    )

    # Install the persistent tool module and warm its caches before profiling.
    client.call(remote_ops.heads, addr=addr, count=500, annotate=True)
    out = client.call(
        remote_ops.profile_remote,
        operation=operation,
        args=call_args,
        reps=args.reps,
    )
    per = out["total"] / out["reps"] * 1000
    print(f"# {out['total'] * 1000:.0f}ms total, {per:.1f}ms per call\n")
    print(out["stats"])
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
