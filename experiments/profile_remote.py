"""Profile an operation INSIDE the database process.

`bench_ops.py` says how long an operation takes; this says where that time
goes. The snippet ships cProfile into the Code Mode sandbox, runs the real
remote-library function there in a loop, and returns the stats as text -- so
the split between IDA's own calls and OUR python in `remote_tools.py` is
visible, which no client-side timer can see.

    PYTHONPATH=. ~/ida-venv/bin/python experiments/profile_remote.py [BINARY]
    PYTHONPATH=. ~/ida-venv/bin/python experiments/profile_remote.py --op decompile

Read the `tottime` column: time in that function excluding subcalls. IDA
builtins (generate_disasm_line, get_flags, next_head...) are the floor; a
python frame from ida_tui_remote near the top is ours, and ours is fixable.
"""
from __future__ import annotations

import argparse
import os
import sys

from idatui.codemode_client import CodeModeClient, _REMOTE_MODULE, _script

# Runs in the database process. `a` is the bound argument dict.
PROFILE = '''
import cProfile, pstats, io, sys
_m = sys.modules.get(%(mod)r)
if _m is None:
    result = {"error": "remote lib not installed yet"}
else:
    call = a["call"]
    reps = int(a["reps"])
    ns = {"_m": _m, "a": a}
    src = "for _ in range(%%d):\\n    _m.%%s" %% (reps, call)
    code = compile(src, "<profile>", "exec")
    pr = cProfile.Profile()
    pr.enable()
    exec(code, ns)
    pr.disable()
    buf = io.StringIO()
    st = pstats.Stats(pr, stream=buf).sort_stats("tottime")
    st.print_stats(int(a["lines"]))
    result = {"stats": buf.getvalue(), "total": st.total_tt, "reps": reps}
''' % {"mod": _REMOTE_MODULE}

CALLS = {
    # One full listing page, exactly as the background grower asks for it.
    "heads": 'heads(addr=a["addr"], count=500, annotate=True)',
    "heads_plain": 'heads(addr=a["addr"], count=500, annotate=False)',
    "heads_skeleton": 'heads(addr=a["addr"], count=500, annotate=True, text=False)',
    "decompile": 'decompile(a["addr"])',
    "disasm": 'disasm(a["addr"], 500)',
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?", default="targets/bash")
    ap.add_argument("--op", default="heads", choices=sorted(CALLS))
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--lines", type=int, default=18)
    ap.add_argument("--addr", default=None, help="default: the .text start")
    args = ap.parse_args()

    client = CodeModeClient(os.path.abspath(args.binary))
    client.connect()

    addr = args.addr
    if addr is None:
        regions = client.invoke("file_regions")
        rows = regions.get("regions") or regions.get("result") or []
        text = next((r for r in rows if ".text" in str(r.get("name", ""))), None)
        addr = (text or rows[0])["start"] if rows else "0x0"
    print(f"# {os.path.basename(args.binary)}  op={args.op}  addr={addr}  reps={args.reps}")

    # Prime: the remote lib installs lazily, and its lru_caches must be warm or
    # the profile measures cache misses that the real workload never pays.
    client.invoke("heads", addr=addr, count=500, annotate=True)

    # _script binds the args as JSON and adds the pack epilogue, exactly as a
    # real operation is shipped -- so this measures the same path, not a
    # special one.
    out = client._unpack(client.execute_python(_script(
        {"call": CALLS[args.op], "addr": addr,
         "reps": args.reps, "lines": args.lines}, PROFILE), timeout=600))
    if "error" in out:
        print("FAILED:", out["error"])
        return 1
    per = out["total"] / out["reps"] * 1000
    print(f"# {out['total']*1000:.0f}ms total, {per:.1f}ms per call\n")
    print(out["stats"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
