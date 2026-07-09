#!/usr/bin/env python3
"""Live smoke test for idatui.client against a running ida-pro-mcp server.

Run with the venv Python while a server is up (see spawn.sh):

    IDA_MCP_DB=<session_id> python3 tests/smoke_client.py
    # or:  python3 tests/smoke_client.py --db <session_id>

Exercises: handshake+warm latency, happy-path payloads, the full error taxonomy
(hard tool errors vs soft per-item errors), session resolution, connection-pool
reuse, and concurrent calls from threads.
"""
import concurrent.futures
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.client import (  # noqa: E402
    IDAClient,
    IDASessionError,
    IDAToolError,
)

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {detail}")


def main(argv):
    url = "http://127.0.0.1:8745/mcp"
    db = os.environ.get("IDA_MCP_DB")
    it = iter(argv)
    for a in it:
        if a == "--url":
            url = next(it)
        elif a == "--db":
            db = next(it)

    ida = IDAClient(url, db=db)
    ida.connect()

    print("[sessions]")
    sessions = ida.list_sessions()
    check("list_sessions returns >=1", len(sessions) >= 1, str(sessions))
    if db is None:
        usable = [s for s in sessions if s.session_id]
        if len(usable) == 1:
            db = usable[0].session_id
        else:
            print(f"  (multiple/zero sessions; pin one with --db) -> {usable}")
            print("  Options:", ", ".join(f"{s.session_id}={s.filename}" for s in usable))
            return 2
    ida.set_db(db)
    print(f"  using db={db}")

    print("[handshake / latency]")
    # Warm calls; measure.
    for _ in range(3):
        ida.health()
    times = []
    for _ in range(20):
        t = time.time()
        ida.call("list_funcs", queries=[{"count": 50}])
        times.append((time.time() - t) * 1e3)
    times.sort()
    med = times[len(times) // 2]
    print(f"  list_funcs x20 warm: min={times[0]:.1f} med={med:.1f} max={times[-1]:.1f} ms")
    check("warm call under 50ms median", med < 50, f"med={med:.1f}ms")

    print("[happy path]")
    h = ida.health()
    check("health is dict", isinstance(h, dict), type(h).__name__)
    funcs = ida.call("list_funcs", queries=[{"count": 5}])
    check("list_funcs shape", isinstance(funcs, (list, dict)), type(funcs).__name__)
    dis = ida.call("disasm", addr="main", max_instructions=10)
    lines = dis.get("asm", {}).get("lines") if isinstance(dis, dict) else None
    check("disasm main has lines", bool(lines), str(dis)[:120])
    check("disasm line carries addr", bool(lines and "addr" in lines[0]),
          str(lines[0]) if lines else "no lines")

    print("[error taxonomy]")
    # Hard tool error: wrong params -> isError true -> IDAToolError
    try:
        ida.call("xrefs_to", targets=["main"])
        check("bad params raises IDAToolError", False, "no exception")
    except IDAToolError as e:
        check("bad params raises IDAToolError", True)
        check("  ...message surfaced", "addrs" in e.message or "param" in e.message.lower(),
              e.message)
    # Hard tool error: unknown tool -> isError true
    try:
        ida.call("definitely_not_a_tool")
        check("unknown tool raises IDAToolError", False, "no exception")
    except IDAToolError:
        check("unknown tool raises IDAToolError", True)
    # Soft/per-item error: bad addr to decompile -> isError false -> DATA, not raise
    try:
        payload = ida.call("decompile", addr="zzz_nope_addr")
        soft = isinstance(payload, dict) and payload.get("error")
        check("soft error returned as data (not raised)", bool(soft), str(payload)[:160])
    except IDAToolError as e:
        check("soft error returned as data (not raised)", False, f"raised: {e}")

    print("[session resolution]")
    tmp = IDAClient(url, db=None)
    tmp.connect()
    all_sessions = tmp.list_sessions()
    usable = [s for s in all_sessions if s.session_id]
    if len(usable) > 1:
        try:
            tmp.resolve_db()
            check("multi-session resolve raises", False, "no exception")
        except IDASessionError:
            check("multi-session resolve raises", True)
    else:
        check("single-session auto-resolves", tmp.resolve_db() == usable[0].session_id)
    tmp.close()

    print("[connection reuse]")
    # Fire many calls; pool should keep idle conns bounded and all succeed.
    ok = 0
    for _ in range(30):
        if ida.call("list_funcs", queries=[{"count": 1}]) is not None:
            ok += 1
    check("30 sequential calls all succeed (pooled)", ok == 30, f"{ok}/30")

    print("[concurrency]")
    def worker(i):
        return ida.call("disasm", addr="main", max_instructions=5)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(worker, range(40)))
    good = sum(1 for r in results if isinstance(r, dict) and r.get("asm"))
    check("40 concurrent calls across 8 threads", good == 40, f"{good}/40")

    ida.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
