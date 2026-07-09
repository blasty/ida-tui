#!/usr/bin/env python3
"""Stress the 'many lines of text' problem: paging huge listings/functions.

Validates the windowing strategy the TUI will use so we never hand a widget more
than a viewport-sized slice. Prints concise stats only.

    python3 tests/stress_paging.py --db <session_id>
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.client import IDAClient  # noqa: E402

URL = "http://127.0.0.1:8745/mcp"
# Verified server cap: list_* honors count up to ~700, then silently collapses
# to a 10-item default. Clamp with margin.
SAFE_PAGE = 500


def ms(fn):
    t = time.time()
    r = fn()
    return (time.time() - t) * 1e3, r


def q0(payload):
    """Unwrap a *_query/list_* payload: {'result':[{'data':[...],'next_offset':N}]}."""
    res = payload.get("result", payload)
    if isinstance(res, list):
        res = res[0] if res else {}
    return res.get("data", []), res.get("next_offset")


def page_all_funcs(c, page=SAFE_PAGE):
    """Enumerate the entire function list correctly: advance by len(data), NOT by
    next_offset (which is just offset+count and skips over the per-call cap)."""
    funcs, offset, pages, t0 = [], 0, 0, time.time()
    while True:
        payload = c.call("list_funcs", queries=[{"offset": offset, "count": page}])
        data, _ = q0(payload)
        funcs.extend(data)
        pages += 1
        if len(data) < page:  # short page => reached the end
            break
        offset += len(data)
    return funcs, pages, (time.time() - t0) * 1e3


def disasm_meta(c, addr):
    # total_instructions is a TOP-LEVEL field, not under 'asm'.
    payload = c.call("disasm", addr=addr, max_instructions=1, include_total=True)
    return payload.get("total_instructions", payload.get("instruction_count"))


def main(argv):
    db = None
    it = iter(argv)
    for a in it:
        if a == "--db":
            db = next(it)
    c = IDAClient(URL, db=db)
    c.connect()
    if db is None:
        c.set_db(c.resolve_db())
    print(f"db={c.db}  ({c.health().get('module')})")

    # ---- 1. Full function list via cursor pagination ------------------- #
    print("\n[1] page entire function list (cursor)")
    funcs, pages, total_ms = page_all_funcs(c, page=SAFE_PAGE)
    n = len(funcs)
    print(f"  {n} functions in {pages} pages, {total_ms:.0f}ms "
          f"({total_ms / max(n,1):.3f}ms/func)")

    def sz(f):
        s = f["size"]
        return int(s, 16) if isinstance(s, str) else s
    biggest = sorted(funcs, key=sz, reverse=True)[:5]
    print("  biggest by bytes:")
    for f in biggest:
        print(f"    {f['addr']:>12}  {sz(f):#8x}  {f['name']}")

    # ---- 2. Instruction counts of the biggest -------------------------- #
    print("\n[2] instruction totals of biggest funcs")
    fattest = None
    fattest_n = 0
    for f in biggest:
        dt, total = ms(lambda f=f: disasm_meta(c, f["addr"]))
        print(f"    {f['name']:<28} {str(total):>8} insns  (meta {dt:.1f}ms)")
        if isinstance(total, int) and total > fattest_n:
            fattest, fattest_n = f, total

    # ---- 3. Windowed paging INTO the fattest function ------------------ #
    print(f"\n[3] window-scroll fattest func {fattest['name']} ({fattest_n} insns)")
    WIN = 60  # a viewport
    offsets = list(range(0, max(fattest_n - WIN, 1), max((fattest_n // 12), 1)))
    times = []
    for off in offsets:
        dt, payload = ms(lambda off=off: c.call(
            "disasm", addr=fattest["addr"], offset=off, max_instructions=WIN))
        lines = payload.get("asm", {}).get("lines", [])
        times.append(dt)
        assert len(lines) <= WIN, f"got {len(lines)} > window {WIN}"
    print(f"  {len(offsets)} windowed reads @win={WIN}: "
          f"min={min(times):.1f} med={statistics.median(times):.1f} "
          f"max={max(times):.1f} ms  (payload capped to <= {WIN} lines)")

    # ---- 3b. O(offset) latency curve (the key hazard) ------------------ #
    print("\n[3b] disasm offset-latency curve (offset paging is O(offset))")
    for off in [0, 1000, 5000, 20000, min(50000, fattest_n - WIN)]:
        if off < 0:
            continue
        dt, _ = ms(lambda off=off: c.call(
            "disasm", addr=fattest["addr"], offset=off, max_instructions=WIN))
        print(f"    offset={off:>6}: {dt:6.1f}ms")

    # ---- 4. Simulated 'hold page-down' throughput ---------------------- #
    print("\n[4] rapid sequential scroll (hold page-down)")
    reads, t0, off = 0, time.time(), 0
    while time.time() - t0 < 2.0:
        c.call("disasm", addr=fattest["addr"], offset=off, max_instructions=WIN)
        off = (off + WIN) % max(fattest_n - WIN, 1)
        reads += 1
    dur = time.time() - t0
    print(f"  {reads} windowed reads in {dur:.1f}s = {reads / dur:.0f} reads/s "
          f"(~{reads / dur * WIN:.0f} lines/s)")

    # ---- 5. Decompile: truncation AND hard-failure on monsters --------- #
    print("\n[5] decompile on fattest func (may fail on huge funcs)")
    dt, payload = ms(lambda: c.call("decompile", addr=fattest["addr"]))
    code = payload.get("code") if isinstance(payload, dict) else None
    if not code:
        err = payload.get("error") if isinstance(payload, dict) else payload
        print(f"  decompile {dt:.0f}ms -> FAILED (soft error, not raised): {err}")
    else:
        marker = "chars total]" in code[-40:]
        print(f"  decompile {dt:.0f}ms, returned {len(code)} chars, "
              f"server-truncated={marker}")
        if marker:
            print(f"    tail: ...{code[-60:]!r}")

    c.close()
    print("\nOK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
