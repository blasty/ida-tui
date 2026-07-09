#!/usr/bin/env python3
"""Validate the domain/paging layer against a real, large binary.

Run with a session open on a big binary (e.g. libcrypto.so.3, 10k funcs):

    python3 tests/test_domain.py --db <session_id>

Checks: correct full pagination (advance by len, not next_offset), viewport
slicing across block boundaries, window caching (revisit is instant), prefetch
warming, cached instruction totals, decompile success + hard-failure handling,
and address resolution.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.client import IDAClient  # noqa: E402
from idatui.domain import DISASM_BLOCK, LIST_PAGE, Program  # noqa: E402

URL = "http://127.0.0.1:8745/mcp"
PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def ms(fn):
    t = time.time()
    r = fn()
    return (time.time() - t) * 1e3, r


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
    prog = Program(c)
    module = c.health().get("module")
    total_funcs = c.call("survey_binary").get("statistics", {}).get("total_functions")
    print(f"db={c.db} module={module} survey_total_functions={total_funcs}")

    # ---- function index: full enumeration correctness ------------------ #
    print("\n[function index]")
    idx = prog.functions()
    dt, _ = ms(lambda: idx.load_all())
    n = len(idx)
    check("enumerated all functions (matches survey)", n == total_funcs,
          f"got {n} vs survey {total_funcs}")
    print(f"    loaded {n} funcs in {dt:.0f}ms ({dt / max(n,1):.3f}ms/func), "
          f"page={LIST_PAGE}")
    # no duplicates, monotonic-ish uniqueness by addr
    addrs = [idx.get(i).addr for i in range(min(n, 3000))]
    check("no duplicate addrs in first 3000", len(addrs) == len(set(addrs)))
    # viewport slice (adapt to binary size)
    wstart = min(1000, max(n - 50, 0))
    wlen = min(50, n - wstart)
    w = idx.window(wstart, wlen)
    check(f"window({wstart},{wlen}) returns {wlen}", len(w) == wlen, str(len(w)))

    # ---- filtered index uses server-side glob -------------------------- #
    print("\n[filtered index]")
    sub = prog.functions(filter="sub_*")
    sub.ensure(10)
    check("filter sub_* yields sub_ names", all(f.name.startswith("sub_") for f in sub.window(0, 10)),
          str([f.name for f in sub.window(0, 5)]))

    # ---- pick the fattest function for disasm stress ------------------- #
    print("\n[disasm windowing]")
    fattest = max((idx.get(i) for i in range(n)), key=lambda f: f.size)
    dm = prog.disasm(fattest.addr, fattest.name)
    dt, total = ms(dm.total)
    check("total() returns positive count", total > 0, str(total))
    dt2, total2 = ms(dm.total)
    check("total() cached (2nd call ~instant)", dt2 < dt / 2 + 1, f"{dt:.0f}ms -> {dt2:.1f}ms")
    print(f"    fattest {fattest.name}: {total} insns, total() {dt:.0f}ms then {dt2:.1f}ms")

    # viewport across a block boundary
    start = DISASM_BLOCK - 5
    win = dm.lines(start, 60, prefetch=False)
    check("viewport spans block boundary, right length",
          len(win) == min(60, max(total - start, 0)), f"got {len(win)}")
    # addresses strictly increasing and contiguous slice
    eas = [ln.ea for ln in win]
    check("viewport addrs strictly increasing", all(b > a for a, b in zip(eas, eas[1:])),
          str(eas[:4]))

    # deep window: first slow (O(offset)), revisit instant (cached)
    if total > DISASM_BLOCK * 4:
        deep = (total // DISASM_BLOCK - 1) * DISASM_BLOCK
        dt_cold, a = ms(lambda: dm.lines(deep, 60, prefetch=False))
        dt_warm, b = ms(lambda: dm.lines(deep, 60, prefetch=False))
        check("deep window revisit is cached/instant", dt_warm < dt_cold / 2 + 1,
              f"cold={dt_cold:.0f}ms warm={dt_warm:.1f}ms")
        check("cached window identical", [l.ea for l in a] == [l.ea for l in b])
        print(f"    deep@{deep}: cold={dt_cold:.0f}ms warm={dt_warm:.1f}ms")

    # prefetch warms the next block
    print("\n[prefetch]")
    dm2 = prog.disasm(fattest.addr + 0)  # same model (cached by ea)
    fresh = prog.disasm(idx.get(0).addr, idx.get(0).name)
    fresh.lines(0, 60, prefetch=True)  # should prefetch block 1
    time.sleep(0.3)
    check("prefetch warmed a neighbor block", fresh.cached_blocks() >= 2,
          f"cached_blocks={fresh.cached_blocks()}")

    # ---- decompile: success + hard-failure ----------------------------- #
    print("\n[decompile]")
    # a small function likely decompiles
    small = min((idx.get(i) for i in range(n)), key=lambda f: f.size if f.size > 4 else 1 << 30)
    d_small = prog.decompile(small.addr)
    check("small func decompiles or fails cleanly", isinstance(d_small.failed, bool))
    dt_c, _ = ms(lambda: prog.decompile(small.addr))
    check("decompile cached (2nd ~instant)", dt_c < 5, f"{dt_c:.1f}ms")
    # the monster should hard-fail as a soft error (not raise)
    d_big = prog.decompile(fattest.addr)
    check("monster decompile handled (failed flag, no raise)",
          d_big.failed or d_big.code is not None,
          f"failed={d_big.failed} err={d_big.error}")
    print(f"    small {small.name}: failed={d_small.failed} "
          f"trunc={d_small.truncated} chars={d_small.total_chars}")
    print(f"    monster {fattest.name}: failed={d_big.failed} err={d_big.error}")

    # ---- resolve ------------------------------------------------------- #
    print("\n[resolve]")
    check("resolve hex", prog.resolve(hex(fattest.addr)) == fattest.addr)
    check("resolve int passthrough", prog.resolve(fattest.addr) == fattest.addr)
    named = next((idx.get(i) for i in range(n) if not idx.get(i).name.startswith("sub_")), None)
    if named:
        try:
            r = prog.resolve(named.name)
            check("resolve symbol name", r == named.addr, f"{hex(r)} vs {hex(named.addr)} ({named.name})")
        except KeyError as e:
            check("resolve symbol name", False, str(e))

    prog.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
