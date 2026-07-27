#!/usr/bin/env python3
"""The trace dock: registers, timeline, and stepping through time.

Needs IDA and a trace. Generates its own trace with the QEMU tracer if the
tracer is built; skips with a message otherwise, since neither the emulator nor
the trace is part of this repo.
"""
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from textual.widgets import Static  # noqa: E402

from idatui.app import IdaTui, ListingView, TraceDock  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACER = os.path.expanduser(
    "~/.pi/agent/skills/tenet-trace/scripts/tenet-trace")
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


async def wait(pred, pilot, t=240.0):
    for _ in range(int(t / 0.05)):
        await pilot.pause(0.05)
        try:
            if pred():
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


def make_trace(tmp, binary):
    out = os.path.join(tmp, "t")
    try:
        subprocess.run([TRACER, "-o", out, binary, "hi"],
                       capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    log = out + ".0.log"
    return log if os.path.exists(log) else None


async def run() -> int:
    binary = os.path.join(REPO, "targets", "echo")
    with tempfile.TemporaryDirectory() as tmp:
        # Scratch copy: opening a binary writes a database beside it, and the
        # suite must not edit anything tracked.
        target = os.path.join(tmp, "echo")
        shutil.copy2(binary, target)
        log = make_trace(tmp, target)
        if not log:
            print(f"  skip: could not record a trace (tracer at {TRACER})")
            return 0

        app = IdaTui(open_path=target, keepalive=False, trace_path=log)
        async with app.run_test(size=(160, 44)) as pilot:
            ok = await wait(lambda: app._trace is not None, pilot, 300)
            check("the trace loads alongside the binary", ok)
            if not ok:
                return 1
            t = app._trace
            check("it has instructions", t.length > 10, f"{t.length}")

            # Rebasing: the tracer runs the binary relocated, so without a slide
            # nothing in the trace matches anything on screen.
            check("trace addresses were rebased onto the database",
                  t.slide != 0 and t.ip(0) < 0x1000000,
                  f"slide={t.slide:#x} ip0={t.ip(0):#x}")
            idx = app._func_index
            touched = [f.name for f in idx.all_loaded() if t.executions(f.addr)]
            check("and now line up with real functions",
                  len(touched) > 1 and "main" in touched, f"{touched[:6]}")

            dock = app.query_one(TraceDock)
            check("the dock is docked and visible", dock.display)
            head = str(dock.query_one("#trace-head", Static).render())
            check("it shows where we are in time", "0" in head and "%" in head,
                  head[:60])
            regs = str(dock.query_one("#trace-regs", Static).render())
            check("and the register state at that time", "rip" in regs.lower(),
                  regs[:60])

            # -- stepping --------------------------------------------------- #
            lst = app.query_one(ListingView)
            lst.focus()
            await pilot.pause(0.4)
            await pilot.press("]")
            await wait(lambda: app._t == 1, pilot, 20)
            check("] steps forward one instruction", app._t == 1, f"t={app._t}")
            check("the code view follows the trace",
                  lst._cursor_ea() == t.ip(1),
                  f"{lst._cursor_ea()} vs {t.ip(1)}")
            await pilot.press("[")
            await wait(lambda: app._t == 0, pilot, 20)
            check("[ steps backward", app._t == 0, f"t={app._t}")
            await pilot.press("[")
            await pilot.pause(0.4)
            check("and stops at the start of the trace", app._t == 0)

            # -- step over -------------------------------------------------- #
            # A call pushes, so the callee runs with SP below where we started;
            # stepping until SP comes back up lands after the return. Find a
            # real call in this trace rather than assuming one is at a fixed
            # place.
            sp = "rsp" if "rsp" in t.reg_at else "esp"
            call_at = None
            for i in range(1, min(t.length - 1, 400)):
                a, b = t.register(sp, i), t.register(sp, i + 1)
                if a and b and b < a:
                    ret = next((j for j in range(i + 1, t.length)
                                if (t.register(sp, j) or 0) >= a), None)
                    if ret and ret > i + 3:
                        call_at = (i, ret)
                        break
            if call_at is None:
                check("found a call to step over", False, "none in this trace")
            else:
                i, ret = call_at
                app._seek(i)
                await wait(lambda: app._t == i, pilot, 20)
                await pilot.press("}")
                await wait(lambda: app._t != i, pilot, 30)
                check("} steps OVER a call instead of into it",
                      app._t == ret, f"{i} -> {app._t}, expected {ret}")
                check("which is further than a plain step", app._t > i + 1)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
