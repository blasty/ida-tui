#!/usr/bin/env python3
"""ARM/Thumb decoding switch, against real Thumb code.

Thumb isn't a property of the bytes — it's a mode the CPU is in — so a raw image
gives IDA no way to know. At a Thumb entry point it decodes 16-bit instructions
as 32-bit ARM and produces confident nonsense, and `c` either fails or carves
garbage. `t` switches the mode.

Uses experiments/fibonacci.bin (real Thumb), so the encodings are not a guess.
Needs IDA. ~40s.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from textual.widgets import Static  # noqa: E402

from idatui.app import DecompView, IdaTui, ListingView  # noqa: E402

PASS = FAIL = 0
BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "experiments", "fibonacci.bin")


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


async def run() -> int:
    # A fresh database every time: the T flag and the segment's addressing mode
    # are SAVED in the .i64, so a previous run would answer the question for us.
    for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        try:
            os.remove(BIN + ext)
        except OSError:
            pass

    app = IdaTui(open_path=BIN, keepalive=False, load_args="-parm")
    async with app.run_test(size=(140, 44)) as pilot:
        await wait(lambda: app._func_index is not None
                   and app._func_index.complete, pilot)
        await wait(lambda: app._cur is not None, pilot, 60)
        lst = app.query_one(ListingView)
        lst.focus()
        lst.cursor = lst.model.index_of_ea(0)
        lst._scroll_cursor_into_view()
        await pilot.pause(0.3)
        check("starts undefined at the entry", lst.model.get(lst.cursor).kind == "unknown",
              f"{lst.model.get(lst.cursor).text!r}")

        # `c` in the wrong mode: this is the failure being fixed. It must NOT
        # quietly carve garbage — either it refuses, or whatever it makes is not
        # the Thumb prologue.
        m0 = lst.model
        await pilot.press("c")
        await pilot.pause(2.5)
        h = lst.model.get(lst.model.index_of_ea(0))
        check("`c` alone does not produce the Thumb prologue",
              h is None or h.kind != "code" or "PUSH" not in h.text.upper(),
              f"{h.text if h else None!r}")

        m1 = lst.model
        await pilot.press("t")
        await wait(lambda: lst.model is not m1 and lst.model is not None, pilot, 60)
        await pilot.pause(0.5)

        status = str(app.query_one("#status", Static).render())
        check("the status says it switched to Thumb", "Thumb" in status, status[:90])
        # Thumb doesn't exist in AArch64, and -parm on a headerless blob gives a
        # 64-bit segment, so setting T alone would change nothing and look broken.
        check("and says it forced the segment to 32-bit",
              "32-bit" in status, status[:90])

        m = lst.model
        rows = [m.get(m.index_of_ea(ea)) for ea in (0x0, 0x2, 0x4)]
        check("the entry decodes as Thumb",
              rows[0] is not None and rows[0].kind == "code"
              and "PUSH" in rows[0].text.upper(),
              f"{rows[0].text if rows[0] else None!r}")
        # 16-bit instructions: the addresses are 2 apart, which is the whole
        # point — in ARM mode these would be one 4-byte instruction.
        check("instructions are 16-bit wide",
              all(r is not None and r.kind == "code" and r.size == 2 for r in rows),
              f"{[(hex(r.ea), r.size, r.text) for r in rows if r]}")
        check("and it kept disassembling past the first one",
              sum(1 for i in range(20) if (m.get(i) or h).kind == "code") > 5,
              "expected a run of instructions, not one")

        # Toggling back must be possible — the mode is a guess and guesses get
        # revised.
        m2 = lst.model
        lst.cursor = lst.model.index_of_ea(0)
        await pilot.press("t")
        await wait(lambda: lst.model is not m2 and lst.model is not None, pilot, 60)
        await pilot.pause(0.5)
        status = str(app.query_one("#status", Static).render())
        check("`t` toggles back to ARM", "ARM @" in status, status[:80])

    # -- and the reason a carved function wouldn't decompile ---------------- #
    # Bare 'arm' gives a 64-BIT database. Thumb doesn't exist there, and
    # Hex-Rays refuses a 32-bit function outright ("only 64-bit functions can be
    # decompiled in the current database") — so `t` produces correct-looking
    # disassembly that F5 can never turn into pseudocode. The database's bitness
    # is fixed at load and cannot be corrected afterwards, so the only honest
    # thing is to say so.
    for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        try:
            os.remove(BIN + ext)
        except OSError:
            pass
    app = IdaTui(open_path=BIN, keepalive=False, load_args="-parm")   # 64-bit
    async with app.run_test(size=(140, 44)) as pilot:
        await wait(lambda: app._func_index is not None
                   and app._func_index.complete, pilot)
        await wait(lambda: app._cur is not None, pilot, 60)
        lst = app.query_one(ListingView)
        lst.focus()
        lst.cursor = lst.model.index_of_ea(0)
        lst._scroll_cursor_into_view()
        await pilot.pause(0.3)
        m = lst.model
        await pilot.press("t")
        await wait(lambda: lst.model is not m and lst.model is not None, pilot, 60)
        await pilot.pause(0.5)
        status = str(app.query_one("#status", Static).render())
        check("a 64-bit database warns that Hex-Rays won't decompile",
              "64-bit" in status and "decompile" in status, status[:120])
        check("and names the fix", "ARMv7-A" in status, status[:120])

        # And if you ignore that and carry on, the failure has to say WHY. The
        # plain decompile tool reports "Decompilation failed at 0x0" and drops
        # the reason, which is the only part that tells you what to do — with it
        # missing, F5 doing nothing is indistinguishable from a bug in the TUI.
        lst.cursor = lst.model.index_of_ea(0)
        await pilot.pause(0.2)
        mp = lst.model
        await pilot.press("p")
        await wait(lambda: lst.model is not mp and lst.model is not None, pilot, 60)
        await wait(lambda: app._func_index is not None
                   and len(app._func_index) > 0, pilot, 60)
        await pilot.press("tab")
        await wait(lambda: "cannot decompile" in
                   str(app.query_one("#status", Static).render()), pilot, 90)
        status = str(app.query_one("#status", Static).render())
        # The message must say what to DO. Hex-Rays' own sentence ("only 64-bit
        # functions can be decompiled in the current database") describes the
        # database, not the fix, and is long enough that a status bar cuts off
        # the end — which is where an appended hint would have lived.
        check("a failed decompile names the fix, not just the diagnosis",
              "Ctrl+L" in status and "ARMv7-A" in status, status[:130])
        check("and the reason survives the view reloading under it",
              "cannot decompile" in status, status[:130])
        check("the message fits a narrow status bar",
              len(status) < 110, f"{len(status)} chars: {status[:130]}")

    # -- the whole point: a 32-bit database decompiles ---------------------- #
    for ext in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        try:
            os.remove(BIN + ext)
        except OSError:
            pass
    app = IdaTui(open_path=BIN, keepalive=False, load_args="-parm:ARMv7-A")
    async with app.run_test(size=(140, 44)) as pilot:
        await wait(lambda: app._func_index is not None
                   and app._func_index.complete, pilot)
        # A 32-bit ARM database also lets auto-analysis do its job on Thumb code,
        # which is why this one lands in the symbol picker rather than nowhere.
        check("a 32-bit ARM database finds functions by itself",
              len(app._func_index) > 5, f"n={len(app._func_index)}")
        await pilot.press("escape")
        await pilot.pause(0.5)
        f = app._func_index.all_loaded()[0]
        app._goto_ea(f.addr, push=True)
        await wait(lambda: app._cur is not None
                   and app.query_one(ListingView).model is not None, pilot, 60)
        app.query_one(ListingView).focus()
        await pilot.press("tab")
        dec = app.query_one(DecompView)
        got = await wait(lambda: dec.display and dec._texts, pilot, 90)
        check("Tab decompiles a Thumb function", got and len(dec._texts) > 3,
              f"lines={len(dec._texts or [])}")
        check("and it reads like C",
              any("(" in t and ")" in t for t in (dec._texts or [])[:3]),
              f"{(dec._texts or [])[:3]}")

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    if not os.path.isfile(BIN):
        print(f"no such binary: {BIN}")
        raise SystemExit(2)
    raise SystemExit(asyncio.run(run()))
