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

from idatui.app import IdaTui, ListingView  # noqa: E402

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

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    if not os.path.isfile(BIN):
        print(f"no such binary: {BIN}")
        raise SystemExit(2)
    raise SystemExit(asyncio.run(run()))
