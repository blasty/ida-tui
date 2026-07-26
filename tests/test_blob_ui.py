#!/usr/bin/env python3
"""A blob that analyses to NOTHING must still be usable.

Zero functions is the normal outcome for a raw image described wrongly — and it
used to leave two empty panes and a status that said "functions still loading…",
which was a lie: loading had finished, there was simply nothing to land on.

Needs IDA (spawns a real worker). ~40s.
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from textual.widgets import Static  # noqa: E402

from idatui.app import ConfirmScreen, IdaTui, ListingView  # noqa: E402

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


async def run() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        blob = os.path.join(tmp, "rnd.bin")
        with open(blob, "wb") as f:
            f.write(os.urandom(64 * 1024))     # random: IDA will find no code

        # Skip the dialog by answering up front; this test is about what
        # happens AFTER a described blob turns out to contain nothing.
        app = IdaTui(open_path=blob, keepalive=False, load_args="-parm -b400")
        async with app.run_test(size=(140, 44)) as pilot:
            ok = await wait(lambda: app._func_index is not None
                            and app._func_index.complete, pilot)
            check("a random blob still finishes loading", ok)
            check("and really has no functions", len(app._func_index) == 0,
                  f"n={len(app._func_index)}")

            landed = await wait(lambda: app._cur is not None, pilot, 60)
            check("it lands somewhere instead of leaving empty panes", landed,
                  f"cur={app._cur}")
            lst = app.query_one(ListingView)
            check("the listing actually has rows to show",
                  lst.total > 0, f"total={lst.total}")
            check("landed at the image base", app._cur is not None
                  and app._cur.ea == 0x4000, f"{app._cur.ea if app._cur else None:#x}")

            status = str(app.query_one("#status", Static).render())
            check("the status says there are no functions (not 'still loading')",
                  "no functions" in status and "still loading" not in status,
                  status[:90])
            check("and points at the likely cause",
                  "processor" in status and "Ctrl+L" in status, status[:90])

            # The hint is a property of the database, so it must survive moving
            # around — an earlier version wrote it once and the next status
            # write erased it.
            lst.focus()
            await pilot.press("down")
            await pilot.press("down")
            await pilot.pause(0.3)
            status2 = str(app.query_one("#status", Static).render())
            check("the hint survives navigating", "no functions" in status2,
                  status2[:90])

            await pilot.press("ctrl+l")
            opened = await wait(lambda: isinstance(app.screen, ConfirmScreen), pilot, 20)
            check("Ctrl+L offers to reload with different options", opened,
                  f"screen={type(app.screen).__name__}")
            if opened:
                note = str(app.screen.query_one("#confirm-note", Static).render())
                check("and says nothing is lost when there's nothing to lose",
                      "nothing is lost" in note, note[:70])
                await pilot.press("escape")
                await pilot.pause(0.3)
                check("declining leaves the binary open",
                      not isinstance(app.screen, ConfirmScreen) and app._cur is not None)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
