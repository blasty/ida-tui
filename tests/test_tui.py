#!/usr/bin/env python3
"""Headless pilot test for the Phase-1 TUI (no real terminal needed).

    python3 tests/test_tui.py --db <session_id>

Drives the app via Textual's Pilot: boots, loads the function list, opens a
function into the virtualized disasm view, scrolls it, and checks the cursor /
status update. Uses ~/ida-venv python (has textual).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.app import DecompView, DisasmView, FunctionsPanel, IdaTui  # noqa: E402
from textual.widgets import DataTable, Static  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


async def wait_until(pilot, pred, timeout=30.0, step=0.2):
    waited = 0.0
    while waited < timeout:
        if pred():
            return True
        await pilot.pause(step)
        waited += step
    return False


async def run(db):
    url = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:8745/mcp")
    app = IdaTui(url=url, db=db, keepalive=False)
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#func-table", DataTable)
        status = app.query_one("#status", Static)

        loaded = await wait_until(pilot, lambda: table.row_count > 0)
        check("function list populated", loaded, f"rows={table.row_count}")

        got_all = await wait_until(
            pilot, lambda: "functions" in str(status.render()) and "…" not in str(status.render()),
            timeout=30,
        )
        check("function load completed (status settled)", got_all, str(status.render()))
        nfuncs = table.row_count
        print(f"    loaded {nfuncs} functions")

        # Open the biggest function we can find (scan a sample of rows for size).
        # Simpler: select the row whose Size column is largest among first N.
        biggest_i, biggest_sz = 0, -1
        scan = min(nfuncs, 4000)
        for i in range(scan):
            row = table.get_row_at(i)
            sz = int(str(row[2]), 16)
            if sz > biggest_sz:
                biggest_sz, biggest_i = sz, i

        table.move_cursor(row=biggest_i)
        await pilot.pause(0.1)
        table.focus()
        await pilot.press("enter")

        view = app.query_one(DisasmView)
        opened = await wait_until(pilot, lambda: view.total > 0, timeout=30)
        check("disasm view opened with a total", opened, f"total={view.total}")
        print(f"    opened func with {view.total} instructions")

        # Wait for the first lines to be cached, then verify a rendered line.
        cached = await wait_until(
            pilot, lambda: view.model is not None and view.model.cached_line(0) is not None,
            timeout=20,
        )
        check("first instruction cached", cached)

        # Scroll down a page and confirm cursor advances + status shows an ea.
        for _ in range(5):
            await pilot.press("pagedown")
            await pilot.pause(0.05)
        moved = view.cursor > 0
        check("pagedown moved the cursor", moved, f"cursor={view.cursor}")
        await wait_until(pilot, lambda: view.model.cached_line(view.cursor) is not None, 15)
        check("cursor line eventually cached (bg fetch)",
              view.model.cached_line(view.cursor) is not None)
        check("status shows an address", "@ 0x" in str(status.render()), str(status.render()))

        # Jump to bottom of a (possibly huge) function; must not hang.
        await pilot.press("end")
        await pilot.pause(0.1)
        check("goto-bottom lands near end",
              view.cursor >= view.total - 1, f"cursor={view.cursor}/{view.total}")

        # Filter round-trip.
        await pilot.press("slash")
        await pilot.pause(0.1)
        for ch in "sub_1*":
            await pilot.press(ch if ch != "*" else "asterisk")
        await pilot.press("enter")
        filtered = await wait_until(
            pilot, lambda: table.row_count > 0 and table.row_count < nfuncs, timeout=15
        )
        check("filter narrowed the list", filtered, f"rows={table.row_count} of {nfuncs}")

        # Toggle the functions pane show/hide.
        left = app.query_one("#left", FunctionsPanel)
        await pilot.press("ctrl+b")
        await pilot.pause(0.1)
        check("ctrl+b hides functions pane + focuses disasm",
              not left.display and isinstance(app.focused, DisasmView),
              f"display={left.display} focus={type(app.focused).__name__}")
        await pilot.press("ctrl+b")
        await pilot.pause(0.1)
        check("ctrl+b again restores pane + focuses table",
              left.display and isinstance(app.focused, DataTable),
              f"display={left.display} focus={type(app.focused).__name__}")

        # Decompiler toggle: open a function, Tab -> pseudocode, Shift+Tab -> back.
        table.focus()
        table.move_cursor(row=biggest_i)
        await pilot.press("enter")
        dis = app.query_one(DisasmView)
        dec = app.query_one(DecompView)
        await wait_until(pilot, lambda: dis.total > 0, timeout=20)
        await pilot.press("tab")
        pc = await wait_until(pilot, lambda: dec.display and dec.loaded_ea is not None, 25)
        check("tab shows pseudocode", pc and app._active == "decomp",
              f"active={app._active} disp={dec.display}")
        check("pseudocode has many lines", dec.total > 20, f"lines={dec.total}")
        # Highlighting: at least one styled (colored) segment across the body.
        styled = any(
            seg.style is not None and seg.style.color is not None
            for strip in dec._strips[: min(dec.total, 200)]
            for seg in strip
        )
        check("pseudocode is syntax-highlighted", styled)
        await pilot.press("shift+tab")
        await pilot.pause(0.2)
        check("shift+tab returns to disassembly",
              app._active == "disasm" and dis.display and not dec.display,
              f"active={app._active}")


def main(argv):
    db = None
    it = iter(argv)
    for a in it:
        if a == "--db":
            db = next(it)
    asyncio.run(run(db))
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
