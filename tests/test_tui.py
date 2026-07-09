#!/usr/bin/env python3
"""Headless pilot test for the Phase-1 TUI (no real terminal needed).

    python3 tests/test_tui.py --db <session_id>
    python3 tests/test_tui.py --db <session_id> --stop-after "search finds"

Drives the app via Textual's Pilot: boots, loads the function list, opens a
function into the virtualized disasm view, scrolls it, and checks the cursor /
status update. Uses ~/ida-venv python (has textual).

--stop-after <substr> ends the run once a check whose name contains <substr> has
been evaluated, skipping the (often expensive) tail -- handy for fast iteration
on a single feature. The default (no flag) runs the whole suite.
"""
import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.app import (  # noqa: E402
    DecompView, DisasmView, FunctionsPanel, IdaTui, XrefsScreen,
)
from textual.widgets import DataTable, Input, OptionList, Static  # noqa: E402
from rich.text import Text  # noqa: E402

PASS = FAIL = 0
STOP_AFTER = None  # --stop-after <substr>: end the run once a matching check ran


class _StopSuite(Exception):
    """Unwind cleanly once the requested --stop-after check has been evaluated."""


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")
    if STOP_AFTER and STOP_AFTER in name:
        raise _StopSuite


async def wait_until(pilot, pred, timeout=30.0, step=0.02):
    # Poll finely so a condition that resolves quickly (the common case on a warm
    # session) is detected promptly instead of up to `step` late across the ~50
    # call sites; the timeout ceiling is unchanged.
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
        left = app.query_one("#left")
        check("function pane width is capped (doesn't eat the screen)",
              left.size.width <= 44, f"width={left.size.width}")

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
        await pilot.pause(0.05)
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
            await pilot.pause(0.025)
        moved = view.cursor > 0
        check("pagedown moved the cursor", moved, f"cursor={view.cursor}")
        await wait_until(pilot, lambda: view.model.cached_line(view.cursor) is not None, 15)
        check("cursor line eventually cached (bg fetch)",
              view.model.cached_line(view.cursor) is not None)
        check("status shows an address", "@ 0x" in str(status.render()), str(status.render()))

        # Jump to bottom of a (possibly huge) function; must not hang.
        await pilot.press("end")
        await pilot.pause(0.05)
        check("goto-bottom lands near end",
              view.cursor >= view.total - 1, f"cursor={view.cursor}/{view.total}")

        # Filter round-trip. '/' is context-sensitive: it filters when the
        # function table is focused (and searches when a code view is focused),
        # so focus the table first.
        table.focus()
        await pilot.pause(0.05)
        await pilot.press("slash")
        await pilot.pause(0.05)
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
        await pilot.pause(0.05)
        check("ctrl+b hides functions pane + focuses disasm",
              not left.display and isinstance(app.focused, DisasmView),
              f"display={left.display} focus={type(app.focused).__name__}")
        await pilot.press("ctrl+b")
        await pilot.pause(0.05)
        check("ctrl+b again restores pane + focuses table",
              left.display and isinstance(app.focused, DataTable),
              f"display={left.display} focus={type(app.focused).__name__}")

        # The 'sub_1*' round-trip above left the list filtered; clear it so the
        # full table is back and biggest_i (an unfiltered row index) is valid.
        app.clear_filter()
        await wait_until(pilot, lambda: table.row_count == nfuncs, timeout=15)

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
        await pilot.pause(0.1)
        check("shift+tab returns to disassembly",
              app._active == "disasm" and dis.display and not dec.display,
              f"active={app._active}")

        # A (re)decompile shows a grayed 'decompiling…' overlay while it runs.
        await pilot.press("tab")
        await wait_until(pilot, lambda: app._active == "decomp", timeout=10)
        await wait_until(pilot, lambda: dec.loaded_ea is not None, timeout=20)
        dec.loaded_ea = None            # force a reload (as rename/refresh does)
        app._show_active()
        cover = dec._cover_widget
        check("decompile shows a 'decompiling…' overlay",
              dec.loading and cover is not None
              and "decomp-loading" in cover.classes
              and "decompiling" in str(cover.render()),
              f"loading={dec.loading} cover={cover!r}")
        await wait_until(pilot, lambda: not dec.loading and dec._cover_widget is None,
                         timeout=25)
        check("overlay clears when the decompile finishes",
              not dec.loading and dec._cover_widget is None)
        # Line-number gutter.
        dec.scroll_to(0, 0, animate=False)
        await pilot.pause(0.025)
        row0 = "".join(seg.text for seg in dec.render_line(0))
        check("pseudocode has a numbered gutter (line 1 first)",
              dec._gutter > 0 and row0[:dec._gutter].strip() == "1",
              f"gutter={dec._gutter} row0={row0[:10]!r}")
        await pilot.press("tab")  # back to disasm for the rest of the tests
        await wait_until(pilot, lambda: app._active == "disasm", timeout=10)

        # Vim-style search in the disassembly view.
        line0 = dis.model.cached_line(0)
        raw = (line0.text.split() or ["push"])[0] if line0 else "push"
        term = "".join(c for c in raw if c.isalnum())[:4] or "push"
        await pilot.press("slash")
        await pilot.pause(0.1)
        for ch in term:
            await pilot.press(ch)
        await pilot.press("enter")
        await wait_until(pilot, lambda: bool(dis._matches), timeout=25)
        check("search finds matches", len(dis._matches) > 0, f"term={term!r}")
        check("cursor sits on a match", dis.cursor in dis._matches, f"cursor={dis.cursor}")
        check("match substring highlighted",
              bool(dis._ranges.get(dis.cursor)), str(dis._ranges.get(dis.cursor)))
        check("search cursor lands on the match's starting column",
              dis.cursor_x == dis._ranges[dis.cursor][0][0],
              f"cursor_x={dis.cursor_x} ranges={dis._ranges.get(dis.cursor)}")
        prev = dis.cursor
        await pilot.press("slash")
        await pilot.pause(0.05)
        await pilot.press("enter")
        await pilot.pause(0.05)
        check("'/' repeats to next match",
              dis.cursor != prev and dis.cursor in dis._matches, f"cursor={dis.cursor}")
        await pilot.press("question_mark")
        await pilot.pause(0.05)
        await pilot.press("enter")
        await pilot.pause(0.05)
        check("'?' repeats to previous match", dis.cursor in dis._matches,
              f"cursor={dis.cursor}")

        # Incremental search + visible bar + Esc cancel.
        si = app.query_one("#search", Input)
        status = app.query_one("#status", Static)
        await pilot.press("slash")
        await pilot.pause(0.1)
        check("search bar visible, status hidden (no overlap)",
              si.display and not status.display, f"si={si.display} status={status.display}")
        from textual.widgets import Footer as _Footer
        footer = app.query_one(_Footer)
        check("search input is rendered above the footer (not overlapping)",
              si.region.height >= 1 and si.region.y < footer.region.y,
              f"search={si.region} footer={footer.region}")
        for ch in term:
            await pilot.press(ch)
            await pilot.pause(0.05)
        check("matches highlight incrementally (before Enter)",
              len(dis._matches) > 0 and si.value == term, f"val={si.value!r}")
        await pilot.press("escape")
        await pilot.pause(0.1)
        check("Esc cancels: status restored, matches cleared",
              status.display and not si.display and not dis._matches,
              f"status={status.display} si={si.display} m={len(dis._matches)}")

        # Incremental function-name filter + highlight + Esc-clear.
        table.focus()
        await pilot.pause(0.05)
        if app._filter_term:  # clear any leftover filter from earlier
            await pilot.press("escape")
            await pilot.pause(0.1)
        full = table.row_count
        await pilot.press("slash")
        await pilot.pause(0.1)
        for ch in "sub_":
            await pilot.press(ch)
            await pilot.pause(0.05)
        await pilot.pause(0.1)
        check("filter narrows incrementally as you type",
              0 < table.row_count < full, f"{table.row_count}/{full}")
        cell = table.get_row_at(0)[1]
        check("filter highlights matched substring in name",
              isinstance(cell, Text) and any(s.style for s in cell.spans), repr(str(cell)))
        await pilot.press("enter")
        await pilot.pause(0.1)
        check("Enter keeps filter + focuses table",
              isinstance(app.focused, DataTable) and table.row_count < full)
        await pilot.press("escape")
        await pilot.pause(0.15)
        check("Esc on the list clears the filter", table.row_count == full,
              f"{table.row_count}/{full}")

        # Follow (Enter) + back (Esc) + xrefs (x), using a real call site.
        dis = app.query_one(DisasmView)
        dis.focus()
        await pilot.pause(0.05)
        lines = dis.model.lines(0, 400, prefetch=False)
        call_idx = next((i for i, ln in enumerate(lines)
                         if ln.text.startswith("call ")), None)
        if call_idx is None:
            check("found a call line to exercise follow/xrefs", False, "no call in first 400")
        else:
            dis.cursor = call_idx
            dis.refresh()
            orig = app._cur.ea
            orig_name = app._cur.name
            depth = len(app._nav)
            await pilot.press("enter")
            await wait_until(pilot, lambda: len(app._nav) > depth, timeout=25)
            check("Enter follows the call into another function",
                  app._cur.ea != orig and len(app._nav) > depth, f"cur={app._cur.ea:#x}")
            await pilot.press("escape")
            await pilot.pause(0.1)
            check("Esc returns from the follow", app._cur.ea == orig, f"cur={app._cur.ea:#x}")
            dis.cursor = call_idx
            dis.refresh()
            await pilot.press("x")
            opened = await wait_until(
                pilot, lambda: isinstance(app.screen, XrefsScreen), timeout=25)
            check("'x' opens the xrefs popup", opened,
                  f"screen={type(app.screen).__name__}")
            if opened:
                check("xrefs popup has entries",
                      app.screen.query_one(OptionList).option_count >= 1)
                await pilot.press("escape")
                await pilot.pause(0.1)
                check("Esc closes the xrefs popup",
                      not isinstance(app.screen, XrefsScreen))

            # Selecting an xref must land on the referencing SITE (right function
            # AND line), not the function under the cursor.
            xf = None
            for cand in app.program.functions().all_loaded()[:600]:
                codex = [x for x in app.program.xrefs_to(cand.addr)
                         if x.type == "code" and x.frm]
                if codex:
                    xf = (cand, codex[0])
                    break
            if xf is None:
                check("found a function with a code xref", False)
            else:
                xfn, xref = xf
                xexp = app.program.disasm(xref.fn_addr).index_of_ea(xref.frm)
                await pilot.press("g")
                await pilot.pause(0.1)
                for ch in xfn.name:
                    await pilot.press(ch)
                await pilot.press("enter")
                await wait_until(pilot, lambda: dis.total > 0 and app._cur.ea == xfn.addr,
                                 timeout=20)
                dis.focus()
                dis.cursor, dis.cursor_x = 0, 0  # on the entry (address column)
                await pilot.press("x")
                await wait_until(pilot, lambda: isinstance(app.screen, XrefsScreen), 25)
                app.screen.query_one(OptionList).highlighted = 0
                await pilot.press("enter")
                await wait_until(pilot, lambda: not isinstance(app.screen, XrefsScreen), 25)
                await wait_until(pilot, lambda: app._cur.ea == xref.fn_addr, timeout=25)
                await pilot.pause(0.15)
                check("xref-select lands on the referencing function + line",
                      app._cur.ea == xref.fn_addr and dis.cursor == xexp,
                      f"cur={app._cur.ea:#x} (want {xref.fn_addr:#x}) "
                      f"cursor={dis.cursor} (want {xexp})")

                # Same jump, but with the DECOMPILER pane active: it must land on
                # the reference LINE in pseudocode, not the top of the function.
                # (Repro of the reported bug; _on_xref_chosen is the dialog's
                # selection callback, the exact seam that was broken.)
                dec = app.query_one(DecompView)
                dcode = app.program.decompile(xref.fn_addr)
                dexp, be = -1, -1  # expected pseudocode line for the ref site
                if not dcode.failed and dcode.code:
                    for i, ln in enumerate(dcode.code.splitlines()):
                        for mm in re.findall(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/", ln):
                            e = int(mm, 16)
                            if be < e <= xref.frm:
                                be, dexp = e, i
                if dexp >= 0:
                    app._open_function(xfn.addr, xfn.name)  # start elsewhere
                    await wait_until(pilot, lambda: app._cur.ea == xfn.addr, 20)
                    app._active = "decomp"
                    app._show_active()
                    await wait_until(pilot, lambda: dec.loaded_ea == xfn.addr, 25)
                    app._on_xref_chosen(xref.frm)  # pick the caller from the dialog
                    await wait_until(pilot, lambda: dec.loaded_ea == xref.fn_addr, 25)
                    await pilot.pause(0.1)
                    check("xref-select lands on the reference LINE in pseudocode",
                          dec.cursor == dexp, f"dec.cursor={dec.cursor} want={dexp}")
                    app._active = "disasm"     # restore for the following blocks
                    app._show_active()
                    await pilot.pause(0.05)

            # The xref-select sub-test above navigated 'dis' to another function;
            # return to the original and materialize the call line so the column
            # cursor operates on a cached (non-empty) line.
            app._open_function(orig, orig_name)
            await wait_until(pilot, lambda: dis.total > 0 and app._cur.ea == orig, 20)
            dis.model.lines(0, 400, prefetch=False)
            # Column cursor: h/l move it; following the symbol under the cursor.
            dis.focus()
            dis.cursor = call_idx
            dis.cursor_x = 5
            dis.refresh()
            await pilot.pause(0.025)
            await pilot.press("h")
            check("h moves the column cursor left", dis.cursor_x == 4, f"x={dis.cursor_x}")
            await pilot.press("l")
            await pilot.press("l")
            check("l moves the column cursor right", dis.cursor_x == 6, f"x={dis.cursor_x}")
            plain = dis._line_plain(call_idx) or ""
            m = re.search(r"\b(sub_[0-9A-Fa-f]+)", plain)
            if m:
                dis.cursor = call_idx
                dis.cursor_x = m.start(1) + 1
                dis.refresh()
                await pilot.pause(0.05)
                check("word-under-cursor is the operand symbol",
                      dis.word_under_cursor() == m.group(1),
                      f"{dis.word_under_cursor()!r} vs {m.group(1)!r}")
                depth = len(app._nav)
                want = app.program.resolve(m.group(1))
                await pilot.press("enter")
                await wait_until(pilot, lambda: len(app._nav) > depth, timeout=25)
                check("follows the symbol under the cursor",
                      app._cur.ea == want, f"cur={app._cur.ea:#x} want={want:#x}")

        # Mouse: single click places the cursor; double-click follows.
        table.focus()
        table.move_cursor(row=biggest_i)
        await pilot.press("enter")
        await wait_until(pilot, lambda: dis.total > 0, timeout=20)
        dis.focus()
        await pilot.pause(0.1)
        mrow = mcol = msym = mline = None
        for _ in range(40):  # page down until a 'call sub_' is on screen
            top = round(dis.scroll_offset.y)
            dis.model.lines(top, dis.size.height + 2, prefetch=False)
            for r in range(min(dis.size.height, dis.total - top)):
                plain = dis._line_plain(top + r)
                if plain and "call" in plain:
                    mm = re.search(r"\b(sub_[0-9A-Fa-f]+)", plain)
                    if mm:
                        mrow, mcol, msym, mline = r, mm.start(1), mm.group(1), top + r
                        break
            if mrow is not None:
                break
            await pilot.press("pagedown")
            await pilot.pause(0.025)
        if mrow is None:
            check("found a call line for the mouse test", False, "no visible call sub_")
        else:
            await pilot.click(dis, offset=(mcol + 1, mrow))  # +1: left padding
            await pilot.pause(0.05)
            check("single click places the cursor on the clicked token",
                  dis.cursor == mline and dis.word_under_cursor() == msym,
                  f"cursor={dis.cursor} (want {mline}) word={dis.word_under_cursor()!r}")
            depth = len(app._nav)
            want = app.program.resolve(msym)
            await pilot.click(dis, offset=(mcol + 1, mrow), times=2)
            await wait_until(pilot, lambda: len(app._nav) > depth, timeout=25)
            check("double-click follows the symbol", app._cur.ea == want,
                  f"cur={app._cur.ea:#x} want={want:#x}")
            # Back restores the exact cursor position (line AND column).
            await pilot.press("escape")
            await wait_until(pilot, lambda: app._cur.ea != want, timeout=20)
            await wait_until(pilot, lambda: dis.total > 0 and dis.cursor == mline, timeout=20)
            check("back restores the exact line + column",
                  dis.cursor == mline and dis.word_under_cursor() == msym,
                  f"cursor={dis.cursor} (want {mline}) word={dis.word_under_cursor()!r}")

        # Pseudocode-view position is tracked independently across jumps.
        prog = app.program
        fi = prog.functions()
        fi.ensure(500)
        pick = None
        for fn in fi.all_loaded()[:500]:
            d = prog.decompile(fn.addr)
            if d.failed or not d.code:
                continue
            dl = d.code.split("\n")
            if len(dl) < 12:
                continue
            for i, txt in enumerate(dl):
                if i < 8:
                    continue
                dm2 = re.search(r"\b(sub_[0-9A-Fa-f]+)", txt)
                if dm2 and dm2.group(1) != fn.name:
                    pick = (fn, i, dm2.start(1), dm2.group(1))
                    break
            if pick:
                break
        if pick is None:
            check("found a pseudocode line to test decomp nav", False)
        else:
            fn, drow, dcol, dsym = pick
            await pilot.press("g")
            await pilot.pause(0.1)
            for ch in fn.name:
                await pilot.press(ch)
            await pilot.press("enter")
            await wait_until(pilot, lambda: dis.total > 0, timeout=20)
            await pilot.press("tab")
            await wait_until(pilot, lambda: dec.loaded_ea == fn.addr, timeout=20)
            dec.cursor = drow
            dec.cursor_x = dcol
            dec._after_cursor_move()
            await pilot.pause(0.05)
            depth = len(app._nav)
            await pilot.press("enter")  # follow the sym under the pseudocode cursor
            await wait_until(pilot, lambda: len(app._nav) > depth, timeout=25)
            await pilot.press("escape")
            await wait_until(pilot, lambda: dec.loaded_ea == fn.addr, timeout=25)
            await pilot.pause(0.1)
            check("pseudocode-view position restored after jump+back",
                  dec.cursor == drow and dec.word_under_cursor() == dsym,
                  f"cursor={dec.cursor} (want {drow}) word={dec.word_under_cursor()!r}")

            # Follow must still work when the name is stale (as right after a
            # rename, before the pseudocode text catches up): the ea-marker
            # fallback follows by address regardless of the (old) token.
            dstale = app.program.resolve(dsym)
            old_line = dec._texts[drow] if drow < len(dec._texts) else ""
            if "/*0x" in old_line and dsym in old_line:
                tmpname = f"stale_{os.getpid()}"
                app.program.client.call(
                    "rename", batch={"func": {"addr": hex(dstale), "name": tmpname}})
                app.program.bump_names()
                d2 = len(app._nav)
                app._follow_decomp(old_line, dsym)  # dsym is now the OLD name
                await wait_until(pilot, lambda: len(app._nav) > d2, timeout=25)
                check("decomp follow works with a stale name (ea-marker fallback)",
                      app._cur.ea == dstale, f"cur={app._cur.ea:#x} want={dstale:#x}")
                app.program.client.call(
                    "rename", batch={"func": {"addr": hex(dstale), "name": dsym}})
                app.program.bump_names()

        # Column sort: click headers to sort by name / address.
        if app._filter_term:
            app._apply_filter("")
            await pilot.pause(0.05)
        await pilot.click(table, offset=(15, 0))  # Function header
        await pilot.pause(0.15)
        snames = [str(table.get_row_at(i)[1]) for i in range(min(20, table.row_count))]
        check("click Function header sorts by name",
              app._sort_col == 1 and snames == sorted(snames, key=str.lower),
              f"sort_col={app._sort_col}")
        first_asc = str(table.get_row_at(0)[1])
        await pilot.click(table, offset=(15, 0))  # reverse
        await pilot.pause(0.15)
        check("click again reverses the sort",
              app._sort_reverse and str(table.get_row_at(0)[1]) != first_asc)
        await pilot.click(table, offset=(3, 0))  # Address header
        await pilot.pause(0.15)
        saddrs = [int(str(table.get_row_at(i)[0]), 16) for i in range(min(20, table.row_count))]
        check("click Address header sorts by address",
              app._sort_col == 0 and saddrs == sorted(saddrs), f"sort_col={app._sort_col}")

        # Rename via 'n' (reuse the pseudocode sub_ ref found above).
        if pick is not None:
            fn, drow, dcol, dsym = pick
            dtarget = app.program.resolve(dsym)
            await pilot.press("g")
            await pilot.pause(0.1)
            for ch in fn.name:
                await pilot.press(ch)
            await pilot.press("enter")
            await wait_until(pilot, lambda: dis.total > 0, timeout=20)
            if app._active != "decomp":
                await pilot.press("tab")
            await wait_until(pilot, lambda: dec.loaded_ea == fn.addr, timeout=20)
            dec.focus()
            dec.cursor, dec.cursor_x = drow, dcol + 1
            dec.refresh()
            await pilot.pause(0.05)
            newname = f"ren_{os.getpid()}"
            await pilot.press("n")
            await pilot.pause(0.1)
            ri = app.query_one("#rename", Input)
            check("'n' opens the rename prompt prefilled with the symbol",
                  ri.display and ri.value == dsym, f"val={ri.value!r}")
            ri.value = newname
            await pilot.press("enter")
            await wait_until(
                pilot,
                lambda: app._func_index.by_addr(dtarget)
                and app._func_index.by_addr(dtarget).name == newname,
                timeout=25,
            )
            check("rename updates the function name",
                  app._func_index.by_addr(dtarget).name == newname,
                  app._func_index.by_addr(dtarget).name)
            # revert via the API for reliable, race-free cleanup
            rr = app.program.client.call(
                "rename", batch={"func": {"addr": hex(dtarget), "name": dsym}})
            check("rename reverted cleanly",
                  rr.get("summary", {}).get("ok", 0) == 1, str(rr.get("summary")))

            # A Hex-Rays goto label has no rename API; pressing 'n' on one must be
            # refused up front with a clear message, not open a prompt that then
            # fails with a misleading 'local variable not found'.
            def _find_label():
                for i, t in enumerate(dec._texts):
                    mm = re.search(r"\bLABEL_\d+\b", t)
                    if mm:
                        return i, mm.start(), mm.group(0)
                return None
            lab = _find_label()
            if lab is None:  # current func has none; main reliably has labels
                await pilot.press("g")
                await pilot.pause(0.1)
                for ch in "main":
                    await pilot.press(ch)
                await pilot.press("enter")
                await wait_until(pilot, lambda: app._cur and app._cur.name == "main", 20)
                if app._active != "decomp":
                    await pilot.press("tab")
                await wait_until(pilot, lambda: dec.loaded_ea == app._cur.ea, 25)
                lab = _find_label()
            if lab is not None:
                li, lc, ltok = lab
                dec.focus()
                dec.cursor, dec.cursor_x = li, lc + 1
                dec.refresh()
                await pilot.pause(0.05)
                await pilot.press("n")
                await pilot.pause(0.1)
                ri2 = app.query_one("#rename", Input)
                st = str(app.query_one("#status").render())
                check("renaming a pseudocode label is refused with a clear message",
                      (not ri2.display) and "label" in st.lower(),
                      f"display={ri2.display} status={st!r}")
            else:
                check("found a pseudocode label to test", False, "no LABEL_ found")

            # Add a comment on the current pseudocode line via ';' and confirm it
            # renders after the decompiler refreshes.
            cline = next((i for i, t in enumerate(dec._texts)
                          if i > 5 and "/*0x" in t and t.strip() and "//" not in t), None)
            if cline is not None:
                cea = dec._line_ea(cline)
                dec.focus()
                dec.cursor, dec.cursor_x = cline, 2
                dec.refresh()
                await pilot.pause(0.05)
                await pilot.press("semicolon")
                await pilot.pause(0.1)
                ci = app.query_one("#comment", Input)
                cnote = f"note_{os.getpid()}"
                check("';' opens the comment prompt on the current line", ci.display,
                      f"display={ci.display}")
                ci.value = cnote
                await pilot.press("enter")
                await wait_until(
                    pilot, lambda: dec.loaded_ea == app._cur.ea
                    and any(cnote in t for t in dec._texts), timeout=25)
                check("comment appears in the pseudocode after ';'",
                      any(cnote in t for t in dec._texts), "comment not shown")
                # revert via the API for clean, race-free cleanup
                app.program.client.call(
                    "set_comments", items=[{"addr": hex(cea), "comment": ""}])
            else:
                check("found a pseudocode line to comment", False, "no marker line")

            # Decompiler follow of a name NOT in refs (the function's own name).
            await pilot.press("g")
            await pilot.pause(0.1)
            for ch in fn.name:
                await pilot.press(ch)
            await pilot.press("enter")
            await wait_until(pilot, lambda: dis.total > 0, timeout=20)
            if app._active != "decomp":
                await pilot.press("tab")
            await wait_until(pilot, lambda: dec.loaded_ea == fn.addr, timeout=20)
            nx = dec._texts[0].find(fn.name) if dec._texts else -1
            if nx >= 0:
                dec.focus()
                dec.cursor, dec.cursor_x = 0, nx + 1
                dec.refresh()
                await pilot.pause(0.05)
                depth = len(app._nav)
                await pilot.press("enter")
                moved = await wait_until(pilot, lambda: len(app._nav) > depth, timeout=25)
                check("decompiler follows a name not in refs (resolve fallback)",
                      moved and app._cur.ea == fn.addr, f"moved={moved}")

        # Scroll position (not just the cursor) is restored on back, both views.
        async def goto_name(name):
            await pilot.press("g")
            await pilot.pause(0.1)
            for ch in name:
                await pilot.press(ch)
            await pilot.press("enter")

        # pick two distinct, decently-sized functions
        big = sorted(fi.all_loaded(), key=lambda f: f.size, reverse=True)
        fa = next((f for f in big if f.size > 0x400), big[0])
        fb = next((f for f in big if f.addr != fa.addr), big[-1])
        await goto_name(fa.name)
        await wait_until(pilot, lambda: dis.total > 40 and app._cur.ea == fa.addr, timeout=20)
        if app._active != "disasm":
            await pilot.press("tab")
        await pilot.pause(0.1)
        for _ in range(4):
            await pilot.press("ctrl+d")
        await pilot.pause(0.1)
        # Put the cursor in the MIDDLE of the viewport so the test is
        # non-degenerate: with rel>0, restoring only the cursor (scroll-into-view)
        # would derive a different scroll, so this actually checks scroll restore.
        base = round(dis.scroll_offset.y)
        mid = base + min(dis.size.height // 2, max(dis.total - base - 1, 0))
        dis.cursor, dis.cursor_x = mid, 0
        dis.refresh()
        dis._after_cursor_move()
        await pilot.pause(0.05)
        want_sy, want_cur = round(dis.scroll_offset.y), dis.cursor
        want_rel = want_cur - want_sy
        await goto_name(fb.name)
        await wait_until(pilot, lambda: app._cur.ea == fb.addr, timeout=20)
        # Record the scroll at each repaint so we catch the "scroll_offset moved
        # but the pane wasn't repainted" bug (which scroll_offset checks miss).
        renders: list[int] = []
        _orig_rl = dis.render_line
        def _traced(y, _o=_orig_rl):
            if y == 0:
                renders.append(round(dis.scroll_offset.y))
            return _o(y)
        dis.render_line = _traced
        await pilot.press("escape")
        await wait_until(pilot, lambda: app._cur.ea == fa.addr, timeout=20)
        await wait_until(pilot, lambda: dis.total > 40, timeout=20)
        await pilot.pause(0.25)
        check("disasm scroll + cursor restored on back (mid-viewport)",
              round(dis.scroll_offset.y) == want_sy and dis.cursor == want_cur and want_rel > 0,
              f"scroll={round(dis.scroll_offset.y)} (want {want_sy}) "
              f"cursor={dis.cursor} (want {want_cur}) rel_before={want_rel}")
        check("pane is repainted at the restored scroll (no stale top frame)",
              bool(renders) and renders[-1] == want_sy,
              f"last repaint scroll={renders[-1] if renders else None} (want {want_sy})")
        dis.render_line = _orig_rl

        # PageUp/Down keep the cursor at the same viewport-relative row.
        await goto_name(fa.name)
        await wait_until(pilot, lambda: dis.total > 100 and app._cur.ea == fa.addr, timeout=20)
        if app._active != "disasm":
            await pilot.press("tab")
        await pilot.pause(0.1)
        for _ in range(6):
            await pilot.press("j")
        await pilot.pause(0.05)
        rel = dis.cursor - round(dis.scroll_offset.y)
        await pilot.press("pagedown")
        await pilot.pause(0.05)
        check("PageDown preserves the viewport-relative row",
              dis.cursor - round(dis.scroll_offset.y) == rel,
              f"rel={dis.cursor - round(dis.scroll_offset.y)} want={rel}")
        await pilot.press("pageup")
        await pilot.pause(0.05)
        check("PageUp preserves the viewport-relative row",
              dis.cursor - round(dis.scroll_offset.y) == rel,
              f"rel={dis.cursor - round(dis.scroll_offset.y)} want={rel}")

        # Rename refresh across history: rename a callee while viewing it, then
        # 'back' to the caller (cached earlier) shows the new name.
        table.focus()
        table.move_cursor(row=biggest_i)
        await pilot.press("enter")
        await wait_until(pilot, lambda: dis.total > 0, timeout=20)
        bea = app._cur.ea
        # cache the caller's pseudocode too, so the stale-decomp path is exercised
        await pilot.press("tab")
        await wait_until(pilot, lambda: dec.loaded_ea == bea, timeout=20)
        await pilot.press("tab")
        dis.focus()
        await pilot.pause(0.1)
        hrow = hsym = None
        for _ in range(40):
            top = round(dis.scroll_offset.y)
            dis.model.lines(top, dis.size.height + 2, prefetch=False)
            for r in range(min(dis.size.height, dis.total - top)):
                p = dis._line_plain(top + r)
                if p and "call sub_" in p:
                    mm = re.search(r"\bcall (sub_[0-9A-Fa-f]+)", p)
                    if mm:
                        hrow, hsym = top + r, mm.group(1)
                        break
            if hrow is not None:
                break
            await pilot.press("pagedown")
            await pilot.pause(0.025)
        if hrow is not None:
            htarget = app.program.resolve(hsym)
            await pilot.press("g")
            await pilot.pause(0.1)
            for ch in hsym:
                await pilot.press(ch)
            await pilot.press("enter")
            await wait_until(pilot, lambda: app._cur.ea == htarget, timeout=20)
            if app._active != "decomp":
                await pilot.press("tab")
            await wait_until(pilot, lambda: dec.loaded_ea == htarget, timeout=20)
            nx = dec._texts[0].find(hsym) if dec._texts else -1
            if nx >= 0:
                dec.focus()
                dec.cursor, dec.cursor_x = 0, nx + 1
                dec.refresh()
                await pilot.pause(0.05)
                hnew = f"h_{os.getpid()}"
                await pilot.press("n")
                await pilot.pause(0.1)
                app.query_one("#rename", Input).value = hnew
                await pilot.press("enter")
                await wait_until(
                    pilot,
                    lambda: app._func_index.by_addr(htarget)
                    and app._func_index.by_addr(htarget).name == hnew,
                    timeout=25,
                )
                if app._active != "disasm":
                    await pilot.press("tab")
                await pilot.press("escape")
                await wait_until(
                    pilot, lambda: dis.total > 0 and app._cur.ea != htarget, timeout=25)
                await pilot.pause(0.2)
                dis.model.lines(hrow, 4, prefetch=False)
                await pilot.pause(0.1)
                hline = dis._line_plain(hrow)
                check("caller disasm shows renamed callee after 'back'",
                      hline is not None and hnew in hline, f"line={hline!r}")
                # and the caller's cached pseudocode must refresh too
                await pilot.press("tab")
                await wait_until(pilot, lambda: dec.loaded_ea == bea, timeout=25)
                await pilot.pause(0.15)
                check("caller pseudocode shows renamed callee after 'back'",
                      any(hnew in tx for tx in dec._texts),
                      "pseudocode still stale")
                app.program.client.call(
                    "rename", batch={"func": {"addr": hex(htarget), "name": hsym}})


def main(argv):
    global STOP_AFTER
    db = None
    it = iter(argv)
    for a in it:
        if a == "--db":
            db = next(it)
        elif a == "--stop-after":
            # Iterate fast on one feature: run up to (and including) the first
            # check whose name contains this substring, then stop (skips the
            # expensive tail). Full run is the default (no flag).
            STOP_AFTER = next(it)
    try:
        asyncio.run(run(db))
    except _StopSuite:
        print(f"  … stopped after '{STOP_AFTER}'")
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
