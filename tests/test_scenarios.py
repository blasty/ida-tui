#!/usr/bin/env python3
"""Scenario-based pilot suite for the TUI (replaces the monolithic test_tui.py).

    python3 tests/test_scenarios.py --db <session_id>
    python3 tests/test_scenarios.py --db <session_id> --only hex,retype
    python3 tests/test_scenarios.py --db <session_id> --list

One app/session is booted once; every ``@scenario`` runs against it in isolation:
the runner resets a known baseline before each (dismiss modals, hide the names
pane, clear the filter, focus a code view) and catches per-scenario exceptions,
so a broken/flaky scenario fails *alone* instead of cascading. Add a test = write
a small self-contained scenario that opens its own function via ``c.open(...)``.
Uses ~/ida-venv python (has textual).

--only <substr[,substr]>  run only matching scenarios
--stop-after <substr>     stop once a check whose name contains <substr> ran
--list                    print scenario names and exit
"""
import asyncio
import os
import re
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.app import (  # noqa: E402
    ConfirmScreen, DecompView, DisasmView, FunctionsPanel, HexView, IdaTui,
    ListingView, StringsPalette, StructEditor, SymbolPalette, XrefsScreen,
    _str_display, _word_occurrences,
)
from textual.widgets import (  # noqa: E402
    DataTable, Footer, Input, OptionList, Static, TextArea,
)
from rich.text import Text  # noqa: E402
from idatui._sync import wait_for  # noqa: E402

PASS = FAIL = 0
STOP_AFTER = None
SCENARIOS: list[tuple[str, object]] = []


class _StopSuite(Exception):
    pass


def scenario(name):
    def deco(fn):
        SCENARIOS.append((name, fn))
        return fn
    return deco


# --------------------------------------------------------------------------- #
# Shared context + helpers
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, app, pilot):
        self.app = app
        self.pilot = pilot
        self.scenario = ""
        self._biggest = None
        self._pick = None

    # -- assertions / primitives ------------------------------------------ #
    def check(self, name, cond, detail=""):
        global PASS, FAIL
        tag = f"[{self.scenario}] " if self.scenario else ""
        if cond:
            PASS += 1
            print(f"  ok   {tag}{name}")
        else:
            FAIL += 1
            print(f"  FAIL {tag}{name}   {detail}")
        if STOP_AFTER and STOP_AFTER in name:
            raise _StopSuite

    async def wait(self, pred, t=20.0, step=0.02):
        return await wait_for(pred, self.pilot.pause, t, step)

    async def press(self, *keys):
        for k in keys:
            await self.pilot.press(k)

    async def pause(self, d=0.05):
        await self.pilot.pause(d)

    async def type(self, text):
        for ch in text:
            await self.pilot.press(ch)

    def status(self):
        return str(self.app.query_one("#status", Static).render())

    # -- shorthands ------------------------------------------------------- #
    @property
    def dis(self):
        return self.app.query_one(ListingView)  # unified code view (was DisasmView)

    @property
    def dec(self):
        return self.app.query_one(DecompView)

    @property
    def lst(self):
        return self.app.query_one(ListingView)

    @property
    def hex(self):
        return self.app.query_one(HexView)

    @property
    def table(self):
        return self.app.query_one("#func-table", DataTable)

    @property
    def prog(self):
        return self.app.program

    # -- discovery -------------------------------------------------------- #
    def all_funcs(self):
        idx = self.prog.functions()
        if len(idx) == 0 and not idx.complete:
            idx.load_all()  # a prior bump_items() cleared the index cache
        return idx.all_loaded()

    def find_func(self, pred, limit=400):
        for f in self.all_funcs()[:limit]:
            if pred(f):
                return f
        return None

    def biggest(self):
        if self._biggest is None:
            self._biggest = max(self.all_funcs(), key=lambda f: f.size)
        return self._biggest

    def pick_decomp_ref(self):
        """(fn, line, col, sym): a decompilable function whose pseudocode (past
        line 8) references a *different* sub_ function. Cached."""
        if self._pick is not None:
            return self._pick
        for fn in self.all_funcs()[:500]:
            d = self.prog.decompile(fn.addr)
            if d.failed or not d.code:
                continue
            dl = d.code.split("\n")
            if len(dl) < 12:
                continue
            for i, txt in enumerate(dl):
                if i < 8:
                    continue
                m = re.search(r"\b(sub_[0-9A-Fa-f]+)", txt)
                if m and m.group(1) != fn.name:
                    self._pick = (fn, i, m.start(1), m.group(1))
                    return self._pick
        return None

    # -- navigation (setup; fast internal path) --------------------------- #
    async def open(self, target, view="listing", t=25):
        """Open a function (name or ea) at its entry in the unified listing. With
        ``view='decomp'`` it then F5s into the pseudocode. Returns the Func."""
        ea = self.prog.resolve(target) if isinstance(target, str) else int(target)
        fn = self.prog.function_of(ea)
        if fn is None:
            raise RuntimeError(f"no function for {target!r}")
        self.app._open_function(fn.addr, fn.name)
        await self.wait(lambda: self.app._cur and self.app._cur.ea == fn.addr, t)
        # Wait for the cursor to actually LAND on the target, not merely for
        # _cur.ea to match: re-opening a function we already navigated to (its
        # _cur.ea is stale-true) schedules an async re-navigation, and proceeding
        # before it lands would leave the cursor parked wherever we last were.
        await self.wait(lambda: self.lst.total > 0
                        and self.lst._cursor_ea() == fn.addr, t)
        if view == "decomp":
            self.lst.focus()
            await self.press("tab")  # F5/Tab -> decompile the function at cursor
            await self.wait(lambda: self.app._active == "decomp"
                            and self.dec.loaded_ea == fn.addr, t)
        return fn

    async def open_biggest(self, view="listing"):
        return await self.open(self.biggest().addr, view)

    async def goto_ui(self, target):
        """Navigate via the 'g' goto prompt (exercises the real UI path)."""
        await self.press("g")
        await self.pause(0.1)
        await self.type(str(target))
        await self.press("enter")

    async def reveal_pane(self):
        left = self.app.query_one("#left", FunctionsPanel)
        if not left.display:
            await self.press("ctrl+b")
            await self.wait(lambda: left.display, 5)

    # -- lifecycle -------------------------------------------------------- #
    async def boot(self):
        app = self.app
        await self.wait(lambda: self.table.row_count > 0, 60)
        # Load is done when the index is complete (robust vs the status line,
        # which startup auto-land immediately overwrites with the landed fn).
        await self.wait(
            lambda: app._func_index is not None and app._func_index.complete, 60)
        if app._func_index is not None and not app._func_index.complete:
            app._func_index.load_all()

    async def reset(self):
        """Baseline before each scenario: dismiss modals, hide inputs + the names
        pane, clear the filter, default to pseudocode, focus a code view."""
        app = self.app
        for _ in range(4):
            if len(app.screen_stack) <= 1:
                break
            app.pop_screen()
            await self.pause(0.05)
        for iid in ("search", "rename", "comment", "retype", "goto", "func-filter"):
            inp = app.query_one(f"#{iid}", Input)
            if inp.display:
                inp.display = False
                inp.can_focus = False
        app.query_one("#status", Static).display = True
        if app._filter_term:
            app.clear_filter()
        left = app.query_one("#left", FunctionsPanel)
        if left.display:
            left.display = False
        app._pref = "decomp"
        if app._active == "hex":
            app._active = "decomp"
        app._split = False
        await self.pause(0.02)


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
@scenario("startup")
async def s_startup(c: Ctx):
    c.check("function list populated", c.table.row_count > 0, f"rows={c.table.row_count}")
    left = c.app.query_one("#left")
    c.check("names pane starts hidden (overlay-first)", not left.display,
            f"display={left.display}")
    await c.reveal_pane()
    c.check("function pane width is capped (doesn't eat the screen)",
            left.size.width <= 44, f"width={left.size.width}")
    c.check("function load completed (index complete)",
            c.app._func_index is not None and c.app._func_index.complete, c.status())
    print(f"    {c.table.row_count} functions loaded")


@scenario("auto_land")
async def s_auto_land(c: Ctx):
    """Startup lands on main()/an entry function when present, else pops the
    symbol picker — never a blank pane."""
    app = c.app
    # simulate a fresh startup landing
    for _ in range(3):
        if len(app.screen_stack) > 1:
            app.pop_screen()
            await c.pause(0.05)
    app._cur = None
    app._did_auto_land = False
    fn = app._entry_func()
    app._auto_land()
    await c.pause(0.2)
    if fn is not None:
        await c.wait(lambda: app._cur is not None and app._cur.ea == fn.addr, 20)
        c.check("auto-land jumps to the entry function (main) when present",
                app._cur is not None and app._cur.ea == fn.addr,
                f"entry={fn.name}@{fn.addr:#x} cur={app._cur}")
    else:
        await c.wait(lambda: isinstance(app.screen, SymbolPalette), 10)
        c.check("auto-land pops the symbol picker when there's no entry fn",
                isinstance(app.screen, SymbolPalette), f"screen={app.screen}")
        app.pop_screen()
    # guard fires once: a second call is a no-op
    prev = app._cur
    app._auto_land()
    c.check("auto-land is idempotent (guarded)", app._cur is prev)


@scenario("palette")
async def s_palette(c: Ctx):
    app, pilot = c.app, c.pilot
    await c.press("ctrl+n")
    pal_open = await c.wait(lambda: isinstance(app.screen, SymbolPalette), 10)
    c.check("Ctrl+N opens the symbol palette", pal_open,
            f"screen={type(app.screen).__name__}")
    if not pal_open:
        return
    pal = app.screen
    pinp = pal.query_one(Input)
    pinp.value = "main"
    await c.wait(lambda: pal._results and pal._results[0].name == "main", 10)
    c.check("palette fuzzy-finds (top result matches the query)",
            bool(pal._results) and pal._results[0].name == "main",
            f"top={pal._results[0].name if pal._results else None}")
    pinp.value = "eror"  # scattered subsequence of 'error'
    await c.wait(lambda: any(f.name == "error" for f in pal._results), 10)
    c.check("palette matches a fuzzy subsequence",
            any(f.name == "error" for f in pal._results),
            f"results={[f.name for f in pal._results[:4]]}")
    pinp.value = "main"
    await c.wait(lambda: pal._results and pal._results[0].name == "main", 10)
    want = pal._results[0].addr
    await c.press("enter")
    await c.wait(lambda: not isinstance(app.screen, SymbolPalette), 10)
    await c.wait(lambda: app._cur and app._cur.ea == want, 20)
    c.check("selecting a palette entry opens that function",
            bool(app._cur) and app._cur.ea == want,
            f"cur={app._cur.ea if app._cur else None}")
    await c.press("ctrl+n")
    await c.wait(lambda: isinstance(app.screen, SymbolPalette), 10)
    await c.press("escape")
    await c.wait(lambda: not isinstance(app.screen, SymbolPalette), 10)
    c.check("Esc closes the palette", not isinstance(app.screen, SymbolPalette))


@scenario("command_palette")
async def s_command_palette(c: Ctx):
    app = c.app
    await c.open_biggest("listing")
    await c.press("ctrl+p")
    opened = await c.wait(
        lambda: type(app.screen).__name__ == "CommandPalette", 10)
    c.check("Ctrl+P opens the command palette", opened,
            f"screen={type(app.screen).__name__}")
    if not opened:
        return
    inp = app.screen.query_one(Input)
    inp.value = "hex"  # filter to the 'Hex view' command
    await c.pause(0.5)  # let the async search + option list settle
    await c.press("enter")
    landed = await c.wait(lambda: app._active == "hex", 10)
    c.check("a palette command executes (Hex view opens)", landed,
            f"active={app._active}")
    if landed:
        await c.press("backslash")  # leave hex
        await c.wait(lambda: app._active != "hex", 5)


@scenario("strings")
async def s_strings(c: Ctx):
    app = c.app
    await c.open_biggest("listing")
    items = app.program.strings()
    c.check("program.strings() lists the binary's literals", len(items) > 3,
            f"n={len(items)}")
    if not items:
        return
    c.check("strings carry addr/text/length",
            all(s.addr > 0 and s.text and s.length > 0 for s in items[:5]),
            f"first={items[0]}")
    await c.press("quotation_mark")
    opened = await c.wait(lambda: isinstance(app.screen, StringsPalette), 25)
    c.check('\'"\' opens the strings browser', opened,
            f"screen={type(app.screen).__name__}")
    if not opened:
        return
    pal = app.screen
    c.check("the browser lists strings", len(pal._results) > 0,
            f"results={len(pal._results)}")
    # filter on a fragment of a real (unescaped) literal
    target = next((s for s in items
                   if len(s.text) >= 6 and _str_display(s.text) == s.text), None)
    if target is not None:
        frag = target.text[:6]
        pal.query_one(Input).value = frag
        await c.pause(0.2)
        ok = (pal._results
              and all(frag.lower() in s.text.lower() for s in pal._results))
        c.check("filtering narrows to matching strings", bool(ok),
                f"frag={frag!r} n={len(pal._results)}")
        want = pal._results[0].addr
        await c.press("enter")
        await c.wait(lambda: not isinstance(app.screen, StringsPalette), 10)
        landed = await c.wait(lambda: c.lst._cursor_ea() == want, 20)
        c.check("Enter jumps to the string in the unified listing", landed,
                f"cursor={c.lst._cursor_ea()} want={want:#x}")
    else:
        await c.press("escape")


@scenario("split_view")
async def s_split_view(c: Ctx):
    app, lst, dec = c.app, c.lst, c.dec
    await c.open_biggest("listing")
    await c.press("s")
    shown = await c.wait(lambda: app._split and lst.display and dec.display, 20)
    c.check("'s' enters split view (both panes shown)", shown,
            f"split={app._split} lst={lst.display} dec={dec.display}")
    loaded = await c.wait(lambda: dec.loaded_ea == app._cur.ea, 25)
    c.check("split loads the pseudocode alongside the listing", loaded,
            f"loaded={dec.loaded_ea} cur={app._cur.ea if app._cur else None}")
    await c.wait(lambda: "[split" in c.status(), 5)
    c.check("split view shows a split-aware status", "[split" in c.status(),
            f"status={c.status()!r}")
    # phase 3: the rich per-line instruction map (decomp_map tool, run on the
    # pilot's real worker) — verify it returns, aligns with the markers, and
    # bands a whole region for a multi-instruction C line.
    m = app.program.decomp_map(app._cur.ea)
    c.check("decomp_map returns per-line ea sets", len(m) > 5, f"lines={len(m)}")
    aligned = sum(1 for i in range(min(len(m), len(dec._line_eas)))
                  if m[i] and dec._line_eas[i] is not None
                  and dec._line_eas[i] in m[i])
    c.check("decomp_map aligns with the pseudocode markers", aligned >= 3,
            f"aligned={aligned}/{len(dec._line_eas)}")
    multi = next((i for i, eas in enumerate(m) if len(eas) > 1), None)
    if multi is not None:
        app._split_eamap = m
        dec.focus()          # the decomp must BE the driver for a decomp-driven
        app._active = "decomp"  # sync (else its align() re-syncs listing-driven)
        dec.cursor = multi
        dec._scroll_cursor_into_view()  # key-nav always does; the anchor needs it
        await c.pause(0.1)
        app._sync_split("decomp")
        await c.pause(0.1)
        c.check("a multi-instruction C line bands a region (>1 listing row)",
                len(lst._link_rows) > 1,
                f"line={multi} eas={len(m[multi])} rows={sorted(lst._link_rows)[:8]}")
        lst.focus()
        app._active = "listing"
        await c.pause(0.05)
    else:
        c.check("a multi-instruction C line bands a region (>1 listing row)",
                True, "no multi-instruction line in this function (skipped)")
    # listing drives: move it, the decomp band must track the covering C line
    lst.focus()
    for _ in range(6):
        await c.press("j")
    await c.pause(0.2)
    lea = lst._cursor_ea()
    dl = dec._link_line
    c.check("listing cursor links the covering pseudocode line",
            dl is not None and lea is not None and dec._line_eas[dl] is not None
            and dec._line_eas[dl] <= lea,
            f"link_line={dl} lea={hex(lea) if lea else None}")
    # the companion pane sits LEVEL with the driver's cursor (visual coherence):
    # the linked row lands at the same viewport offset, not merely on-screen.
    deep = [i for i, eas in enumerate(m) if eas][10:]
    row = lst.model.ensure_ea(m[deep[0]][0]) if (deep and lst.model) else None
    if row is not None and row > 12:
        lst.scroll_to(y=row - 10, animate=False)
        await c.pause(0.2)          # let the deferred scroll land
        lst.cursor = row            # driver cursor now at viewport offset 10
        app._sync_split("listing")
        await c.pause(0.2)          # let the companion's scroll land
        drv = lst.cursor - round(lst.scroll_offset.y)
        link, top = dec._link_line, round(dec.scroll_offset.y)
        # exact, modulo the unavoidable clamps (can't scroll above line 0, nor
        # past the end when the pseudocode is shorter than the viewport)
        want = min(max(0, (link or 0) - drv),
                   max(0, dec.total - dec._visible_height()))
        c.check("the companion pane sits level with the driver's cursor",
                link is not None and top == want,
                f"driver_row={drv} link={link} dec_top={top} want={want}")
        # a PURE scroll (wheel/scrollbar) moves no cursor — it must still drag
        # the companion along (anchors on the viewport once the cursor is gone)
        before_cur, before_dec = lst.cursor, round(dec.scroll_offset.y)
        lst.scroll_to(y=round(lst.scroll_offset.y) + 30, animate=False)
        await c.pause(0.35)
        c.check("a pure scroll in the driver drags the companion along",
                lst.cursor == before_cur
                and round(dec.scroll_offset.y) != before_dec,
                f"cursor {before_cur}->{lst.cursor} "
                f"dec_top {before_dec}->{round(dec.scroll_offset.y)}")
    await c.press("tab")
    await c.pause(0.1)
    c.check("Tab in split focuses the pseudocode pane", app._active == "decomp",
            f"active={app._active}")
    # decomp drives: put the cursor on an addressed pseudocode line (past the
    # variable decls); the listing band must track the covering instruction row.
    target = next((i for i, e in enumerate(dec._line_eas) if e is not None), None)
    c.check("pseudocode has addressed lines", target is not None,
            "no /*0xEA*/ markers in the pseudocode")
    if target is not None:
        dec.cursor = target
        dec._scroll_cursor_into_view()
        await c.pause(0.1)
        app._sync_split("decomp")
        await c.pause(0.1)
        want = lst.model.ensure_ea(dec._line_eas[target])
        c.check("decomp cursor links the instruction row in the listing",
                want in lst._link_rows,
                f"link_rows={sorted(lst._link_rows)[:6]} want={want}")
        # and that linked row actually paints a background band (base rows have
        # no bg; `want` is a deep code row, never the listing's own cursor row)
        lst.reveal(want)
        await c.pause(0.05)
        y = want - round(lst.scroll_offset.y)
        banded = (0 <= y < lst.size.height and any(
            s.style and s.style.bgcolor is not None for s in lst.render_line(y)))
        c.check("the linked instruction row renders a highlight band", banded,
                f"y={y} cursor_row={lst.cursor}")
    await c.press("tab")
    await c.pause(0.1)
    c.check("Tab again focuses the listing pane", app._active == "listing",
            f"active={app._active}")
    # a mouse click on the other pane also makes it the driver (not just Tab)
    await c.pilot.click(DecompView, offset=(10, 5))
    await c.pause(0.15)
    c.check("clicking the pseudocode pane makes it the driver",
            app._active == "decomp", f"active={app._active}")
    await c.press("tab")  # restore listing as the driver
    await c.pause(0.1)
    # cross-function follow: the listing cursor leaving the decompiled function
    # re-points the decomp pane to whatever function it's now in.
    await c.wait(lambda: app._split_range is not None, 10)
    other = c.find_func(lambda f: f.addr != app._cur.ea and f.size > 40)
    row = lst.model.ensure_ea(other.addr) if other is not None else None
    if other is not None and row is not None and row >= 0:
        lst.focus()
        app._active = "listing"
        lst.cursor = row
        lst._scroll_cursor_into_view()
        await c.pause(0.1)
        app._sync_split("listing")  # cursor now outside the decompiled fn
        followed = await c.wait(lambda: dec.loaded_ea == other.addr, 25)
        c.check("listing cursor crossing into another function re-syncs the decomp",
                followed, f"dec={dec.loaded_ea} want={other.addr}")
    # navigation in split keeps BOTH panes on the (new) function
    nf = c.find_func(lambda f: f.addr != app._cur.ea and f.size > 80)
    if nf is not None:
        await c.press("g")
        await c.type(hex(nf.addr))
        await c.press("enter")
        nav = await c.wait(lambda: app._cur and app._cur.ea == nf.addr, 15)
        c.check("goto in split navigates", nav,
                f"cur={app._cur.ea if app._cur else None} want={nf.addr}")
        both = await c.wait(lambda: dec.loaded_ea == nf.addr and app._split
                            and lst.display and dec.display, 25)
        c.check("split reloads both panes on navigation", both,
                f"dec={dec.loaded_ea} split={app._split}")
    await c.press("s")
    gone = await c.wait(lambda: not app._split and lst.display
                        and not dec.display, 10)
    c.check("'s' exits split back to a single view", gone,
            f"split={app._split} lst={lst.display} dec={dec.display}")
    c.check("exiting split clears the link bands",
            not lst._link_rows and dec._link_line is None,
            f"rows={lst._link_rows} line={dec._link_line}")


@scenario("decomp_fallback")
async def s_fallback(c: Ctx):
    app = c.app
    failing = next((f for f in reversed(c.all_funcs())
                    if c.prog.decompile(f.addr).failed), None)
    if failing is None:
        c.check("found a decompile-failing function", False)
        return
    # Open the failing function in the listing, then F5: decompile fails -> the
    # view stays on the linear listing (no error panel).
    await c.open(failing.addr, "listing")
    c.dis.focus()
    await c.press("tab")
    await c.wait(lambda: app._active == "listing"
                 and "fail" in c.status().lower(), 25)
    c.check("F5/Tab on an undecompilable function falls back to the listing",
            app._active == "listing" and c.dis.display,
            f"active={app._active} status={c.status()!r}")
    # a decompilable function F5s into pseudocode
    await c.open("main", "decomp")
    c.check("a decompilable function F5s into pseudocode",
            app._active == "decomp" and c.dec.display, f"active={app._active}")


@scenario("structs")
async def s_structs(c: Ctx):
    app = c.app
    await c.press("ctrl+t")
    se_open = await c.wait(lambda: isinstance(app.screen, StructEditor), 10)
    c.check("Ctrl+T opens the struct editor", se_open,
            f"screen={type(app.screen).__name__}")
    if not se_open:
        return
    se = app.screen
    await c.wait(lambda: bool(se._structs), 15)
    c.check("struct editor lists existing structs", len(se._structs) > 0,
            f"n={len(se._structs)}")
    ta = se.query_one(TextArea)
    tname = next((s.name for s in se._structs if s.name == "timespec"),
                 se._structs[0].name)
    idx = next(i for i, s in enumerate(se._structs) if s.name == tname)
    se.query_one(OptionList).highlighted = idx
    se.on_option_list_option_selected(type("E", (), {"option_index": idx})())
    await c.wait(lambda: tname in ta.text and "{" in ta.text, 15)
    c.check("selecting a struct shows its C definition",
            tname in ta.text and "{" in ta.text, f"text={ta.text[:40]!r}")
    app._clipboard = ""
    se.query_one(TextArea).focus()
    await c.press("ctrl+y")
    await c.wait(lambda: app._clipboard == ta.text, 10)
    c.check("Ctrl+Y copies the struct definition to the clipboard",
            bool(app._clipboard) and app._clipboard == ta.text,
            f"clip_len={len(app._clipboard)}")
    sname = "TuiEdTest"
    await c.press("ctrl+n")
    await c.pause(0.05)
    ta.text = f"struct {sname} {{ int a; char b[8]; }};"
    await c.press("ctrl+s")
    await c.wait(lambda: any(s.name == sname for s in se._structs), 15)
    c.check("Ctrl+S declares a new struct",
            any(s.name == sname for s in se._structs), "not created")
    await c.wait(lambda: "\n" in ta.text, 10)
    c.check("save auto-formats the definition in the editor",
            ta.text.count("\n") >= 3 and f"struct {sname}" in ta.text
            and not se._is_dirty(), f"text={ta.text[:50]!r}")
    idx = next(i for i, s in enumerate(se._structs) if s.name == sname)
    se.on_option_list_option_selected(type("E", (), {"option_index": idx})())
    await c.wait(lambda: sname in ta.text, 10)
    ta.text = f"struct {sname} {{ int a; char b[8]; long c; }};"
    await c.press("ctrl+s")
    await c.wait(lambda: next((s.members for s in se._structs if s.name == sname), 0) == 3, 15)
    c.check("Ctrl+S updates an existing struct in place",
            next((s.members for s in se._structs if s.name == sname), 0) == 3,
            "member count not 3")
    ta.text = f"struct {sname} {{ int a; char b[8]; long c; int __unused; }};"
    await c.press("ctrl+s")
    await c.wait(lambda: "save failed" in str(se.query_one("#se-status").render()), 15)
    st = str(se.query_one("#se-status").render())
    c.check("a rejected save fails loudly, naming the reserved field",
            "save failed" in st and "__unused" in st, f"status={st!r}")
    c.check("a rejected save leaves the struct unchanged",
            next((s.members for s in se._structs if s.name == sname), 0) == 3, "changed")
    c.check("a rejected save keeps your edited text", "__unused" in ta.text)
    other = next(i for i, s in enumerate(se._structs) if s.name != sname)
    se.on_option_list_option_selected(type("E", (), {"option_index": other})())
    guard = await c.wait(lambda: isinstance(app.screen, ConfirmScreen), 10)
    c.check("unsaved edits prompt before switching structs", guard,
            f"screen={type(app.screen).__name__}")
    await c.press("enter")
    await c.wait(lambda: isinstance(app.screen, StructEditor) and not se._is_dirty(), 15)
    idx = next(i for i, s in enumerate(se._structs) if s.name == sname)
    se.query_one(OptionList).focus()
    se.query_one(OptionList).highlighted = idx
    await c.press("d")
    confirmed = await c.wait(lambda: isinstance(app.screen, ConfirmScreen), 10)
    c.check("delete asks for confirmation", confirmed,
            f"screen={type(app.screen).__name__}")
    await c.press("enter")
    await c.wait(lambda: isinstance(app.screen, StructEditor), 10)
    await c.wait(lambda: not any(s.name == sname for s in se._structs)
                 or "del_type" in str(se.query_one("#se-status").render()), 15)
    st = str(se.query_one("#se-status").render())
    gone = not any(s.name == sname for s in se._structs)
    c.check("confirming delete removes the struct (or reports missing tool)",
            gone or "del_type" in st, f"gone={gone} status={st!r}")
    se.query_one(OptionList).focus()
    await c.press("escape")
    await c.wait(lambda: not isinstance(app.screen, StructEditor), 10)
    c.check("Esc closes the struct editor", not isinstance(app.screen, StructEditor))


@scenario("open_default_view")
async def s_open(c: Ctx):
    app = c.app
    fn = c.biggest()
    app._open_function(fn.addr, fn.name)
    await c.wait(lambda: app._cur and app._cur.ea == fn.addr, 20)
    await c.wait(lambda: c.lst.total > 0, 30)
    c.check("opening a function shows the linear listing by default",
            app._active == "listing" and c.lst.display and c.lst.total > 0,
            f"active={app._active} total={c.lst.total}")
    print(f"    biggest = {fn.name} ({c.lst.total} listing rows)")


@scenario("disasm_nav")
async def s_disasm_nav(c: Ctx):
    app, view = c.app, c.dis
    await c.open_biggest("listing")
    view.focus()
    c.check("first instruction cached",
            view.model is not None and view.model.cached_line(0) is not None)
    for _ in range(5):
        await c.press("pagedown")
        await c.pause(0.025)
    c.check("pagedown moved the cursor", view.cursor > 0, f"cursor={view.cursor}")
    await c.wait(lambda: view.model.cached_line(view.cursor) is not None, 15)
    c.check("cursor line eventually cached (bg fetch)",
            view.model.cached_line(view.cursor) is not None)
    c.check("status shows an address", "@ 0x" in c.status(), c.status())
    # Ctrl+Y copies the current code line.
    view.focus()
    cur_line = view._line_plain(view.cursor)
    app._clipboard = ""
    await c.press("ctrl+y")
    await c.wait(lambda: app._clipboard == cur_line, 10)
    c.check("Ctrl+Y copies the current code line to the clipboard",
            bool(cur_line) and app._clipboard == cur_line, f"clip={app._clipboard!r}")
    # goto-bottom must not hang on a huge function (ctrl+end; plain 'end' now
    # moves the cursor to end-of-line).
    await c.press("ctrl+end")
    await c.pause(0.05)
    c.check("goto-bottom lands near end", view.cursor >= view.total - 1,
            f"cursor={view.cursor}/{view.total}")


@scenario("hex")
async def s_hex(c: Ctx):
    app, view = c.app, c.dis
    await c.open_biggest("listing")
    view.focus()
    view.cursor = 4  # a non-entry instruction
    await c.pause(0.05)
    code_ea = view._cursor_ea()
    await c.press("backslash")
    await c.wait(lambda: app._active == "hex", 10)
    hx = c.hex
    await c.wait(lambda: hx.model is not None
                and hx.model.row(hx.cursor // 16)[1] is not None, 20)
    c.check("backslash opens the hex view synced to the code cursor",
            app._active == "hex" and code_ea is not None and hx.cursor_va() == code_ea,
            f"active={app._active} hexva={hx.cursor_va():#x} ea={code_ea}")
    want = app.program.read_bytes(code_ea, 1)
    _, rb = hx.model.row(hx.cursor // 16)
    c.check("hex shows the actual byte at that address",
            rb is not None and rb[hx.cursor % 16] == want[0],
            f"got={rb[hx.cursor % 16] if rb else None} want={want[0]}")
    await c.press("l")
    await c.pause(0.1)
    c.check("hex cursor steps one byte", hx.cursor_va() == code_ea + 1,
            f"va={hx.cursor_va():#x}")
    fo = app.program.file_offset(hx.cursor_va())
    c.check("hex carries a file offset for a mapped (.text) address",
            fo is not None and hx.model.file_offset(hx.cursor_va()) == fo, f"fo={fo}")
    rng = app.program.image_range()
    target_va = rng[0] + (rng[1] - rng[0]) // 2
    await c.press("g")
    await c.pause(0.1)
    await c.type(hex(target_va))
    await c.press("enter")
    await c.wait(lambda: hx.cursor_va() == target_va, 15)
    c.check("'g' in the hex view jumps the cursor to an address",
            hx.cursor_va() == target_va, f"va={hx.cursor_va():#x} want={target_va:#x}")
    # -- a user scroll freezes the cursor's screen row (points at a new byte) --
    await c.press("g")
    await c.type(hex(rng[0]))
    await c.press("enter")
    await c.wait(lambda: hx.cursor_va() == rng[0], 10)
    for _ in range(8):        # cursor to viewport row 8 (top still 0)
        await c.press("j")
    await c.pause(0.1)
    top0 = round(hx.scroll_offset.y)
    screen_row = hx.cursor // 16 - top0
    hx.scroll_to(y=top0 + 30, animate=False)  # user scroll down 30 rows
    await c.pause(0.15)
    top1 = round(hx.scroll_offset.y)
    c.check("hex viewport scrolled", top1 >= top0 + 20, f"top0={top0} top1={top1}")
    c.check("hex cursor's screen row stays frozen on scroll",
            hx.cursor // 16 - top1 == screen_row,
            f"screen_row={screen_row} now={hx.cursor // 16 - top1} top1={top1}")
    PAD = 1  # HexView { padding: 0 1 } -> content is inset one col
    await c.pilot.click(HexView, offset=(PAD + 19 + 3 * 3, 5))  # hex byte 3, row 5
    await c.pause(0.1)
    c.check("clicking the hex pane moves the cursor to the clicked byte",
            hx.cursor == (top1 + 5) * 16 + 3,
            f"cursor={hx.cursor} want={(top1 + 5) * 16 + 3} top1={top1}")
    await c.pilot.click(HexView, offset=(PAD + 70 + 10, 7))  # ascii byte 10, row 7
    await c.pause(0.1)
    c.check("clicking the ascii pane maps to the right byte",
            hx.cursor == (top1 + 7) * 16 + 10,
            f"cursor={hx.cursor} want={(top1 + 7) * 16 + 10}")
    await c.press("backslash")
    await c.wait(lambda: app._active != "hex", 10)
    c.check("backslash returns from hex to the code view",
            app._active == "listing", f"active={app._active}")


@scenario("filter")
async def s_filter(c: Ctx):
    app, table = c.app, c.table
    await c.reveal_pane()
    nfuncs = table.row_count
    # row selection opens a function
    fn = c.biggest()
    ridx = next((i for i in range(nfuncs)
                 if int(str(table.get_row_at(i)[0]), 16) == fn.addr), 0)
    table.move_cursor(row=ridx)
    table.focus()
    await c.press("enter")
    await c.wait(lambda: app._cur and app._cur.ea == fn.addr, 20)
    c.check("selecting a table row opens that function",
            bool(app._cur) and app._cur.ea == fn.addr, f"cur={app._cur.ea if app._cur else None}")
    # filter round-trip
    table.focus()
    await c.press("slash")
    await c.pause(0.05)
    for ch in "sub_1*":
        await c.press(ch if ch != "*" else "asterisk")
    await c.press("enter")
    filtered = await c.wait(lambda: 0 < table.row_count < nfuncs, 15)
    c.check("filter narrowed the list", filtered, f"rows={table.row_count} of {nfuncs}")
    # pane toggle
    left = app.query_one("#left", FunctionsPanel)
    await c.press("ctrl+b")
    await c.pause(0.05)
    c.check("ctrl+b hides functions pane + focuses the code view",
            not left.display and isinstance(app.focused, (ListingView, DecompView)),
            f"display={left.display} focus={type(app.focused).__name__}")
    await c.press("ctrl+b")
    await c.pause(0.05)
    c.check("ctrl+b again restores pane + focuses table",
            left.display and isinstance(app.focused, DataTable),
            f"display={left.display} focus={type(app.focused).__name__}")


@scenario("view_toggle")
async def s_view_toggle(c: Ctx):
    app, dis, dec = c.app, c.dis, c.dec
    await c.open_biggest("decomp")
    pc = await c.wait(lambda: dec.display and dec.loaded_ea is not None
                      and app._active == "decomp", 25)
    c.check("pseudocode view shows", pc, f"active={app._active}")
    c.check("pseudocode has many lines", dec.total > 20, f"lines={dec.total}")
    styled = any(seg.style is not None and seg.style.color is not None
                 for strip in dec._strips[:min(dec.total, 200)] for seg in strip)
    c.check("pseudocode is syntax-highlighted", styled)
    await c.press("tab")
    await c.pause(0.1)
    c.check("tab switches to disassembly",
            app._active == "listing" and dis.display and not dec.display,
            f"active={app._active}")
    # F5/Tab from the listing must raise the 'decompiling…' overlay synchronously,
    # BEFORE the background decompile runs (regression: it used to decompile first
    # in _decomp_from_listing, so the overlay only flashed once cached).
    dec.loaded_ea = None
    app.action_toggle_view()
    cover = dec._cover_widget
    c.check("F5 from the listing raises the 'decompiling…' overlay",
            dec.loading and cover is not None and "decomp-loading" in cover.classes
            and "decompiling" in str(cover.render()),
            f"loading={dec.loading} cover={cover!r}")
    await c.wait(lambda: app._active == "decomp" and not dec.loading
                 and dec._cover_widget is None, 25)
    c.check("overlay clears when the decompile finishes",
            not dec.loading and dec._cover_widget is None)
    # F5 on an ALREADY-loaded function must still clear the overlay (regression:
    # the F5-raised overlay had nothing to clear it in the 'already loaded' branch
    # -> spinner stuck forever).
    await c.press("tab")  # -> listing
    await c.wait(lambda: app._active == "listing", 10)
    app.action_toggle_view()  # F5 the same, cached function again
    cleared = await c.wait(lambda: app._active == "decomp" and not dec.loading
                           and dec._cover_widget is None, 15)
    c.check("re-decompiling an already-loaded function clears the overlay", cleared,
            f"loading={dec.loading} cover={dec._cover_widget!r}")
    # line-number gutter
    dec.scroll_to(0, 0, animate=False)
    await c.pause(0.025)
    row0 = "".join(seg.text for seg in dec.render_line(0))
    c.check("pseudocode has a numbered gutter (line 1 first)",
            dec._gutter > 0 and row0[:dec._gutter].strip() == "1",
            f"gutter={dec._gutter} row0={row0[:10]!r}")
    # Home/End move along the line here too (they used to scroll to top/bottom).
    line = next((i for i, t in enumerate(dec._texts)
                 if t.startswith("  ") and t.strip()), None)
    if line is not None:
        text = dec._texts[line]
        dec.focus()
        dec.cursor, dec.cursor_x = line, 0
        dec.refresh()
        await c.pause(0.05)
        top = round(dec.scroll_offset.y)
        await c.press("end")
        await c.pause(0.05)
        c.check("<end> in pseudocode goes to end-of-line, not the bottom",
                dec.cursor == line and dec.cursor_x == max(len(text) - 1, 0)
                and round(dec.scroll_offset.y) == top,
                f"line={dec.cursor} col={dec.cursor_x} len={len(text)}")
        await c.press("home")
        await c.pause(0.05)
        c.check("<home> in pseudocode goes to start-of-line",
                dec.cursor == line and dec.cursor_x == 0,
                f"line={dec.cursor} col={dec.cursor_x}")
        await c.press("shift+home")
        await c.pause(0.05)
        c.check("<shift+home> skips the indentation",
                dec.cursor_x == len(text) - len(text.lstrip()),
                f"col={dec.cursor_x} indent={len(text) - len(text.lstrip())}")
        await c.press("ctrl+end")
        await c.pause(0.1)
        c.check("<ctrl+end> still goes to the bottom",
                dec.cursor >= dec.total - 1, f"{dec.cursor}/{dec.total}")
        await c.press("ctrl+home")
        await c.pause(0.1)
        c.check("<ctrl+home> still goes to the top", dec.cursor == 0,
                f"{dec.cursor}")


@scenario("search")
async def s_search(c: Ctx):
    app, dis = c.app, c.dis
    await c.open_biggest("listing")
    dis.focus()
    # derive the term from the instruction at the cursor (the function entry),
    # not segment head 0 (which may still be streaming in)
    line0 = dis.model.cached_line(dis.cursor)
    raw = (line0.text.split() or ["push"])[0] if line0 else "push"
    term = "".join(ch for ch in raw if ch.isalnum())[:4] or "push"
    await c.press("slash")
    await c.pause(0.1)
    await c.type(term)
    await c.press("enter")
    # the unified listing searches the whole segment (load_all) -> allow time
    await c.wait(lambda: bool(dis._matches), 45)
    c.check("search finds matches", len(dis._matches) > 0, f"term={term!r}")
    c.check("cursor sits on a match", dis.cursor in dis._matches, f"cursor={dis.cursor}")
    c.check("match substring highlighted",
            bool(dis._ranges.get(dis.cursor)), str(dis._ranges.get(dis.cursor)))
    c.check("search cursor lands on the match's starting column",
            bool(dis._ranges.get(dis.cursor))
            and dis.cursor_x == dis._ranges[dis.cursor][0][0],
            f"cursor_x={dis.cursor_x} ranges={dis._ranges.get(dis.cursor)}")
    prev = dis.cursor
    await c.press("slash")
    await c.pause(0.05)
    await c.press("enter")
    await c.pause(0.05)
    c.check("'/' repeats to next match",
            dis.cursor != prev and dis.cursor in dis._matches, f"cursor={dis.cursor}")
    await c.press("question_mark")
    await c.pause(0.05)
    await c.press("enter")
    await c.pause(0.05)
    c.check("'?' repeats to previous match", dis.cursor in dis._matches,
            f"cursor={dis.cursor}")
    # incremental preview + visible bar + Esc cancel
    si = app.query_one("#search", Input)
    status = app.query_one("#status", Static)
    await c.press("slash")
    await c.pause(0.1)
    c.check("search bar visible, status hidden (no overlap)",
            si.display and not status.display, f"si={si.display} status={status.display}")
    footer = app.query_one(Footer)
    c.check("search input is rendered above the footer (not overlapping)",
            si.region.height >= 1 and si.region.y < footer.region.y,
            f"search={si.region} footer={footer.region}")
    for ch in term:
        await c.press(ch)
        await c.pause(0.05)
    c.check("matches highlight incrementally (before Enter)",
            len(dis._matches) > 0 and si.value == term, f"val={si.value!r}")
    await c.press("escape")
    await c.pause(0.1)
    c.check("Esc cancels: status restored, matches cleared",
            status.display and not si.display and not dis._matches,
            f"status={status.display} si={si.display} m={len(dis._matches)}")


@scenario("incr_filter")
async def s_incr_filter(c: Ctx):
    app, table = c.app, c.table
    await c.reveal_pane()
    table.focus()
    full = table.row_count
    await c.press("slash")
    await c.pause(0.1)
    for ch in "sub_":
        await c.press(ch)
        await c.pause(0.05)
    await c.pause(0.1)
    c.check("filter narrows incrementally as you type",
            0 < table.row_count < full, f"{table.row_count}/{full}")
    cell = table.get_row_at(0)[1]
    c.check("filter highlights matched substring in name",
            isinstance(cell, Text) and any(s.style for s in cell.spans), repr(str(cell)))
    await c.press("enter")
    await c.pause(0.1)
    c.check("Enter keeps filter + focuses table",
            isinstance(app.focused, DataTable) and table.row_count < full)
    await c.press("escape")
    await c.pause(0.15)
    c.check("Esc on the list clears the filter", table.row_count == full,
            f"{table.row_count}/{full}")


@scenario("follow_xrefs")
async def s_follow_xrefs(c: Ctx):
    app, dis, dec = c.app, c.dis, c.dec
    await c.open_biggest("listing")
    dis.focus()
    lines = dis.model.lines(0, 400, prefetch=False)
    call_idx = next((i for i, ln in enumerate(lines)
                     if ln.text.startswith("call ")), None)
    if call_idx is None:
        c.check("found a call line to exercise follow/xrefs", False, "no call in first 400")
        return
    dis.cursor = call_idx
    dis.refresh()
    orig = app._cur.ea
    orig_name = app._cur.name
    depth = len(app._nav)
    await c.press("enter")
    await c.wait(lambda: len(app._nav) > depth, 25)
    c.check("Enter follows the call into another function",
            app._cur.ea != orig and len(app._nav) > depth, f"cur={app._cur.ea:#x}")
    await c.press("escape")
    await c.pause(0.1)
    c.check("Esc returns from the follow", app._cur.ea == orig, f"cur={app._cur.ea:#x}")
    dis.cursor = call_idx
    dis.refresh()
    await c.press("x")
    opened = await c.wait(lambda: isinstance(app.screen, XrefsScreen), 25)
    c.check("'x' opens the xrefs popup", opened, f"screen={type(app.screen).__name__}")
    if opened:
        c.check("xrefs popup has entries",
                app.screen.query_one(OptionList).option_count >= 1)
        await c.press("escape")
        await c.pause(0.1)
        c.check("Esc closes the xrefs popup", not isinstance(app.screen, XrefsScreen))

    xf = None
    for cand in c.all_funcs()[:600]:
        codex = [x for x in app.program.xrefs_to(cand.addr) if x.type == "code" and x.frm]
        if codex:
            xf = (cand, codex[0])
            break
    if xf is None:
        c.check("found a function with a code xref", False)
    else:
        xfn, xref = xf
        await c.goto_ui(xfn.name)
        await c.wait(lambda: c.lst.total > 0 and app._cur.ea == xfn.addr, 20)
        c.lst.focus()
        await c.press("x")
        await c.wait(lambda: isinstance(app.screen, XrefsScreen), 25)
        app.screen.query_one(OptionList).highlighted = 0
        await c.press("enter")
        await c.wait(lambda: not isinstance(app.screen, XrefsScreen), 25)
        # xref-select lands the listing cursor on the referencing SITE (frm)
        await c.wait(lambda: c.lst._cursor_ea() == xref.frm, 25)
        c.check("xref-select lands the cursor on the referencing site",
                c.lst._cursor_ea() == xref.frm,
                f"cur_ea={c.lst._cursor_ea()} want={xref.frm:#x}")
        # F5 at the site decompiles the referencing function
        c.lst.focus()
        await c.press("tab")
        landed = await c.wait(
            lambda: (app._active == "decomp" and dec.loaded_ea == xref.fn_addr)
            or (app._active == "listing" and "fail" in c.status().lower()), 25)
        if app._active == "decomp":
            c.check("F5 at the xref site decompiles the referencing function",
                    dec.loaded_ea == xref.fn_addr, f"loaded={dec.loaded_ea}")
            await c.press("tab")
            await c.wait(lambda: app._active == "listing", 20)

        app._open_function(orig, orig_name)
        await c.wait(lambda: dis.total > 0 and app._cur.ea == orig, 20)
        dis.model.lines(0, 400, prefetch=False)
        dis.focus()
        dis.cursor = call_idx
        dis.cursor_x = 5
        dis.refresh()
        await c.pause(0.025)
        await c.press("h")
        c.check("h moves the column cursor left", dis.cursor_x == 4, f"x={dis.cursor_x}")
        await c.press("l", "l")
        c.check("l moves the column cursor right", dis.cursor_x == 6, f"x={dis.cursor_x}")
        plain = dis._line_plain(call_idx) or ""
        m = re.search(r"\b(sub_[0-9A-Fa-f]+)", plain)
        if m:
            dis.cursor = call_idx
            dis.cursor_x = m.start(1) + 1
            dis.refresh()
            await c.pause(0.05)
            c.check("word-under-cursor is the operand symbol",
                    dis.word_under_cursor() == m.group(1),
                    f"{dis.word_under_cursor()!r} vs {m.group(1)!r}")
            depth = len(app._nav)
            want = app.program.resolve(m.group(1))
            await c.press("enter")
            await c.wait(lambda: len(app._nav) > depth, 25)
            c.check("follows the symbol under the cursor",
                    app._cur.ea == want, f"cur={app._cur.ea:#x} want={want:#x}")


@scenario("xref_labels")
async def s_xref_labels(c: Ctx):
    from collections import Counter, defaultdict
    app, dis, dec = c.app, c.dis, c.dec
    multi = None
    for cand in c.all_funcs()[:200]:
        callers = Counter(x.fn_addr for x in app.program.xrefs_to(cand.addr) if x.fn_name)
        if any(n >= 2 for n in callers.values()):
            multi = cand
            break
    if multi is None:
        c.check("found a function with multiple same-caller xrefs", False)
        return
    await c.open(multi.addr, "listing")
    dis.focus()
    dis.cursor = max(dis.model.index_of_ea(multi.addr), 0)  # segment head at fn
    dis.cursor_x = 0
    dis.refresh()
    await c.press("x")
    await c.wait(lambda: isinstance(app.screen, XrefsScreen), 25)
    labels = [t for _, t in app.screen._items]
    locs = [l.split("[")[0].split(None, 1)[1].strip() for l in labels]
    byfn = defaultdict(set)
    for x in locs:
        if "+0x" in x:
            nm, off = x.split("+0x", 1)
            byfn[nm].add(off)
    c.check("xref labels distinguish multiple sites in a function by offset",
            any(len(offs) >= 2 for offs in byfn.values()), f"locs={locs[:8]}")
    c.check("no xref label is a bare '?'", all(x != "?" for x in locs), f"locs={locs[:8]}")
    await c.press("escape")
    await c.wait(lambda: not isinstance(app.screen, XrefsScreen), 25)
    # pre-selection: 'x' at a call site highlights that site in the dialog
    bycaller = defaultdict(list)
    for x in app.program.xrefs_to(multi.addr):
        if x.fn_name and x.type == "code":
            bycaller[x.fn_addr].append(x)
    csites = next((sorted(v, key=lambda x: x.frm)
                   for v in bycaller.values() if len(v) >= 2), None)
    if not csites:
        c.check("found a caller with multiple sites for preselect", False)
        return
    site = csites[len(csites) // 2]
    await c.open(site.fn_addr, "decomp")
    li = app._decomp_line_for(site.fn_addr, site.frm)
    col = dec._texts[li].find(multi.name) if 0 <= li < len(dec._texts) else -1
    if col < 0:
        c.check("found the callee token for preselect", False)
        return
    dec.focus()
    dec.cursor, dec.cursor_x = li, col + 1
    dec.refresh()
    await c.pause(0.05)
    await c.press("x")
    await c.wait(lambda: isinstance(app.screen, XrefsScreen), 25)
    hl = app.screen.query_one(OptionList).highlighted
    it = app.screen._items
    c.check("xref dialog pre-selects the site it was invoked from",
            hl is not None and it[hl][0] == site.frm,
            f"hl={hl} frm={hex(it[hl][0]) if hl is not None else None} want={hex(site.frm)}")
    await c.press("escape")
    await c.wait(lambda: not isinstance(app.screen, XrefsScreen), 25)


@scenario("mouse")
async def s_mouse(c: Ctx):
    app, dis = c.app, c.dis
    await c.open_biggest("listing")
    dis.focus()
    await c.pause(0.1)
    mrow = mcol = msym = mline = None
    for _ in range(40):
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
        await c.press("pagedown")
        await c.pause(0.025)
    if mrow is None:
        c.check("found a call line for the mouse test", False, "no visible call sub_")
        return
    await c.pilot.click(dis, offset=(mcol + 1, mrow))
    await c.pause(0.05)
    c.check("single click places the cursor on the clicked token",
            dis.cursor == mline and dis.word_under_cursor() == msym,
            f"cursor={dis.cursor} (want {mline}) word={dis.word_under_cursor()!r}")
    depth = len(app._nav)
    want = app.program.resolve(msym)
    await c.pilot.click(dis, offset=(mcol + 1, mrow), times=2)
    await c.wait(lambda: len(app._nav) > depth, 25)
    c.check("double-click follows the symbol", app._cur.ea == want,
            f"cur={app._cur.ea:#x} want={want:#x}")
    await c.press("escape")
    await c.wait(lambda: app._cur.ea != want, 20)
    await c.wait(lambda: dis.total > 0 and dis.cursor == mline, 20)
    c.check("back restores the exact line + column",
            dis.cursor == mline and dis.word_under_cursor() == msym,
            f"cursor={dis.cursor} (want {mline}) word={dis.word_under_cursor()!r}")


@scenario("decomp_nav")
async def s_decomp_nav(c: Ctx):
    app, dis, dec = c.app, c.dis, c.dec
    pick = c.pick_decomp_ref()
    if pick is None:
        c.check("found a pseudocode line to test decomp nav", False)
        return
    fn, drow, dcol, dsym = pick
    await c.open(fn.addr, "decomp")
    dec.focus()
    dec.cursor, dec.cursor_x = drow, dcol
    dec._after_cursor_move()
    await c.pause(0.05)
    depth = len(app._nav)
    await c.press("enter")  # follow the sym under the pseudocode cursor
    await c.wait(lambda: len(app._nav) > depth, 25)
    await c.press("escape")
    await c.wait(lambda: dec.loaded_ea == fn.addr, 25)
    await c.pause(0.1)
    c.check("pseudocode-view position restored after jump+back",
            dec.cursor == drow and dec.word_under_cursor() == dsym,
            f"cursor={dec.cursor} (want {drow}) word={dec.word_under_cursor()!r}")
    # follow works with a STALE name (post-rename): ea-marker fallback
    dstale = app.program.resolve(dsym)
    old_line = dec._texts[drow] if drow < len(dec._texts) else ""
    old_ea = dec._line_ea(drow)
    if old_ea is not None and dsym in old_line:
        tmp = f"stale_{os.getpid()}"
        app.program.client.call("rename", batch={"func": {"addr": hex(dstale), "name": tmp}})
        app.program.bump_names()
        d2 = len(app._nav)
        app._follow_decomp(old_line, dsym, old_ea)
        await c.wait(lambda: len(app._nav) > d2, 25)
        c.check("decomp follow works with a stale name (ea-marker fallback)",
                app._cur.ea == dstale, f"cur={app._cur.ea:#x} want={dstale:#x}")
        app.program.client.call("rename", batch={"func": {"addr": hex(dstale), "name": dsym}})
        app.program.bump_names()


@scenario("decomp_follow_self")
async def s_decomp_follow_self(c: Ctx):
    # Follow a name NOT in refs (the function's own name at line 0): the
    # resolve() fallback still navigates. Isolated so no stale decompile
    # worker from another jump can race the view back.
    app, dec = c.app, c.dec
    pick = c.pick_decomp_ref()
    if pick is None:
        c.check("found a function to test self-follow", False)
        return
    fn = pick[0]
    await c.open(fn.addr, "decomp")
    nx = dec._texts[0].find(fn.name) if dec._texts else -1
    if nx < 0:
        c.check("found the function name on line 0", False)
        return
    dec.focus()
    dec.cursor, dec.cursor_x = 0, nx + 1
    dec.refresh()
    await c.pause(0.05)
    depth = len(app._nav)
    await c.press("enter")
    moved = await c.wait(lambda: len(app._nav) > depth, 25)
    c.check("decompiler follows a name not in refs (resolve fallback)",
            moved and app._cur.ea == fn.addr,
            f"moved={moved} cur={hex(app._cur.ea)} want={hex(fn.addr)}")


@scenario("sort")
async def s_sort(c: Ctx):
    app, table = c.app, c.table
    await c.reveal_pane()
    await c.pilot.click(table, offset=(15, 0))  # Function header
    await c.pause(0.15)
    snames = [str(table.get_row_at(i)[1]) for i in range(min(20, table.row_count))]
    c.check("click Function header sorts by name",
            app._sort_col == 1 and snames == sorted(snames, key=str.lower),
            f"sort_col={app._sort_col}")
    first_asc = str(table.get_row_at(0)[1])
    await c.pilot.click(table, offset=(15, 0))  # reverse
    await c.pause(0.15)
    c.check("click again reverses the sort",
            app._sort_reverse and str(table.get_row_at(0)[1]) != first_asc)
    await c.pilot.click(table, offset=(3, 0))  # Address header
    await c.pause(0.15)
    saddrs = [int(str(table.get_row_at(i)[0]), 16) for i in range(min(20, table.row_count))]
    c.check("click Address header sorts by address",
            app._sort_col == 0 and saddrs == sorted(saddrs), f"sort_col={app._sort_col}")


@scenario("rename")
async def s_rename(c: Ctx):
    app, dec = c.app, c.dec
    pick = c.pick_decomp_ref()
    if pick is None:
        c.check("found a pseudocode ref to rename", False)
        return
    fn, drow, dcol, dsym = pick
    dtarget = app.program.resolve(dsym)
    await c.open(fn.addr, "decomp")
    dec.focus()
    dec.cursor, dec.cursor_x = drow, dcol + 1
    dec.refresh()
    await c.pause(0.05)
    newname = f"ren_{os.getpid()}"
    await c.press("n")
    await c.pause(0.1)
    ri = app.query_one("#rename", Input)
    c.check("'n' opens the rename prompt prefilled with the symbol",
            ri.display and ri.value == dsym, f"val={ri.value!r}")
    ri.value = newname
    await c.press("enter")
    await c.wait(lambda: app._func_index.by_addr(dtarget)
                 and app._func_index.by_addr(dtarget).name == newname, 25)
    c.check("rename updates the function name",
            app._func_index.by_addr(dtarget).name == newname,
            app._func_index.by_addr(dtarget).name)
    rr = app.program.client.call("rename", batch={"func": {"addr": hex(dtarget), "name": dsym}})
    c.check("rename reverted cleanly",
            rr.get("summary", {}).get("ok", 0) == 1, str(rr.get("summary")))
    # goto label refuse
    def _find_label():
        for i, t in enumerate(dec._texts):
            mm = re.search(r"\bLABEL_\d+\b", t)
            if mm:
                return i, mm.start(), mm.group(0)
        return None
    lab = _find_label()
    if lab is None:
        await c.open("main", "decomp")
        lab = _find_label()
    if lab is not None:
        li, lc, _ = lab
        dec.focus()
        dec.cursor, dec.cursor_x = li, lc + 1
        dec.refresh()
        await c.pause(0.05)
        await c.press("n")
        await c.pause(0.1)
        ri2 = app.query_one("#rename", Input)
        c.check("renaming a pseudocode label is refused with a clear message",
                (not ri2.display) and "label" in c.status().lower(),
                f"display={ri2.display} status={c.status()!r}")
    else:
        c.check("found a pseudocode label to test", False, "no LABEL_ found")
    # comment via ';'
    cline = next((i for i in range(len(dec._texts))
                  if i > 5 and dec._line_ea(i) is not None
                  and dec._texts[i].strip() and "//" not in dec._texts[i]), None)
    if cline is not None:
        cea = dec._line_ea(cline)
        dec.focus()
        dec.cursor, dec.cursor_x = cline, 2
        dec.refresh()
        await c.pause(0.05)
        await c.press("semicolon")
        await c.pause(0.1)
        ci = app.query_one("#comment", Input)
        cnote = f"note_{os.getpid()}"
        c.check("';' opens the comment prompt on the current line", ci.display,
                f"display={ci.display}")
        ci.value = cnote
        await c.press("enter")
        await c.wait(lambda: dec.loaded_ea == app._cur.ea
                     and any(cnote in t for t in dec._texts), 25)
        c.check("comment appears in the pseudocode after ';'",
                any(cnote in t for t in dec._texts), "comment not shown")
        app.program.client.call("set_comments", items=[{"addr": hex(cea), "comment": ""}])
    else:
        c.check("found a pseudocode line to comment", False, "no marker line")


@scenario("comment_func")
async def s_comment_func(c: Ctx):
    # Commenting the signature/declaration line (which carries no address) falls
    # back to a function-level comment at the entry ea instead of being refused.
    app, dec = c.app, c.dec
    pick = c.pick_decomp_ref()
    if pick is None:
        c.check("found a function for the comment test", False)
        return
    fn = pick[0]
    await c.open(fn.addr, "decomp")
    dec.focus()
    dec.cursor, dec.cursor_x = 0, 2  # the signature line
    dec.refresh()
    await c.pause(0.05)
    c.check("signature line has no address of its own", dec._line_ea(0) is None,
            f"ea={dec._line_ea(0)}")
    await c.press("semicolon")
    await c.pause(0.1)
    ci = app.query_one("#comment", Input)
    note = f"fn_note_{os.getpid()}"
    c.check("';' on the signature line opens a function-comment prompt",
            ci.display and "function comment" in str(ci.placeholder).lower(),
            f"display={ci.display} ph={ci.placeholder!r}")
    # literal '\n' in the comment becomes a real newline -> multi-line render
    a, b = f"{note}_A", f"{note}_B"
    ci.value = f"{a}\\n{b}"
    await c.press("enter")
    await c.wait(lambda: dec.loaded_ea == fn.addr
                 and any(a in t for t in dec._texts)
                 and any(b in t for t in dec._texts), 25)
    la = next((i for i, t in enumerate(dec._texts) if a in t), None)
    lb = next((i for i, t in enumerate(dec._texts) if b in t), None)
    c.check("multi-line function comment renders on separate lines",
            la is not None and lb is not None and lb > la
            and a not in dec._texts[lb],
            f"la={la} lb={lb}")
    app.program.client.call("set_comments", items=[{"addr": hex(fn.addr), "comment": ""}])


@scenario("retype")
async def s_retype(c: Ctx):
    app, dec = c.app, c.dec
    cf = await c.open("main", "decomp")
    fts = app.program.func_types(cf.addr)
    if fts is None or not fts.prototype:
        c.check("got structured function types (func_types tool)", False)
        return
    old_proto = fts.prototype
    nm_col = dec._texts[0].find(cf.name)
    dec.focus()
    dec.cursor, dec.cursor_x = 0, (nm_col + 1 if nm_col >= 0 else 0)
    dec.refresh()
    await c.pause(0.05)
    await c.press("y")
    await c.wait(lambda: app.query_one("#retype", Input).display, 10)
    ri = app.query_one("#retype", Input)
    c.check("'y' on a function prefills its prototype",
            ri.display and ri.value == old_proto, f"val={ri.value!r} want={old_proto!r}")
    ri.value = f"void __fastcall {cf.name}(int zz_retype_arg)"
    await c.press("enter")
    await c.wait(lambda: (lambda f: bool(f) and "zz_retype_arg" in f.prototype)(
        app.program.func_types(cf.addr)), 20)
    after = app.program.func_types(cf.addr)
    c.check("applying a retype changes the function prototype",
            after is not None and "zz_retype_arg" in after.prototype,
            f"proto={after.prototype if after else None!r}")
    app.program.set_function_type(cf.addr, old_proto)  # restore
    # the retype above kicked off a recompile+reload; let it land before we start
    # placing the cursor, or the reload resets it under us.
    app.program.bump_names()
    await c.wait(lambda: not dec.loading and dec.loaded_ea == cf.addr
                 and bool(dec._texts), 25)
    await c.pause(0.3)

    # -- 'y' on a LOCAL variable retypes that variable, not the prototype --- #
    fts = app.program.func_types(cf.addr)
    lv = next((v for v in (fts.lvars if fts else []) if not v.is_arg), None)
    if lv is not None:
        line = next((i for i, t in enumerate(dec._texts)
                     if _word_occurrences(t, lv.name)), None)
        if line is not None:
            col = _word_occurrences(dec._texts[line], lv.name)[0][0]
            dec.focus()
            dec.cursor, dec.cursor_x = line, col + 1  # inside the word
            dec.refresh()
            await c.pause(0.05)
            await c.press("y")
            await c.wait(lambda: app.query_one("#retype", Input).display, 10)
            ri = app.query_one("#retype", Input)
            c.check("'y' on a local variable prefills that variable's type",
                    ri.value == lv.type and lv.name in str(ri.placeholder),
                    f"val={ri.value!r} want={lv.type!r} ph={ri.placeholder!r}")
            ri.value = "unsigned __int64"
            await c.press("enter")
            changed = await c.wait(lambda: (lambda f: bool(f) and any(
                v.name == lv.name and v.type == "unsigned __int64"
                for v in f.lvars))(app.program.func_types(cf.addr)), 25)
            c.check("applying it retypes the local variable", changed,
                    f"{lv.name}: wanted unsigned __int64")
            after = app.program.func_types(cf.addr)
            c.check("retyping a local leaves the prototype alone",
                    after is not None and after.prototype == old_proto,
                    f"proto={after.prototype if after else None!r}")

    # -- 'y' on a GLOBAL retypes the global, not the enclosing function ----- #
    # The lvar retype above recompiled too — settle again, or the scan below
    # indexes into pseudocode that's about to be replaced.
    await c.wait(lambda: not dec.loading and dec.loaded_ea == cf.addr
                 and bool(dec._texts), 25)
    await c.pause(0.3)

    # Pick a global that actually appears as a word in the pseudocode — a symbol
    # from decompile().refs often doesn't (a string ref renders as its literal).
    lvnames = {v.name for v in (fts.lvars if fts else [])}
    glob = None
    for i, t in enumerate(dec._texts):
        for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", t):
            if w in lvnames or w == cf.name:
                continue
            try:
                a = app.program.resolve(w)
            except Exception:  # noqa: BLE001
                continue
            if app.program.func_types(a) is not None:
                continue
            d = app.program.data_type(a) or {}
            if (d.get("name") and not d.get("is_func")
                    and "(" not in (d.get("type") or "")):
                glob = (w, a, d, i)
                break
        if glob:
            break
    if glob is not None:
        gname, gaddr, dt, line = glob
        glob = type("G", (), {"addr": gaddr})()  # keep the checks below readable
        if line is not None:
            col = _word_occurrences(dec._texts[line], gname)[0][0]
            dec.focus()
            dec.cursor, dec.cursor_x = line, col + 1  # inside the word
            dec.refresh()
            await c.pause(0.05)
            c.check("the cursor sits on the global",
                    dec.word_under_cursor() == gname,
                    f"word={dec.word_under_cursor()!r} want={gname!r} "
                    f"line={line} col={col} text={dec._texts[line][:60]!r}")
            await c.press("y")
            await c.wait(lambda: app.query_one("#retype", Input).display, 10)
            ri = app.query_one("#retype", Input)
            c.check("'y' on a global prefills the global's type (not the proto)",
                    ri.value != old_proto and gname in str(ri.placeholder),
                    f"val={ri.value!r} ph={ri.placeholder!r}")
            ri.value = "unsigned __int64"
            await c.press("enter")
            retyped = await c.wait(
                lambda: (app.program.data_type(glob.addr) or {}).get("type")
                == "unsigned __int64", 25)
            c.check("applying it retypes the global", retyped,
                    f"type={(app.program.data_type(glob.addr) or {}).get('type')!r}")
            after = app.program.func_types(cf.addr)
            c.check("retyping a global leaves the prototype alone",
                    after is not None and after.prototype == old_proto,
                    f"proto={after.prototype if after else None!r}")
            if dt.get("type"):  # restore
                app.program.set_data_type(glob.addr, dt["type"])


@scenario("scroll_restore")
async def s_scroll_restore(c: Ctx):
    app, dis = c.app, c.dis
    big = sorted(c.all_funcs(), key=lambda f: f.size, reverse=True)
    fa = next((f for f in big if f.size > 0x400), big[0])
    fb = next((f for f in big if f.addr != fa.addr), big[-1])
    await c.goto_ui(fa.name)
    await c.wait(lambda: dis.total > 40 and app._cur.ea == fa.addr, 20)
    if app._active != "listing":
        await c.press("tab")
    await c.pause(0.1)
    for _ in range(4):
        await c.press("ctrl+d")
    await c.pause(0.1)
    base = round(dis.scroll_offset.y)
    mid = base + min(dis.size.height // 2, max(dis.total - base - 1, 0))
    dis.cursor, dis.cursor_x = mid, 0
    dis.refresh()
    dis._after_cursor_move()
    await c.pause(0.05)
    want_sy, want_cur = round(dis.scroll_offset.y), dis.cursor
    want_rel = want_cur - want_sy
    await c.goto_ui(fb.name)
    await c.wait(lambda: app._cur.ea == fb.addr, 20)
    renders: list[int] = []
    _orig_rl = dis.render_line
    def _traced(y, _o=_orig_rl):
        if y == 0:
            renders.append(round(dis.scroll_offset.y))
        return _o(y)
    dis.render_line = _traced
    await c.press("escape")
    await c.wait(lambda: app._cur.ea == fa.addr, 20)
    await c.wait(lambda: dis.total > 40, 20)
    await c.pause(0.25)
    c.check("disasm scroll + cursor restored on back (mid-viewport)",
            round(dis.scroll_offset.y) == want_sy and dis.cursor == want_cur and want_rel > 0,
            f"scroll={round(dis.scroll_offset.y)} (want {want_sy}) "
            f"cursor={dis.cursor} (want {want_cur}) rel_before={want_rel}")
    c.check("pane is repainted at the restored scroll (no stale top frame)",
            bool(renders) and renders[-1] == want_sy,
            f"last repaint scroll={renders[-1] if renders else None} (want {want_sy})")
    dis.render_line = _orig_rl


@scenario("paging")
async def s_paging(c: Ctx):
    app, dis = c.app, c.dis
    big = sorted(c.all_funcs(), key=lambda f: f.size, reverse=True)
    fa = next((f for f in big if f.size > 0x400), big[0])
    await c.goto_ui(fa.name)
    await c.wait(lambda: dis.total > 100 and app._cur.ea == fa.addr, 20)
    if app._active != "listing":
        await c.press("tab")
    await c.pause(0.1)
    for _ in range(6):
        await c.press("j")
    await c.pause(0.05)
    rel = dis.cursor - round(dis.scroll_offset.y)
    await c.press("pagedown")
    await c.pause(0.05)
    c.check("PageDown preserves the viewport-relative row",
            dis.cursor - round(dis.scroll_offset.y) == rel,
            f"rel={dis.cursor - round(dis.scroll_offset.y)} want={rel}")
    await c.press("pageup")
    await c.pause(0.05)
    c.check("PageUp preserves the viewport-relative row",
            dis.cursor - round(dis.scroll_offset.y) == rel,
            f"rel={dis.cursor - round(dis.scroll_offset.y)} want={rel}")


@scenario("rename_history")
async def s_rename_history(c: Ctx):
    app, dis, dec = c.app, c.dis, c.dec
    await c.open_biggest("listing")
    bea = app._cur.ea
    await c.press("tab")  # warm the caller's pseudocode too
    await c.wait(lambda: dec.loaded_ea == bea, 20)
    await c.press("tab")
    dis.focus()
    await c.pause(0.1)
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
        await c.press("pagedown")
        await c.pause(0.025)
    if hrow is None:
        c.check("found a call sub_ for the rename-history test", False)
        return
    htarget = app.program.resolve(hsym)
    await c.goto_ui(hsym)
    await c.wait(lambda: app._cur.ea == htarget, 20)
    if app._active != "decomp":
        await c.press("tab")
    await c.wait(lambda: dec.loaded_ea == htarget, 20)
    nx = dec._texts[0].find(hsym) if dec._texts else -1
    if nx < 0:
        c.check("found the callee name in its pseudocode", False)
        return
    dec.focus()
    dec.cursor, dec.cursor_x = 0, nx + 1
    dec.refresh()
    await c.pause(0.05)
    hnew = f"h_{os.getpid()}"
    await c.press("n")
    await c.pause(0.1)
    app.query_one("#rename", Input).value = hnew
    await c.press("enter")
    await c.wait(lambda: app._func_index.by_addr(htarget)
                 and app._func_index.by_addr(htarget).name == hnew, 25)
    if app._active != "listing":
        await c.press("tab")
    await c.press("escape")
    await c.wait(lambda: dis.total > 0 and app._cur.ea != htarget, 25)
    await c.pause(0.2)
    dis.model.lines(hrow, 4, prefetch=False)
    await c.pause(0.1)
    hline = dis._line_plain(hrow)
    c.check("caller disasm shows renamed callee after 'back'",
            hline is not None and hnew in hline, f"line={hline!r}")
    await c.press("tab")
    await c.wait(lambda: dec.loaded_ea == bea, 25)
    await c.pause(0.15)
    c.check("caller pseudocode shows renamed callee after 'back'",
            any(hnew in tx for tx in dec._texts), "pseudocode still stale")
    app.program.client.call("rename", batch={"func": {"addr": hex(htarget), "name": hsym}})


@scenario("region_define")
async def s_region_define(c: Ctx):
    """A non-function address opens a flat listing (region) instead of being
    refused, and 'p' there creates a function and upgrades the view."""
    app = c.app
    fn = c.find_func(lambda f: 0x10 <= f.size <= 0x60 and f.name.startswith("sub_"))
    if fn is None:
        c.check("found a small sub_ function for the region test", False)
        return
    addr, size = fn.addr, fn.size
    try:
        # setup: undefine the whole function so [addr, addr+size) is a bare region
        c.prog.undefine(addr, size=size)
        c.prog.bump_items()
        c.check("function removed by undefine",
                c.prog.function_of(addr) is None, "still a function")

        # navigate there via the real 'g' prompt -> opens the flat LISTING view
        # (a non-function region), not refused
        await c.goto_ui(hex(addr))
        await c.wait(lambda: app._cur is not None and app._cur.ea == addr, 25)
        c.check("goto to a non-function address opens the listing view (not refused)",
                app._cur is not None and app._cur.is_region
                and app._active == "listing" and c.lst.display,
                f"cur={app._cur} active={app._active} status={c.status()!r}")
        await c.wait(lambda: c.lst.total > 0 and c.lst._cursor_ea() is not None, 25)
        c.check("listing renders heads and the cursor sits on the target address",
                c.lst.total > 0 and c.lst._cursor_ea() == addr,
                f"total={c.lst.total} cur_ea={c.lst._cursor_ea()}")
        # the flat listing spans the whole segment, not just this function
        seg = c.prog.segment_bounds(addr)
        c.check("listing spans the whole segment (more heads than one function)",
                seg is not None and c.lst.total > 1, f"total={c.lst.total} seg={seg}")

        # 'p' on the entry head (re)creates the function and UPGRADES to DisasmView
        c.lst.focus()
        c.lst.cursor, c.lst.cursor_x = c.lst.model.index_of_ea(addr), 0
        await c.pause(0.05)
        await c.press("p")
        await c.wait(lambda: c.prog.function_of(addr) is not None
                     and app._cur is not None and not app._cur.is_region, 25)
        c.check("'p' creates a function and upgrades the listing to a function view",
                c.prog.function_of(addr) is not None and not app._cur.is_region
                and app._cur.ea == addr and app._active in ("listing", "decomp"),
                f"fn={c.prog.function_of(addr)} cur={app._cur} active={app._active}")
    finally:
        # idempotency: guarantee the function is back even if a check failed
        if c.prog.function_of(addr) is None:
            try:
                c.prog.define_func(addr)
            except Exception:  # noqa: BLE001
                pass
        c.prog.bump_items()


@scenario("listing_view")
async def s_listing_view(c: Ctx):
    """The flat listing view over a data segment: renders code AND data heads,
    navigates, and reaches hex — without any function in play."""
    app = c.app
    # find a data segment (has a non-code head somewhere) via the listing itself
    data_ea = None
    for start, end, name in c.prog.sections():
        if start >= end:
            continue
        lm = c.prog.listing(start)
        if lm is None:
            continue
        lm.ensure(40)
        if any(h.kind == "data" for h in lm.window(0, 40)):
            data_ea = start
            break
    if data_ea is None:
        c.check("found a segment with data items", False)
        return

    await c.goto_ui(hex(data_ea))
    await c.wait(lambda: app._cur is not None and app._active == "listing"
                 and c.lst.total > 0, 25)
    c.check("navigating to a data segment opens the listing view",
            app._active == "listing" and c.lst.display and c.lst.total > 0,
            f"active={app._active} total={c.lst.total}")
    kinds = {h.kind for h in c.lst.model.window(0, 40)}
    c.check("listing shows data heads (not just code)", "data" in kinds, str(kinds))

    # a rendered data line carries the item text (e.g. db/dd/string)
    c.lst.focus()
    first_data = next((i for i in range(min(c.lst.total, 60))
                       if c.lst.model.get(i) and c.lst.model.get(i).kind == "data"), None)
    c.check("a data head exists in the first screenful", first_data is not None,
            f"total={c.lst.total}")
    if first_data is not None:
        c.lst.cursor = first_data
        await c.pause(0.05)
        plain = c.lst._line_plain(first_data)
        c.check("data line renders its item text", bool(plain and plain.strip()),
                f"plain={plain!r}")
        c.check("listing cursor reports the head address",
                c.lst._cursor_ea() == c.lst.model.get(first_data).ea, str(c.lst._cursor_ea()))

    # backslash from the listing opens hex at the cursor address; and back
    cur_ea = c.lst._cursor_ea()
    await c.press("backslash")
    await c.wait(lambda: app._active == "hex" and c.hex.display, 15)
    c.check("backslash from the listing opens the hex view", app._active == "hex",
            f"active={app._active}")
    await c.press("backslash")
    await c.wait(lambda: app._active == "listing", 15)
    c.check("returning from hex lands back on the listing (not a func view)",
            app._active == "listing" and c.lst.display, f"active={app._active}")

    # 'd' defines typed data over an undefined run. Synthesize the run
    # deterministically: undefine a data head, then re-type it via the prompt.
    dhead = next((c.lst.model.get(i) for i in range(min(c.lst.total, 200))
                  if c.lst.model.get(i) and c.lst.model.get(i).kind == "data"
                  and (c.lst.model.get(i).size or 0) >= 4), None)
    if dhead is None:
        c.check("found a data head to re-type", False)
        return
    dea = dhead.ea
    try:
        c.prog.undefine(dea, size=4)
        c.prog.bump_items()
        # reopen the listing so the model reflects the new undefined run
        await c.goto_ui(hex(dea))
        await c.wait(lambda: app._active == "listing" and c.lst.total > 0
                     and c.lst.model.index_of_ea(dea) >= 0, 25)
        ui = c.lst.model.index_of_ea(dea)
        c.check("undefining a data head yields an unknown run in the listing",
                ui >= 0 and c.lst.model.get(ui).kind == "unknown",
                f"kind={c.lst.model.get(ui).kind if ui>=0 else None}")
        c.lst.focus()
        c.lst.cursor = ui
        await c.pause(0.05)
        await c.press("d")
        await c.pause(0.1)
        mdi = app.query_one("#makedata", Input)
        c.check("'d' opens the make-data prompt prefilled with a type",
                mdi.display and bool(mdi.value), f"display={mdi.display} val={mdi.value!r}")
        mdi.value = "char[4]"
        await c.press("enter")
        await c.wait(lambda: app._active == "listing"
                     and c.lst.model.index_of_ea(dea) >= 0
                     and c.lst.model.get(c.lst.model.index_of_ea(dea)) is not None
                     and c.lst.model.get(c.lst.model.index_of_ea(dea)).kind == "data", 25)
        di = c.lst.model.index_of_ea(dea)
        c.check("'d' turns the undefined run into a typed data item",
                di >= 0 and c.lst.model.get(di).kind == "data",
                f"kind={c.lst.model.get(di).kind if di>=0 else None}")
    finally:
        c.prog.bump_items()


@scenario("listing_name_addr")
async def s_listing_name_addr(c: Ctx):
    """In the listing, 'n' names the ADDRESS under the cursor — so you can name a
    bare/undefined byte (e.g. the free byte at addr+1 after shrinking a u16 to a
    u8), which the symbol-by-name rename path can't do."""
    app = c.app
    # pick a data segment and a >=2-byte data head to shrink
    data_ea = None
    for start, end, name in c.prog.sections():
        if start >= end:
            continue
        lm = c.prog.listing(start)
        if lm is None:
            continue
        lm.ensure(60)
        if any(h.kind == "data" and (h.size or 0) >= 2 for h in lm.window(0, 60)):
            data_ea = start
            break
    if data_ea is None:
        c.check("found a data segment with a >=2-byte item", False)
        return
    dh = next(h for h in c.prog.listing(data_ea).window(0, 60)
              if h.kind == "data" and (h.size or 0) >= 2)
    A = dh.ea
    newname = f"after_{os.getpid()}"
    try:
        # shrink the >=2-byte item to a single byte -> A+1 becomes undefined
        c.prog.make_data(A, "unsigned __int8")
        c.prog.bump_items()
        await c.goto_ui(hex(A + 1))
        await c.wait(lambda: app._active == "listing" and app._cur is not None
                     and app._cur.ea == A + 1, 25)
        head = c.lst.cur_head()
        c.check("cursor lands on the now-undefined byte at addr+1",
                head is not None and head.ea == A + 1 and head.kind == "unknown",
                f"head={head}")
        # 'n' opens the address-name prompt (even though there's no symbol)
        c.lst.focus()
        await c.press("n")
        await c.pause(0.1)
        ri = app.query_one("#rename", Input)
        c.check("'n' opens the name prompt on an unnamed byte",
                ri.display, f"display={ri.display}")
        ri.value = newname
        await c.press("enter")
        await c.wait(lambda: app._active == "listing"
                     and c.lst.model.index_of_ea(A + 1) >= 0
                     and c.lst.model.get(c.lst.model.index_of_ea(A + 1)) is not None
                     and c.lst.model.get(c.lst.model.index_of_ea(A + 1)).name == newname, 25)
        hi = c.lst.model.index_of_ea(A + 1)
        c.check("naming a bare byte at addr+1 sticks",
                hi >= 0 and c.lst.model.get(hi).name == newname,
                f"name={c.lst.model.get(hi).name if hi>=0 else None}")
    finally:
        # revert: drop the label and restore raw bytes at A
        try:
            c.prog.client.call("rename", batch={"data": {"addr": hex(A + 1), "new": ""}})
        except Exception:  # noqa: BLE001
            pass
        c.prog.undefine(A, size=8)
        c.prog.bump_items()


@scenario("listing_make_string")
async def s_listing_make_string(c: Ctx):
    """'a' in the listing makes a string literal at the cursor (IDA's 'A')."""
    app = c.app
    target = None
    for start, end, name in c.prog.sections():
        if start >= end:
            continue
        lm = c.prog.listing(start)
        if lm is None:
            continue
        lm.ensure(80)
        h = next((h for h in lm.window(0, 80)
                  if h.kind == "data" and "'" in h.text), None)
        if h is not None:
            target = h.ea
            break
    if target is None:
        c.check("found a string data item to remake", False)
        return
    A = target
    try:
        c.prog.undefine(A, size=8)
        c.prog.bump_items()
        await c.goto_ui(hex(A))
        await c.wait(lambda: app._active == "listing" and app._cur is not None
                     and app._cur.ea == A, 25)
        c.check("target is undefined before 'a'",
                c.lst.cur_head() is not None and c.lst.cur_head().kind == "unknown",
                f"head={c.lst.cur_head()}")
        c.lst.focus()
        await c.press("a")
        await c.wait(lambda: c.lst.model.index_of_ea(A) >= 0
                     and c.lst.model.get(c.lst.model.index_of_ea(A)) is not None
                     and c.lst.model.get(c.lst.model.index_of_ea(A)).kind == "data"
                     and "'" in c.lst.model.get(c.lst.model.index_of_ea(A)).text, 25)
        hi = c.lst.model.index_of_ea(A)
        c.check("'a' creates a string literal at the cursor",
                hi >= 0 and c.lst.model.get(hi).kind == "data"
                and "'" in c.lst.model.get(hi).text,
                f"head={c.lst.model.get(hi) if hi >= 0 else None}")
    finally:
        try:
            c.prog.make_string(A)  # restore the original string
        except Exception:  # noqa: BLE001
            pass
        c.prog.bump_items()


@scenario("listing_struct_expand")
async def s_listing_struct_expand(c: Ctx):
    """A struct-typed global expands into indented member rows in the listing."""
    app = c.app
    # a writable data address: reuse a data segment's first data head
    A = None
    for start, end, name in c.prog.sections():
        if start >= end:
            continue
        lm = c.prog.listing(start)
        if lm is None:
            continue
        lm.ensure(60)
        h = next((h for h in lm.window(0, 60) if h.kind == "data"), None)
        if h is not None:
            A = h.ea
            break
    if A is None:
        c.check("found a data address for the struct test", False)
        return
    try:
        c.prog.client.call(
            "declare_type",
            decls=["struct TuiExpandS { int a; char b[4]; short c; };"])
        c.prog.make_data(A, "TuiExpandS")
        c.prog.bump_items()
        await c.goto_ui(hex(A))
        await c.wait(lambda: app._active == "listing" and app._cur is not None
                     and app._cur.ea == A and c.lst.total > 0, 25)
        # the summary head, then member rows for a/b/c
        si = c.lst.model.index_of_ea(A)
        members = [c.lst.model.get(si + 1 + k) for k in range(3)]
        names = [m.text for m in members if m is not None]
        c.check("struct global expands into member rows",
                all(m is not None and m.kind == "member" for m in members)
                and any("a" in t for t in names) and any("b" in t for t in names),
                f"members={names}")
        c.check("member rows carry field addresses",
                members[1] is not None and members[1].ea == A + 4,
                f"ea={members[1].ea if members[1] else None:#x} want={A+4:#x}")
    finally:
        try:
            c.prog.undefine(A, size=16)
        except Exception:  # noqa: BLE001
            pass
        c.prog.bump_items()


@scenario("continuous_view")
async def s_continuous_view(c: Ctx):
    """The default code view is ONE continuous listing: opening a function shows
    the whole segment (functions + data interleaved, with opcodes); F5/Tab
    decompiles the function at the cursor and back."""
    app = c.app
    fn = await c.open_biggest("listing")
    fn_ea = fn.addr
    await c.wait(lambda: app._active == "listing" and c.lst.display, 10)
    c.check("a function opens in the continuous listing by default",
            app._active == "listing" and c.lst.display
            and c.lst._cursor_ea() == fn_ea,
            f"active={app._active} disp={c.lst.display} cur_ea={c.lst._cursor_ea()}")
    # the listing spans the whole segment, not just the function
    c.lst.model.load_all()
    seg = c.prog.segment_bounds(fn_ea)
    seg_rows = len(c.lst.model)
    # a function's own instruction count is far smaller than the segment
    fdis = c.prog.disasm(fn_ea, fn.name)
    c.check("the continuous listing extends past the function's bounds",
            seg_rows > fdis.total(), f"listing={seg_rows} func={fdis.total()}")
    kinds = {c.lst.model.get(i).kind for i in range(seg_rows)}
    c.check("continuous listing interleaves code with data/undefined",
            "code" in kinds and ("data" in kinds or "unknown" in kinds), str(kinds))
    # rendering parity with disasm: code lines carry opcode bytes
    cidx = next((i for i in range(seg_rows)
                 if c.lst.model.get(i).kind == "code"), None)
    c.check("continuous listing renders opcode bytes (parity with disasm)",
            cidx is not None and c.lst.model.get(cidx).raw
            and c.lst._op_field(c.lst.model.get(cidx)).strip() != "",
            f"raw={c.lst.model.get(cidx).raw if cidx is not None else None!r}")
    # F5/Tab at the function -> decompiler, and back to the same spot
    c.lst.focus()
    await c.press("tab")
    await c.wait(lambda: (app._active == "decomp" and c.dec.loaded_ea == fn_ea)
                 or (app._active == "listing" and "fail" in c.status().lower()), 25)
    if app._active == "decomp":
        c.check("F5/Tab decompiles the function under the cursor",
                c.dec.loaded_ea == fn_ea, f"loaded={c.dec.loaded_ea}")
        await c.press("tab")
        await c.wait(lambda: app._active == "listing", 25)
        c.check("F5/Tab in the decompiler returns to the listing at the same ea",
                app._active == "listing" and c.lst._cursor_ea() == fn_ea,
                f"active={app._active} cur_ea={c.lst._cursor_ea()}")
    else:
        c.check("undecompilable function falls back to the listing",
                app._active == "listing", f"active={app._active}")


@scenario("func_banners")
async def s_func_banners(c: Ctx):
    """The unified listing shows IDA-style function boundary banners: a
    SUBROUTINE separator + 'name proc near' header and a 'name endp' footer,
    and those banner rows are display-only (navigation lands on real code)."""
    app = c.app
    fn = await c.open_biggest("listing")
    c.lst.model.load_all()
    heads = [c.lst.model.get(i) for i in range(len(c.lst.model))]
    ci = c.lst.model.index_of_ea(fn.addr)
    c.check("navigation to a function lands on its code head, not a banner",
            ci >= 0 and c.lst.model.get(ci).kind == "code",
            f"kind={c.lst.model.get(ci).kind if ci >= 0 else None}")
    c.check("a SUBROUTINE separator banner is present",
            any(h.kind == "sep" and "S U B R O U T I N E" in h.text for h in heads))
    c.check("a 'name proc' header is present",
            any(h.kind == "funchdr" and h.text.endswith(" proc") for h in heads))
    c.check("a 'name endp' footer is present",
            any(h.kind == "funchdr" and h.text.endswith("endp") for h in heads))
    # the proc header for the origin function carries its name
    hdr = next((h for h in heads if h.kind == "funchdr"
                and h.text == f"{fn.name} proc"), None)
    c.check("the proc header names the function", hdr is not None, f"fn={fn.name}")


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
async def run(binary, only=None):
    # Own idalib worker: opens the binary in-process over a unix socket.
    app = IdaTui(open_path=binary, keepalive=False)
    async with app.run_test(size=(140, 44)) as pilot:
        c = Ctx(app, pilot)
        await c.boot()
        for name, fn in SCENARIOS:
            if only and not any(o in name for o in only):
                continue
            c.scenario = name
            _t0 = asyncio.get_event_loop().time()
            try:
                await c.reset()
                await fn(c)
                print(f"── {name}  ({asyncio.get_event_loop().time() - _t0:.1f}s)")
            except _StopSuite:
                raise
            except Exception as e:  # noqa: BLE001 — isolate: one scenario's crash
                print(f"── {name}  ({asyncio.get_event_loop().time() - _t0:.1f}s) CRASHED")
                c.check("scenario did not crash", False, f"{type(e).__name__}: {e}")
                traceback.print_exc()


def main(argv):
    global STOP_AFTER
    only = None
    binary = None
    it = iter(argv)
    for a in it:
        if a == "--only":
            only = next(it).split(",")
        elif a == "--stop-after":
            STOP_AFTER = next(it)
        elif a in ("--worker", "--binary"):
            binary = os.path.abspath(os.path.expanduser(next(it)))
        elif a == "--list":
            for name, _ in SCENARIOS:
                print(name)
            return 0
        elif not a.startswith("-"):
            binary = os.path.abspath(os.path.expanduser(a))
    if binary is None:  # default target for the pilot
        binary = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "targets", "echo")
    try:
        asyncio.run(run(binary, only))
    except _StopSuite:
        print(f"  … stopped after '{STOP_AFTER}'")
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
