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
    StructEditor, SymbolPalette, XrefsScreen,
)
from textual.widgets import (  # noqa: E402
    DataTable, Footer, Input, OptionList, Static, TextArea,
)
from rich.text import Text  # noqa: E402

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
        waited = 0.0
        while waited < t:
            if pred():
                return True
            await self.pilot.pause(step)
            waited += step
        return False

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
        return self.app.query_one(DisasmView)

    @property
    def dec(self):
        return self.app.query_one(DecompView)

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
        return self.prog.functions().all_loaded()

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
    async def open(self, target, view="decomp", t=25):
        """Open a function (name or ea) to its entry, in ``view`` ('decomp' or
        'disasm'). Returns the Func."""
        ea = self.prog.resolve(target) if isinstance(target, str) else int(target)
        fn = self.prog.function_of(ea)
        if fn is None:
            raise RuntimeError(f"no function for {target!r}")
        self.app._pref = view
        self.app._open_function(fn.addr, fn.name)
        await self.wait(lambda: self.app._cur and self.app._cur.ea == fn.addr, t)
        if view == "decomp":
            await self.wait(lambda: self.dec.loaded_ea == fn.addr, t)
        else:
            await self.wait(lambda: self.dis.total > 0, t)
        return fn

    async def open_biggest(self, view="disasm"):
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
        await self.wait(
            lambda: "functions" in self.status() and "…" not in self.status(), 60)
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
    c.check("function load completed (status settled)",
            "functions" in c.status() and "…" not in c.status(), c.status())
    print(f"    {c.table.row_count} functions loaded")


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


@scenario("decomp_fallback")
async def s_fallback(c: Ctx):
    app = c.app
    d_view, c_view = c.dis, c.dec
    failing = next((f for f in reversed(c.all_funcs())
                    if c.prog.decompile(f.addr).failed), None)
    if failing is None:
        c.check("found a decompile-failing function", False)
        return
    app._pref = "decomp"
    app._goto(hex(failing.addr))
    await c.wait(lambda: app._cur and app._cur.ea == failing.addr, 20)
    await c.wait(lambda: app._active == "disasm", 20)
    c.check("decompile failure falls back to disassembly (preference kept)",
            app._active == "disasm" and d_view.display and not c_view.display
            and app._pref == "decomp",
            f"active={app._active} pref={app._pref} "
            f"disp(dis={d_view.display},dec={c_view.display})")
    app._goto("main")
    await c.wait(lambda: app._cur and app._cur.name == "main", 20)
    await c.wait(lambda: app._active == "decomp" and c_view.display, 25)
    c.check("preference preserved: next function opens as pseudocode",
            app._active == "decomp" and c_view.display, f"active={app._active}")


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
    app._pref = "decomp"
    app._open_function(fn.addr, fn.name)
    await c.wait(lambda: app._cur and app._cur.ea == fn.addr, 20)
    await c.wait(lambda: c.dis.total > 0, 30)
    c.check("disasm model loads with a total", c.dis.total > 0, f"total={c.dis.total}")
    print(f"    biggest = {fn.name} ({c.dis.total} instrs)")
    pc = await c.wait(lambda: app._active == "decomp" and c.dec.display
                      and c.dec.loaded_ea == fn.addr, 25)
    c.check("opening a function shows pseudocode by default", pc, f"active={app._active}")


@scenario("disasm_nav")
async def s_disasm_nav(c: Ctx):
    app, view = c.app, c.dis
    await c.open_biggest("disasm")
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
    # goto-bottom must not hang on a huge function.
    await c.press("end")
    await c.pause(0.05)
    c.check("goto-bottom lands near end", view.cursor >= view.total - 1,
            f"cursor={view.cursor}/{view.total}")


@scenario("hex")
async def s_hex(c: Ctx):
    app, view = c.app, c.dis
    await c.open_biggest("disasm")
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
    await c.press("backslash")
    await c.wait(lambda: app._active != "hex", 10)
    c.check("backslash returns from hex to the code view",
            app._active == "disasm", f"active={app._active}")


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
            not left.display and isinstance(app.focused, (DisasmView, DecompView)),
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
            app._active == "disasm" and dis.display and not dec.display,
            f"active={app._active}")
    await c.press("tab")
    await c.wait(lambda: app._active == "decomp", 10)
    # a (re)decompile shows the grayed overlay
    dec.loaded_ea = None
    app._show_active()
    cover = dec._cover_widget
    c.check("decompile shows a 'decompiling…' overlay",
            dec.loading and cover is not None and "decomp-loading" in cover.classes
            and "decompiling" in str(cover.render()),
            f"loading={dec.loading} cover={cover!r}")
    await c.wait(lambda: not dec.loading and dec._cover_widget is None, 25)
    c.check("overlay clears when the decompile finishes",
            not dec.loading and dec._cover_widget is None)
    # line-number gutter
    dec.scroll_to(0, 0, animate=False)
    await c.pause(0.025)
    row0 = "".join(seg.text for seg in dec.render_line(0))
    c.check("pseudocode has a numbered gutter (line 1 first)",
            dec._gutter > 0 and row0[:dec._gutter].strip() == "1",
            f"gutter={dec._gutter} row0={row0[:10]!r}")


@scenario("search")
async def s_search(c: Ctx):
    app, dis = c.app, c.dis
    await c.open_biggest("disasm")
    dis.focus()
    line0 = dis.model.cached_line(0)
    raw = (line0.text.split() or ["push"])[0] if line0 else "push"
    term = "".join(ch for ch in raw if ch.isalnum())[:4] or "push"
    await c.press("slash")
    await c.pause(0.1)
    await c.type(term)
    await c.press("enter")
    await c.wait(lambda: bool(dis._matches), 25)
    c.check("search finds matches", len(dis._matches) > 0, f"term={term!r}")
    c.check("cursor sits on a match", dis.cursor in dis._matches, f"cursor={dis.cursor}")
    c.check("match substring highlighted",
            bool(dis._ranges.get(dis.cursor)), str(dis._ranges.get(dis.cursor)))
    c.check("search cursor lands on the match's starting column",
            dis.cursor_x == dis._ranges[dis.cursor][0][0],
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
    await c.open_biggest("disasm")
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
        xexp = app.program.disasm(xref.fn_addr).index_of_ea(xref.frm)
        await c.press("g")
        await c.pause(0.1)
        await c.type(xfn.name)
        await c.press("enter")
        await c.wait(lambda: dis.total > 0 and app._cur.ea == xfn.addr, 20)
        dis.focus()
        dis.cursor, dis.cursor_x = 0, 0
        await c.press("x")
        await c.wait(lambda: isinstance(app.screen, XrefsScreen), 25)
        app.screen.query_one(OptionList).highlighted = 0
        await c.press("enter")
        await c.wait(lambda: not isinstance(app.screen, XrefsScreen), 25)
        await c.wait(lambda: app._cur.ea == xref.fn_addr, 25)
        await c.pause(0.15)
        c.check("xref-select lands on the referencing function + line",
                app._cur.ea == xref.fn_addr and dis.cursor == xexp,
                f"cur={app._cur.ea:#x} (want {xref.fn_addr:#x}) "
                f"cursor={dis.cursor} (want {xexp})")

        dcode = app.program.decompile(xref.fn_addr)
        dexp, be = -1, -1
        if not dcode.failed and dcode.code:
            for i, ln in enumerate(dcode.code.splitlines()):
                for mm in re.findall(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/", ln):
                    e = int(mm, 16)
                    if be < e <= xref.frm:
                        be, dexp = e, i
        if dexp >= 0:
            app._pref = "decomp"
            app._open_function(xfn.addr, xfn.name)
            await c.wait(lambda: app._cur.ea == xfn.addr and app._active == "decomp", 20)
            await c.wait(lambda: dec.loaded_ea == xfn.addr, 25)
            app._xref_focus_name = xfn.name
            app._on_xref_chosen(xref.frm)
            await c.wait(lambda: dec.loaded_ea == xref.fn_addr, 25)
            await c.pause(0.1)
            c.check("xref-select lands on the reference LINE in pseudocode",
                    dec.cursor == dexp, f"dec.cursor={dec.cursor} want={dexp}")
            landed = dec._texts[dec.cursor] if dec.cursor < len(dec._texts) else ""
            tokm = re.search(rf"\b{re.escape(xfn.name)}\b", landed)
            want_col = tokm.start() if tokm else 0
            c.check("xref-select lands the column on the reference token",
                    dec.cursor_x == want_col,
                    f"cursor_x={dec.cursor_x} want={want_col} "
                    f"token={xfn.name!r} line={landed.strip()!r}")
            anch = [(i, dec._line_ea(i)) for i in range(len(dec._texts))
                    if dec._line_ea(i) is not None]
            if len(anch) >= 4:
                start_ln = anch[1][0]
                far_ea = anch[len(anch) // 2][1]
                exp2 = app._decomp_line_for(app._cur.ea, far_ea)
                dec.focus()
                dec.cursor = start_ln
                dec.refresh()
                await c.pause(0.05)
                app._on_xref_chosen(far_ea)
                await c.wait(lambda: dec.cursor == exp2, 20)
                c.check("xref-select moves the cursor within the same function",
                        dec.cursor == exp2 and exp2 != start_ln,
                        f"dec.cursor={dec.cursor} want={exp2} start={start_ln}")
            app._pref = "disasm"
            app._active = "disasm"
            app._show_active()
            await c.pause(0.05)

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
    await c.open(multi.addr, "disasm")
    dis.focus()
    dis.cursor, dis.cursor_x = 0, 0
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
    await c.open_biggest("disasm")
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


@scenario("scroll_restore")
async def s_scroll_restore(c: Ctx):
    app, dis = c.app, c.dis
    big = sorted(c.all_funcs(), key=lambda f: f.size, reverse=True)
    fa = next((f for f in big if f.size > 0x400), big[0])
    fb = next((f for f in big if f.addr != fa.addr), big[-1])
    await c.goto_ui(fa.name)
    await c.wait(lambda: dis.total > 40 and app._cur.ea == fa.addr, 20)
    if app._active != "disasm":
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
    if app._active != "disasm":
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
    await c.open_biggest("disasm")
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
    if app._active != "disasm":
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


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
async def run(db, only=None):
    url = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:8745/mcp")
    app = IdaTui(url=url, db=db, keepalive=False)
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
    db = only = None
    it = iter(argv)
    for a in it:
        if a == "--db":
            db = next(it)
        elif a == "--only":
            only = next(it).split(",")
        elif a == "--stop-after":
            STOP_AFTER = next(it)
        elif a == "--list":
            for name, _ in SCENARIOS:
                print(name)
            return 0
    try:
        asyncio.run(run(db, only))
    except _StopSuite:
        print(f"  … stopped after '{STOP_AFTER}'")
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
