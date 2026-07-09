"""idatui Phase 1 TUI: a two-pane, keyboard-first IDA frontend.

Left  : function list (lazy-loaded, filterable).
Right : virtualized disassembly listing for the selected function.

Design notes:
* The disassembly view is a real virtualized ``ScrollView``: it only ever renders
  the visible ~viewport of lines, painting instantly from the domain block cache
  and scheduling background fetches for misses. A 52k-instruction function scrolls
  without ever materializing 52k lines in a widget.
* All network/domain work runs in Textual worker threads; the UI never blocks.
* An address-history stack backs Enter (follow) / Esc (back), IDA-style.
* On startup we bump the worker idle-TTL and run a keepalive heartbeat so the
  session never gets reaped while we chill.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.segment import Segment
from rich.style import Style
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.geometry import Region, Size
from textual.message import Message
from textual.reactive import reactive
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import DataTable, Footer, Header, Input, Static

from .highlight import highlight_c

from .client import IDAClient
from .domain import DisasmModel, Func, Program

# Styles for the disassembly listing.
_S_ADDR = Style(color="grey58")
_S_LABEL = Style(color="yellow", bold=True)
_S_INSN = Style(color="white")
_S_MNEM = Style(color="cyan")
_S_CURSOR = Style(bgcolor="grey30")
_S_DIM = Style(color="grey42", italic=True)
_S_MATCH = Style(bgcolor="#7a5c00")  # all search matches
_S_MATCH_CUR = Style(bgcolor="#b58900", color="black")  # the current match


@dataclass
class NavEntry:
    ea: int
    name: str
    cursor: int = 0


class SearchRequested(Message):
    """A code view asks the app to open the search prompt."""

    def __init__(self, view: "SearchMixin", direction: int) -> None:
        super().__init__()
        self.view = view
        self.direction = direction


def _overlay_ranges(strip: Strip, ranges: list[tuple[int, int]], style: Style) -> Strip:
    """Return a copy of ``strip`` with ``style`` merged over the given cell
    ranges (pseudocode/disasm are ASCII, so char offset == cell offset)."""
    total = strip.cell_length
    parts: list[Strip] = []
    pos = 0
    for a, b in ranges:
        a = max(a, 0)
        b = min(b, total)
        if a >= b:
            continue
        if a > pos:
            parts.append(strip.crop(pos, a))
        parts.append(strip.crop(a, b).apply_style(style))
        pos = b
    if pos < total:
        parts.append(strip.crop(pos, total))
    return Strip.join(parts) if parts else strip


class SearchMixin:
    """Vim-style in-view search shared by the disasm and pseudocode views.

    ``/`` searches forward, ``?`` backward; an empty query repeats the last one.
    ``n``/``N`` jump next/prev. All matches are highlighted; the cursor lands on
    the current match. Subclasses provide the line-text source via the three
    ``_search_*`` hooks (disasm indexes lazily; pseudocode has text in hand).
    """

    # NOTE: Textual only merges BINDINGS from DOMNode subclasses, so a plain
    # mixin's BINDINGS are ignored. Each view lists SEARCH_BINDINGS explicitly.
    SEARCH_BINDINGS = [
        Binding("slash", "search(1)", "Search"),
        Binding("question_mark", "search(-1)", "Search ↑", show=False),
        Binding("n", "search_repeat(1)", "Next", show=False),
        Binding("N", "search_repeat(-1)", "Prev", show=False),
    ]

    # --- state (subclasses must init these in __init__) ---
    _term: str
    _matches: list[int]
    _ranges: dict[int, list[tuple[int, int]]]

    # --- hooks a subclass implements ---
    def _search_line_count(self) -> int:
        raise NotImplementedError

    def _search_line_text(self, i: int) -> str | None:
        raise NotImplementedError

    def _search_ensure(self, done) -> None:
        """Ensure all line texts are available, then call ``done()`` on the UI
        thread. Default: assume ready."""
        done()

    # --- actions ---
    def action_search(self, direction: int) -> None:
        self.post_message(SearchRequested(self, direction))

    def action_search_repeat(self, direction: int) -> None:
        self.search_repeat(direction)

    # --- driven by the app's prompt ---
    def set_search(self, term: str, direction: int) -> None:
        self._term = term
        self._ci = term.islower()  # smartcase
        self._pending_dir = direction
        self._search_ensure(self._after_search_ready)

    def _after_search_ready(self) -> None:
        self._compute_matches()
        self._app_status(f"/{self._term}/  {len(self._matches)} matches")
        self.refresh()
        if self._matches:
            self.search_repeat(self._pending_dir, include_current=True)

    def _compute_matches(self) -> None:
        term = self._term
        needle = term.lower() if getattr(self, "_ci", True) else term
        matches: list[int] = []
        ranges: dict[int, list[tuple[int, int]]] = {}
        for i in range(self._search_line_count()):
            s = self._search_line_text(i)
            if not s:
                continue
            hay = s.lower() if getattr(self, "_ci", True) else s
            pos, rs = 0, []
            while True:
                j = hay.find(needle, pos)
                if j < 0:
                    break
                rs.append((j, j + len(term)))
                pos = j + len(term)
            if rs:
                matches.append(i)
                ranges[i] = rs
        self._matches = matches
        self._ranges = ranges

    def search_repeat(self, direction: int, include_current: bool = False) -> None:
        if not getattr(self, "_term", ""):
            return
        if not self._matches:
            self._app_status(f"no matches for /{self._term}/")
            return
        cur = self.cursor
        if direction >= 0:
            nxt = next((m for m in self._matches
                        if (m >= cur if include_current else m > cur)), self._matches[0])
        else:
            nxt = next((m for m in reversed(self._matches) if m < cur), self._matches[-1])
        self._goto_line(nxt)
        k = self._matches.index(nxt) + 1
        self._app_status(f"/{self._term}/  {k}/{len(self._matches)}  line {nxt}")

    def _goto_line(self, idx: int) -> None:
        total = self._search_line_count()
        self.cursor = max(0, min(total - 1, idx))
        self.scroll_to(y=max(self.cursor - self._visible_height() // 2, 0), animate=False)
        self.refresh()

    def clear_search(self) -> None:
        self._term = ""
        self._matches = []
        self._ranges = {}
        self.refresh()

    def _match_style(self, idx: int) -> Style:
        return _S_MATCH_CUR if idx == self.cursor else _S_MATCH

    def _app_status(self, text: str) -> None:
        app = self.app
        if hasattr(app, "_status"):
            app._status(text)


# --------------------------------------------------------------------------- #
# Virtualized disassembly view
# --------------------------------------------------------------------------- #
class DisasmView(SearchMixin, ScrollView, can_focus=True):
    """A line-virtualized disassembly listing for a single function."""

    BINDINGS = [
        Binding("j,down", "cursor_down", "Down", show=False),
        Binding("k,up", "cursor_up", "Up", show=False),
        Binding("ctrl+d", "half_page(1)", "½↓", show=False),
        Binding("ctrl+u", "half_page(-1)", "½↑", show=False),
        Binding("pagedown,f", "page(1)", "PgDn", show=False),
        Binding("pageup,b", "page(-1)", "PgUp", show=False),
        Binding("home", "goto_top", "Top", show=False),
        Binding("G,end", "goto_bottom", "Bottom", show=False),
        Binding("tab,shift+tab", "app.toggle_view", "Pseudocode", priority=True),
        *SearchMixin.SEARCH_BINDINGS,
    ]

    cursor = reactive(0, repaint=False)

    class CursorMoved(Message):
        """Posted when the disasm cursor moves; carries the instruction ea."""

        def __init__(self, index: int, ea: int | None) -> None:
            super().__init__()
            self.index = index
            self.ea = ea

    def __init__(self) -> None:
        super().__init__()
        self.model: DisasmModel | None = None
        self.total = 0
        self._name = ""
        self._term = ""
        self._matches: list[int] = []
        self._ranges: dict[int, list[tuple[int, int]]] = {}
        self._search_texts: list[str] | None = None

    # -- public API -------------------------------------------------------- #
    def load(self, model: DisasmModel, name: str, cursor: int = 0) -> None:
        self.model = model
        self._name = name
        self.total = 0
        self.cursor = cursor
        self.virtual_size = Size(0, 0)
        self._matches = []
        self._ranges = {}
        self._search_texts = None
        self._prime()

    # -- search hooks ------------------------------------------------------ #
    @staticmethod
    def _fmt(line) -> str:  # type: ignore[no-untyped-def]
        s = f"{line.ea:08X}  "
        if line.label:
            s += f"{line.label}: "
        return s + line.text

    def _search_line_count(self) -> int:
        return self.total

    def _search_line_text(self, i: int) -> str | None:
        t = self._search_texts
        return t[i] if t is not None and 0 <= i < len(t) else None

    def _search_ensure(self, done) -> None:
        if self._search_texts is not None:
            done()
            return
        self._app_status(f"/{self._term}/  indexing {self.total} lines…")
        self._index_for_search(done)

    @work(thread=True, exclusive=True, group="search-index")
    def _index_for_search(self, done) -> None:
        model = self.model
        if model is None:
            self.app.call_from_thread(done)
            return
        texts: list[str] = []
        off, total = 0, self.total
        while off < total:
            lines = model.lines(off, DisasmModel.BLOCK, prefetch=False)
            if not lines:
                break
            texts.extend(self._fmt(ln) for ln in lines)
            off += len(lines)
        self._search_texts = texts
        self.app.call_from_thread(done)

    @work(thread=True, exclusive=True, group="disasm-prime")
    def _prime(self) -> None:
        model = self.model
        if model is None:
            return
        total = model.total()
        height = max(self.size.height, 1)
        model.lines(0, min(total, height + DisasmModel.BLOCK), prefetch=True)
        if self.cursor:
            model.lines(max(self.cursor - 2, 0), height, prefetch=True)
        self.app.call_from_thread(self._on_primed, total)

    def _on_primed(self, total: int) -> None:
        self.total = total
        self.virtual_size = Size(0, total)
        self._scroll_cursor_into_view()
        self.refresh()

    # -- rendering --------------------------------------------------------- #
    def render_line(self, y: int) -> Strip:
        model = self.model
        width = self.size.width
        if model is None or self.total == 0:
            return Strip([Segment("".ljust(width), _S_DIM)])
        top = round(self.scroll_offset.y)
        if y == 0:  # once per refresh: warm the visible window + a little ahead
            self._ensure_window(top)
        idx = top + y
        if idx >= self.total:
            return Strip([Segment("".ljust(width), _S_INSN)])
        line = model.cached_line(idx)
        cursor = idx == self.cursor
        base = _S_CURSOR if cursor else None
        if line is None:
            seg = Segment(f"  {idx:>8}  …".ljust(width), (base or Style()) + _S_DIM)
            return Strip([seg])
        segs: list[Segment] = []
        addr = f"{line.ea:08X}"
        segs.append(Segment(f"{addr}  ", _join(base, _S_ADDR)))
        if line.label:
            segs.append(Segment(f"{line.label}: ", _join(base, _S_LABEL)))
        text = line.text
        mnem, _, rest = text.partition(" ")
        segs.append(Segment(mnem, _join(base, _S_MNEM)))
        if rest:
            segs.append(Segment(" " + rest, _join(base, _S_INSN)))
        strip = Strip(segs)
        if idx in self._ranges:
            strip = _overlay_ranges(strip, self._ranges[idx], self._match_style(idx))
        return strip.adjust_cell_length(width, _join(base, _S_INSN) or _S_INSN)

    def _ensure_window(self, top: int) -> None:
        if self.model is None:
            return
        height = max(self.size.height, 1)
        start = max(top - DisasmModel.BLOCK, 0)
        count = height + 2 * DisasmModel.BLOCK
        if not self.model.is_cached(top, height):
            self._fetch_window(start, count)
        else:
            self.model.ensure_async(start, count)  # warm neighbors

    @work(thread=True, exclusive=False, group="disasm-fetch")
    def _fetch_window(self, start: int, count: int) -> None:
        model = self.model
        if model is None:
            return
        model.lines(start, count, prefetch=True)
        self.app.call_from_thread(self.refresh)

    # -- navigation -------------------------------------------------------- #
    def _visible_height(self) -> int:
        return max(self.size.height, 1)

    def _scroll_cursor_into_view(self) -> None:
        height = self._visible_height()
        top = round(self.scroll_offset.y)
        if self.cursor < top:
            self.scroll_to(y=self.cursor, animate=False)
        elif self.cursor >= top + height:
            self.scroll_to(y=max(self.cursor - height + 1, 0), animate=False)

    def _move(self, delta: int) -> None:
        if self.total == 0:
            return
        old = self.cursor
        before = round(self.scroll_offset.y)
        self.cursor = max(0, min(self.total - 1, self.cursor + delta))
        self._scroll_cursor_into_view()
        if round(self.scroll_offset.y) != before:
            self.refresh()  # scrolled: the whole viewport shifted
        else:
            _refresh_lines(self, old, self.cursor)  # only the two changed rows
        self.post_message(DisasmView.CursorMoved(self.cursor, self._cursor_ea()))

    def _cursor_ea(self) -> int | None:
        if self.model is None:
            return None
        line = self.model.cached_line(self.cursor)
        return line.ea if line else None

    def action_cursor_down(self) -> None:
        self._move(1)

    def action_cursor_up(self) -> None:
        self._move(-1)

    def action_half_page(self, direction: int) -> None:
        self._move(direction * (self._visible_height() // 2))

    def action_page(self, direction: int) -> None:
        self._move(direction * self._visible_height())

    def action_goto_top(self) -> None:
        self._move(-self.total)

    def action_goto_bottom(self) -> None:
        self._move(self.total)


def _join(base: Style | None, style: Style) -> Style:
    return (base + style) if base is not None else style


def _refresh_lines(view, *indices: int) -> None:
    """Repaint only the given virtual line indices (cheap in-place cursor move)."""
    top = round(view.scroll_offset.y)
    height = view.size.height
    width = view.size.width
    for idx in indices:
        row = idx - top
        if 0 <= row < height:
            view.refresh(Region(0, row, width, 1))


# --------------------------------------------------------------------------- #
# Decompiler (pseudocode) view
# --------------------------------------------------------------------------- #
class DecompView(SearchMixin, ScrollView, can_focus=True):
    """Read-only, line-virtualized Hex-Rays pseudocode with Pygments C
    highlighting. Lines are highlighted once at load and cached as Strips, so
    cursor movement and scrolling are O(1) (no TextArea/tree-sitter overhead).
    """

    BINDINGS = [
        Binding("tab,shift+tab", "app.toggle_view", "Disasm", priority=True),
        Binding("j,down", "cursor_down", "Down", show=False),
        Binding("k,up", "cursor_up", "Up", show=False),
        Binding("ctrl+d", "half_page(1)", "½↓", show=False),
        Binding("ctrl+u", "half_page(-1)", "½↑", show=False),
        Binding("pagedown,f", "page(1)", "PgDn", show=False),
        Binding("pageup,b", "page(-1)", "PgUp", show=False),
        Binding("home", "goto_top", "Top", show=False),
        Binding("G,end", "goto_bottom", "Bottom", show=False),
        *SearchMixin.SEARCH_BINDINGS,
    ]

    cursor = reactive(0, repaint=False)

    def __init__(self) -> None:
        super().__init__(id="decomp")
        self.loaded_ea: int | None = None
        self._strips: list[Strip] = []
        self._texts: list[str] = []
        self._term = ""
        self._matches: list[int] = []
        self._ranges: dict[int, list[tuple[int, int]]] = {}

    def show(self, ea: int, text: str) -> None:
        seglists = highlight_c(text)
        self._strips = [Strip(segs) for segs in seglists]
        self._texts = ["".join(seg.text for seg in segs) for segs in seglists]
        self.loaded_ea = ea
        self.cursor = 0
        self._matches = []
        self._ranges = {}
        maxw = max((s.cell_length for s in self._strips), default=0)
        self.virtual_size = Size(maxw, len(self._strips))
        self.scroll_to(0, 0, animate=False)
        self.refresh()

    @property
    def total(self) -> int:
        return len(self._strips)

    # -- search hooks ------------------------------------------------------ #
    def _search_line_count(self) -> int:
        return len(self._strips)

    def _search_line_text(self, i: int) -> str | None:
        return self._texts[i] if 0 <= i < len(self._texts) else None

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        top = round(self.scroll_offset.y)
        idx = top + y
        if idx >= len(self._strips):
            return Strip.blank(width)
        x = round(self.scroll_offset.x)
        base = self._strips[idx]
        if idx in self._ranges:
            base = _overlay_ranges(base, self._ranges[idx], self._match_style(idx))
        strip = base.crop(x, x + width).adjust_cell_length(width)
        if idx == self.cursor:
            strip = strip.apply_style(_S_CURSOR)
        return strip

    # -- navigation (mirrors DisasmView) ---------------------------------- #
    def _visible_height(self) -> int:
        return max(self.size.height, 1)

    def _scroll_cursor_into_view(self) -> None:
        height = self._visible_height()
        top = round(self.scroll_offset.y)
        if self.cursor < top:
            self.scroll_to(y=self.cursor, animate=False)
        elif self.cursor >= top + height:
            self.scroll_to(y=max(self.cursor - height + 1, 0), animate=False)

    def _move(self, delta: int) -> None:
        if not self._strips:
            return
        old = self.cursor
        before = round(self.scroll_offset.y)
        self.cursor = max(0, min(len(self._strips) - 1, self.cursor + delta))
        self._scroll_cursor_into_view()
        if round(self.scroll_offset.y) != before:
            self.refresh()
        else:
            _refresh_lines(self, old, self.cursor)

    def action_cursor_down(self) -> None:
        self._move(1)

    def action_cursor_up(self) -> None:
        self._move(-1)

    def action_half_page(self, direction: int) -> None:
        self._move(direction * (self._visible_height() // 2))

    def action_page(self, direction: int) -> None:
        self._move(direction * self._visible_height())

    def action_goto_top(self) -> None:
        self._move(-len(self._strips))

    def action_goto_bottom(self) -> None:
        self._move(len(self._strips))


# --------------------------------------------------------------------------- #
# Function list panel
# --------------------------------------------------------------------------- #
class FunctionsPanel(Vertical):
    def compose(self) -> ComposeResult:
        self._filter = Input(placeholder="filter (glob, e.g. sub_*)  —  Enter to apply", id="func-filter")
        self._filter.display = False
        yield self._filter
        table = DataTable(id="func-table", cursor_type="row", zebra_stripes=True)
        table.add_column("Address", width=12)
        table.add_column("Function", width=28)
        table.add_column("Size", width=8)
        yield table


# --------------------------------------------------------------------------- #
# The app
# --------------------------------------------------------------------------- #
class IdaTui(App):
    CSS = """
    Screen { layout: vertical; }
    #panes { height: 1fr; }
    #left { width: 42%; border-right: solid $panel; }
    #func-table { height: 1fr; }
    #func-filter { dock: top; }
    DisasmView { width: 1fr; padding: 0 1; }
    DecompView { width: 1fr; }
    #search { dock: bottom; height: 1; }
    #status { dock: bottom; height: 1; background: $panel; color: $text; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "filter", "Filter"),
        Binding("g", "goto", "Goto"),
        Binding("ctrl+b", "toggle_functions", "Names"),
        Binding("tab,shift+tab", "toggle_view", "Disasm/Pseudocode"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, url: str, db: str | None, keepalive: bool = True,
                 open_path: str | None = None) -> None:
        super().__init__()
        self._url = url
        self._db = db
        self._open_path = open_path
        self._do_keepalive = keepalive
        self.client: IDAClient | None = None
        self.program: Program | None = None
        self._ka = None
        self._nav: list[NavEntry] = []
        self._cur_filter: str | None = None
        self._active = "disasm"  # or "decomp"
        self._cur: NavEntry | None = None
        self._search_ctx: tuple[object | None, int] = (None, 1)

    # -- layout ------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="panes"):
            with FunctionsPanel(id="left"):
                pass
            yield DisasmView()
            dv = DecompView()
            dv.display = False
            yield dv
        si = Input(id="search")
        si.display = False
        si.can_focus = False
        yield si
        yield Static("connecting…", id="status")
        yield Footer()

    def on_mount(self) -> None:
        # Keep the hidden command input out of the focus chain until summoned.
        inp = self.query_one("#func-filter", Input)
        inp.can_focus = False
        self.query_one("#func-table", DataTable).focus()
        self._connect()

    # -- status helper ----------------------------------------------------- #
    def _status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    # -- connection + initial load ---------------------------------------- #
    @work(thread=True, exclusive=True, group="connect")
    def _connect(self) -> None:
        try:
            client = IDAClient(self._url, db=self._db)
            client.connect()
            if self._open_path is not None:
                self.app.call_from_thread(self._status, f"opening {self._open_path}…")
                import os
                path = os.path.abspath(os.path.expanduser(self._open_path))
                res = client.call("idb_open", input_path=path,
                                  idle_ttl_sec=1_000_000_000, timeout=1800.0)
                if not (isinstance(res, dict) and res.get("success")):
                    err = res.get("error") if isinstance(res, dict) else res
                    self.app.call_from_thread(self._status, f"open failed: {err}")
                    return
                client.set_db(res["session"]["session_id"])
            elif self._db is None:
                client.set_db(client.resolve_db())
            health = client.health()
            module = health.get("module", "?")
            if self._do_keepalive:
                try:
                    client.bump_idle_ttl()
                except Exception:
                    pass
                self._ka = client.keepalive(interval=120.0).start()
            program = Program(client)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"connect failed: {e}")
            return
        self.client = client
        self.program = program
        self.app.call_from_thread(self._status, f"{module} — loading functions…")
        self._load_functions()

    @work(thread=True, exclusive=True, group="load-funcs")
    def _load_functions(self, filter: str | None = None) -> None:
        assert self.program is not None
        idx = self.program.functions(filter=filter)
        # Stream rows in as pages arrive so the UI fills progressively.
        table_reset = {"done": False}

        def reset_table():
            t = self.query_one("#func-table", DataTable)
            t.clear()
            table_reset["done"] = True

        self.app.call_from_thread(reset_table)
        last = 0
        module = self._module()
        while not idx.complete:
            idx.load_next_page()
            rows = idx.window(last, len(idx) - last)
            last = len(idx)
            if rows:
                self.app.call_from_thread(self._append_rows, rows)
                self.app.call_from_thread(
                    self._status, f"{module} — {last} functions…"
                )
        self.app.call_from_thread(self._status, f"{module} — {len(idx)} functions")

    def _module(self) -> str:
        try:
            return self.client.health().get("module", "?") if self.client else "?"
        except Exception:  # noqa: BLE001
            return "?"

    def _append_rows(self, rows: list[Func]) -> None:
        table = self.query_one("#func-table", DataTable)
        for f in rows:
            table.add_row(f"{f.addr:08X}", f.name, f"{f.size:#x}", key=str(f.addr))

    # -- actions ----------------------------------------------------------- #
    def action_toggle_functions(self) -> None:
        """Show/hide the functions pane; give the disasm view all the width."""
        left = self.query_one("#left", FunctionsPanel)
        left.display = not left.display
        if not left.display:
            self.query_one(DisasmView).focus()
        else:
            self.query_one("#func-table", DataTable).focus()

    def action_toggle_view(self) -> None:
        """Tab: switch the code pane between disassembly and pseudocode."""
        if self._cur is None:
            return
        self._active = "decomp" if self._active == "disasm" else "disasm"
        self._show_active()

    def action_filter(self) -> None:
        inp = self.query_one("#func-filter", Input)
        inp.placeholder = "filter (glob, e.g. sub_*)  —  Enter to apply"
        inp.can_focus = True
        inp.display = True
        inp.value = self._cur_filter or ""
        inp.focus()

    def action_goto(self) -> None:
        inp = self.query_one("#func-filter", Input)
        inp.display = True
        inp.placeholder = "goto: name or 0xADDR — Enter"
        inp.can_focus = True
        inp.value = ""
        inp.focus()
        self._goto_mode = True

    def action_back(self) -> None:
        if len(self._nav) > 1:
            self._nav.pop()
            self._open_entry(self._nav[-1], push=False)
        else:
            self.query_one("#func-table", DataTable).focus()

    # -- input submit (filter / goto) ------------------------------------- #
    def on_search_requested(self, msg: SearchRequested) -> None:
        self._search_ctx = (msg.view, msg.direction)
        inp = self.query_one("#search", Input)
        inp.placeholder = "search  /" if msg.direction >= 0 else "search backward  ?"
        inp.can_focus = True
        inp.display = True
        inp.value = ""
        inp.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        inp = event.input
        inp.display = False
        inp.can_focus = False
        if inp.id == "search":
            view, direction = self._search_ctx
            if view is not None:
                if value:
                    view.set_search(value, direction)
                else:
                    view.search_repeat(direction)
                view.focus()
            return
        if getattr(self, "_goto_mode", False):
            self._goto_mode = False
            inp.placeholder = "filter (glob, e.g. sub_*)  —  Enter to apply"
            self.query_one("#func-table", DataTable).focus()
            if value:
                self._goto(value)
            return
        # filter mode
        self._cur_filter = value or None
        self.query_one("#func-table", DataTable).focus()
        self._load_functions(filter=self._cur_filter)

    @work(thread=True, exclusive=True, group="goto")
    def _goto(self, target: str) -> None:
        assert self.program is not None
        try:
            ea = self.program.resolve(target)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"goto: {e}")
            return
        f = self.program.functions().by_addr(ea)
        name = f.name if f else target
        self.app.call_from_thread(self._open_function, ea, name)

    # -- opening functions ------------------------------------------------- #
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ea = int(event.row_key.value)
        table = self.query_one("#func-table", DataTable)
        row = table.get_row(event.row_key)
        name = row[1] if row else hex(ea)
        self._open_function(ea, name)

    def _open_function(self, ea: int, name: str, push: bool = True) -> None:
        entry = NavEntry(ea=ea, name=name, cursor=0)
        if push:
            self._nav.append(entry)
        self._open_entry(entry, push=False)

    def _open_entry(self, entry: NavEntry, push: bool) -> None:
        if self.program is None:
            return
        self._cur = entry
        model = self.program.disasm(entry.ea, entry.name)
        self.query_one(DisasmView).load(model, entry.name, cursor=entry.cursor)
        self._show_active()

    def _show_active(self) -> None:
        dis = self.query_one(DisasmView)
        dec = self.query_one(DecompView)
        if self._active == "disasm":
            dec.display = False
            dis.display = True
            dis.focus()
            self._status_for_cur("disasm")
        else:
            dis.display = False
            dec.display = True
            dec.focus()
            if self._cur is not None and dec.loaded_ea != self._cur.ea:
                self._status(f"{self._cur.name} — decompiling…")
                self._load_decomp(self._cur.ea, self._cur.name)
            else:
                self._status_for_cur("pseudocode")

    def _status_for_cur(self, mode: str) -> None:
        if self._cur is not None:
            self._status(f"{self._cur.name}  @ {self._cur.ea:#x}   [{mode}]")

    @work(thread=True, exclusive=True, group="decomp")
    def _load_decomp(self, ea: int, name: str) -> None:
        assert self.program is not None
        dec = self.program.decompile(ea)
        self.app.call_from_thread(self._apply_decomp, ea, name, dec)

    def _apply_decomp(self, ea: int, name: str, dec) -> None:  # type: ignore[no-untyped-def]
        view = self.query_one(DecompView)
        if dec.failed:
            view.show(ea, f"/* decompilation failed at {ea:#x}: {dec.error} */\n")
            self._status(f"{name} — decompile failed; Tab for disasm")
        else:
            note = "  (truncated)" if dec.truncated else ""
            view.show(ea, dec.code or "")
            self._status(f"{name}  @ {ea:#x}   [pseudocode {len(dec.code or '')} chars]{note}")

    def on_disasm_view_cursor_moved(self, msg: DisasmView.CursorMoved) -> None:
        if self._nav:
            self._nav[-1].cursor = msg.index
        ea = msg.ea
        if ea is not None:
            name = self._nav[-1].name if self._nav else ""
            self._status(f"{name}  @ {ea:#x}   (line {msg.index})")

    # -- teardown ---------------------------------------------------------- #
    def on_unmount(self) -> None:
        if self._ka is not None:
            self._ka.stop()
        if self.program is not None:
            self.program.close()
        if self.client is not None:
            self.client.close()
