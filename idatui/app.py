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

import re
from dataclasses import dataclass

from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.geometry import Region, Size
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import DataTable, Footer, Header, Input, OptionList, Static
from textual.widgets.option_list import Option

from .highlight import highlight_c

from .client import IDAClient, IDAToolError
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
_S_NAME_MATCH = Style(bgcolor="#b58900", color="black")  # filter match in a name
_S_WORD = Style(bgcolor="#264f78")  # identifier under the cursor
_S_CELL = Style(reverse=True)      # the block cursor cell
_S_LINENO = Style(color="grey37")             # pseudocode line-number gutter
_S_LINENO_CUR = Style(color="grey66", bold=True)  # gutter on the cursor line


@dataclass
class NavEntry:
    ea: int
    name: str
    cursor: int = 0        # disasm line (instruction index)
    cursor_x: int = 0      # disasm column
    scroll_y: int = -1     # disasm viewport top (-1 = derive from cursor)
    dec_cursor: int = 0    # pseudocode line
    dec_cursor_x: int = 0  # pseudocode column
    dec_scroll_y: int = -1 # pseudocode viewport top (-1 = derive)
    dec_scroll_x: int = 0  # pseudocode horizontal scroll


class SearchRequested(Message):
    """A code view asks the app to open the search prompt."""

    def __init__(self, view: "SearchMixin", direction: int) -> None:
        super().__init__()
        self.view = view
        self.direction = direction


class FollowRequested(Message):
    """A code view asks to follow the reference under the cursor."""

    def __init__(self, view) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.view = view


class XrefsRequested(Message):
    """A code view asks for cross-references to the item under the cursor."""

    def __init__(self, view) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.view = view


class RenameRequested(Message):
    """A code view asks to rename the symbol under the cursor."""

    def __init__(self, view, name: str | None) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.view = view
        self.name = name


class NavMixin:
    """Follow / xrefs actions shared by the code views (bindings live on each
    view since Textual only merges BINDINGS from DOMNode subclasses)."""

    NAV_BINDINGS = [
        Binding("enter", "follow", "Follow"),
        Binding("x", "xrefs", "Xrefs"),
        Binding("n", "rename", "Rename"),
    ]

    def action_follow(self) -> None:
        self.post_message(FollowRequested(self))

    def action_xrefs(self) -> None:
        self.post_message(XrefsRequested(self))

    def action_rename(self) -> None:
        self.post_message(RenameRequested(self, self.word_under_cursor()))


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


def _word_bounds(text: str, x: int) -> tuple[int, int]:
    """[start, end) of the identifier at column ``x`` (empty span if none)."""
    n = len(text)
    if n == 0:
        return (0, 0)
    x = max(0, min(x, n - 1))
    isw = lambda c: c.isalnum() or c == "_"  # noqa: E731
    if not isw(text[x]):
        return (x, x)
    s = x
    while s > 0 and isw(text[s - 1]):
        s -= 1
    e = x
    while e < n and isw(text[e]):
        e += 1
    return (s, e)


def _overlay_over(strip: Strip, ranges: list[tuple[int, int]], style: Style) -> Strip:
    """Like _overlay_ranges but ``style`` OVERRIDES the existing cell styles
    (used for the cursor cell / word, which must win over the line background)."""
    total = strip.cell_length
    parts: list[Strip] = []
    pos = 0
    for a, b in ranges:
        a, b = max(a, 0), min(b, total)
        if a >= b:
            continue
        if a > pos:
            parts.append(strip.crop(pos, a))
        mid = strip.crop(a, b)
        parts.append(Strip([Segment(s.text, (s.style or Style()) + style) for s in mid]))
        pos = b
    if pos < total:
        parts.append(strip.crop(pos, total))
    return Strip.join(parts) if parts else strip


def _cursor_decorate(strip: Strip, plain: str, x: int) -> Strip:
    """Add the cursor-line background, the word-under-cursor highlight, and the
    block cursor cell at column ``x``."""
    total = strip.cell_length
    strip = strip.apply_style(_S_CURSOR)  # line background (fills empty bg)
    if total > 0:
        xx = max(0, min(x, total - 1))
        ws, we = _word_bounds(plain, xx)
        if we > ws:
            strip = _overlay_over(strip, [(ws, we)], _S_WORD)
        strip = _overlay_over(strip, [(xx, xx + 1)], _S_CELL)
    return strip


class ColumnCursor:
    """Horizontal (column) cursor for the code views: h/l/←/→, w/b word hops,
    0/$ line ends. Requires the view to define the ``cursor_x`` reactive and the
    ``_line_plain(idx)`` / ``_hscroll()`` hooks.
    """

    COL_BINDINGS = [
        Binding("l,right", "col_right", "→", show=False),
        Binding("h,left", "col_left", "←", show=False),
        Binding("w", "col_word(1)", "word→", show=False),
        Binding("b", "col_word(-1)", "word←", show=False),
        Binding("0", "col_home", "bol", show=False),
        Binding("dollar_sign", "col_end", "eol", show=False),
    ]

    def _line_plain(self, idx: int) -> str | None:
        raise NotImplementedError

    def _hscroll(self) -> None:
        pass

    def _clamp_x(self) -> None:
        plain = self._line_plain(self.cursor)
        if plain is not None:
            self.cursor_x = min(self.cursor_x, max(len(plain) - 1, 0))

    def _move_x(self, dx: int) -> None:
        plain = self._line_plain(self.cursor) or ""
        self.cursor_x = max(0, min(max(len(plain) - 1, 0), self.cursor_x + dx))
        self._hscroll()
        _refresh_lines(self, self.cursor)

    def action_col_left(self) -> None:
        self._move_x(-1)

    def action_col_right(self) -> None:
        self._move_x(1)

    def action_col_home(self) -> None:
        self.cursor_x = 0
        self._hscroll()
        _refresh_lines(self, self.cursor)

    def action_col_end(self) -> None:
        plain = self._line_plain(self.cursor) or ""
        self.cursor_x = max(len(plain) - 1, 0)
        self._hscroll()
        _refresh_lines(self, self.cursor)

    def action_col_word(self, direction: int) -> None:
        plain = self._line_plain(self.cursor) or ""
        n = len(plain)
        if n == 0:
            return
        isw = lambda c: c.isalnum() or c == "_"  # noqa: E731
        i = max(0, min(self.cursor_x, n - 1))
        if direction > 0:
            while i < n and isw(plain[i]):
                i += 1
            while i < n and not isw(plain[i]):
                i += 1
            self.cursor_x = min(i, n - 1)
        else:
            i -= 1
            while i > 0 and not isw(plain[i]):
                i -= 1
            while i > 0 and isw(plain[i - 1]):
                i -= 1
            self.cursor_x = max(i, 0)
        self._hscroll()
        _refresh_lines(self, self.cursor)

    def word_under_cursor(self) -> str | None:
        plain = self._line_plain(self.cursor)
        if not plain:
            return None
        s, e = _word_bounds(plain, min(self.cursor_x, len(plain) - 1))
        return plain[s:e] or None

    def _col_offset(self) -> int:
        """Cells to the left of the code content (e.g. a line-number gutter)."""
        return 0

    # -- mouse ------------------------------------------------------------- #
    def _after_cursor_move(self) -> None:
        pass

    def _set_cursor_at(self, line: int, col: int) -> None:
        total = self.total
        if total <= 0:
            return
        self.cursor = max(0, min(total - 1, line))
        plain = self._line_plain(self.cursor)
        maxx = max(len(plain) - 1, 0) if plain is not None else col
        self.cursor_x = max(0, min(maxx, col))
        self._scroll_cursor_into_view()
        self._hscroll()
        self.refresh()
        self._after_cursor_move()

    def on_click(self, event) -> None:  # type: ignore[no-untyped-def]
        off = event.get_content_offset(self)
        if off is None:
            return
        line = round(self.scroll_offset.y) + off.y
        if line >= self.total:
            return
        self.focus()
        col = round(self.scroll_offset.x) + off.x - self._col_offset()
        self._set_cursor_at(line, max(col, 0))
        if event.chain >= 2:  # double-click == place cursor + follow
            self.post_message(FollowRequested(self))

    # -- paging (keeps the cursor at the same viewport-relative row) ------- #
    def _page_scroll(self, lines: int) -> None:
        total = self.total
        if total <= 0:
            return
        height = self._visible_height()
        top = round(self.scroll_offset.y)
        max_top = max(total - height, 0)
        new_top = max(0, min(max_top, top + lines))
        delta = new_top - top
        if delta == 0:  # already at an edge: jump the cursor to the extreme
            self.cursor = (total - 1) if lines > 0 else 0
        else:  # move cursor by the same delta -> relative row preserved
            self.cursor = max(0, min(total - 1, self.cursor + delta))
        self._clamp_x()
        self.scroll_to(y=new_top, animate=False)
        self.refresh()
        self._after_cursor_move()

    def action_page(self, direction: int) -> None:
        self._page_scroll(direction * self._visible_height())

    def action_half_page(self, direction: int) -> None:
        self._page_scroll(direction * (self._visible_height() // 2))

    def _apply_scroll(self, y: int, x: int = 0) -> None:
        """Set the scroll offset reliably after a (re)load. Applied now and again
        after the next refresh — when the view was just shown its size isn't
        computed yet, so an immediate scroll_to clamps to 0; the deferred pass
        re-applies it and forces a repaint so the pane never shows a stale frame.
        """
        y = max(0, y)
        self.scroll_to(x=x, y=y, animate=False)

        def _fix(yy: int = y, xx: int = x) -> None:
            self.scroll_to(x=xx, y=yy, animate=False)
            self.refresh(layout=True)

        self.call_after_refresh(_fix)


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

    # --- driven by the app's prompt (incremental / as-you-type) ---
    def search_begin(self, direction: int) -> None:
        self._search_origin = self.cursor
        self._search_origin_x = self.cursor_x
        self._search_dir = direction

    def search_update(self, term: str) -> None:
        """Live preview: highlight all matches and jump from the origin."""
        if not term:
            self._term = ""
            self._matches = []
            self._ranges = {}
            self.cursor = getattr(self, "_search_origin", self.cursor)
            self.cursor_x = getattr(self, "_search_origin_x", self.cursor_x)
            self.refresh()
            self._app_status("/")
            return
        self._term = term
        self._ci = term.islower()  # smartcase
        self._search_ensure(self._after_incremental)

    def _after_incremental(self) -> None:
        self._compute_matches()
        self.refresh()
        self._jump_from(getattr(self, "_search_origin", 0),
                        getattr(self, "_search_dir", 1), include_current=True)
        n = len(self._matches)
        self._app_status(f"/{self._term}   {n} match{'' if n == 1 else 'es'}")

    def _jump_from(self, origin: int, direction: int, include_current: bool) -> None:
        if not self._matches:
            return
        if direction >= 0:
            nxt = next((m for m in self._matches
                        if (m >= origin if include_current else m > origin)),
                       self._matches[0])
        else:
            nxt = next((m for m in reversed(self._matches)
                        if (m <= origin if include_current else m < origin)),
                       self._matches[-1])
        self._goto_line(nxt)

    def search_commit(self) -> None:
        if self._term:
            self._last_term = self._term

    def search_cancel(self) -> None:
        self._term = ""
        self._matches = []
        self._ranges = {}
        self.cursor = getattr(self, "_search_origin", self.cursor)
        self.cursor_x = getattr(self, "_search_origin_x", self.cursor_x)
        self.scroll_to(y=max(self.cursor - self._visible_height() // 2, 0), animate=False)
        self.refresh()

    def repeat_last(self, direction: int) -> None:
        term = getattr(self, "_last_term", "")
        if not term:
            self._app_status("no previous search")
            return
        self._term = term
        self._ci = term.islower()
        self._search_ensure(lambda: (self._compute_matches(), self.refresh(),
                                     self.search_repeat(direction)))

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
        # Land the cursor on the start of the (first) match on this line.
        ranges = self._ranges.get(self.cursor)
        if ranges:
            self.cursor_x = ranges[0][0]
        self.scroll_to(y=max(self.cursor - self._visible_height() // 2, 0), animate=False)
        self._hscroll()  # bring the match column into horizontal view
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
class DisasmView(SearchMixin, NavMixin, ColumnCursor, ScrollView, can_focus=True):
    """A line-virtualized disassembly listing for a single function."""

    BINDINGS = [
        Binding("j,down", "cursor_down", "Down", show=False),
        Binding("k,up", "cursor_up", "Up", show=False),
        Binding("ctrl+d", "half_page(1)", "½↓", show=False),
        Binding("ctrl+u", "half_page(-1)", "½↑", show=False),
        Binding("pagedown", "page(1)", "PgDn", show=False),
        Binding("pageup", "page(-1)", "PgUp", show=False),
        Binding("home", "goto_top", "Top", show=False),
        Binding("G,end", "goto_bottom", "Bottom", show=False),
        Binding("tab,shift+tab", "app.toggle_view", "Pseudocode", priority=True),
        *SearchMixin.SEARCH_BINDINGS,
        *NavMixin.NAV_BINDINGS,
        *ColumnCursor.COL_BINDINGS,
    ]

    cursor = reactive(0, repaint=False)
    cursor_x = reactive(0, repaint=False)

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
        self._pending_scroll_y: int | None = None
        self._term = ""
        self._matches: list[int] = []
        self._ranges: dict[int, list[tuple[int, int]]] = {}
        self._search_texts: list[str] | None = None

    def _line_plain(self, idx: int) -> str | None:
        if self.model is None:
            return None
        line = self.model.cached_line(idx)
        if line is None:
            return None
        s = f"{line.ea:08X}  "
        if line.label:
            s += f"{line.label}: "
        return s + line.text

    # -- public API -------------------------------------------------------- #
    def load(self, model: DisasmModel, name: str, cursor: int = 0,
             cursor_x: int = 0, scroll_y: int | None = None) -> None:
        self.model = model
        self._name = name
        self.total = 0
        self.cursor = cursor
        self.cursor_x = cursor_x
        self._pending_scroll_y = scroll_y
        # NB: don't zero virtual_size here — that snaps the scroll to 0 and
        # causes a visible jump before _on_primed restores the target scroll.
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
        self._clamp_x()  # cursor line is now cached; keep the column in range
        if self._pending_scroll_y is not None and self._pending_scroll_y >= 0:
            self._apply_scroll(min(self._pending_scroll_y, max(total - 1, 0)))
        else:
            self._scroll_cursor_into_view()
        self._pending_scroll_y = None
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
        is_cursor = idx == self.cursor
        if line is None:
            strip = Strip([Segment(f"  {idx:>8}  …", _S_DIM)])
        else:
            segs: list[Segment] = [Segment(f"{line.ea:08X}  ", _S_ADDR)]
            if line.label:
                segs.append(Segment(f"{line.label}: ", _S_LABEL))
            mnem, _, rest = line.text.partition(" ")
            segs.append(Segment(mnem, _S_MNEM))
            if rest:
                segs.append(Segment(" " + rest, _S_INSN))
            strip = Strip(segs)
        if idx in self._ranges:
            strip = _overlay_ranges(strip, self._ranges[idx], self._match_style(idx))
        if is_cursor:
            strip = _cursor_decorate(strip, self._line_plain(idx) or "", self.cursor_x)
        return strip.adjust_cell_length(width, _S_INSN)

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
        self._clamp_x()
        self._scroll_cursor_into_view()
        if round(self.scroll_offset.y) != before:
            self.refresh()  # scrolled: the whole viewport shifted
        else:
            _refresh_lines(self, old, self.cursor)  # only the two changed rows
        self.post_message(DisasmView.CursorMoved(self.cursor, self._cursor_ea()))

    def _after_cursor_move(self) -> None:
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
class DecompView(SearchMixin, NavMixin, ColumnCursor, ScrollView, can_focus=True):
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
        Binding("pagedown", "page(1)", "PgDn", show=False),
        Binding("pageup", "page(-1)", "PgUp", show=False),
        Binding("home", "goto_top", "Top", show=False),
        Binding("G,end", "goto_bottom", "Bottom", show=False),
        *SearchMixin.SEARCH_BINDINGS,
        *NavMixin.NAV_BINDINGS,
        *ColumnCursor.COL_BINDINGS,
    ]

    cursor = reactive(0, repaint=False)
    cursor_x = reactive(0, repaint=False)

    class CursorMoved(Message):
        """Posted when the pseudocode cursor moves; carries the line's ea."""

        def __init__(self, index: int, ea: int | None) -> None:
            super().__init__()
            self.index = index
            self.ea = ea

    def __init__(self) -> None:
        super().__init__(id="decomp")
        self.loaded_ea: int | None = None
        self._strips: list[Strip] = []
        self._texts: list[str] = []
        self._gutter = 0  # line-number gutter width (cells)
        self._term = ""
        self._matches: list[int] = []
        self._ranges: dict[int, list[tuple[int, int]]] = {}

    def _line_plain(self, idx: int) -> str | None:
        return self._texts[idx] if 0 <= idx < len(self._texts) else None

    def _col_offset(self) -> int:
        return self._gutter

    def _hscroll(self) -> None:
        width = max(self.size.width - self._gutter, 1)  # code viewport (past gutter)
        sx = round(self.scroll_offset.x)
        if self.cursor_x < sx:
            self.scroll_to(x=self.cursor_x, animate=False)
        elif self.cursor_x >= sx + width:
            self.scroll_to(x=self.cursor_x - width + 1, animate=False)

    def show(self, ea: int, text: str, cursor: int = 0, cursor_x: int = 0,
             scroll_y: int = -1, scroll_x: int = 0) -> None:
        seglists = highlight_c(text)
        self._strips = [Strip(segs) for segs in seglists]
        self._texts = ["".join(seg.text for seg in segs) for segs in seglists]
        self.loaded_ea = ea
        total = len(self._strips)
        self.cursor = max(0, min(max(total - 1, 0), cursor))
        self.cursor_x = cursor_x
        self._matches = []
        self._ranges = {}
        # Gutter wide enough for the largest line number + a trailing space.
        self._gutter = (len(str(total)) + 1) if total else 0
        maxw = max((s.cell_length for s in self._strips), default=0)
        self.virtual_size = Size(maxw + self._gutter, total)
        self._clamp_x()
        if scroll_y >= 0:
            self._apply_scroll(min(scroll_y, max(total - 1, 0)), scroll_x)
        else:
            self.scroll_to(0, 0, animate=False)
            self._scroll_cursor_into_view()
            self._hscroll()
        self.refresh()

    def get_loading_widget(self):  # type: ignore[override]
        # Shown (grayed, centered) while a (re)decompile is in flight.
        return Static("― decompiling… ―", classes="decomp-loading")

    def _line_ea(self, idx: int) -> int | None:
        if not (0 <= idx < len(self._texts)):
            return None
        ms = re.findall(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/", self._texts[idx])
        return int(ms[-1], 16) if ms else None

    def _after_cursor_move(self) -> None:
        self.post_message(DecompView.CursorMoved(self.cursor, self._line_ea(self.cursor)))

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
        gw = self._gutter
        top = round(self.scroll_offset.y)
        idx = top + y
        if idx >= len(self._strips):
            if gw:
                return Strip([Segment(" " * gw, _S_LINENO)]).adjust_cell_length(width)
            return Strip.blank(width)
        x = round(self.scroll_offset.x)
        base = self._strips[idx]
        if idx in self._ranges:
            base = _overlay_ranges(base, self._ranges[idx], self._match_style(idx))
        if idx == self.cursor:
            base = _cursor_decorate(base, self._texts[idx], self.cursor_x)
        code_w = max(width - gw, 0)
        code = base.crop(x, x + code_w).adjust_cell_length(code_w)
        if gw <= 0:
            return code
        style = _S_LINENO_CUR if idx == self.cursor else _S_LINENO
        gutter = Strip([Segment(f"{idx + 1:>{gw - 1}} ", style)])
        return Strip.join([gutter, code]).adjust_cell_length(width)

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
        self._clamp_x()
        self._scroll_cursor_into_view()
        if round(self.scroll_offset.y) != before:
            self.refresh()
        else:
            _refresh_lines(self, old, self.cursor)
        self._after_cursor_move()

    def action_cursor_down(self) -> None:
        self._move(1)

    def action_cursor_up(self) -> None:
        self._move(-1)

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
        table.add_column("Address", width=10)
        table.add_column("Function", width=21)
        table.add_column("Size", width=7)
        yield table


# --------------------------------------------------------------------------- #
# Xrefs popup
# --------------------------------------------------------------------------- #
class XrefsScreen(ModalScreen):
    """A modal list of cross-references; Enter jumps, Esc closes."""

    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, label: str, items: list[tuple[int, str]]) -> None:
        super().__init__()
        self._label = label
        self._items = items

    def compose(self) -> ComposeResult:
        with Vertical(id="xref-box"):
            yield Static(self._label, id="xref-title")
            yield OptionList(*[Option(text) for _, text in self._items], id="xref-list")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(self._items[event.option_index][0])

    def action_close(self) -> None:
        self.dismiss(None)


# --------------------------------------------------------------------------- #
# The app
# --------------------------------------------------------------------------- #
class IdaTui(App):
    CSS = """
    Screen { layout: vertical; }
    #panes { height: 1fr; }
    #left { width: 30%; min-width: 42; max-width: 44; border-right: solid $panel; }
    #func-table { height: 1fr; }
    #func-filter { dock: top; }
    DisasmView { width: 1fr; padding: 0 1; }
    DecompView { width: 1fr; }
    #search {
        height: 1; border: none; padding: 0 1;
        background: $primary-darken-2; color: $text;
    }
    #rename {
        height: 1; border: none; padding: 0 1;
        background: $warning-darken-2; color: $text;
    }
    #status { height: 1; background: $panel; color: $text; padding: 0 1; }
    .decomp-loading {
        width: 100%; height: 100%; content-align: center middle;
        background: $panel-darken-1; color: $text-muted; text-style: italic bold;
    }
    XrefsScreen { align: center middle; }
    #xref-box { width: 84; max-height: 70%; height: auto; border: thick $accent; background: $panel; }
    #xref-title { dock: top; height: 1; background: $accent; color: $text; padding: 0 1; }
    #xref-list { height: auto; max-height: 100%; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "filter", "Filter"),
        Binding("g", "goto", "Goto"),
        Binding("ctrl+b", "toggle_functions", "Names"),
        Binding("tab,shift+tab", "toggle_view", "Disasm/Pseudocode", priority=True),
        Binding("ctrl+s", "save", "Save"),
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
        self._func_index = None  # the unfiltered FunctionIndex (source of truth)
        self._filter_term = ""
        self._pending_filter = ""
        self._filter_timer = None
        self._sort_col = 0        # 0=addr, 1=name, 2=size
        self._sort_reverse = False
        self._active = "disasm"  # or "decomp"
        self._cur: NavEntry | None = None
        self._search_ctx: tuple[object | None, int] = (None, 1)
        self._rename_ctx: tuple[object | None, str] = (None, "")
        self._dirty = False

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
        ri = Input(id="rename")
        ri.display = False
        ri.can_focus = False
        yield ri
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
                # Moderate idle TTL: the keepalive heartbeat (below) keeps the
                # session alive while the TUI runs; once it exits the worker
                # idles out and frees its slot (avoids piling up to max-workers).
                res = client.call("idb_open", input_path=path,
                                  idle_ttl_sec=1800, timeout=1800.0)
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
                # Keep the session warm while we run; don't make it immortal, so
                # it's reclaimed after the TUI closes.
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
    def _load_functions(self) -> None:
        assert self.program is not None
        idx = self.program.functions()
        self._func_index = idx
        self.app.call_from_thread(lambda: self.query_one("#func-table", DataTable).clear())
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
        # If a filter is active (typed during load), re-apply it over the full set.
        if self._filter_term:
            self.app.call_from_thread(self._apply_filter, self._filter_term)
        else:
            self.app.call_from_thread(self._status, f"{module} — {len(idx)} functions")

    def _module(self) -> str:
        try:
            return self.client.health().get("module", "?") if self.client else "?"
        except Exception:  # noqa: BLE001
            return "?"

    def _append_rows(self, rows: list[Func]) -> None:
        if self._filter_term:  # streaming paused while a filter is active
            return
        table = self.query_one("#func-table", DataTable)
        for f in rows:
            table.add_row(f"{f.addr:08X}", f.name, f"{f.size:#x}", key=str(f.addr))

    # -- incremental function-name filter --------------------------------- #
    def _apply_filter(self, term: str) -> None:
        """Client-side incremental filter over the cached function list, with the
        matched substring highlighted in each name. Glob (``*``/``?``) or plain
        substring; smartcase (case-insensitive unless the query has uppercase).
        """
        import fnmatch

        term = term.strip()
        self._filter_term = term
        idx = self._func_index
        if idx is None:
            return
        funcs = idx.all_loaded()
        total = len(funcs)
        ci = term.islower()
        is_glob = ("*" in term) or ("?" in term)
        needle = term.lower() if ci else term
        pat = needle if (is_glob and ("*" in needle or "?" in needle)) else f"*{needle}*"
        matched: list[tuple[Func, tuple[int, int] | None]] = []
        for f in funcs:
            if not term:
                matched.append((f, None))
                continue
            hay = f.name.lower() if ci else f.name
            if is_glob:
                if fnmatch.fnmatch(hay, pat):
                    matched.append((f, None))
            else:
                i = hay.find(needle)
                if i >= 0:
                    matched.append((f, (i, i + len(term))))
        keyfn = {
            0: lambda fr: fr[0].addr,
            1: lambda fr: fr[0].name.lower(),
            2: lambda fr: fr[0].size,
        }[self._sort_col]
        matched.sort(key=keyfn, reverse=self._sort_reverse)
        table = self.query_one("#func-table", DataTable)
        table.clear()
        for f, rng in matched:
            if rng:
                name: object = Text(f.name)
                name.stylize(_S_NAME_MATCH, rng[0], rng[1])
            else:
                name = f.name
            table.add_row(f"{f.addr:08X}", name, f"{f.size:#x}", key=str(f.addr))
        if term:
            self._status(f"filter '{term}':  {len(matched)}/{total}")
        else:
            self._status(f"{self._module()} — {total} functions")

    def _apply_pending_filter(self) -> None:
        self._filter_timer = None
        self._apply_filter(self._pending_filter)

    def clear_filter(self) -> None:
        self._apply_filter("")

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """Click a column header to sort by it; click again to reverse."""
        col = event.column_index
        if col == self._sort_col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self._update_sort_headers()
        self._apply_filter(self._filter_term)

    def _update_sort_headers(self) -> None:
        table = self.query_one("#func-table", DataTable)
        bases = ["Address", "Function", "Size"]
        arrow = " ▼" if self._sort_reverse else " ▲"
        for i, col in enumerate(table.columns.values()):
            col.label = Text(bases[i] + (arrow if i == self._sort_col else ""))
        table._require_update_dimensions = True
        table.refresh()

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
        inp.placeholder = "filter names…  Enter=keep  Esc=clear"
        inp.can_focus = True
        inp.display = True
        inp.value = self._filter_term
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
        table = self.query_one("#func-table", DataTable)
        if self.focused is table and self._filter_term:
            self.clear_filter()  # Esc on the list clears an active filter
            return
        if len(self._nav) > 1:
            self._nav.pop()
            self._open_entry(self._nav[-1], push=False)
        else:
            table.focus()

    # -- input submit (filter / goto) ------------------------------------- #
    def on_search_requested(self, msg: SearchRequested) -> None:
        self._search_ctx = (msg.view, msg.direction)
        msg.view.search_begin(msg.direction)
        self.query_one("#status", Static).display = False  # give the row to search
        inp = self.query_one("#search", Input)
        inp.placeholder = "type to search…  Enter=keep  Esc=cancel"
        inp.can_focus = True
        inp.display = True
        inp.value = ""
        inp.focus()

    # -- follow / xrefs ---------------------------------------------------- #
    def on_follow_requested(self, msg: FollowRequested) -> None:
        view = msg.view
        word = view.word_under_cursor()
        if isinstance(view, DisasmView):
            ea = view._cursor_ea()
            if ea is not None:
                self._follow_disasm(ea, word)
        elif isinstance(view, DecompView) and view._texts:
            self._follow_decomp(view._texts[view.cursor], word)

    def on_xrefs_requested(self, msg: XrefsRequested) -> None:
        view = msg.view
        word = view.word_under_cursor()
        if isinstance(view, DisasmView):
            ea = view._cursor_ea()
            if ea is not None:
                self._xrefs_disasm(ea, word)
        elif isinstance(view, DecompView) and view._texts:
            self._xrefs_decomp(view._texts[view.cursor], word)

    @staticmethod
    def _looks_like_symbol(word: str | None) -> bool:
        # A symbol has a letter but is not a bare hex number (the address column
        # and hex operands are hex-only, e.g. "0026D4C0" -> follow via xref).
        if not word or not any(c.isalpha() for c in word):
            return False
        return not all(c in "0123456789abcdefABCDEF" for c in word)

    @work(thread=True, group="nav")
    def _follow_disasm(self, ea: int, word: str | None) -> None:
        assert self.program is not None
        # Prefer the symbol under the cursor (handles multiple refs on a line).
        if self._looks_like_symbol(word):
            try:
                self._do_navigate(self.program.resolve(word), push=True)
                return
            except Exception:  # noqa: BLE001 -- not a resolvable name; fall back
                pass
        xr = self.program.xrefs_from(ea)
        tgt = next((x for x in xr if x.type == "code" and x.to), None)
        tgt = tgt or next((x for x in xr if x.to), None)
        if tgt is None or tgt.to is None:
            self.app.call_from_thread(self._status, "nothing to follow here")
            return
        self._do_navigate(tgt.to, push=True)

    @work(thread=True, group="nav")
    def _follow_decomp(self, line: str, word: str | None) -> None:
        if self._cur is None:
            return
        dec = self.program.decompile(self._cur.ea)
        addr = None
        if word:  # the ref whose name is exactly the token under the cursor
            addr = next((r.addr for r in dec.refs if r.name == word), None)
        # A named function under the cursor may not be listed in refs
        # (e.g. self-reference, or refs truncated) — resolve it directly.
        if addr is None and self._looks_like_symbol(word):
            try:
                addr = self.program.resolve(word)
            except Exception:  # noqa: BLE001
                addr = None
        if addr is None:
            addr = self._ref_on_line(line)
        if addr is None:
            self.app.call_from_thread(self._status, "nothing to follow on this line")
            return
        self._do_navigate(addr, push=True)

    def _ref_on_line(self, line: str) -> int | None:
        """Address of the first decompiler ref whose name appears on ``line``."""
        if self._cur is None or self.program is None:
            return None
        dec = self.program.decompile(self._cur.ea)
        toks = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", line))
        for r in dec.refs:
            if r.name in toks:
                return r.addr
        return None

    @work(thread=True, group="xrefs")
    def _xrefs_disasm(self, ea: int, word: str | None) -> None:
        assert self.program is not None
        subj: int | None = None
        if self._looks_like_symbol(word):
            try:
                subj = self.program.resolve(word)
            except Exception:  # noqa: BLE001
                subj = None
        if subj is None:
            frm = self.program.xrefs_from(ea)
            subj = next((x.to for x in frm if x.type == "code" and x.to), ea)
        self._xrefs_present(subj)

    @work(thread=True, group="xrefs")
    def _xrefs_decomp(self, line: str, word: str | None) -> None:
        subj: int | None = None
        if self._cur is not None and word:
            dec = self.program.decompile(self._cur.ea)
            subj = next((r.addr for r in dec.refs if r.name == word), None)
        if subj is None and self._looks_like_symbol(word):
            try:
                subj = self.program.resolve(word)
            except Exception:  # noqa: BLE001
                subj = None
        if subj is None:
            subj = self._ref_on_line(line) or (self._cur.ea if self._cur else None)
        if subj is not None:
            self._xrefs_present(subj)

    def _xrefs_present(self, subj: int) -> None:  # worker context
        assert self.program is not None
        xr = self.program.xrefs_to(subj)
        fn = self.program.function_of(subj)
        if fn is not None:
            label = f"xrefs to {fn.name}"
            if subj != fn.addr:
                label += f"+{subj - fn.addr:#x}"
        else:
            label = f"xrefs to {subj:#x}"
        items = [(x.frm, f"{x.frm:08X}  {x.fn_name or '?':<24}  [{x.type}]") for x in xr]
        self.app.call_from_thread(self._present_xrefs, label, items)

    def _present_xrefs(self, label: str, items: list[tuple[int, str]]) -> None:
        if not items:
            self._status(f"{label}: none")
            return
        self._status(f"{label}: {len(items)}")
        self.push_screen(XrefsScreen(label, items), self._on_xref_chosen)

    def _on_xref_chosen(self, addr: int | None) -> None:
        if addr is not None:
            self._goto_ea(addr, push=True)

    # -- rename ------------------------------------------------------------ #
    def on_rename_requested(self, msg: RenameRequested) -> None:
        if not msg.name:
            self._status("nothing to rename under the cursor")
            return
        self._rename_ctx = (msg.view, msg.name)
        self.query_one("#status", Static).display = False
        inp = self.query_one("#rename", Input)
        inp.placeholder = f"rename '{msg.name}' —  Enter=apply  Esc=cancel"
        inp.can_focus = True
        inp.display = True
        inp.value = msg.name
        inp.focus()

    def _end_rename(self) -> None:
        inp = self.query_one("#rename", Input)
        inp.display = False
        inp.can_focus = False
        self.query_one("#status", Static).display = True
        view, _ = self._rename_ctx
        if view is not None:
            view.focus()

    @work(thread=True, exclusive=True, group="rename")
    def _do_rename(self, view, old: str, new: str) -> None:  # type: ignore[no-untyped-def]
        assert self.program is not None
        prog, cur = self.program, self._cur
        kind = "data"
        addr: int | None = None
        batch: dict = {"data": {"old": old, "new": new}}
        resolved: int | None = None
        try:
            resolved = prog.resolve(old)
        except Exception:  # noqa: BLE001
            resolved = None
        if resolved is not None:
            fn = prog.function_of(resolved)
            if fn is not None and fn.addr == resolved:
                kind, addr = "func", resolved
                batch = {"func": {"addr": hex(resolved), "name": new}}
            else:
                kind, batch = "data", {"data": {"old": old, "new": new}}
        elif isinstance(view, DecompView) and cur is not None:
            dec = prog.decompile(cur.ea)
            ref = next((r for r in dec.refs if r.name == old), None)
            if ref is not None:
                fn = prog.function_of(ref.addr)
                if fn is not None and fn.addr == ref.addr:
                    kind, addr = "func", ref.addr
                    batch = {"func": {"addr": hex(ref.addr), "name": new}}
                else:
                    kind, batch = "data", {"data": {"old": old, "new": new}}
            else:
                kind = "local"
                batch = {"local": {"func_addr": hex(cur.ea), "old": old, "new": new}}
        elif cur is not None:  # disasm view
            if old.startswith(("var_", "arg_")):
                kind = "stack"
                batch = {"stack": {"func_addr": hex(cur.ea), "old": old, "new": new}}
        try:
            res = prog.client.call("rename", batch=batch)
        except IDAToolError as e:
            self.app.call_from_thread(self._status, f"rename failed: {e.message}")
            return
        summary = res.get("summary", {}) if isinstance(res, dict) else {}
        if not (summary.get("ok", 0) > 0 and summary.get("failed", 0) == 0):
            msg = "rename failed"
            for catk in ("func", "data", "local", "stack"):
                items = res.get(catk) if isinstance(res, dict) else None
                if isinstance(items, list) and items and items[0].get("error"):
                    msg = f"rename failed: {items[0]['error']}"
            self.app.call_from_thread(self._status, msg)
            return
        self.app.call_from_thread(self._after_rename, kind, addr, old, new)

    def _after_rename(self, kind: str, addr: int | None, old: str, new: str) -> None:
        cur = self._cur
        # A renamed symbol can appear in many functions, so invalidate globally;
        # each function refreshes its names the next time it's viewed.
        self.program.bump_names()
        if cur is not None:
            self._save_current_pos()
            self.query_one(DecompView).loaded_ea = None  # force pseudocode reload
            self._open_entry(cur, push=False)
        if kind == "func" and addr is not None and self._func_index is not None:
            self._func_index.update_name(addr, new)
            for e in self._nav:
                if e.ea == addr:
                    e.name = new
            # Update the one cell in place (a full rebuild would race the
            # initial streaming load and duplicate row keys).
            table = self.query_one("#func-table", DataTable)
            try:
                name_col = list(table.columns.keys())[1]
                table.update_cell(str(addr), name_col, new)
            except Exception:  # noqa: BLE001 -- row filtered out / not yet streamed
                pass
        self._dirty = True
        self._status(f"renamed  {old} → {new}   (Ctrl+S to save)")

    @work(thread=True, exclusive=True, group="save")
    def _save(self) -> None:
        assert self.program is not None
        try:
            self.program.client.call("idb_save", timeout=300.0)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"save failed: {e}")
            return
        self._dirty = False
        self.app.call_from_thread(self._status, "saved to disk")

    def action_save(self) -> None:
        if self.program is None:
            return
        self._status("saving…")
        self._save()

    # -- navigation to an arbitrary address ------------------------------- #
    @work(thread=True, group="nav")
    def _goto_ea(self, ea: int, push: bool = True) -> None:
        self._do_navigate(ea, push)

    def _do_navigate(self, ea: int, push: bool) -> None:  # worker context
        assert self.program is not None
        fn = self.program.function_of(ea)
        if fn is None:
            self.app.call_from_thread(self._status, f"no function contains {ea:#x}")
            return
        model = self.program.disasm(fn.addr, fn.name)
        idx = 0 if ea == fn.addr else model.index_of_ea(ea)
        self.app.call_from_thread(self._open_at, fn.addr, fn.name, idx, push)

    def _open_at(self, ea: int, name: str, cursor: int, push: bool) -> None:
        if push:
            self._save_current_pos()
        entry = NavEntry(ea=ea, name=name, cursor=cursor)
        if push:
            self._nav.append(entry)
        self._open_entry(entry, push=False)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            view, _ = self._search_ctx
            if view is not None:
                view.search_update(event.value)
            return
        if event.input.id == "func-filter" and not getattr(self, "_goto_mode", False):
            self._pending_filter = event.value
            if self._filter_timer is not None:
                self._filter_timer.stop()
            self._filter_timer = self.set_timer(0.08, self._apply_pending_filter)

    def _end_search(self, cancel: bool = False) -> None:
        inp = self.query_one("#search", Input)
        inp.display = False
        inp.can_focus = False
        self.query_one("#status", Static).display = True
        view, _ = self._search_ctx
        if view is not None:
            if cancel:
                view.search_cancel()
            view.focus()

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key != "escape":
            return
        if self.query_one("#search", Input).display:
            event.stop()
            event.prevent_default()
            self._end_search(cancel=True)
            return
        if self.query_one("#rename", Input).display:
            event.stop()
            event.prevent_default()
            self._end_rename()
            return
        fi = self.query_one("#func-filter", Input)
        if fi.display:
            event.stop()
            event.prevent_default()
            fi.display = False
            fi.can_focus = False
            if getattr(self, "_goto_mode", False):
                self._goto_mode = False
            else:
                self.clear_filter()  # Esc in the filter box clears it
            self.query_one("#func-table", DataTable).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        inp = event.input
        inp.display = False
        inp.can_focus = False
        if inp.id == "search":
            view, direction = self._search_ctx
            if view is not None:
                if value:
                    view.search_commit()
                else:
                    view.repeat_last(direction)
            self._end_search()
            return
        if inp.id == "rename":
            view, old = self._rename_ctx
            self._end_rename()
            if view is not None and value and value != old:
                self._do_rename(view, old, value)
            return
        if getattr(self, "_goto_mode", False):
            self._goto_mode = False
            self.query_one("#func-table", DataTable).focus()
            if value:
                self._goto(value)
            return
        # filter mode: already applied incrementally; Enter just confirms + closes.
        self._apply_filter(value)
        self.query_one("#func-table", DataTable).focus()

    @work(thread=True, exclusive=True, group="goto")
    def _goto(self, target: str) -> None:
        assert self.program is not None
        try:
            ea = self.program.resolve(target)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"goto: {e}")
            return
        # Navigate to the containing function at the right line (handles both a
        # function name and a mid-function address).
        self._do_navigate(ea, push=True)

    # -- opening functions ------------------------------------------------- #
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ea = int(event.row_key.value)
        f = self._func_index.by_addr(ea) if self._func_index else None
        name = f.name if f else hex(ea)
        self._open_function(ea, name)

    def _save_current_pos(self) -> None:
        """Snapshot the active views' cursor + scroll into the top history entry
        (called just before we navigate away)."""
        if not self._nav:
            return
        e = self._nav[-1]
        dis = self.query_one(DisasmView)
        e.cursor, e.cursor_x = dis.cursor, dis.cursor_x
        e.scroll_y = round(dis.scroll_offset.y)
        dec = self.query_one(DecompView)
        if dec.loaded_ea == e.ea:
            e.dec_cursor, e.dec_cursor_x = dec.cursor, dec.cursor_x
            e.dec_scroll_y = round(dec.scroll_offset.y)
            e.dec_scroll_x = round(dec.scroll_offset.x)

    def _open_function(self, ea: int, name: str, push: bool = True) -> None:
        if push:
            self._save_current_pos()
        entry = NavEntry(ea=ea, name=name, cursor=0)
        if push:
            self._nav.append(entry)
        self._open_entry(entry, push=False)

    def _open_entry(self, entry: NavEntry, push: bool) -> None:
        if self.program is None:
            return
        self._cur = entry
        model = self.program.disasm(entry.ea, entry.name)
        sy = entry.scroll_y if entry.scroll_y >= 0 else None
        self.query_one(DisasmView).load(
            model, entry.name, cursor=entry.cursor, cursor_x=entry.cursor_x, scroll_y=sy)
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
                dec.loading = True  # gray out + 'decompiling…' overlay
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
        view.loading = False
        if self._active == "decomp":
            view.focus()  # loading cover had blurred it; restore focus
        # Restore the saved pseudocode position when returning to this function.
        cur = self._cur
        same = cur is not None and cur.ea == ea
        c = cur.dec_cursor if same else 0
        cx = cur.dec_cursor_x if same else 0
        sy = cur.dec_scroll_y if (same and cur.dec_scroll_y >= 0) else -1
        sx = cur.dec_scroll_x if same else 0
        if dec.failed:
            view.show(ea, f"/* decompilation failed at {ea:#x}: {dec.error} */\n")
            self._status(f"{name} — decompile failed; Tab for disasm")
        else:
            note = "  (truncated)" if dec.truncated else ""
            view.show(ea, dec.code or "", cursor=c, cursor_x=cx, scroll_y=sy, scroll_x=sx)
            self._status(f"{name}  @ {ea:#x}   [pseudocode {len(dec.code or '')} chars]{note}")

    def on_decomp_view_cursor_moved(self, msg: DecompView.CursorMoved) -> None:
        if self._nav:
            self._nav[-1].dec_cursor = msg.index
            self._nav[-1].dec_cursor_x = self.query_one(DecompView).cursor_x
        if self._cur is not None:
            loc = f" @ {msg.ea:#x}" if msg.ea is not None else ""
            self._status(f"{self._cur.name}{loc}   [pseudocode line {msg.index}]")

    def on_disasm_view_cursor_moved(self, msg: DisasmView.CursorMoved) -> None:
        if self._nav:
            # Keep the top-of-history position current (line + column) so that
            # returning here later lands exactly where we left.
            self._nav[-1].cursor = msg.index
            self._nav[-1].cursor_x = self.query_one(DisasmView).cursor_x
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
