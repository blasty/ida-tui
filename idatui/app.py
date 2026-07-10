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

import os
import re
import subprocess
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
from textual.widgets import (
    DataTable, Footer, Header, Input, OptionList, Static, TextArea,
)
from textual.widgets.option_list import Option

from .highlight import highlight_c

from .client import IDAClient, IDAToolError
from .domain import DisasmModel, Func, Program, Struct

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

# Hex-Rays appends a `/*0xEA*/` address marker to each pseudocode line (we fetch
# with include_addresses so we have a per-line anchor). Matched here to extract
# the address and strip the marker from the display.
_ADDR_MARK_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/")
_ADDR_MARK_STRIP_RE = re.compile(r"\s*/\*\s*0x[0-9A-Fa-f]+\s*\*/")


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


class CommentRequested(Message):
    """A code view asks to set a comment on the current line."""

    def __init__(self, view) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.view = view


class NavMixin:
    """Follow / xrefs actions shared by the code views (bindings live on each
    view since Textual only merges BINDINGS from DOMNode subclasses)."""

    NAV_BINDINGS = [
        Binding("enter", "follow", "Follow"),
        Binding("x", "xrefs", "Xrefs"),
        Binding("n", "rename", "Rename"),
        Binding("semicolon", "comment", "Comment"),
        Binding("y", "copy_line", "Copy line"),
    ]

    def action_follow(self) -> None:
        self.post_message(FollowRequested(self))

    def action_xrefs(self) -> None:
        self.post_message(XrefsRequested(self))

    def action_rename(self) -> None:
        self.post_message(RenameRequested(self, self.word_under_cursor()))

    def action_comment(self) -> None:
        self.post_message(CommentRequested(self))

    def action_copy_line(self) -> None:
        plain = self._line_plain(self.cursor)
        if not plain:
            return
        n = self.app._copy(plain)
        self.app._status(f"copied line ({n} chars) to clipboard")


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
        self._line_eas: list[int | None] = []  # per-line address (marker stripped)
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
        # Pull each line's `/*0xEA*/` marker into _line_eas, then strip it from
        # the displayed text (clutter) before highlighting. Stripping only edits
        # within lines, so line indices still align with the domain's raw code.
        line_eas: list[int | None] = []
        clean: list[str] = []
        for ln in text.split("\n"):
            eas = _ADDR_MARK_RE.findall(ln)
            line_eas.append(int(eas[-1], 16) if eas else None)
            clean.append(_ADDR_MARK_STRIP_RE.sub("", ln).rstrip())
        seglists = highlight_c("\n".join(clean))
        self._strips = [Strip(segs) for segs in seglists]
        self._texts = ["".join(seg.text for seg in segs) for segs in seglists]
        total = len(self._strips)
        # highlight_c may drop a lone trailing blank line; keep _line_eas aligned.
        self._line_eas = (line_eas[:total] + [None] * total)[:total]
        self.loaded_ea = ea
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

    def goto(self, cursor: int, cursor_x: int = 0, scroll_y: int = -1,
             scroll_x: int = 0) -> None:
        """Move the cursor/scroll on the already-loaded text (no re-highlight).
        Used to jump to a target inside the function already displayed, e.g. an
        xref/goto that resolves to this same function.

        All scrolling routes through ``_apply_scroll`` (which re-applies after the
        next refresh with ``layout=True``): unlike the reload path there's no new
        layout pass to force a repaint, so a plain ``scroll_to`` would leave a
        stale frame until the next interaction.
        """
        total = len(self._strips)
        if total == 0:
            return
        self.cursor = max(0, min(total - 1, cursor))
        self.cursor_x = cursor_x
        self._clamp_x()
        if scroll_y < 0:  # derive a viewport that shows the (line, column)
            height = self._visible_height()
            top = round(self.scroll_offset.y)
            if self.cursor < top:
                scroll_y = self.cursor
            elif self.cursor >= top + height:
                scroll_y = max(self.cursor - height + 1, 0)
            else:
                scroll_y = top
            width = max(self.size.width - self._gutter, 1)
            sx = round(self.scroll_offset.x)
            if self.cursor_x < sx:
                scroll_x = self.cursor_x
            elif self.cursor_x >= sx + width:
                scroll_x = self.cursor_x - width + 1
            else:
                scroll_x = sx
        self._apply_scroll(min(max(scroll_y, 0), max(total - 1, 0)), max(scroll_x, 0))
        self._after_cursor_move()

    def get_loading_widget(self):  # type: ignore[override]
        # Shown (grayed, centered) while a (re)decompile is in flight.
        return Static("― decompiling… ―", classes="decomp-loading")

    def _line_ea(self, idx: int) -> int | None:
        return self._line_eas[idx] if 0 <= idx < len(self._line_eas) else None

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

    def __init__(self, label: str, items: list[tuple[int, str]],
                 preselect: int = 0) -> None:
        super().__init__()
        self._label = label
        self._items = items
        self._preselect = preselect

    def compose(self) -> ComposeResult:
        with Vertical(id="xref-box"):
            yield Static(self._label, id="xref-title")
            yield OptionList(*[Option(text) for _, text in self._items], id="xref-list")

    def on_mount(self) -> None:
        ol = self.query_one(OptionList)
        # Start on the site we invoked xrefs from, so stepping a long list keeps
        # your place (and scroll it into view).
        if 0 <= self._preselect < len(self._items):
            ol.highlighted = self._preselect
        ol.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(self._items[event.option_index][0])

    def action_close(self) -> None:
        self.dismiss(None)


# --------------------------------------------------------------------------- #
# Symbol palette (fuzzy finder overlay)
# --------------------------------------------------------------------------- #
def _fuzzy(name: str, q: str):
    """Fuzzy subsequence match of ``q`` in ``name`` (case-insensitive). Returns
    ``(score, positions)`` or None. Higher score = better; positions are the
    matched character indices (for highlighting)."""
    if not q:
        return (0.0, ())
    nl = name.lower()
    pos: list[int] = []
    i = 0
    for ch in q:
        j = nl.find(ch, i)
        if j < 0:
            return None
        pos.append(j)
        i = j + 1
    span = pos[-1] - pos[0]
    score = -(span * 2.0) - pos[0] - len(name) * 0.01
    if q in nl:
        score += 50.0
    if nl.startswith(q):
        score += 100.0
    return (score, tuple(pos))


class SymbolPalette(ModalScreen):
    """A command-palette overlay: type to fuzzy-find a symbol, Enter opens it."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("down,ctrl+n", "cursor_down", show=False),
        Binding("up,ctrl+p", "cursor_up", show=False),
    ]
    LIMIT = 200

    def __init__(self, funcs: list[Func]) -> None:
        super().__init__()
        self._funcs = funcs
        self._results: list[Func] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="pal-box"):
            yield Static(" symbols", id="pal-title")
            yield Input(placeholder="fuzzy find symbol…  ↑↓ select · Enter open · Esc close",
                        id="pal-input")
            yield OptionList(id="pal-list")

    def on_mount(self) -> None:
        self._apply("")
        self.query_one("#pal-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()  # don't leak to the app's #search/#filter handlers
        self._apply(event.value.strip())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_choose()

    def _apply(self, query: str) -> None:
        if query:
            scored = []
            for f in self._funcs:
                m = _fuzzy(f.name, query)
                if m is not None:
                    scored.append((m[0], m[1], f))
            scored.sort(key=lambda t: (-t[0], t[2].name))
            rows = [(f, pos) for _, pos, f in scored[:self.LIMIT]]
        else:
            rows = [(f, ()) for f in self._funcs[:self.LIMIT]]
        self._results = [f for f, _ in rows]
        ol = self.query_one(OptionList)
        ol.clear_options()
        opts = []
        for f, pos in rows:
            label = Text()
            label.append(f"{f.addr:08X}  ", _S_ADDR)
            nm = Text(f.name)
            for p in pos:
                if p < len(f.name):
                    nm.stylize(_S_NAME_MATCH, p, p + 1)
            label.append_text(nm)
            opts.append(Option(label))
        ol.add_options(opts)
        if self._results:
            ol.highlighted = 0
        self.query_one("#pal-title", Static).update(
            f" symbols: {len(self._results)}" + ("+" if len(self._results) == self.LIMIT else ""))

    def action_cursor_down(self) -> None:
        ol = self.query_one(OptionList)
        if ol.option_count:
            ol.highlighted = min((ol.highlighted or 0) + 1, ol.option_count - 1)

    def action_cursor_up(self) -> None:
        ol = self.query_one(OptionList)
        if ol.option_count:
            ol.highlighted = max((ol.highlighted or 0) - 1, 0)

    def action_choose(self) -> None:
        ol = self.query_one(OptionList)
        i = ol.highlighted
        if i is not None and 0 <= i < len(self._results):
            self.dismiss(self._results[i].addr)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if 0 <= event.option_index < len(self._results):
            self.dismiss(self._results[event.option_index].addr)

    def action_close(self) -> None:
        self.dismiss(None)


# --------------------------------------------------------------------------- #
# Confirmation dialog
# --------------------------------------------------------------------------- #
class ConfirmScreen(ModalScreen):
    """A tiny yes/no confirmation; dismisses True (confirm) or False (cancel)."""

    BINDINGS = [
        Binding("enter,y", "confirm", "Confirm"),
        Binding("escape,n", "cancel", "Cancel"),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Static(self._message, id="confirm-msg")
            yield Static("[Enter/y] confirm      [Esc/n] cancel", id="confirm-help")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


# --------------------------------------------------------------------------- #
# Struct editor (C-style local type editor)
# --------------------------------------------------------------------------- #
class StructEditor(ModalScreen):
    """CRUD editor for local structs/unions, written as plain C.

    Left: the list of structs. Right: an editable C definition. Enter loads the
    selected struct; Ctrl+S declares (creates or updates) it; Ctrl+N starts a
    new one; Delete removes the highlighted struct; Esc returns to the list then
    closes.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("ctrl+n", "new", "New", priority=True),
        Binding("ctrl+y", "copy", "Copy", priority=True),
        Binding("delete,d", "delete", "Delete", show=False),
        Binding("escape", "close", "Close"),
    ]

    NEW_TEMPLATE = "struct NewStruct\n{\n    int field;\n};\n"

    def __init__(self, program: Program) -> None:
        super().__init__()
        self._program = program
        self._structs: list[Struct] = []
        self._loaded: str | None = None  # name currently in the editor

    def compose(self) -> ComposeResult:
        with Vertical(id="se-box"):
            with Horizontal(id="se-panes"):
                with Vertical(id="se-left"):
                    yield Static(" structs", id="se-title")
                    yield OptionList(id="se-list")
                with Vertical(id="se-right"):
                    yield Static(" C definition", id="se-hint")
                    yield TextArea("", id="se-edit")
            yield Static(
                "Enter edit · Ctrl+S save · Ctrl+Y copy · Ctrl+N new · d/Del delete · Esc close",
                id="se-status")

    def on_mount(self) -> None:
        self._refresh()
        self.query_one("#se-list", OptionList).focus()

    # -- data --------------------------------------------------------------- #
    @work(thread=True, exclusive=True, group="se-refresh")
    def _refresh(self, select: str | None = None) -> None:
        try:
            structs = self._program.list_structs()
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._set_status, f"list failed: {e}")
            return
        self.app.call_from_thread(self._populate, structs, select)

    def _populate(self, structs: list[Struct], select: str | None) -> None:
        self._structs = structs
        ol = self.query_one("#se-list", OptionList)
        ol.clear_options()
        for s in structs:
            kw = "union" if s.is_union else "struct"
            label = Text()
            label.append(s.name, _S_LABEL)
            label.append(f"   {s.size:#x}  {s.members}f  {kw}", _S_DIM)
            ol.add_option(Option(label))
        if structs:
            idx = 0
            if select is not None:
                idx = next((i for i, s in enumerate(structs) if s.name == select), 0)
            ol.highlighted = idx

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        i = event.option_index
        if 0 <= i < len(self._structs):
            self._load(self._structs[i].name)

    @work(thread=True, exclusive=True, group="se-load")
    def _load(self, name: str) -> None:
        try:
            src = self._program.struct_source(name)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._set_status, f"load failed: {e}")
            return
        self.app.call_from_thread(self._set_editor, name, src)

    def _set_editor(self, name: str, src: str) -> None:
        self._loaded = name
        ta = self.query_one("#se-edit", TextArea)
        ta.text = src
        ta.focus()
        self._set_status(f"editing {name}  —  Ctrl+S to apply changes")

    # -- actions ------------------------------------------------------------ #
    def action_save(self) -> None:
        text = self.query_one("#se-edit", TextArea).text.strip()
        if not text:
            self._set_status("nothing to declare")
            return
        self._set_status("declaring…")
        self._save(text)

    @work(thread=True, exclusive=True, group="se-save")
    def _save(self, text: str) -> None:
        try:
            err = self._program.declare_type(text)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._set_status, f"declare failed: {e}")
            return
        m = re.search(r"\b(?:struct|union)\s+([A-Za-z_]\w*)", text)
        name = m.group(1) if m else None
        self.app.call_from_thread(self._after_save, name, err)

    def _after_save(self, name: str | None, err: str | None) -> None:
        if err:
            self._set_status(f"declare failed: {(err.strip() or 'parse error')[:80]}")
            return
        self._loaded = name
        if getattr(self.app, "_dirty", None) is not None:
            self.app._dirty = True  # struct change is unsaved until Ctrl+S in the app
        self._refresh(select=name)
        self._set_status(f"saved {name}" if name else "saved")

    def action_new(self) -> None:
        ta = self.query_one("#se-edit", TextArea)
        ta.text = self.NEW_TEMPLATE
        self._loaded = None
        ta.focus()
        self._set_status("new struct — edit and Ctrl+S")

    def action_delete(self) -> None:
        # Delete is only meaningful from the list; a bare 'd' in the editor types.
        if self.focused is self.query_one("#se-edit", TextArea):
            return
        ol = self.query_one("#se-list", OptionList)
        i = ol.highlighted
        if i is None or not (0 <= i < len(self._structs)):
            return
        s = self._structs[i]
        kind = "union" if s.is_union else "struct"
        self.app.push_screen(
            ConfirmScreen(f"Delete {kind} '{s.name}' ?"),
            lambda ok, name=s.name: self._delete(name) if ok else None)

    @work(thread=True, exclusive=True, group="se-del")
    def _delete(self, name: str) -> None:
        try:
            err = self._program.delete_type(name)
        except Exception as e:  # noqa: BLE001
            err = str(e)
        self.app.call_from_thread(self._after_delete, name, err)

    def _after_delete(self, name: str, err: str | None) -> None:
        if err:
            self._set_status(err)
            return
        if getattr(self.app, "_dirty", None) is not None:
            self.app._dirty = True
        self._refresh()
        self._set_status(f"deleted {name}")

    def action_copy(self) -> None:
        """Ctrl+Y: copy the selection, or the whole C definition, to the clipboard."""
        ta = self.query_one("#se-edit", TextArea)
        text = ta.selected_text or ta.text
        if not text:
            self._set_status("nothing to copy")
            return
        n = self.app._copy(text)
        what = "selection" if ta.selected_text else "definition"
        self._set_status(f"copied {what} ({n} chars) to clipboard")

    def action_close(self) -> None:
        # A stray Esc while editing returns to the list instead of discarding.
        if self.focused is self.query_one("#se-edit", TextArea):
            self.query_one("#se-list", OptionList).focus()
            return
        self.dismiss(None)

    def _set_status(self, text: str) -> None:
        self.query_one("#se-status", Static).update(text)


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
    #comment {
        height: 1; border: none; padding: 0 1;
        background: $success-darken-2; color: $text;
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
    SymbolPalette { align: center middle; }
    #pal-box { width: 96; max-width: 92%; height: auto; max-height: 80%;
               border: thick $accent; background: $panel; }
    #pal-title { dock: top; height: 1; background: $accent; color: $text; padding: 0 1; }
    #pal-input { border: none; height: 1; margin: 0 1; background: $panel; color: $text; }
    #pal-list { height: auto; max-height: 24; }
    StructEditor { align: center middle; }
    #se-box { width: 90%; height: 84%; border: thick $accent; background: $panel; }
    #se-panes { height: 1fr; }
    #se-left { width: 38; border-right: solid $accent; }
    #se-right { width: 1fr; }
    #se-title, #se-hint { height: 1; background: $accent; color: $text; padding: 0 1; }
    #se-list { height: 1fr; }
    #se-edit { height: 1fr; border: none; }
    #se-status { height: 1; background: $panel-darken-2; color: $text-muted; padding: 0 1; }
    ConfirmScreen { align: center middle; }
    #confirm-box { width: 60; height: auto; border: thick $warning;
                   background: $panel; padding: 1 2; }
    #confirm-msg { height: auto; }
    #confirm-help { height: 1; color: $text-muted; margin-top: 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+n", "symbols", "Symbols"),
        Binding("ctrl+t", "structs", "Structs"),
        Binding("g", "goto", "Goto"),
        Binding("slash", "filter", "Filter", show=False),
        Binding("ctrl+b", "toggle_functions", "Names", show=False),
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
        self._pref = "decomp"    # preferred code view (changed by Tab)
        self._active = "decomp"  # currently shown view (falls back on decomp fail)
        self._cur: NavEntry | None = None
        self._search_ctx: tuple[object | None, int] = (None, 1)
        self._rename_ctx: tuple[object | None, str] = (None, "")
        self._comment_ctx: tuple[object | None, int, str] = (None, 0, "")
        self._xref_focus_name: str | None = None
        self._dirty = False

    # -- layout ------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="panes"):
            fp = FunctionsPanel(id="left")
            fp.display = False  # overlay-first: reveal the docked pane with Ctrl+B
            yield fp
            dis = DisasmView()
            dis.display = False
            yield dis
            yield DecompView()  # pseudocode is the default view
        si = Input(id="search")
        si.display = False
        si.can_focus = False
        yield si
        ri = Input(id="rename")
        ri.display = False
        ri.can_focus = False
        yield ri
        ci = Input(id="comment")
        ci.display = False
        ci.can_focus = False
        yield ci
        yield Static("connecting…", id="status")
        yield Footer()

    def on_mount(self) -> None:
        # Keep the hidden command input out of the focus chain until summoned.
        inp = self.query_one("#func-filter", Input)
        inp.can_focus = False
        # The names pane is an overlay now (Ctrl+N); focus the default code view
        # (pseudocode) so app bindings work before anything is opened.
        self.query_one(DecompView).focus()
        self._connect()

    # -- status helper ----------------------------------------------------- #
    def _status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    # -- clipboard --------------------------------------------------------- #
    def _copy(self, text: str) -> int:
        """Copy ``text`` to the clipboard and return its length. Uses the OSC 52
        escape (Textual) and, inside tmux, also ``tmux load-buffer -w`` — the
        combination is what actually reaches the system clipboard over
        tmux/ssh when the app has the mouse captured (so drag-select can't).
        """
        try:
            self.copy_to_clipboard(text)  # OSC 52
        except Exception:  # noqa: BLE001
            pass
        if os.environ.get("TMUX"):
            try:
                subprocess.run(
                    ["tmux", "load-buffer", "-w", "-"],
                    input=text.encode("utf-8", "replace"),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
        return len(text)

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
            self.app.call_from_thread(
                self._status, f"{module} — {len(idx)} functions   (Ctrl+N: find symbol)")

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
        """Show/hide the classic docked functions pane (the overlay is Ctrl+N)."""
        left = self.query_one("#left", FunctionsPanel)
        left.display = not left.display
        if not left.display:
            self.query_one(DecompView if self._active == "decomp"
                           else DisasmView).focus()
        else:
            self.query_one("#func-table", DataTable).focus()

    def action_structs(self) -> None:
        """Ctrl+T: open the C-style struct editor overlay."""
        if self.program is None:
            self._status("not connected yet")
            return
        self.push_screen(StructEditor(self.program))

    def action_symbols(self) -> None:
        """Ctrl+N: fuzzy-find a symbol in a command-palette overlay."""
        idx = self._func_index
        funcs = idx.all_loaded() if idx is not None else []
        if not funcs:
            self._status("functions still loading…")
            return
        self.push_screen(SymbolPalette(funcs), self._on_symbol_chosen)

    def _on_symbol_chosen(self, addr: int | None) -> None:
        if addr is None:
            return
        f = self._func_index.by_addr(addr) if self._func_index else None
        self._open_function(addr, f.name if f else hex(addr))

    def action_toggle_view(self) -> None:
        """Tab: switch the code pane between disassembly and pseudocode."""
        if self._cur is None:
            return
        self._active = "decomp" if self._active == "disasm" else "disasm"
        self._pref = self._active  # an explicit toggle sets the preference
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
        elif self.query_one("#left", FunctionsPanel).display:
            table.focus()
        else:
            self.query_one(DecompView if self._active == "decomp"
                           else DisasmView).focus()

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
            # The instruction's ordinary fall-through edge (to the next line) is
            # an indistinguishable 'code' xref; pass it so follow can skip it and
            # land on a call/jump's real target instead of the next instruction.
            nxt = view.model.cached_line(view.cursor + 1) if view.model else None
            if ea is not None:
                self._follow_disasm(ea, word, nxt.ea if nxt else None)
        elif isinstance(view, DecompView) and view._texts:
            self._follow_decomp(view._texts[view.cursor], word,
                                view._line_ea(view.cursor))

    def on_xrefs_requested(self, msg: XrefsRequested) -> None:
        view = msg.view
        word = view.word_under_cursor()
        if isinstance(view, DisasmView):
            ea = view._cursor_ea()
            if ea is not None:
                # span = this instruction .. the next, to pre-select the dialog
                # entry for the site we invoked xrefs from.
                nxt = view.model.cached_line(view.cursor + 1) if view.model else None
                self._xrefs_disasm(ea, word, ea, nxt.ea if nxt else None)
        elif isinstance(view, DecompView) and view._texts:
            here = view._line_ea(view.cursor)
            end = None
            if here is not None:
                for j in range(view.cursor + 1, len(view._line_eas)):
                    e = view._line_eas[j]
                    if e is not None and e > here:
                        end = e
                        break
            self._xrefs_decomp(view._texts[view.cursor], word, here, end)

    @staticmethod
    def _looks_like_symbol(word: str | None) -> bool:
        # A symbol has a letter but is not a bare hex number (the address column
        # and hex operands are hex-only, e.g. "0026D4C0" -> follow via xref).
        if not word or not any(c.isalpha() for c in word):
            return False
        return not all(c in "0123456789abcdefABCDEF" for c in word)

    @work(thread=True, group="nav")
    def _follow_disasm(self, ea: int, word: str | None,
                       next_ea: int | None = None) -> None:
        assert self.program is not None
        # Prefer the symbol under the cursor (handles multiple refs on a line).
        if self._looks_like_symbol(word):
            try:
                self._do_navigate(self.program.resolve(word), push=True)
                return
            except Exception:  # noqa: BLE001 -- not a resolvable name; fall back
                pass
        xr = self.program.xrefs_from(ea)
        # Drop the ordinary fall-through edge (its target is the next
        # instruction): on a call/branch it would otherwise be picked before the
        # real target and 'follow' would just step to the next line.
        cand = [x for x in xr if x.to and x.to != next_ea]
        tgt = next((x for x in cand if x.type == "code"), None)
        tgt = tgt or next((x for x in cand), None)
        if tgt is None or tgt.to is None:
            self.app.call_from_thread(self._status, "nothing to follow here")
            return
        self._do_navigate(tgt.to, push=True)

    @work(thread=True, group="nav")
    def _follow_decomp(self, line: str, word: str | None,
                       line_ea: int | None = None) -> None:
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
        if addr is None and line_ea is not None:
            # Address-based fallback: follow a code xref from this statement's ea
            # (the stripped /*0xEA*/ anchor). Immune to a stale name (e.g. right
            # after a rename, before the pseudocode text catches up).
            xr = self.program.xrefs_from(line_ea)
            addr = next((x.to for x in xr if x.type == "code" and x.to), None)
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
    def _xrefs_disasm(self, ea: int, word: str | None,
                      here_ea: int | None = None, here_end: int | None = None) -> None:
        assert self.program is not None
        subj: int | None = None
        if self._looks_like_symbol(word):
            try:
                subj = self.program.resolve(word)
            except Exception:  # noqa: BLE001
                subj = None
        if subj is None:
            # xrefs to the current address itself. (Do NOT chase a from-xref: on
            # a plain instruction the only code from-xref is the ordinary-flow
            # fall-through to the next instruction, which would point xrefs at
            # the wrong place. At a function entry, xrefs-to == the callers.)
            subj = ea
        self._xrefs_present(subj, word, here_ea, here_end)

    @work(thread=True, group="xrefs")
    def _xrefs_decomp(self, line: str, word: str | None,
                      here_ea: int | None = None, here_end: int | None = None) -> None:
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
            self._xrefs_present(subj, word, here_ea, here_end)

    @staticmethod
    def _xref_preselect(xr, here_ea, here_end) -> int:  # type: ignore[no-untyped-def]
        """Index of the xref whose `frm` is the site we invoked xrefs from: an
        exact match, else the one falling in the current line/instruction span."""
        if here_ea is None:
            return 0
        span = None
        for i, x in enumerate(xr):
            if x.frm == here_ea:
                return i
            if span is None and here_end is not None and here_ea <= x.frm < here_end:
                span = i
        return span if span is not None else 0

    def _xrefs_present(self, subj: int, subj_name: str | None = None,
                       here_ea: int | None = None,
                       here_end: int | None = None) -> None:  # worker
        assert self.program is not None
        xr = self.program.xrefs_to(subj)
        fn = self.program.function_of(subj)
        if fn is not None:
            label = f"xrefs to {fn.name}"
            if subj != fn.addr:
                label += f"+{subj - fn.addr:#x}"
        else:
            label = f"xrefs to {subj:#x}"
        # Token to land the cursor on at each site: the symbol xrefs was invoked
        # on, else the referenced function's name.
        focus = subj_name if self._looks_like_symbol(subj_name) else None
        if focus is None and fn is not None and fn.addr == subj:
            focus = fn.name
        items = []
        for x in xr:
            if x.fn_name:
                # location = function + offset, so multiple sites in the same
                # function are distinguishable (sub_2300+0x1c, not just sub_2300).
                off = (x.frm - x.fn_addr) if x.fn_addr is not None else 0
                loc = f"{x.fn_name}+{off:#x}" if off else x.fn_name
            else:
                # not inside a function: name the section it lives in (a GOT/reloc
                # data slot or a loose thunk) instead of a bare '?'.
                loc = self.program.section_of(x.frm) or "<no seg>"
            items.append((x.frm, f"{x.frm:08X}  {loc:<26}  [{x.type}]"))
        preselect = self._xref_preselect(xr, here_ea, here_end)
        self.app.call_from_thread(self._present_xrefs, label, items, focus, preselect)

    def _present_xrefs(self, label: str, items: list[tuple[int, str]],
                       focus_name: str | None = None, preselect: int = 0) -> None:
        if not items:
            self._status(f"{label}: none")
            return
        self._xref_focus_name = focus_name
        self._status(f"{label}: {len(items)}")
        self.push_screen(XrefsScreen(label, items, preselect), self._on_xref_chosen)

    def _on_xref_chosen(self, addr: int | None) -> None:
        if addr is not None:
            self._goto_ea(addr, push=True, focus_name=self._xref_focus_name)

    # -- rename ------------------------------------------------------------ #
    @staticmethod
    def _is_pseudocode_label(view, name: str) -> bool:
        """True if ``name`` is a Hex-Rays goto label in ``view``. The rename tool
        has no label category (only func/global/local/stack), so renaming one
        fails with a misleading 'local variable not found'; detect it up front
        and explain instead. A label is the default ``LABEL_n`` or any token used
        as a ``goto`` target."""
        if not isinstance(view, DecompView):
            return False
        if re.fullmatch(r"LABEL_\d+", name):
            return True
        body = "\n".join(getattr(view, "_texts", []) or [])
        return re.search(rf"\bgoto\s+{re.escape(name)}\b", body) is not None

    def on_rename_requested(self, msg: RenameRequested) -> None:
        if not msg.name:
            self._status("nothing to rename under the cursor")
            return
        if self._is_pseudocode_label(msg.view, msg.name):
            self._status(
                f"can't rename pseudocode label '{msg.name}' "
                "(Hex-Rays goto labels aren't renamable via the API)")
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

    # -- comments ---------------------------------------------------------- #
    def _line_ea_for(self, view) -> int | None:  # type: ignore[no-untyped-def]
        """Address of the line under the cursor in either code view."""
        if isinstance(view, DisasmView):
            return view._cursor_ea()
        if isinstance(view, DecompView):
            return view._line_ea(view.cursor)
        return None

    @staticmethod
    def _existing_comment(view) -> str:
        """Current line comment (for prefill), parsed from the rendered text. In
        pseudocode a comment is `// text` before the trailing /*0xEA*/ markers;
        C has no `//` operator, so the last `//` is unambiguously the comment."""
        if isinstance(view, DecompView) and 0 <= view.cursor < len(view._texts):
            s = re.sub(r"(?:/\*\s*0x[0-9A-Fa-f]+\s*\*/\s*)+$", "", view._texts[view.cursor])
            i = s.rfind("//")
            return s[i + 2:].strip() if i >= 0 else ""
        return ""

    def on_comment_requested(self, msg: CommentRequested) -> None:
        ea = self._line_ea_for(msg.view)
        if ea is None:
            self._status("no address on this line to comment")
            return
        existing = self._existing_comment(msg.view)
        self._comment_ctx = (msg.view, ea, existing)
        self.query_one("#status", Static).display = False
        inp = self.query_one("#comment", Input)
        inp.placeholder = f"comment @ {ea:#x} —  Enter=apply (empty=clear)  Esc=cancel"
        inp.can_focus = True
        inp.display = True
        inp.value = existing
        inp.focus()

    def _end_comment(self) -> None:
        inp = self.query_one("#comment", Input)
        inp.display = False
        inp.can_focus = False
        self.query_one("#status", Static).display = True
        view, _, _ = self._comment_ctx
        if view is not None:
            view.focus()

    @work(thread=True, exclusive=True, group="comment")
    def _do_comment(self, ea: int, text: str) -> None:
        assert self.program is not None
        try:
            res = self.program.set_comment(ea, text)
        except IDAToolError as e:
            self.app.call_from_thread(self._status, f"comment failed: {e.message}")
            return
        data = res.get("result") if isinstance(res, dict) else None
        if isinstance(data, list) and data and isinstance(data[0], dict) and data[0].get("error"):
            self.app.call_from_thread(self._status, f"comment failed: {data[0]['error']}")
            return
        self.app.call_from_thread(self._after_comment, ea, text)

    def _after_comment(self, ea: int, text: str) -> None:
        cur = self._cur
        # A comment shows in both views but only after Hex-Rays recompiles, so
        # reuse the name-generation invalidation (bumps gen -> decompile is
        # force_recompiled lazily; disasm block caches are cleared).
        self.program.bump_names()
        if cur is not None:
            self._save_current_pos()
            self.query_one(DecompView).loaded_ea = None  # force pseudocode reload
            self._open_entry(cur, push=False)
        self._dirty = True
        verb = "cleared comment" if not text else "commented"
        self._status(f"{verb} @ {ea:#x}   (Ctrl+S to save)")

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
    def _goto_ea(self, ea: int, push: bool = True,
                 focus_name: str | None = None) -> None:
        self._do_navigate(ea, push, focus_name)

    def _do_navigate(self, ea: int, push: bool,
                     focus_name: str | None = None) -> None:  # worker context
        assert self.program is not None
        fn = self.program.function_of(ea)
        if fn is None:
            self.app.call_from_thread(self._status, f"no function contains {ea:#x}")
            return
        model = self.program.disasm(fn.addr, fn.name)
        idx = 0 if ea == fn.addr else model.index_of_ea(ea)
        # The disasm cursor alone doesn't position the pseudocode pane. For a
        # mid-function target with the decompiler active, resolve the address to
        # its pseudocode line (via the per-line /*0xEA*/ markers) so the jump
        # lands on the reference there too (e.g. selecting an xref). A plain
        # function-entry jump is line 0 in both views -> skip the decompile.
        # With a focus_name (the symbol the xref was on), also land the column
        # on that token where it appears in the line.
        dec_idx, dec_col = -1, 0
        if self._active == "decomp" and ea != fn.addr:
            dec_idx = self._decomp_line_for(fn.addr, ea)
            if dec_idx >= 0 and focus_name:
                dec_col = self._decomp_col_for(fn.addr, dec_idx, focus_name)
        self.app.call_from_thread(
            self._open_at, fn.addr, fn.name, idx, push, dec_idx, dec_col)

    def _decomp_col_for(self, fn_addr: int, line_idx: int, name: str) -> int:
        """Column of ``name`` (whole-word) on pseudocode line ``line_idx``, so an
        xref jump lands on the referenced token, not the line start. 0 if absent.
        Computed on the marker-stripped line so it matches the displayed text."""
        assert self.program is not None
        try:
            dec = self.program.decompile(fn_addr)
        except Exception:  # noqa: BLE001
            return 0
        lines = (dec.code or "").splitlines()
        if not (0 <= line_idx < len(lines)):
            return 0
        clean = _ADDR_MARK_STRIP_RE.sub("", lines[line_idx])
        m = re.search(rf"\b{re.escape(name)}\b", clean)
        return m.start() if m else 0

    def _decomp_line_for(self, fn_addr: int, ea: int) -> int:
        """Pseudocode line index best matching address ``ea``: the line whose
        /*0xEA*/ marker is the largest address <= ``ea``. -1 if unavailable
        (decompile failed / no markers). Runs in a worker (decompile is sync)."""
        assert self.program is not None
        try:
            dec = self.program.decompile(fn_addr)
        except Exception:  # noqa: BLE001
            return -1
        if dec.failed or not dec.code:
            return -1
        best_idx, best_ea = -1, -1
        for i, line in enumerate(dec.code.splitlines()):
            for m in re.findall(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/", line):
                e = int(m, 16)
                if best_ea < e <= ea:
                    best_ea, best_idx = e, i
        return best_idx

    def _open_at(self, ea: int, name: str, cursor: int, push: bool,
                 dec_cursor: int = -1, dec_cursor_x: int = 0) -> None:
        if push:
            self._save_current_pos()
        entry = NavEntry(ea=ea, name=name, cursor=cursor)
        if dec_cursor >= 0:
            entry.dec_cursor = dec_cursor
            entry.dec_cursor_x = dec_cursor_x
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
        if self.query_one("#comment", Input).display:
            event.stop()
            event.prevent_default()
            self._end_comment()
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
        if inp.id == "comment":
            view, ea, existing = self._comment_ctx
            self._end_comment()
            if view is not None and value != existing:  # empty value clears it
                self._do_comment(ea, value)
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
        # Each open honours the preferred view; a decomp failure last time fell
        # back to disasm without changing the preference, so retry decomp here.
        self._active = self._pref
        model = self.program.disasm(entry.ea, entry.name)
        sy = entry.scroll_y if entry.scroll_y >= 0 else None
        self.query_one(DisasmView).load(
            model, entry.name, cursor=entry.cursor, cursor_x=entry.cursor_x, scroll_y=sy)
        dec = self.query_one(DecompView)
        # If the decompiler already shows this function, _show_active won't reload
        # it (and thus won't reposition), so move its cursor to the target line
        # here — e.g. an xref/goto whose target is inside the current function.
        reposition_dec = dec.loaded_ea == entry.ea
        self._show_active()
        if reposition_dec and self._active == "decomp":
            dsy = entry.dec_scroll_y if entry.dec_scroll_y >= 0 else -1
            dec.goto(entry.dec_cursor, entry.dec_cursor_x, dsy, entry.dec_scroll_x)

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
        if dec.failed:
            # No pseudocode for this function: fall back to the disassembly view
            # rather than showing an error panel. Keep the pseudocode preference
            # so the next (decompilable) function still opens as pseudocode.
            if self._cur is None or self._cur.ea != ea:
                return  # navigated away; stale result
            self._active = "disasm"
            self._show_active()
            self._status(
                f"{name} — no pseudocode (decompile failed); showing disassembly")
            return
        if self._active == "decomp":
            view.focus()  # loading cover had blurred it; restore focus
        # Restore the saved pseudocode position when returning to this function.
        cur = self._cur
        same = cur is not None and cur.ea == ea
        c = cur.dec_cursor if same else 0
        cx = cur.dec_cursor_x if same else 0
        sy = cur.dec_scroll_y if (same and cur.dec_scroll_y >= 0) else -1
        sx = cur.dec_scroll_x if same else 0
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
