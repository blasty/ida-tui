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

import asyncio
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
    DataTable, Footer, Input, OptionList, Static, TextArea,
)
from textual.widgets.option_list import Option

from .highlight import highlight_c

from .client import IDAClient, IDAToolError
from .domain import DisasmModel, Func, Head, ListingModel, Program, Struct

# Styles for the disassembly listing.
_S_ADDR = Style(color="grey58")
_S_LABEL = Style(color="yellow", bold=True)
_S_INSN = Style(color="white")
_S_MNEM = Style(color="cyan")
_S_OPBYTES = Style(color="grey50")  # raw opcode bytes column
_S_DATA = Style(color="#c8a15a")   # data items in the flat listing (db/dw/strings)
_S_UNK = Style(color="grey54", italic=True)  # undefined bytes in the flat listing
_S_MEMBER = Style(color="#9a8a6a")  # struct field rows (expanded, indented)
_S_SEP = Style(color="grey42")      # function boundary separators / banners
_S_FUNCHDR = Style(color="#d7a021", bold=True)  # 'name proc'/'endp' headers

_LST_INDENT = "    "   # one depth level: function names sit at level 0, code at 1
_OP_LIMIT = 8         # opcode bytes shown in the 'limited' column mode
_JUMP_CONTEXT = 4     # lines of context kept above a jump target (cursor stays on it)

# Tokens that look like identifiers but aren't renamable symbols (so 'n' on them
# in the listing names the address instead of trying to rename the token).
_ASM_KEYWORDS = frozenset({
    "db", "dw", "dd", "dq", "dt", "byte", "word", "dword", "qword", "tbyte",
    "offset", "short", "near", "far", "ptr", "dup", "cs", "ds", "es", "fs",
    "gs", "ss", "align", "public", "assume", "end",
})
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
    is_region: bool = False  # not inside a function (flat listing view)
    view: str = "listing"  # which code view to restore this entry in


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


class RetypeRequested(Message):
    """A code view asks to retype the function/variable under the cursor."""

    def __init__(self, view, name: str | None) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.view = view
        self.name = name


class EditItemRequested(Message):
    """The disasm view asks to change item structure (IDA c/d/u/p) at the line
    under the cursor. ``kind`` is 'code' | 'func' | 'undef'."""

    def __init__(self, view, kind: str) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.view = view
        self.kind = kind


class MakeDataRequested(Message):
    """The listing view asks to define typed data (IDA 'd') at the current head."""

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
        Binding("y", "retype", "Retype"),
        Binding("semicolon", "comment", "Comment"),
        Binding("ctrl+y", "copy_line", "Copy line"),
    ]

    def action_follow(self) -> None:
        self.post_message(FollowRequested(self))

    def action_xrefs(self) -> None:
        self.post_message(XrefsRequested(self))

    def action_rename(self) -> None:
        self.post_message(RenameRequested(self, self.word_under_cursor()))

    def action_comment(self) -> None:
        self.post_message(CommentRequested(self))

    def action_retype(self) -> None:
        self.post_message(RetypeRequested(self, self.word_under_cursor()))

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


def _word_occurrences(text: str, word: str) -> list[tuple[int, int]]:
    """[start, end) spans of every WHOLE-word occurrence of ``word`` in ``text``
    (for highlight-all-occurrences of the token under the cursor)."""
    if not word or not text:
        return []
    isw = lambda c: c.isalnum() or c == "_"  # noqa: E731
    out: list[tuple[int, int]] = []
    n = len(word)
    i = 0
    while True:
        j = text.find(word, i)
        if j < 0:
            break
        before_ok = j == 0 or not isw(text[j - 1])
        after_ok = j + n >= len(text) or not isw(text[j + n])
        if before_ok and after_ok:
            out.append((j, j + n))
        i = j + n
    return out


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

    _hl_word: str | None = None  # token to highlight across all visible lines

    def _line_plain(self, idx: int) -> str | None:
        raise NotImplementedError

    def _refresh_hl(self) -> None:
        """Recompute the highlight-all token from the word under the cursor; if it
        changed, repaint the whole viewport (occurrences elsewhere changed)."""
        w = self.word_under_cursor()
        if not (w and len(w) >= 2 and (w[0].isalpha() or w[0] == "_")):
            w = None
        if w != self._hl_word:
            self._hl_word = w
            self.refresh()

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
        self._refresh_hl()

    def action_col_left(self) -> None:
        self._move_x(-1)

    def action_col_right(self) -> None:
        self._move_x(1)

    def action_col_home(self) -> None:
        self.cursor_x = 0
        self._hscroll()
        _refresh_lines(self, self.cursor)
        self._refresh_hl()

    def action_col_end(self) -> None:
        plain = self._line_plain(self.cursor) or ""
        self.cursor_x = max(len(plain) - 1, 0)
        self._hscroll()
        _refresh_lines(self, self.cursor)
        self._refresh_hl()

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
        self._refresh_hl()

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
        self._refresh_hl()
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
        self._refresh_hl()

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
        Binding("o", "toggle_opcodes", "Opcodes", show=False),
        Binding("c", "define_code", "Code", show=False),
        Binding("p", "define_func", "Func", show=False),
        Binding("u", "undefine", "Undef", show=False),
        Binding("tab,shift+tab", "app.toggle_view", "Pseudocode", priority=True),
        Binding("f5", "app.toggle_view", "Decompile", priority=True),
        Binding("L", "app.continuous_here", "Listing"),
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
        self._show_ops = True
        self._op_w = 0  # char width of the hex-bytes field (excl. trailing gap)

    def _op_field(self, line) -> str:  # type: ignore[no-untyped-def]
        """The padded opcode-bytes column (empty when hidden). Kept identical
        between the rendered strip and the plain text so cursor/search offsets
        line up."""
        if not self._show_ops or self._op_w <= 0:
            return ""
        raw = line.raw or b""
        return " ".join(f"{b:02X}" for b in raw).ljust(self._op_w) + "  "

    def _line_plain(self, idx: int) -> str | None:
        if self.model is None:
            return None
        line = self.model.cached_line(idx)
        if line is None:
            return None
        s = f"{line.ea:08X}  " + self._op_field(line)
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
    def _fmt(self, line) -> str:  # type: ignore[no-untyped-def]
        s = f"{line.ea:08X}  " + self._op_field(line)
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
        self._update_op_w()  # provisional width from the primed window
        self._scan_op_width()  # settle it against the whole function
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
            op = self._op_field(line)
            if op:
                segs.append(Segment(op, _S_OPBYTES))
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

    def _update_op_w(self) -> bool:
        """Recompute the opcode column width from the model's widest instruction.
        Returns True if it changed."""
        w = 0
        if self.model is not None and self._show_ops:
            mx = self.model.max_raw_len()
            w = max(mx * 3 - 1, 0) if mx > 0 else 0
        if w != self._op_w:
            self._op_w = w
            return True
        return False

    @work(thread=True, exclusive=True, group="disasm-opwidth")
    def _scan_op_width(self) -> None:
        model = self.model
        if model is None:
            return
        model.scan_bytes()  # fetch all blocks -> stable widest instruction
        self.app.call_from_thread(self._settle_op_w)

    def _settle_op_w(self) -> None:
        if self._update_op_w():
            self._search_texts = None  # layout changed -> stale offsets
            self.refresh()

    def action_toggle_opcodes(self) -> None:
        self._show_ops = not self._show_ops
        self._update_op_w()
        self._search_texts = None  # column layout changed -> reindex on next search
        self._ranges = {}
        self._clamp_x()
        self.refresh()
        self._app_status("opcodes " + ("on" if self._show_ops else "off"))

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
        self._refresh_hl()
        self.post_message(DisasmView.CursorMoved(self.cursor, self._cursor_ea()))

    def _after_cursor_move(self) -> None:
        self.post_message(DisasmView.CursorMoved(self.cursor, self._cursor_ea()))

    def _cursor_ea(self) -> int | None:
        if self.model is None:
            return None
        line = self.model.cached_line(self.cursor)
        return line.ea if line else None

    # -- item structure edits (IDA c/p/u) --------------------------------- #
    def action_define_code(self) -> None:
        self.post_message(EditItemRequested(self, "code"))

    def action_define_func(self) -> None:
        self.post_message(EditItemRequested(self, "func"))

    def action_undefine(self) -> None:
        self.post_message(EditItemRequested(self, "undef"))

    def action_cursor_down(self) -> None:
        self._move(1)

    def action_cursor_up(self) -> None:
        self._move(-1)

    def action_goto_top(self) -> None:
        self._move(-self.total)

    def action_goto_bottom(self) -> None:
        self._move(self.total)


# --------------------------------------------------------------------------- #
# Virtualized flat listing view (code + data + undefined, per segment)
# --------------------------------------------------------------------------- #
class ListingView(SearchMixin, NavMixin, ColumnCursor, ScrollView, can_focus=True):
    """A line-virtualized *flat* listing over one segment: code, data and
    undefined heads interleaved (IDA's disassembly view), unlike ``DisasmView``
    which is bounded to one function. Backed by ``ListingModel`` (the ``heads``
    server tool). Used for non-function regions and raw segment browsing.
    """

    BINDINGS = [
        Binding("j,down", "cursor_down", "Down", show=False),
        Binding("k,up", "cursor_up", "Up", show=False),
        Binding("ctrl+d", "half_page(1)", "½↓", show=False),
        Binding("ctrl+u", "half_page(-1)", "½↑", show=False),
        Binding("pagedown", "page(1)", "PgDn", show=False),
        Binding("pageup", "page(-1)", "PgUp", show=False),
        Binding("home", "goto_top", "Top", show=False),
        Binding("G,end", "goto_bottom", "Bottom", show=False),
        Binding("o", "toggle_opcodes", "Opcodes"),
        Binding("c", "define_code", "Code", show=False),
        Binding("d", "make_data", "Data", show=False),
        Binding("a", "make_string", "Str", show=False),
        Binding("p", "define_func", "Func", show=False),
        Binding("u", "undefine", "Undef", show=False),
        *SearchMixin.SEARCH_BINDINGS,
        *NavMixin.NAV_BINDINGS,
        *ColumnCursor.COL_BINDINGS,
    ]

    cursor = reactive(0, repaint=False)
    cursor_x = reactive(0, repaint=False)

    class CursorMoved(Message):
        """Posted when the listing cursor moves; carries the head ea."""

        def __init__(self, index: int, ea: int | None) -> None:
            super().__init__()
            self.index = index
            self.ea = ea

    def __init__(self) -> None:
        super().__init__()
        self.model: ListingModel | None = None
        self.total = 0
        self._name = ""
        self._pending_scroll_y: int | None = None
        self._term = ""
        self._matches: list[int] = []
        self._ranges: dict[int, list[tuple[int, int]]] = {}
        self._op_mode = 1       # opcode column: 0=off, 1=limited, 2=full ('o' cycles)
        self._op_w = 0          # char width of the hex-bytes field (excl. gap)
        self._search_loading = False
        self._search_pending: list = []  # done-callbacks awaiting the load

    # -- text helpers ------------------------------------------------------ #
    def _head(self, idx: int) -> Head | None:
        return self.model.get(idx) if self.model is not None else None

    @staticmethod
    def _name_prefix(h: Head) -> str:
        return f"{h.name}  " if h.name else ""

    def _op_bytes_text(self, h: Head) -> str:
        """Hex bytes for ``h``, truncated with an ellipsis in 'limited' mode so a
        long x86-64 instruction doesn't blow out the column."""
        raw = h.raw or b""
        if self._op_mode == 1 and len(raw) > _OP_LIMIT:
            return " ".join(f"{b:02X}" for b in raw[:_OP_LIMIT]) + "\u2026"
        return " ".join(f"{b:02X}" for b in raw)

    def _op_field(self, h: Head) -> str:
        """The padded opcode-bytes column (empty when hidden). Shared format so
        cursor/search offsets line up."""
        if self._op_mode == 0 or self._op_w <= 0:
            return ""
        return self._op_bytes_text(h).ljust(self._op_w) + "  "

    def _line_plain(self, idx: int) -> str | None:
        h = self._head(idx)
        if h is None:
            return None
        # Function headers and code labels sit at depth 0 (with the address);
        # everything else is indented one level (opcode+text included).
        if h.kind in ("funchdr", "label"):
            return f"{h.ea:08X}  {h.text}"
        base = f"{h.ea:08X}  " + _LST_INDENT
        if h.kind == "sep":
            return base + h.text
        extra = _LST_INDENT if h.kind == "member" else ""
        return base + self._op_field(h) + extra + self._name_prefix(h) + h.text

    # -- public API -------------------------------------------------------- #
    def load(self, model: ListingModel, name: str, cursor: int = 0,
             cursor_x: int = 0, scroll_y: int | None = None) -> None:
        self.model = model
        self._name = name
        self.total = 0
        self.cursor = cursor
        self.cursor_x = cursor_x
        self._pending_scroll_y = scroll_y
        self._matches = []
        self._ranges = {}
        self._prime()

    @work(thread=True, exclusive=True, group="listing-prime")
    def _prime(self) -> None:
        model = self.model
        if model is None:
            return
        # Load just enough to render the viewport around the cursor, so the
        # listing appears immediately even on a huge segment; the rest streams
        # in via _grow. (load_all here would blank the pane for seconds.)
        height = max(self.size.height, 1)
        model.ensure(self.cursor + height + 2 * ListingModel.PAGE)
        self.app.call_from_thread(self._on_primed, len(model), model.complete)
        if not model.complete:
            self._grow()

    def _on_primed(self, total: int, complete: bool) -> None:
        if self.model is None:
            return
        self.total = total
        self.virtual_size = Size(0, total)
        self.cursor = max(0, min(self.cursor, max(total - 1, 0)))
        self._clamp_x()
        if self._pending_scroll_y is not None and self._pending_scroll_y >= 0:
            self._apply_scroll(min(self._pending_scroll_y, max(total - 1, 0)))
        else:
            self._scroll_cursor_into_view()
        self._pending_scroll_y = None
        self._update_op_w()
        self.refresh()
        self.post_message(ListingView.CursorMoved(self.cursor, self._cursor_ea()))

    def _update_op_w(self) -> bool:
        """Recompute the opcode-column width from the widest code head seen (capped
        in 'limited' mode). Returns True if it changed."""
        w = 0
        if self.model is not None and self._op_mode != 0:
            mx = self.model.max_raw_len()
            if mx > 0:
                if self._op_mode == 1:  # limited: cap bytes, +1 for the ellipsis
                    shown = min(mx, _OP_LIMIT)
                    w = shown * 3 - 1 + (1 if mx > _OP_LIMIT else 0)
                else:  # full
                    w = mx * 3 - 1
        if w != self._op_w:
            self._op_w = w
            return True
        return False

    def action_toggle_opcodes(self) -> None:
        # cycle: off -> limited -> full -> off
        self._op_mode = (self._op_mode + 1) % 3
        self._update_op_w()
        self._ranges = {}  # column layout changed -> stale match offsets
        self._clamp_x()
        self.refresh()
        self._app_status("opcodes: " + {0: "off", 1: f"limited ({_OP_LIMIT} bytes)",
                                        2: "full"}[self._op_mode])

    @work(thread=True, exclusive=True, group="listing-grow")
    def _grow(self) -> None:
        """Stream the rest of the segment's heads in the background, growing the
        virtual size as they land so the scrollbar/paging catch up."""
        model = self.model
        if model is None:
            return
        since = 0
        while not model.complete:
            if model.load_next_page() == 0:
                break
            if self.model is not model:  # a new load() replaced us
                return
            since += 1
            if since >= 4:  # throttle repaints on huge segments
                since = 0
                self.app.call_from_thread(self._grew, len(model))
        self.app.call_from_thread(self._grew, len(model))

    def _grew(self, total: int) -> None:
        if self.model is None or total <= self.total:
            return
        self.total = total
        self.virtual_size = Size(0, total)
        self._update_op_w()  # more code streamed in -> widen the op column
        self.refresh()

    # -- search hooks ----------------------------------------------------- #
    def _search_line_count(self) -> int:
        return self.total

    def _search_line_text(self, i: int) -> str | None:
        return self._line_plain(i)

    def _search_ensure(self, done) -> None:
        # Search needs the whole segment loaded to find every match. Kick off a
        # SINGLE background load (guarded so per-keystroke updates don't spawn
        # one worker each — an exclusive worker would cancel+restart on every
        # keypress and never finish) and queue the callbacks until it lands.
        model = self.model
        if model is None or model.complete:
            done()
            return
        self._search_pending.append(done)
        if not self._search_loading:
            self._search_loading = True
            self._search_load_all()

    @work(thread=True, group="listing-search-load")
    def _search_load_all(self) -> None:
        model = self.model
        if model is not None:
            model.load_all()
        self.app.call_from_thread(self._search_loaded)

    def _search_loaded(self) -> None:
        self._search_loading = False
        if self.model is not None:
            self._grew(len(self.model))
        pending, self._search_pending = self._search_pending, []
        for cb in pending:
            cb()

    # -- rendering --------------------------------------------------------- #
    def render_line(self, y: int) -> Strip:
        model = self.model
        width = self.size.width
        if model is None or self.total == 0:
            return Strip([Segment("".ljust(width), _S_DIM)])
        top = round(self.scroll_offset.y)
        idx = top + y
        if idx >= self.total:
            return Strip([Segment("".ljust(width), _S_INSN)])
        h = model.get(idx)
        if h is None:
            strip = Strip([Segment(f"  {idx:>8}  …", _S_DIM)])
        elif h.kind == "sep":
            strip = Strip([Segment(f"{h.ea:08X}  ", _S_ADDR),
                           Segment(_LST_INDENT + h.text, _S_SEP)])
        elif h.kind == "funchdr":
            # depth-0: address + 'name proc'/'endp' (no indent)
            strip = Strip([Segment(f"{h.ea:08X}  ", _S_ADDR),
                           Segment(h.text, _S_FUNCHDR)])
        elif h.kind == "label":
            # depth-0: address + 'loc_XXX:' on its own line
            strip = Strip([Segment(f"{h.ea:08X}  ", _S_ADDR),
                           Segment(h.text, _S_LABEL)])
        else:
            # depth-1: address, one indent, then opcode+text
            segs: list[Segment] = [Segment(f"{h.ea:08X}  ", _S_ADDR),
                                   Segment(_LST_INDENT, _S_INSN)]
            op = self._op_field(h)
            if op:
                segs.append(Segment(op, _S_OPBYTES))
            if h.kind == "member":
                segs.append(Segment(_LST_INDENT, _S_MEMBER))
            if h.name:
                segs.append(Segment(f"{h.name}  ", _S_LABEL))
            if h.kind == "code":
                mnem, _, rest = h.text.partition(" ")
                segs.append(Segment(mnem, _S_MNEM))
                if rest:
                    segs.append(Segment(" " + rest, _S_INSN))
            elif h.kind == "data":
                segs.append(Segment(h.text, _S_DATA))
            elif h.kind == "member":
                segs.append(Segment(h.text, _S_MEMBER))
            else:
                segs.append(Segment(h.text, _S_UNK))
            strip = Strip(segs)
        plain = self._line_plain(idx) if (self._hl_word or idx == self.cursor) else None
        if idx in self._ranges:
            strip = _overlay_ranges(strip, self._ranges[idx], self._match_style(idx))
        if self._hl_word and plain:
            occ = _word_occurrences(plain, self._hl_word)
            if occ:
                strip = _overlay_ranges(strip, occ, _S_WORD)
        if idx == self.cursor:
            strip = _cursor_decorate(strip, plain or "", self.cursor_x)
        return strip.adjust_cell_length(width, _S_INSN)

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
            self.refresh()
        else:
            _refresh_lines(self, old, self.cursor)
        self.post_message(ListingView.CursorMoved(self.cursor, self._cursor_ea()))

    def _after_cursor_move(self) -> None:
        self.post_message(ListingView.CursorMoved(self.cursor, self._cursor_ea()))

    def _cursor_ea(self) -> int | None:
        h = self._head(self.cursor)
        return h.ea if h else None

    def _next_ea(self) -> int | None:
        h = self._head(self.cursor + 1)
        return h.ea if h else None

    # -- item structure edits (IDA c/p/u) --------------------------------- #
    def action_define_code(self) -> None:
        self.post_message(EditItemRequested(self, "code"))

    def action_define_func(self) -> None:
        self.post_message(EditItemRequested(self, "func"))

    def action_undefine(self) -> None:
        self.post_message(EditItemRequested(self, "undef"))

    def action_make_data(self) -> None:
        self.post_message(MakeDataRequested(self))

    def action_make_string(self) -> None:
        self.post_message(EditItemRequested(self, "string"))

    def cur_head(self) -> Head | None:
        return self._head(self.cursor)

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
        Binding("f5", "app.toggle_view", "Decompile", priority=True),
        Binding("L", "app.continuous_here", "Listing"),
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
        if self._hl_word:
            occ = _word_occurrences(self._texts[idx], self._hl_word)
            if occ:
                base = _overlay_ranges(base, occ, _S_WORD)
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
        self._refresh_hl()
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
# Hex view (raw bytes of the loaded image, VA-addressed, virtualized)
# --------------------------------------------------------------------------- #
_S_HEX = Style(color="grey74")
_S_ASCII = Style(color="#6a9955")
_S_FOFF = Style(color="#c586c0")  # file-offset column (distinct from the VA)


class HexView(ScrollView, can_focus=True):
    """A line-virtualized hex dump of the whole loaded image (16 bytes/row),
    addressed by virtual address. The cursor is a byte offset; it can be synced
    to/from the code views to see the naked bytes under the disasm/pseudocode
    cursor."""

    BINDINGS = [
        Binding("j,down", "move(16)", show=False),
        Binding("k,up", "move(-16)", show=False),
        Binding("l,right", "move(1)", show=False),
        Binding("h,left", "move(-1)", show=False),
        Binding("ctrl+d", "half_page(1)", show=False),
        Binding("ctrl+u", "half_page(-1)", show=False),
        Binding("pagedown", "page(1)", show=False),
        Binding("pageup", "page(-1)", show=False),
        Binding("home", "goto_top", show=False),
        Binding("G,end", "goto_bottom", show=False),
        Binding("enter", "to_code", "To code"),
        Binding("escape", "leave", "Back"),
        Binding("tab,shift+tab", "app.toggle_view", "Code", priority=True),
        Binding("f5", "app.toggle_view", "Decompile", priority=True),
    ]

    cursor = reactive(0, repaint=False)

    class Moved(Message):
        def __init__(self, va: int) -> None:
            super().__init__()
            self.va = va

    class Leave(Message):
        pass

    class ToCode(Message):
        def __init__(self, va: int) -> None:
            super().__init__()
            self.va = va

    def __init__(self) -> None:
        super().__init__(id="hex")
        self.model = None
        self.total = 0

    # -- public API -------------------------------------------------------- #
    def load(self, model, va: int | None = None) -> None:  # type: ignore[no-untyped-def]
        self.model = model
        self.total = model.total_rows()
        self.virtual_size = Size(0, self.total)
        if va is not None:
            off = max(0, min(model.size - 1, va - model.start))
            self.cursor = off
        self._prime(center=True)

    def goto_va(self, va: int) -> None:
        if self.model is None:
            return
        self.cursor = max(0, min(self.model.size - 1, va - self.model.start))
        self._prime(center=True)

    def cursor_va(self) -> int:
        return (self.model.start + self.cursor) if self.model else 0

    @work(thread=True, exclusive=True, group="hex-prime")
    def _prime(self, center: bool = False) -> None:
        model = self.model
        if model is None:
            return
        row = self.cursor // 16
        height = max(self.size.height, 1)
        model.ensure(max(row - 2, 0), height + 4)
        self.app.call_from_thread(self._after_prime, center)

    def _after_prime(self, center: bool) -> None:
        self._scroll_to_cursor(center=center)
        self.refresh()
        self.post_message(HexView.Moved(self.cursor_va()))

    # -- scrolling --------------------------------------------------------- #
    def _visible_height(self) -> int:
        return max(self.size.height, 1)

    def _apply_scroll(self, y: int) -> None:
        y = max(0, y)
        self.scroll_to(y=y, animate=False)

        def _fix(yy: int = y) -> None:
            self.scroll_to(y=yy, animate=False)
            self.refresh(layout=True)

        self.call_after_refresh(_fix)

    def _scroll_to_cursor(self, center: bool = False) -> None:
        height = self._visible_height()
        row = self.cursor // 16
        if center:
            top = max(row - height // 2, 0)
        else:
            top = round(self.scroll_offset.y)
            if row < top:
                top = row
            elif row >= top + height:
                top = row - height + 1
        top = max(0, min(top, max(self.total - 1, 0)))
        self._apply_scroll(top)

    # -- navigation -------------------------------------------------------- #
    def _move(self, delta: int) -> None:
        if self.model is None or self.model.size == 0:
            return
        before = round(self.scroll_offset.y)
        self.cursor = max(0, min(self.model.size - 1, self.cursor + delta))
        self._scroll_to_cursor(center=False)
        if round(self.scroll_offset.y) == before:
            self.refresh()  # cursor moved within the viewport
        self.post_message(HexView.Moved(self.cursor_va()))

    def action_move(self, delta: int) -> None:
        self._move(delta)

    def action_page(self, direction: int) -> None:
        self._move(direction * self._visible_height() * 16)

    def action_half_page(self, direction: int) -> None:
        self._move(direction * (self._visible_height() // 2) * 16)

    def action_goto_top(self) -> None:
        self._move(-self.cursor)

    def action_goto_bottom(self) -> None:
        self._move(self.model.size if self.model else 0)

    def action_to_code(self) -> None:
        self.post_message(HexView.ToCode(self.cursor_va()))

    def action_leave(self) -> None:
        self.post_message(HexView.Leave())

    # -- rendering --------------------------------------------------------- #
    def _ensure_window(self, top: int) -> None:
        if self.model is None:
            return
        height = max(self.size.height, 1)
        if not self.model.is_cached(top, height):
            self._fetch_window(top, height)
        else:
            self.model.ensure_async(top, height)

    @work(thread=True, exclusive=False, group="hex-fetch")
    def _fetch_window(self, top: int, height: int) -> None:
        model = self.model
        if model is None:
            return
        model.ensure(max(top - 2, 0), height + 4)
        self.app.call_from_thread(self.refresh)

    def render_line(self, y: int) -> Strip:
        model = self.model
        width = self.size.width
        if model is None or self.total == 0:
            return Strip([Segment("".ljust(width), _S_DIM)])
        top = round(self.scroll_offset.y)
        if y == 0:
            self._ensure_window(top)
        r = top + y
        if r >= self.total:
            return Strip([Segment("".ljust(width), _S_HEX)])
        va, data = model.row(r)
        cur_row, cur_col = self.cursor // 16, self.cursor % 16
        fo = model.file_offset(va)
        fo_str = f"{fo:08X}" if fo is not None else "--------"
        segs: list[Segment] = [
            Segment(f"{va:08X} ", _S_ADDR),
            Segment(f"{fo_str}  ", _S_FOFF),
        ]
        if data is None:
            segs.append(Segment("… fetching", _S_DIM))
        else:
            n = len(data)
            for i in range(16):
                if i == 8:
                    segs.append(Segment(" ", _S_HEX))
                if i < n:
                    st = _S_CELL if (r == cur_row and i == cur_col) else _S_HEX
                    segs.append(Segment(f"{data[i]:02X} ", st))
                else:
                    segs.append(Segment("   ", _S_HEX))
            segs.append(Segment(" |", _S_DIM))
            for i in range(16):
                if i < n:
                    ch = chr(data[i]) if 32 <= data[i] < 127 else "."
                    st = _S_CELL if (r == cur_row and i == cur_col) else _S_ASCII
                else:
                    ch, st = " ", _S_ASCII
                segs.append(Segment(ch, st))
            segs.append(Segment("|", _S_DIM))
        return Strip(segs).adjust_cell_length(width, _S_HEX)


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
    if not name:  # defensive: never assume a symbol has a name
        return None
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
    # Field names IDA's C parser predefines as macros and refuses to re-parse.
    RESERVED_FIELDS = ("__unused",)

    def __init__(self, program: Program) -> None:
        super().__init__()
        self._program = program
        self._structs: list[Struct] = []
        self._loaded: str | None = None  # name currently in the editor
        self._loaded_src: str | None = None  # its source, to detect unsaved edits

    @classmethod
    def _reserved_field(cls, text: str) -> str | None:
        for nm in cls.RESERVED_FIELDS:
            if re.search(rf"\b{re.escape(nm)}\b", text):
                return nm
        return None

    def _is_dirty(self) -> bool:
        cur = self.query_one("#se-edit", TextArea).text.strip()
        return bool(cur) and cur != (self._loaded_src or "").strip()

    def _confirm_discard(self, then, msg="Discard unsaved changes to the definition?"):
        """Run ``then()`` directly, or after a discard confirmation if dirty."""
        if self._is_dirty():
            self.app.push_screen(ConfirmScreen(msg), lambda ok: then() if ok else None)
        else:
            then()

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
            self._confirm_discard(lambda n=self._structs[i].name: self._load(n))

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
        self._loaded_src = src
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
        # On success, pull the canonical source back so the editor shows the
        # normalized layout/types (auto-format on save).
        formatted = None
        if not err and name:
            try:
                formatted = self._program.struct_source(name)
            except Exception:  # noqa: BLE001
                formatted = None
        self.app.call_from_thread(self._after_save, name, err, text, formatted)

    def _after_save(self, name: str | None, err: str | None, text: str,
                    formatted: str | None) -> None:
        if err:
            # IDA's parse error is usually empty/cryptic; name the likely cause.
            msg = err.strip()
            if not msg or "parse" in msg.lower() or "fail" in msg.lower():
                bad = self._reserved_field(text)
                msg = (f"'{bad}' is a reserved name in IDA's C parser — rename "
                       f"that field to save" if bad else
                       "IDA couldn't parse it (unknown type or reserved field name?)")
            self._set_status(f"save failed — {msg}", error=True)
            return
        self._loaded = name
        if formatted:
            # Reformat the editor to IDA's canonical layout (keeps cursor at top).
            ta = self.query_one("#se-edit", TextArea)
            ta.text = formatted
            self._loaded_src = formatted
        else:
            self._loaded_src = text.strip()  # editor already matches the saved type
        if getattr(self.app, "_dirty", None) is not None:
            self.app._dirty = True  # unsaved-to-disk until Ctrl+S in the app
        self._refresh(select=name)
        self._set_status(f"saved {name}" if name else "saved")

    def action_new(self) -> None:
        self._confirm_discard(self._do_new, "Discard unsaved changes and start new?")

    def _do_new(self) -> None:
        ta = self.query_one("#se-edit", TextArea)
        ta.text = self.NEW_TEMPLATE
        self._loaded = None
        self._loaded_src = self.NEW_TEMPLATE
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
        self._confirm_discard(lambda: self.dismiss(None),
                              "Discard unsaved changes and close?")

    def _set_status(self, text, error: bool = False) -> None:  # type: ignore[no-untyped-def]
        st = self.query_one("#se-status", Static)
        st.update(Text("⚠ " + text, style="bold #ff5f5f") if error else text)


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
    ListingView { width: 1fr; padding: 0 1; }
    HexView { width: 1fr; padding: 0 1; }
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
    #retype {
        height: 1; border: none; padding: 0 1;
        background: $accent-darken-2; color: $text;
    }
    #makedata {
        height: 1; border: none; padding: 0 1;
        background: $secondary-darken-2; color: $text;
    }
    #goto {
        height: 1; border: none; padding: 0 1;
        background: $primary-darken-3; color: $text;
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
        Binding("backslash", "hex", "Hex"),
        Binding("g", "goto", "Goto"),
        Binding("slash", "filter", "Filter", show=False),
        Binding("ctrl+b", "toggle_functions", "Names", show=False),
        Binding("tab,shift+tab", "toggle_view", "Disasm/Pseudocode", priority=True),
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, url: str, db: str | None, keepalive: bool = True,
                 open_path: str | None = None, rpc_path: str | None = None) -> None:
        super().__init__()
        self._url = url
        self._db = db
        self._open_path = open_path
        self._do_keepalive = keepalive
        self._rpc_path = rpc_path
        self._rpc = None
        self.client: IDAClient | None = None
        self.program: Program | None = None
        self._ka = None
        self._nav: list[NavEntry] = []
        self._func_index = None  # the unfiltered FunctionIndex (source of truth)
        self._did_auto_land = False  # startup jump-to-main/picker fires once
        self._filter_term = ""
        self._pending_filter = ""
        self._filter_timer = None
        self._sort_col = 0        # 0=addr, 1=name, 2=size
        self._sort_reverse = False
        self._pref = "listing"   # unified: the linear listing is the code view
        self._active = "listing"  # currently shown view
        self._hex_pending_ea: int | None = None
        self._cur: NavEntry | None = None
        self._decomp_return: NavEntry | None = None  # listing to return to from F5
        self._search_ctx: tuple[object | None, int] = (None, 1)
        self._rename_ctx: tuple[object | None, str] = (None, "")
        self._rename_addr: int | None = None  # set for address-based (listing) naming
        self._comment_ctx: tuple[object | None, int, str] = (None, 0, "")
        self._retype_ctx: tuple[object | None, str, int, str] = (None, "", 0, "")
        self._makedata_ctx: tuple[object | None, int] = (None, 0)
        self._xref_focus_name: str | None = None
        self._dirty = False

    # -- layout ------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        with Horizontal(id="panes"):
            fp = FunctionsPanel(id="left")
            fp.display = False  # overlay-first: reveal the docked pane with Ctrl+B
            yield fp
            # The unified continuous listing is the one code view; DisasmView is
            # deprecated (kept only for DisasmModel, still used by the domain).
            lst = ListingView()
            yield lst
            yield DecompView()
            hx = HexView()
            hx.display = False
            yield hx
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
        ti = Input(id="retype")
        ti.display = False
        ti.can_focus = False
        yield ti
        mdi = Input(id="makedata")
        mdi.display = False
        mdi.can_focus = False
        yield mdi
        gi = Input(id="goto")
        gi.display = False
        gi.can_focus = False
        yield gi
        yield Static("connecting…", id="status")
        yield Footer()

    def on_mount(self) -> None:
        # Keep the hidden command input out of the focus chain until summoned.
        inp = self.query_one("#func-filter", Input)
        inp.can_focus = False
        # The names pane is an overlay now (Ctrl+N); focus the default code view
        # (pseudocode) so app bindings work before anything is opened.
        self.query_one(ListingView).focus()
        self._connect()
        if self._rpc_path:
            self._start_rpc()

    def _start_rpc(self) -> None:
        from .rpc import RpcServer
        self._rpc = RpcServer(self, self._rpc_path)

        async def _serve() -> None:
            await self._rpc.start()
            self._status(f"rpc: listening on {self._rpc_path}")

        asyncio.get_running_loop().create_task(_serve())

    async def on_unmount(self) -> None:
        if self._rpc is not None:
            await self._rpc.stop()

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
        # Land somewhere useful instead of an empty pane: main() if present,
        # otherwise pop the fuzzy symbol picker.
        self.app.call_from_thread(self._auto_land)

    # -- initial landing --------------------------------------------------- #
    #: function names tried (in order) as the startup landing spot
    ENTRY_NAMES = ("main", "_main", "wmain", "WinMain", "wWinMain")

    def _auto_land(self) -> None:
        """On startup, once functions are loaded and nothing is open yet, jump to
        main() if it exists; else open the symbol picker so you're never staring
        at a blank pane. Runs once (guarded by ``_cur``) and never steals focus
        from a user who already navigated."""
        if self._cur is not None or self._did_auto_land or self._func_index is None:
            return
        self._did_auto_land = True
        fn = self._entry_func()
        if fn is not None:
            self._open_function(fn.addr, fn.name)
        else:
            self.action_symbols()

    def _entry_func(self) -> Func | None:
        """The best startup landing function (exact-name match against
        ENTRY_NAMES, in priority order), or None."""
        idx = self._func_index
        if idx is None:
            return None
        by_name = {f.name: f for f in idx.all_loaded()}
        for nm in self.ENTRY_NAMES:
            if nm in by_name:
                return by_name[nm]
        return None

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
                           else ListingView).focus()
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
        """Tab: switch the code pane between disassembly and pseudocode (or leave
        the hex view back to the preferred code view)."""
        if self._cur is None:
            return
        if self._active == "hex":
            self._active = self._code_mode()
            self._show_active()
            return
        if self._active == "listing":
            # F5/Tab in the continuous listing: decompile the function under the
            # cursor (IDA-style), if the cursor is inside a defined routine.
            ea = self.query_one(ListingView)._cursor_ea()
            if ea is None:
                self._status("no address here to decompile")
                return
            self._decomp_from_listing(ea)
            return
        # active == "decomp": F5/Tab returns to the linear listing.
        ret = self._decomp_return
        self._decomp_return = None
        if ret is not None:
            self._cur = ret
            self._active = "listing"
            self._open_entry(ret, push=False)
        elif self._cur is not None:
            # No F5 snapshot (we arrived via a decomp navigation): show THIS entry
            # in the listing at the current pseudocode line's address. Reuse the
            # entry (it is _nav[-1]) rather than spawning a detached one, so cursor
            # moves keep updating it and a later edit reloads at the right spot.
            dec = self.query_one(DecompView)
            ea = dec._line_ea(dec.cursor)
            self._toggle_to_listing(ea if ea is not None else self._cur.ea)
        else:
            self._active = "listing"
            self._show_active()

    @work(thread=True, group="nav")
    def _toggle_to_listing(self, ea: int) -> None:
        assert self.program is not None
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        self.app.call_from_thread(self._apply_toggle_listing, idx)

    def _apply_toggle_listing(self, idx: int) -> None:
        cur = self._cur
        if cur is None:
            self._active = "listing"
            self._show_active()
            return
        cur.view = "listing"
        cur.cursor = idx
        cur.cursor_x = 0
        cur.scroll_y = -1  # derive a viewport (keeps the target in context)
        self._active = "listing"
        self._open_entry(cur, push=False)

    @work(thread=True, group="nav")
    def _decomp_from_listing(self, ea: int) -> None:
        assert self.program is not None
        fn = self.program.function_of(ea)
        if fn is None:
            self.app.call_from_thread(
                self._status,
                "F5 — cursor is not inside a defined function ('p' to make one)")
            return
        dec_idx = self._decomp_line_for(fn.addr, ea)
        self.app.call_from_thread(self._enter_decomp, fn.addr, fn.name, dec_idx)

    def _enter_decomp(self, fn_addr: int, fn_name: str, dec_idx: int) -> None:
        # Snapshot the listing position so F5/Tab returns exactly here.
        lst = self.query_one(ListingView)
        ret = self._cur
        if ret is not None:
            ret.cursor = lst.cursor
            ret.cursor_x = lst.cursor_x
            ret.scroll_y = round(lst.scroll_offset.y)
        self._decomp_return = ret
        entry = NavEntry(ea=fn_addr, name=fn_name, is_region=False,
                         dec_cursor=max(dec_idx, 0))
        self._cur = entry
        self._active = "decomp"
        self._show_active()

    def action_hex(self) -> None:
        """Backslash: show the raw bytes of the loaded image, synced to the code
        cursor; press again (or Tab/Esc) to return to the code view."""
        if self._cur is None or self.program is None:
            return
        if self._active == "hex":
            self._active = self._code_mode()
            self._show_active()
            return
        if self._active in ("listing", "disasm"):
            ea = self.query_one(ListingView)._cursor_ea()
        else:
            dec = self.query_one(DecompView)
            ea = dec._line_ea(dec.cursor)
        self._hex_pending_ea = ea if ea is not None else self._cur.ea
        self._active = "hex"
        self._show_active()

    def action_filter(self) -> None:
        inp = self.query_one("#func-filter", Input)
        inp.placeholder = "filter names…  Enter=keep  Esc=clear"
        inp.can_focus = True
        inp.display = True
        inp.value = self._filter_term
        inp.focus()

    def action_goto(self) -> None:
        inp = self.query_one("#goto", Input)
        inp.placeholder = ("hex goto: 0xADDR or name — Enter" if self._active == "hex"
                           else "goto: name or 0xADDR — Enter")
        inp.can_focus = True
        inp.display = True
        inp.value = ""
        self.query_one("#status", Static).display = False
        inp.focus()

    def _end_goto(self) -> None:
        inp = self.query_one("#goto", Input)
        inp.display = False
        inp.can_focus = False
        self.query_one("#status", Static).display = True

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
                           else ListingView).focus()

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
        elif isinstance(view, ListingView):
            ea = view._cursor_ea()
            if ea is not None:
                self._follow_disasm(ea, word, view._next_ea())
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
        elif isinstance(view, ListingView):
            ea = view._cursor_ea()
            if ea is not None:
                self._xrefs_disasm(ea, word, ea, view._next_ea())
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
        # Following FROM pseudocode: keep the reader in the decompiler when the
        # target is decompilable, instead of dropping to the linear listing.
        self._do_navigate(addr, push=True, prefer_decomp=True)

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
            # If xrefs was invoked from the decompiler, land the jump back in the
            # decompiler (when the target is decompilable) rather than the listing.
            self._goto_ea(addr, push=True, focus_name=self._xref_focus_name,
                          prefer_decomp=(self._active == "decomp"))

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
        # In the flat listing, 'n' names the ADDRESS under the cursor (create a
        # label), not a symbol-by-name. This is what lets you name a bare/
        # undefined byte — e.g. the free byte at addr+1 after shrinking a u16 to
        # a u8 — which the word-under-cursor path can't do (no symbol to rename).
        if isinstance(msg.view, ListingView):
            ea = msg.view._cursor_ea()
            if ea is None:
                self._status("no address on this line to name")
                return
            head = msg.view.cur_head()
            word = msg.view.word_under_cursor()
            mnem = head.text.split(" ", 1)[0] if (head and head.text) else ""
            # If the cursor is on a symbol token (a call/branch target, a data
            # reference, or this head's own label) rename THAT symbol; otherwise
            # create/rename a label at the head's address (bare/undefined bytes).
            if (word and self._looks_like_symbol(word) and word != mnem
                    and word.lower() not in _ASM_KEYWORDS):
                self._rename_ctx = (msg.view, word)
                self._rename_addr = None
                placeholder = f"rename '{word}' —  Enter=apply  Esc=cancel"
                prefill = word
            else:
                cur = head.name if (head is not None and head.name) else ""
                self._rename_ctx = (msg.view, cur)
                self._rename_addr = ea
                placeholder = f"name @ {ea:#x} —  Enter=apply  Esc=cancel"
                prefill = cur
            self.query_one("#status", Static).display = False
            inp = self.query_one("#rename", Input)
            inp.placeholder = placeholder
            inp.can_focus = True
            inp.display = True
            inp.value = prefill
            inp.focus()
            return
        if not msg.name:
            self._status("nothing to rename under the cursor")
            return
        if self._is_pseudocode_label(msg.view, msg.name):
            self._status(
                f"can't rename pseudocode label '{msg.name}' "
                "(Hex-Rays goto labels aren't renamable via the API)")
            return
        self._rename_ctx = (msg.view, msg.name)
        self._rename_addr = None
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
        self._rename_addr = None
        self.query_one("#status", Static).display = True
        view, _ = self._rename_ctx
        if view is not None:
            view.focus()

    # -- comments ---------------------------------------------------------- #
    def _line_ea_for(self, view) -> int | None:  # type: ignore[no-untyped-def]
        """Address of the line under the cursor in either code view."""
        if isinstance(view, (DisasmView, ListingView)):
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
        # Signature / local-declaration lines carry no address; fall back to the
        # function's entry ea so commenting the header annotates the function.
        func_level = ea is None
        if func_level:
            ea = self._cur.ea if self._cur else None
        if ea is None:
            self._status("no address on this line to comment")
            return
        existing = "" if func_level else self._existing_comment(msg.view)
        self._comment_ctx = (msg.view, ea, existing)
        self.query_one("#status", Static).display = False
        inp = self.query_one("#comment", Input)
        inp.placeholder = (
            f"function comment @ {ea:#x} —  Enter=apply (empty=clear)  Esc=cancel"
            if func_level else
            f"comment @ {ea:#x} —  Enter=apply (empty=clear)  Esc=cancel")
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
        # The prompt is single-line, so a literal '\n' (backslash-n) means a real
        # newline — Hex-Rays renders each as its own '//' line. Lets long notes
        # wrap instead of running off the right edge and clipping.
        text = text.replace("\\n", "\n")
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

    def _reload_active_code(self) -> None:
        """Refresh whichever code view is showing after an edit (comment/rename/
        retype), in place: re-decompile if in the decompiler, else reload the
        listing."""
        cur = self._cur
        if cur is None:
            return
        if self._active == "decomp":
            self.query_one(DecompView).loaded_ea = None  # force re-decompile
            self._show_active()
        else:
            # Capture the LIVE listing position straight from the widget (the
            # source of truth) rather than trusting nav-entry tracking, which can
            # go stale. bump_names() discards the segment model, so the reload
            # rebuilds it; feeding the true cursor/scroll keeps the edited line on
            # screen even on a huge segment (otherwise it primes/scrolls to a
            # stale index and the renamed line lands off-screen — looking like the
            # rename never applied).
            lst = self.query_one(ListingView)
            cur.view = "listing"
            if lst.model is not None:
                cur.cursor = lst.cursor
                cur.cursor_x = lst.cursor_x
                cur.scroll_y = round(lst.scroll_offset.y)
            self._open_entry(cur, push=False)

    def _after_comment(self, ea: int, text: str) -> None:
        # A comment shows in both views but only after Hex-Rays recompiles, so
        # reuse the name-generation invalidation (bumps gen -> decompile is
        # force_recompiled lazily; disasm/listing caches are cleared).
        self.program.bump_names()
        self._reload_active_code()
        self._dirty = True
        verb = "cleared comment" if not text else "commented"
        self._status(f"{verb} @ {ea:#x}   (Ctrl+S to save)")

    # -- retype (set type, IDA 'y') --------------------------------------- #
    def on_retype_requested(self, msg: RetypeRequested) -> None:
        if self._cur is None or self.program is None:
            return
        self._prepare_retype(msg.view, msg.name)

    @work(thread=True, exclusive=True, group="retype")
    def _prepare_retype(self, view, word: str | None) -> None:  # type: ignore[no-untyped-def]
        """Work out whether the cursor is on a local variable or a function, and
        fetch the current type/prototype to prefill the prompt."""
        assert self.program is not None and self._cur is not None
        ft = self.program.func_types(self._cur.ea)
        kind: str | None = None
        subject: int = self._cur.ea
        prefill = ""
        # 1) a local variable (or arg) of the current function
        if word and ft is not None:
            lv = next((v for v in ft.lvars if v.name == word), None)
            if lv is not None:
                kind, prefill = "lvar", lv.type
        # 2) a function under the cursor (self or a referenced one)
        if kind is None and self._looks_like_symbol(word):
            try:
                tgt = self.program.resolve(word)
            except Exception:  # noqa: BLE001
                tgt = None
            if tgt is not None:
                tft = self.program.func_types(tgt)
                if tft is not None:
                    kind, subject, prefill = "func", tgt, tft.prototype
        # 3) fall back to the current function itself
        if kind is None and ft is not None:
            kind, subject, prefill = "func", self._cur.ea, ft.prototype
        if kind is None:
            self.app.call_from_thread(self._status, "nothing to retype under the cursor")
            return
        self.app.call_from_thread(self._open_retype, view, kind, subject, word or "", prefill)

    def _open_retype(self, view, kind: str, subject: int, word: str,  # type: ignore[no-untyped-def]
                     prefill: str) -> None:
        self._retype_ctx = (view, kind, subject, word)
        self.query_one("#status", Static).display = False
        inp = self.query_one("#retype", Input)
        label = "prototype" if kind == "func" else f"type for '{word}'"
        inp.placeholder = f"{label} —  Enter=apply  Esc=cancel"
        inp.can_focus = True
        inp.display = True
        inp.value = prefill
        inp.focus()

    def _end_retype(self) -> None:
        inp = self.query_one("#retype", Input)
        inp.display = False
        inp.can_focus = False
        self.query_one("#status", Static).display = True
        view = self._retype_ctx[0]
        if view is not None:
            view.focus()

    @work(thread=True, exclusive=True, group="retype-apply")
    def _do_retype(self, kind: str, subject: int, word: str, new: str) -> None:
        assert self.program is not None
        if kind == "func":
            err = self.program.set_function_type(subject, new)
        else:  # lvar of the current function
            err = self.program.set_lvar_type(self._cur.ea, word, new)
        if err:
            self.app.call_from_thread(self._status, f"retype failed: {err}")
            return
        self.app.call_from_thread(self._after_retype, kind, word)

    def _after_retype(self, kind: str, word: str) -> None:
        # A type change alters the pseudocode (and disasm operand types), so
        # recompile via the name-generation invalidation and reopen in place.
        self.program.bump_names()
        self._reload_active_code()
        self._dirty = True
        what = "prototype" if kind == "func" else f"'{word}'"
        self._status(f"retyped {what}   (Ctrl+S to save)")

    # -- typed data definition (make_data, IDA 'd') ----------------------- #
    @staticmethod
    def _default_data_type(head) -> str:  # type: ignore[no-untyped-def]
        """A sensible prefill C type for defining data over ``head``."""
        sz = getattr(head, "size", 0) or 0
        return {1: "unsigned __int8", 2: "unsigned __int16",
                4: "unsigned __int32", 8: "unsigned __int64"}.get(
                    sz, f"char[{sz}]" if sz > 0 else "unsigned __int8")

    def on_make_data_requested(self, msg: MakeDataRequested) -> None:
        view = msg.view
        ea = view._cursor_ea() if isinstance(view, ListingView) else None
        if ea is None:
            self._status("no address on this line to define data")
            return
        self._makedata_ctx = (view, ea)
        self.query_one("#status", Static).display = False
        inp = self.query_one("#makedata", Input)
        inp.placeholder = (f"data type @ {ea:#x} (e.g. int, char[16], my_struct)"
                           "  —  Enter=apply  Esc=cancel")
        inp.can_focus = True
        inp.display = True
        head = view.cur_head() if isinstance(view, ListingView) else None
        inp.value = self._default_data_type(head) if head is not None else "int"
        inp.focus()

    def _end_makedata(self) -> None:
        inp = self.query_one("#makedata", Input)
        inp.display = False
        inp.can_focus = False
        self.query_one("#status", Static).display = True
        view = self._makedata_ctx[0]
        if view is not None:
            view.focus()

    @work(thread=True, exclusive=True, group="makedata")
    def _do_make_data(self, ea: int, type_decl: str) -> None:  # worker context
        assert self.program is not None
        try:
            self.program.make_data(ea, type_decl)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"make data: {e}")
            return
        self.program.bump_items()
        name = self.program.region_label(ea)
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        self.app.call_from_thread(self._open_at, ea, name, idx, False, -1, 0, True)
        self.app.call_from_thread(
            self._edit_item_done, f"data ({type_decl})", ea)

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
        self._reload_active_code()
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

    @work(thread=True, exclusive=True, group="rename")
    def _do_name_addr(self, addr: int, name: str) -> None:  # worker context
        """Set a label at ``addr`` (listing 'n'). Works on a bare/undefined byte
        — unlike the symbol-by-name path, this names the address directly."""
        assert self.program is not None
        try:
            res = self.program.client.call(
                "rename", batch={"data": {"addr": hex(addr), "new": name}})
        except IDAToolError as e:
            self.app.call_from_thread(self._status, f"name failed: {e.message}")
            return
        summary = res.get("summary", {}) if isinstance(res, dict) else {}
        if not (summary.get("ok", 0) > 0 and summary.get("failed", 0) == 0):
            err = "name failed"
            items = res.get("data") if isinstance(res, dict) else None
            if isinstance(items, list) and items and items[0].get("error"):
                err = f"name failed: {items[0]['error']}"
            self.app.call_from_thread(self._status, err)
            return
        # The label shows in the listing's head rows -> invalidate + reopen.
        self.program.bump_items()
        lm = self.program.listing(addr)
        label = self.program.region_label(addr)
        idx = max(lm.ensure_ea(addr), 0) if lm is not None else 0
        self.app.call_from_thread(self._open_at_named, label, addr, idx, name)

    def _open_at_named(self, label: str, addr: int, idx: int, name: str) -> None:
        self._open_at(addr, label, idx, False, -1, 0, True)
        self._dirty = True
        self._status(f"named {addr:#x} → {name}   (Ctrl+S to save)")

    # -- item structure edits (IDA c/p/u) --------------------------------- #
    def on_edit_item_requested(self, msg: EditItemRequested) -> None:
        ea = (msg.view._cursor_ea()
              if isinstance(msg.view, (DisasmView, ListingView)) else None)
        if ea is None:
            self._status("no address on this line to (re)define")
            return
        self._do_edit_item(msg.kind, ea)

    @work(thread=True, exclusive=True, group="edititem")
    def _do_edit_item(self, kind: str, ea: int) -> None:  # worker context
        assert self.program is not None
        verb = {"code": "defined code", "func": "created function",
                "undef": "undefined", "string": "made string"}[kind]
        try:
            if kind == "code":
                self.program.define_code(ea)
            elif kind == "func":
                self.program.define_func(ea)
            elif kind == "string":
                s = self.program.make_string(ea)
                verb = f"made string ({s[:24]!r})" if s else verb
            else:
                self.program.undefine(ea)
        except Exception as e:  # noqa: BLE001 -- surface soft/hard tool errors
            self.app.call_from_thread(self._status, f"{kind}: {e}")
            return
        # Structure changed everywhere: drop all item/function/decomp caches.
        self.program.bump_items()
        # Re-resolve: a define_func upgrades the region to a real function view;
        # anything else re-reads the (still function-less) listing in place.
        fn = self.program.function_of(ea)
        if fn is not None:
            model = self.program.disasm(fn.addr, fn.name)
            idx = 0 if ea == fn.addr else model.index_of_ea(ea)
            self.app.call_from_thread(
                self._open_at, fn.addr, fn.name, idx, False, -1, 0, False)
        else:
            name = self.program.region_label(ea)
            lm = self.program.listing(ea)
            idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
            self.app.call_from_thread(
                self._open_at, ea, name, idx, False, -1, 0, True)
        self.app.call_from_thread(self._edit_item_done, verb, ea)

    def _edit_item_done(self, verb: str, ea: int) -> None:
        self._dirty = True
        self._status(f"{verb} @ {ea:#x}   (Ctrl+S to save)")

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
                 focus_name: str | None = None, prefer_decomp: bool = False) -> None:
        self._do_navigate(ea, push, focus_name, prefer_decomp)

    def _do_navigate(self, ea: int, push: bool, focus_name: str | None = None,
                     prefer_decomp: bool = False) -> None:  # worker context
        assert self.program is not None
        fn = self.program.function_of(ea)
        # Jumping FROM the decompiler: stay in pseudocode when the target is a
        # decompilable function, landing on the line that matches ``ea``.
        if prefer_decomp and fn is not None:
            dec = self.program.decompile(fn.addr)
            if not dec.failed and dec.code:
                dec_idx = self._decomp_line_for(fn.addr, ea)
                self.app.call_from_thread(
                    self._open_decomp_entry, fn.addr, fn.name, max(dec_idx, 0), push)
                return
        # Otherwise: everything opens the one continuous listing at ``ea``. A
        # function name is used for the status label; a region gets a segment
        # label. F5/Tab decompiles the function under the cursor from here.
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        name = fn.name if fn is not None else self.program.region_label(ea)
        self.app.call_from_thread(
            self._open_at, ea, name, idx, push, -1, 0, fn is None)

    def _open_decomp_entry(self, fn_addr: int, fn_name: str, dec_idx: int,
                           push: bool) -> None:
        """Open ``fn_addr`` in the decompiler as a real navigation (nav history
        aware), landing on pseudocode line ``dec_idx``."""
        if push:
            # Snapshot where we jumped from so 'back' returns there. If that was
            # the pseudocode (F5 makes a transient _cur not yet on the stack),
            # record its position and push it as a decomp entry.
            if self._active == "decomp" and self._cur is not None:
                dv = self.query_one(DecompView)
                src = self._cur
                src.view = "decomp"
                src.dec_cursor = dv.cursor
                src.dec_cursor_x = dv.cursor_x
                src.dec_scroll_y = round(dv.scroll_offset.y)
                if not self._nav or self._nav[-1] is not src:
                    self._nav.append(src)
            else:
                self._save_current_pos()
        self._decomp_return = None  # a real navigation abandons the F5 return
        entry = NavEntry(ea=fn_addr, name=fn_name, view="decomp",
                         dec_cursor=dec_idx)
        if push:
            self._nav.append(entry)
        self._open_entry(entry, push=False)

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
                 dec_cursor: int = -1, dec_cursor_x: int = 0,
                 is_region: bool = False) -> None:
        if push:
            self._save_current_pos()
        self._decomp_return = None  # a real navigation abandons the F5 return
        entry = NavEntry(ea=ea, name=name, cursor=cursor, is_region=is_region)
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
        if event.input.id == "func-filter":
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
        if self.query_one("#retype", Input).display:
            event.stop()
            event.prevent_default()
            self._end_retype()
            return
        if self.query_one("#makedata", Input).display:
            event.stop()
            event.prevent_default()
            self._end_makedata()
            return
        if self.query_one("#goto", Input).display:
            event.stop()
            event.prevent_default()
            self._end_goto()
            (self.query_one(HexView) if self._active == "hex"
             else self._code_view()).focus()
            return
        fi = self.query_one("#func-filter", Input)
        if fi.display:
            event.stop()
            event.prevent_default()
            fi.display = False
            fi.can_focus = False
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
            addr = self._rename_addr  # capture before _end_rename clears it
            self._end_rename()
            if addr is not None:  # listing: name this address (create a label)
                if value and value != old:
                    self._do_name_addr(addr, value)
                return
            if view is not None and value and value != old:
                self._do_rename(view, old, value)
            return
        if inp.id == "comment":
            view, ea, existing = self._comment_ctx
            self._end_comment()
            if view is not None and value != existing:  # empty value clears it
                self._do_comment(ea, value)
            return
        if inp.id == "retype":
            view, kind, subject, word = self._retype_ctx
            self._end_retype()
            if view is not None and value:
                self._do_retype(kind, subject, word, value)
            return
        if inp.id == "makedata":
            view, ea = self._makedata_ctx
            self._end_makedata()
            if view is not None and value:
                self._do_make_data(ea, value)
            return
        if inp.id == "goto":
            self._end_goto()
            (self.query_one(HexView) if self._active == "hex"
             else self._code_view()).focus()
            if value:
                self._goto(value)
            return
        # filter mode: already applied incrementally; Enter just confirms + closes.
        self._apply_filter(value)
        self.query_one("#func-table", DataTable).focus()

    def _code_view(self):  # type: ignore[no-untyped-def]
        return self.query_one(DecompView if self._pref == "decomp" else ListingView)

    def _active_code_view(self):  # type: ignore[no-untyped-def]
        """The currently-shown code widget (for reading the cursor address)."""
        if self._active in ("listing", "disasm"):
            return self.query_one(ListingView)
        if self._active == "decomp":
            return self.query_one(DecompView)
        return None

    def action_continuous_here(self) -> None:
        """'L': open the continuous segment listing at the cursor — one long
        flat view where functions, data and undefined bytes are interleaved,
        instead of the function-bounded disassembly."""
        if self.program is None:
            return
        view = self._active_code_view()
        ea = self._line_ea_for(view) if view is not None else None
        if ea is None and self._cur is not None:
            ea = self._cur.ea
        if ea is None:
            self._status("no address here to open the continuous listing")
            return
        if self._cur is not None and self._cur.is_region:
            self._status("already in the continuous listing")
            return
        self._goto_continuous(ea)

    @work(thread=True, group="nav")
    def _goto_continuous(self, ea: int, push: bool = True) -> None:
        assert self.program is not None
        name = self.program.region_label(ea)
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        self.app.call_from_thread(self._open_at, ea, name, idx, push, -1, 0, True)

    @work(thread=True, exclusive=True, group="goto")
    def _goto(self, target: str) -> None:
        assert self.program is not None
        try:
            ea = self.program.resolve(target)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"goto: {e}")
            return
        if self._active == "hex":
            self.app.call_from_thread(self._hex_goto, ea)
            return
        # Navigate to the containing function at the right line (handles both a
        # function name and a mid-function address).
        self._do_navigate(ea, push=True)

    def _hex_goto(self, ea: int) -> None:
        hx = self.query_one(HexView)
        rng = self.program.image_range() if self.program else None
        if rng is not None and not (rng[0] <= ea < rng[1]):
            self._status(f"{ea:#x} is outside the image ({rng[0]:#x}..{rng[1]:#x})")
            return
        if hx.model is None:
            self._hex_pending_ea = ea
            self._load_hex_model(ea)
        else:
            hx.goto_va(ea)

    # -- opening functions ------------------------------------------------- #
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ea = int(event.row_key.value)
        f = self._func_index.by_addr(ea) if self._func_index else None
        name = f.name if f else hex(ea)
        self._open_function(ea, name)

    def _save_current_pos(self) -> None:
        """Snapshot the listing cursor + scroll into the top history entry
        (called just before we navigate away)."""
        if not self._nav:
            return
        e = self._nav[-1]
        lst = self.query_one(ListingView)
        if lst.model is not None:
            e.cursor, e.cursor_x = lst.cursor, lst.cursor_x
            e.scroll_y = round(lst.scroll_offset.y)

    @work(thread=True, group="nav")
    def _open_function(self, ea: int, name: str | None = None,
                       push: bool = True) -> None:
        # Unified: opening a function is just navigating the one linear listing
        # to its entry address.
        self._do_navigate(ea, push)


    def _code_mode(self) -> str:
        """The code view to return to from hex — always the unified listing."""
        return "listing"

    def _open_entry(self, entry: NavEntry, push: bool) -> None:
        if self.program is None:
            return
        self._cur = entry
        if entry.view == "decomp":
            # This entry was viewed in the decompiler (a jump from pseudocode, or
            # a back/forward to one) — restore it there instead of the listing.
            self._active = "decomp"
            dec = self.query_one(DecompView)
            if dec.loaded_ea == entry.ea:
                # already decompiled: reposition without a recompile
                dec.goto(entry.dec_cursor, entry.dec_cursor_x,
                         entry.dec_scroll_y if entry.dec_scroll_y >= 0 else -1,
                         entry.dec_scroll_x)
            self._show_active()  # loads the pseudocode if loaded_ea != entry.ea
            return
        # Unified model: the code view is always the continuous listing,
        # positioned at this entry. The decompiler is a per-function toggle
        # (F5/Tab -> _decomp_from_listing), never opened implicitly.
        lst = self.query_one(ListingView)
        lm = self.program.listing(entry.ea)
        sy = entry.scroll_y if entry.scroll_y >= 0 else None
        if lm is not None:
            if sy is None:
                # Fresh jump (not a back/forward restore, which carries its own
                # scroll). If the target is already on-screen in the SAME listing,
                # leave the viewport alone and just move the cursor; otherwise
                # scroll so the target sits a few lines below the top for context.
                top = round(lst.scroll_offset.y)
                if lst.model is lm and top <= entry.cursor < top + lst._visible_height():
                    sy = top
                else:
                    sy = max(entry.cursor - _JUMP_CONTEXT, 0)
            lst.load(
                lm, entry.name, cursor=entry.cursor,
                cursor_x=entry.cursor_x, scroll_y=sy)
        self._active = "listing"
        self._show_active()

    # Prompt overlays that own the keyboard while visible; a background
    # navigation must not yank focus out from under them (else typed keys leak
    # into a code view as destructive verbs — e.g. 'u' = undefine).
    _PROMPT_IDS = ("search", "rename", "comment", "retype", "goto", "func-filter")

    def _prompt_active(self) -> bool:
        for iid in self._PROMPT_IDS:
            try:
                if self.query_one(f"#{iid}", Input).display:
                    return True
            except Exception:  # noqa: BLE001 — widget not mounted yet
                pass
        return False

    def _show_active(self) -> None:
        dec = self.query_one(DecompView)
        lst = self.query_one(ListingView)
        hx = self.query_one(HexView)
        # Don't steal focus from an open prompt (search/rename/…) — a late async
        # navigation completing here would otherwise pull it into the code view.
        grab = not self._prompt_active()
        dec.display = lst.display = hx.display = False
        if self._active in ("listing", "disasm"):
            lst.display = True
            if grab:
                lst.focus()
            self._status_for_cur("listing")
        elif self._active == "hex":
            hx.display = True
            if grab:
                hx.focus()
            ea = getattr(self, "_hex_pending_ea", None)
            self._hex_pending_ea = None
            if hx.model is None:
                self._status("hex — loading image…")
                self._load_hex_model(ea)
            elif ea is not None:
                hx.goto_va(ea)
            else:
                self._hex_status(hx.cursor_va())
        else:
            dec.display = True
            if grab:
                dec.focus()
            if self._cur is not None and dec.loaded_ea != self._cur.ea:
                self._status(f"{self._cur.name} — decompiling…")
                dec.loading = True  # gray out + 'decompiling…' overlay
                self._load_decomp(self._cur.ea, self._cur.name)
            else:
                self._status_for_cur("pseudocode")

    # -- hex view ---------------------------------------------------------- #
    @work(thread=True, exclusive=True, group="hex-load")
    def _load_hex_model(self, ea: int | None) -> None:
        assert self.program is not None
        model = self.program.hex_model()
        self.app.call_from_thread(self._apply_hex_model, model, ea)

    def _apply_hex_model(self, model, ea: int | None) -> None:  # type: ignore[no-untyped-def]
        hx = self.query_one(HexView)
        if model is None:
            self._status("hex: no loaded segments")
            return
        hx.load(model, ea)
        if self._active == "hex":
            hx.focus()

    def _hex_status(self, va: int) -> None:
        sec = self.program.section_of(va) if self.program else None
        fo = self.program.file_offset(va) if self.program else None
        foff = f"file+{fo:#x}" if fo is not None else "file:--"
        self._status(f"hex  va={va:#x}  {foff}  [{sec or '?'}]   "
                     "(g goto · Enter→code · Tab/Esc/\\→back)")

    def on_hex_view_moved(self, msg: HexView.Moved) -> None:
        self._hex_status(msg.va)

    def on_hex_view_leave(self, msg: HexView.Leave) -> None:
        self._active = self._code_mode()
        self._show_active()

    def on_hex_view_to_code(self, msg: HexView.ToCode) -> None:
        self._active = self._pref
        self._goto_ea(msg.va, push=True)

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
            # No pseudocode for this function: fall back to the code view rather
            # than an error panel. If we came from the continuous listing (F5),
            # return there; otherwise show the disassembly.
            if self._cur is None or self._cur.ea != ea:
                return  # navigated away; stale result
            if self._decomp_return is not None:
                ret = self._decomp_return
                self._decomp_return = None
                self._cur = ret
                self._active = "listing"
                self._open_entry(ret, push=False)
                self._status(f"{name} — decompile failed; back to the listing")
                return
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

    def on_listing_view_cursor_moved(self, msg: ListingView.CursorMoved) -> None:
        if self._nav:
            self._nav[-1].cursor = msg.index
            self._nav[-1].cursor_x = self.query_one(ListingView).cursor_x
            if msg.index >= 0:
                self._nav[-1].scroll_y = round(self.query_one(ListingView).scroll_offset.y)
        ea = msg.ea
        if ea is not None:
            sec = self.program.section_of(ea) if self.program else None
            self._status(f"{sec or '?'}  @ {ea:#x}   [listing]   "
                         "(c code · p func · u undefine · Enter follow)")

    # -- teardown ---------------------------------------------------------- #
    def on_unmount(self) -> None:
        if self._ka is not None:
            self._ka.stop()
        if self.program is not None:
            self.program.close()
        if self.client is not None:
            self.client.close()
