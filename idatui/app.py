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
from dataclasses import dataclass, field

from rich.align import Align
from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Provider
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.geometry import Region, Size
from textual.message import Message
from textual.reactive import reactive
from textual.theme import Theme
from textual.screen import ModalScreen
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import (
    DataTable, Input, OptionList, Static, TextArea,
)
from textual.widgets.option_list import Option

from .highlight import highlight_c

from .errors import IDAToolError, IDAConnectionError
from .worker_client import WorkerClient
from .domain import DisasmModel, Func, Head, ListingModel, Program, Struct

# Styles for the disassembly listing.
_S_ADDR = Style(color="#6b7684")
_S_LABEL = Style(color="#7aa2f7", bold=True)
_S_INSN = Style(color="#c3cad3")
#: IDA's token kinds -> the measured palette. The rule that keeps a dense
#: disassembly readable: NEUTRALS for the machine (mnemonic brightest because you
#: scan down that column, registers at body weight because they're most of the
#: text), HUES only where they mean something (numbers, strings, symbols),
#: structure recedes so brackets and commas stop competing with operands.
_S_SPAN = {
    "insn": Style(color="#e8ecf2"),      # 15.3:1  mnemonic / directive
    "reg": Style(color="#c3cad3"),       # 11.0:1  registers = body weight
    "num": Style(color="#d8a657"),       #  8.2:1  immediates, offsets
    "str": Style(color="#9ece6a"),       #  9.9:1  string literals
    "name": Style(color="#7aa2f7"),      #  7.2:1  symbols / xref targets
    "seg": Style(color="#93aee0"),       #  8.1:1  segment names
    "cmt": Style(color="#7c8b9e", italic=True),   # 5.2:1
    "punct": Style(color="#626c7a"),     #  3.4:1  brackets, commas, +/-
    "err": Style(color="#c9762f"),       #         IDA's own error marker
    "text": Style(color="#c3cad3"),      # 11.0:1  anything unclassified
}
_S_MNEM = Style(color="#e8ecf2")
_S_OPBYTES = Style(color="#5e6875")  # raw opcode bytes column
_S_DATA = Style(color="#d8a657")
_S_UNK = Style(color="#7c8b9e", italic=True)  # undefined bytes in the flat listing
_S_MEMBER = Style(color="#93aee0")
_S_SEP = Style(color="#5e6875")      # function boundary separators / banners
_S_FUNCHDR = Style(color="#7aa2f7", bold=True)  # 'name proc'/'endp' headers

_LST_INDENT = "    "   # one depth level: function names sit at level 0, code at 1
_OP_LIMIT = 8         # opcode bytes shown in the 'limited' column mode
_JUMP_CONTEXT = 4     # lines of context kept above a jump target (cursor stays on it)
_SPLIT_MIN_WIDTH = 100  # need room for two usable code panes side by side

# Tokens that look like identifiers but aren't renamable symbols (so 'n' on them
# in the listing names the address instead of trying to rename the token).
_ASM_KEYWORDS = frozenset({
    "db", "dw", "dd", "dq", "dt", "byte", "word", "dword", "qword", "tbyte",
    "offset", "short", "near", "far", "ptr", "dup", "cs", "ds", "es", "fs",
    "gs", "ss", "align", "public", "assume", "end",
})
_S_CURSOR = Style(bgcolor="#2a313c")
#: Execution trails. Deliberately faint: they sit UNDER the code palette and
#: must not compete with it — the trail says "you came through here", the text
#: still has to be readable as code. Now is the loudest because there is exactly
#: one of it.
_S_TRAIL_NOW = Style(bgcolor="#3f3410")
_S_TRAIL_PAST = Style(bgcolor="#2b1c17")     # warm: behind you
_S_TRAIL_FUTURE = Style(bgcolor="#152230")   # cool: ahead of you
#: Hex with a trace loaded: bytes the trace SAW at this timestamp vs bytes we're
#: still showing from the file. The distinction matters more than the values —
#: one is evidence, the other is an assumption.
_S_HEX_LIVE = Style(color="#9ece6a")
_S_HEX_STALE = Style(color="#5e6875")
_S_DIM = Style(color="#7c8b9e", italic=True)
_S_MATCH = Style(bgcolor="#7a5c00")  # all search matches
_S_MATCH_CUR = Style(bgcolor="#d0a215", color="#12161c")  # the current match
_S_NAME_MATCH = Style(bgcolor="#d0a215", color="#12161c")  # filter match in a name
_S_WORD = Style(bgcolor="#2a3f5f")  # identifier under the cursor
_S_CELL = Style(reverse=True)      # the block cursor cell
_S_LINENO = Style(color="#626c7a")             # pseudocode line-number gutter
_S_LINENO_CUR = Style(color="#c3cad3", bold=True)  # gutter on the cursor line
_S_DECOMP_SPIN = Style(color="#d0a215", bold=True)   # 'decompiling' spinner glyph
_S_DECOMP_WAIT = Style(color="#7c8b9e", italic=True)  # 'decompiling' label
_S_DECOMP_DOTS = Style(color="#626c7a")               # trailing ellipsis
_S_LINK = Style(bgcolor="#233044")  # split view: rows linked to the other pane's cursor

# Hex-Rays appends a `/*0xEA*/` address marker to each pseudocode line (we fetch
# with include_addresses so we have a per-line anchor). Matched here to extract
# the address and strip the marker from the display.
_ADDR_MARK_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/")
_ADDR_MARK_STRIP_RE = re.compile(r"\s*/\*\s*0x[0-9A-Fa-f]+\s*\*/")


@dataclass
class BinaryState:
    """Everything that makes one project binary's session resumable across a
    switch. Addresses outlive the worker, so nav history survives eviction; the
    Program/index only survive while that worker is still resident."""

    label: str
    program: object | None = None
    func_index: object | None = None
    nav: list = field(default_factory=list)
    cur: object | None = None
    active: str = "listing"
    split: bool = False
    filter_term: str = ""
    dirty: bool = False


@dataclass
class ViewAnchor:
    """Where the user is looking, expressed in ADDRESSES.

    Every path that rebuilds a model must round-trip through this. Row indices
    do NOT survive a rebuild: defining code collapses four undefined byte rows
    into one instruction row, undefining does the reverse, and a rename can add
    or remove banner rows above a function. Anything that remembers an index
    puts the user somewhere else afterwards, which reads as "the edit jumped my
    screen" or, worse, "the edit didn't apply".

    ``flash`` travels with it because the same rebuild also decides what the
    status bar says: the reload writes its own status when it lands, so an edit
    that doesn't hand its message over here gets silently overwritten.
    """

    view: str = "listing"
    ea: int | None = None          # cursor address
    top_ea: int | None = None      # first visible address
    cursor_x: int = 0
    flash: str | None = None
    #: The edit changed which functions exist, so the index must be rebuilt.
    refresh_functions: bool = False


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
# --------------------------------------------------------------------------- #
# Virtualized flat listing view (code + data + undefined, per segment)
# --------------------------------------------------------------------------- #
class ListingView(SearchMixin, NavMixin, ColumnCursor, ScrollView, can_focus=True):
    """A line-virtualized *flat* listing over one segment: code, data and
    undefined heads interleaved (IDA's disassembly view), unlike ``DisasmModel``
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
        Binding("home", "col_home", "bol", show=False),
        Binding("shift+home", "col_insn_home", "insn start", show=False),
        Binding("end", "col_end", "eol", show=False),
        Binding("G,ctrl+end", "goto_bottom", "Bottom", show=False),
        Binding("ctrl+home", "goto_top", "Top", show=False),
        Binding("o", "toggle_opcodes", "Opcodes"),
        Binding("c", "define_code", "Code", show=False),
        Binding("d", "make_data", "Data", show=False),
        Binding("a", "make_string", "Str", show=False),
        Binding("p", "define_func", "Func", show=False),
        Binding("u", "undefine", "Undef", show=False),
        Binding("t", "toggle_thumb", "ARM/Thumb", show=False),
        Binding("T", "thumb_scan", "Scan vectors", show=False),
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

    class Scrolled(Message):
        """Posted when the viewport scrolls (wheel/scrollbar) — the cursor need
        not have moved, so the split view can still follow along."""

    def __init__(self) -> None:
        super().__init__()
        self.model: ListingModel | None = None
        self.total = 0
        self._name = ""
        self._pending_scroll_y: int | None = None
        self._pending_focus: str | None = None
        self._term = ""
        self._matches: list[int] = []
        self._ranges: dict[int, list[tuple[int, int]]] = {}
        self._op_mode = 1       # opcode column: 0=off, 1=limited, 2=full ('o' cycles)
        self._op_w = 0          # char width of the hex-bytes field (excl. gap)
        self._search_loading = False
        self._search_pending: list = []  # done-callbacks awaiting the load
        self._link_rows: set[int] = set()  # split-view: linked instruction rows
        #: {address: 'now'|'past'|'future'} painted under the code (trace mode).
        self.trail: dict[int, str] = {}

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

    @staticmethod
    def _span_segments(h: Head, fallback: Style):
        """Segments for a row's disassembly text.

        Uses IDA's own token classification when the worker supplied it; falls
        back to the old mnemonic/rest split so an older worker (or a row whose
        spans didn't match the text) still renders.
        """
        if h.spans:
            return [Segment(t, _S_SPAN.get(k, fallback)) for k, t in h.spans]
        if h.kind == "code":
            mnem, _, rest = h.text.partition(" ")
            segs = [Segment(mnem, _S_MNEM)]
            if rest:
                segs.append(Segment(" " + rest, fallback))
            return segs
        return [Segment(h.text, fallback)]

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

    def _insn_col(self, idx: int) -> int:
        """Column where the instruction/content text begins, past the address +
        opcode-bytes gutter — the shift+home target. Mirrors ``_line_plain``'s
        prefix so the column lines up with what's rendered."""
        h = self._head(idx)
        if h is None:
            return 0
        if h.kind in ("funchdr", "label"):
            return len(f"{h.ea:08X}  ")
        base = f"{h.ea:08X}  " + _LST_INDENT
        if h.kind == "sep":
            return len(base)
        extra = _LST_INDENT if h.kind == "member" else ""
        return len(base + self._op_field(h) + extra + self._name_prefix(h))

    def action_col_insn_home(self) -> None:
        """shift+home: jump to the start of the instruction text, skipping the
        address + opcode-bytes gutter (home/0 still go to the true line start)."""
        self.cursor_x = self._insn_col(self.cursor)
        self._hscroll()
        _refresh_lines(self, self.cursor)
        self._refresh_hl()

    # -- public API -------------------------------------------------------- #
    def load(self, model: ListingModel, name: str, cursor: int = 0,
             cursor_x: int = 0, scroll_y: int | None = None,
             focus: str | None = None) -> None:
        self.model = model
        self._name = name
        self.total = 0
        self.cursor = cursor
        self.cursor_x = cursor_x
        self._pending_scroll_y = scroll_y
        self._pending_focus = focus  # token to land the cursor column on
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
        self._update_op_w()  # finalize column layout before locating the token
        # Land the cursor on the requested token's column (e.g. the ref an xref
        # jump targets), now that the row is loaded and renderable.
        if self._pending_focus:
            plain = self._line_plain(self.cursor)
            if plain:
                occ = _word_occurrences(plain, self._pending_focus)
                if occ:
                    self.cursor_x = occ[0][0]
            self._pending_focus = None
        self._clamp_x()
        if self._pending_scroll_y is not None and self._pending_scroll_y >= 0:
            self._apply_scroll(min(self._pending_scroll_y, max(total - 1, 0)))
        else:
            self._scroll_cursor_into_view()
        self._pending_scroll_y = None
        self._hscroll()  # bring the cursor column into horizontal view
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
            if h.kind == "member":
                segs.append(Segment(h.text, _S_MEMBER))
            else:
                base = {"code": _S_INSN, "data": _S_DATA}.get(h.kind, _S_UNK)
                segs.extend(self._span_segments(h, base))
            strip = Strip(segs)
        linked = idx in self._link_rows
        if linked:
            strip = strip.apply_style(_S_LINK)  # split-view companion band
        if self.trail and h is not None:
            kind = self.trail.get(h.ea)
            if kind is not None:
                strip = strip.apply_style(
                    _S_TRAIL_NOW if kind == "now" else
                    _S_TRAIL_PAST if kind == "past" else _S_TRAIL_FUTURE)
        plain = self._line_plain(idx) if (self._hl_word or idx == self.cursor) else None
        if idx in self._ranges:
            strip = _overlay_ranges(strip, self._ranges[idx], self._match_style(idx))
        if self._hl_word and plain:
            occ = _word_occurrences(plain, self._hl_word)
            if occ:
                strip = _overlay_ranges(strip, occ, _S_WORD)
        if idx == self.cursor:
            strip = _cursor_decorate(strip, plain or "", self.cursor_x)
        return strip.adjust_cell_length(width, _S_LINK if linked else _S_INSN)

    # -- split-view link highlight ---------------------------------------- #
    def set_link(self, rows) -> None:
        rows = set(rows) if rows else set()
        if rows != self._link_rows:
            self._link_rows = rows
            self.refresh()

    def reveal(self, row: int) -> None:
        """Scroll ``row`` into view without moving the cursor (companion pane)."""
        height = self._visible_height()
        top = round(self.scroll_offset.y)
        if row < top or row >= top + height:
            self.scroll_to(y=max(row - height // 3, 0), animate=False)

    def align(self, row: int, screen_row: int) -> None:
        """Scroll so ``row`` sits at viewport offset ``screen_row`` — keeps this
        (companion) pane visually level with the driver's cursor in split view.
        Clamps at the ends, so alignment is best-effort near the edges."""
        top = max(0, min(row - max(screen_row, 0), max(self.total - 1, 0)))
        if top != round(self.scroll_offset.y):
            self.scroll_to(y=top, animate=False)

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        super().watch_scroll_y(old_value, new_value)
        if round(old_value) != round(new_value):
            self.post_message(ListingView.Scrolled())

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

    def action_toggle_thumb(self) -> None:
        self.post_message(EditItemRequested(self, "thumb"))

    def action_thumb_scan(self) -> None:
        self.post_message(EditItemRequested(self, "thumbscan"))

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
class _DecompLoading(Static):
    """Animated cover shown over the pseudocode pane while a (re)decompile runs.
    A braille spinner + label, dim over the grayed-out code — fits the muted TUI
    palette (no ASCII-bar noise)."""

    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, **kwargs) -> None:
        self._i = 0
        super().__init__(self._label(), **kwargs)

    def _label(self) -> Text:
        t = Text(justify="center")
        t.append(self._FRAMES[self._i], _S_DECOMP_SPIN)
        t.append("  decompiling", _S_DECOMP_WAIT)
        t.append("…", _S_DECOMP_DOTS)
        return t

    def on_mount(self) -> None:
        self.set_interval(1 / 12, self._tick)

    def _tick(self) -> None:
        self._i = (self._i + 1) % len(self._FRAMES)
        self.update(self._label())


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
        # Home/End move the cursor along the line (as in the listing); top and
        # bottom of the function move to the ctrl+ pair (G still works too).
        Binding("home", "col_home", "bol", show=False),
        Binding("shift+home", "col_code_home", "code start", show=False),
        Binding("end", "col_end", "eol", show=False),
        Binding("ctrl+home", "goto_top", "Top", show=False),
        Binding("G,ctrl+end", "goto_bottom", "Bottom", show=False),
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

    class Scrolled(Message):
        """Posted when the viewport scrolls (wheel/scrollbar) — the cursor need
        not have moved, so the split view can still follow along."""

    def __init__(self) -> None:
        super().__init__(id="decomp")
        self.loaded_ea: int | None = None
        self._strips: list[Strip] = []
        self._texts: list[str] = []
        self._gutter = 0  # line-number gutter width (cells)
        self._line_eas: list[int | None] = []  # per-line address (marker stripped)
        self._link_line: int | None = None  # split-view: linked pseudocode line
        #: {line index: 'now'|'past'|'future'} — the execution trail, mapped from
        #: instructions onto pseudocode via decomp_map.
        self.trail: dict[int, str] = {}
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
            # Always baseline the horizontal scroll at 0 for a jump, then scroll
            # right only if the target column falls outside the viewport — never
            # keep a stale horizontal offset from wherever we were before.
            sx = 0
            if self.cursor_x >= sx + width:
                scroll_x = self.cursor_x - width + 1
            else:
                scroll_x = sx
        self._apply_scroll(min(max(scroll_y, 0), max(total - 1, 0)), max(scroll_x, 0))
        # `cursor` is reactive(repaint=False) and _apply_scroll only repaints via
        # call_after_refresh, so a jump that lands in the SAME viewport (Esc back
        # to another spot in the function already on screen) moved the cursor
        # with nothing to redraw it — the pane kept showing the old highlight
        # until the next keypress. Repaint here; _move does the same via
        # _refresh_lines.
        self.refresh()
        self._after_cursor_move()

    def get_loading_widget(self):  # type: ignore[override]
        # Shown (grayed, centered) while a (re)decompile is in flight.
        return _DecompLoading(classes="decomp-loading")

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
        linked = idx == self._link_line
        base = self._strips[idx]
        if linked:
            base = base.apply_style(_S_LINK)  # split-view companion band
        kind = self.trail.get(idx) if self.trail else None
        if kind is not None:
            base = base.apply_style(
                _S_TRAIL_NOW if kind == "now" else
                _S_TRAIL_PAST if kind == "past" else _S_TRAIL_FUTURE)
        if idx in self._ranges:
            base = _overlay_ranges(base, self._ranges[idx], self._match_style(idx))
        if self._hl_word:
            occ = _word_occurrences(self._texts[idx], self._hl_word)
            if occ:
                base = _overlay_ranges(base, occ, _S_WORD)
        if idx == self.cursor:
            base = _cursor_decorate(base, self._texts[idx], self.cursor_x)
        code_w = max(width - gw, 0)
        code = base.crop(x, x + code_w).adjust_cell_length(
            code_w, _S_LINK if linked else None)
        if gw <= 0:
            return code
        style = _S_LINENO_CUR if idx == self.cursor else _S_LINENO
        if linked:
            style = style + _S_LINK
        gutter = Strip([Segment(f"{idx + 1:>{gw - 1}} ", style)])
        return Strip.join([gutter, code]).adjust_cell_length(width)

    # -- split-view link highlight ---------------------------------------- #
    def set_link(self, line: int | None) -> None:
        if line != self._link_line:
            self._link_line = line
            self.refresh()

    def reveal(self, line: int) -> None:
        """Scroll ``line`` into view without moving the cursor (companion pane)."""
        height = self._visible_height()
        top = round(self.scroll_offset.y)
        if line < top or line >= top + height:
            self.scroll_to(y=max(line - height // 3, 0), animate=False)

    def align(self, line: int, screen_row: int) -> None:
        """Scroll so ``line`` sits at viewport offset ``screen_row`` — keeps this
        (companion) pane visually level with the driver's cursor in split view."""
        top = max(0, min(line - max(screen_row, 0), max(len(self._strips) - 1, 0)))
        if top != round(self.scroll_offset.y):
            self.scroll_to(y=top, animate=False)

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        super().watch_scroll_y(old_value, new_value)
        if round(old_value) != round(new_value):
            self.post_message(DecompView.Scrolled())

    def action_col_code_home(self) -> None:
        """shift+home: first non-blank column — past the C indentation, the
        pseudocode analogue of the listing's skip-the-address-gutter."""
        text = self._line_plain(self.cursor) or ""
        self.cursor_x = len(text) - len(text.lstrip()) if text.strip() else 0
        self._hscroll()
        _refresh_lines(self, self.cursor)
        self._refresh_hl()

    def line_for_ea(self, ea: int) -> int | None:
        """The pseudocode line whose marker ea is the largest <= ``ea`` (the C
        line that best covers an instruction address)."""
        best, best_ea = None, -1
        for i, e in enumerate(self._line_eas):
            if e is not None and best_ea < e <= ea:
                best, best_ea = i, e
        return best

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
_S_HEX = Style(color="#c3cad3")
_S_ASCII = Style(color="#9ece6a")
_S_FOFF = Style(color="#d8a657")


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
        #: Trace to read memory from, and the timestamp to read it at. When set,
        #: the dump shows what memory HELD then rather than what the file holds.
        self.trace = None
        self.trace_idx = 0
        self._internal_top: int | None = None  # scroll target we set ourselves

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
        if round(self.scroll_offset.y) != y:
            self._internal_top = y  # cursor-driven scroll incoming; don't follow it

        def _fix(yy: int = y) -> None:
            if round(self.scroll_offset.y) != yy:
                self._internal_top = yy
            self.scroll_to(y=yy, animate=False)
            self.refresh(layout=True)

        self.scroll_to(y=y, animate=False)
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

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        super().watch_scroll_y(old_value, new_value)
        if round(old_value) == round(new_value):
            return
        nt = round(new_value)
        if self._internal_top is not None and nt == self._internal_top:
            self._internal_top = None  # our cursor-driven scroll: cursor already placed
            return
        # A user scroll (wheel / scrollbar): drag the cursor by the same row delta
        # so its screen position stays frozen (it points at a new byte in place).
        self._internal_top = None
        self._shift_cursor(nt - round(old_value))

    def _shift_cursor(self, rows: int) -> None:
        if not rows or self.model is None or self.model.size == 0:
            return
        new = max(0, min(self.cursor + rows * 16, self.model.size - 1))
        if new != self.cursor:
            self.cursor = new
            self.refresh()  # cursor is reactive(repaint=False)
            self.post_message(HexView.Moved(self.cursor_va()))

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

    # -- mouse ------------------------------------------------------------- #
    def _byte_at_x(self, x: int) -> int:
        """Map a content column to a byte index 0..15, across the hex and ASCII
        panes. Matches ``render_line``'s layout: addr(9) + file-offset(10) + 16
        hex cells of 3 cols (with a 1-col gap before byte 8), then ' |' + ASCII."""
        HEX, ASCII = 19, 70
        if x < HEX:                 # clicked the address/offset gutter -> row start
            return 0
        if x < HEX + 49:            # hex byte region
            rel = x - HEX
            if rel >= 24:           # collapse the 1-col gap between the two halves
                rel -= 1
            return min(rel // 3, 15)
        if x < ASCII:               # the ' |' separator -> last byte of the row
            return 15
        return min(x - ASCII, 15)   # ASCII pane (and anything past it)

    def on_click(self, event) -> None:  # type: ignore[no-untyped-def]
        if self.model is None or self.model.size == 0:
            return
        off = event.get_content_offset(self)
        if off is None:
            return
        self.focus()
        row = round(self.scroll_offset.y) + off.y
        x = round(self.scroll_offset.x) + off.x
        new = row * 16 + self._byte_at_x(x)
        self.cursor = max(0, min(self.model.size - 1, new))
        self.refresh()  # cursor is reactive(repaint=False); repaint the highlight
        self.post_message(HexView.Moved(self.cursor_va()))
        if event.chain >= 2:  # double-click == place cursor + jump to code
            self.post_message(HexView.ToCode(self.cursor_va()))

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
        # With a trace loaded the row shows what memory HELD at the current
        # timestamp, not what the file contains. Only the bytes the trace
        # actually saw are overlaid: the rest stay the database's, dimmed, so
        # you can always tell evidence from the file's idea of the world.
        tmem = tknown = None
        if self.trace is not None and data is not None:
            tmem, tknown = self.trace.memory(va, len(data), self.trace_idx)
            if not any(tknown):
                tmem = tknown = None
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
                    live = tknown is not None and tknown[i]
                    val = tmem[i] if live else data[i]
                    if r == cur_row and i == cur_col:
                        st = _S_CELL
                    elif tknown is None:
                        st = _S_HEX
                    else:
                        st = _S_HEX_LIVE if live else _S_HEX_STALE
                    segs.append(Segment(f"{val:02X} ", st))
                else:
                    segs.append(Segment("   ", _S_HEX))
            segs.append(Segment(" |", _S_DIM))
            for i in range(16):
                if i < n:
                    live = tknown is not None and tknown[i]
                    val = tmem[i] if live else data[i]
                    ch = chr(val) if 32 <= val < 127 else "."
                    if r == cur_row and i == cur_col:
                        st = _S_CELL
                    elif tknown is None:
                        st = _S_ASCII
                    else:
                        st = _S_HEX_LIVE if live else _S_HEX_STALE
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

    def __init__(self, label: str, items: list[tuple[object, str]],
                 preselect: int = 0) -> None:
        # payload is an int address, or (binary, address) for a caller in another
        # project binary; dismiss() hands it back untouched.
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
    # Case-insensitive means BOTH sides: the name was lowered but the query
    # wasn't, so a single capital could never match and any query containing one
    # returned nothing at all. Invisible on lowercase C symbols (main, strlen),
    # fatal on libraries that capitalise — "PEM_read_bio" found 0 of 10093
    # functions in libcrypto while the backend resolved it fine.
    ql = q.lower()
    pos: list[int] = []
    i = 0
    for ch in ql:
        j = nl.find(ch, i)
        if j < 0:
            return None
        pos.append(j)
        i = j + 1
    span = pos[-1] - pos[0]
    score = -(span * 2.0) - pos[0] - len(name) * 0.01
    if ql in nl:
        score += 50.0
    if nl.startswith(ql):
        score += 100.0
    return (score, tuple(pos))


class SymbolPalette(ModalScreen):
    """A command-palette overlay: type to fuzzy-find a symbol, Enter opens it."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("down,ctrl+n", "cursor_down", show=False),
        Binding("up,ctrl+p", "cursor_up", show=False),
        # F2, not ctrl+a: the focused Input binds "home,ctrl+a" so it would never
        # reach us. Function keys are untouched by Input.
        Binding("f2", "scope", "This binary / whole project", show=False),
    ]
    LIMIT = 200
    #: Project scope nearly always saturates its cap (every binary contributes),
    #: where a local filter usually returns a handful. Keep the list short so
    #: arrowing through it stays snappy; narrow further by typing.
    PROJECT_LIMIT = 60

    def __init__(self, funcs: list[Func], index=None, binary=None) -> None:
        super().__init__()
        self._funcs = funcs
        self._index = index      # ProjectIndex, when this is a project
        self._binary = binary    # label of the binary we're currently in
        self._project_scope = False
        #: (binary|None, addr, name) — binary is None for a local hit
        self._results: list[tuple] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="pal-box"):
            yield Static(" symbols", id="pal-title", markup=False)
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

    def action_scope(self) -> None:
        if self._index is None:
            return  # not a project: nothing else to search
        self._project_scope = not self._project_scope
        self._apply(self.query_one("#pal-input", Input).value.strip())

    def _apply(self, query: str) -> None:
        # rows: (binary|None, addr, name, match positions)
        if self._project_scope and self._index is not None:
            from .index import KIND_FUNC
            # The trigram index already guarantees every hit CONTAINS the query,
            # so ranking only has to order them — an exact-substring rank (match
            # position, then name length) costs a find() per row instead of a
            # full fuzzy pass, and fetching 3x the display limit rather than 10x
            # keeps the per-keystroke work down on a big project.
            hits = self._index.search(query, kind=KIND_FUNC,
                                      limit=self.PROJECT_LIMIT * 3) if query else []
            q = query.lower()
            scored = []
            for h in hits:
                at = h.text.lower().find(q)
                scored.append((at if at >= 0 else 1 << 30, len(h.text), h.text, h))
            # Sort on an explicit key: the same symbol name in two binaries ties
            # on (position, length, text), and a bare sort() would then fall
            # through to comparing Hit objects, which aren't orderable.
            scored.sort(key=lambda t: (t[0], t[1], t[2], t[3].binary, t[3].addr))
            rows = [(h.binary, h.addr, h.text,
                     tuple(range(at, at + len(q))) if at < (1 << 30) else ())
                    for at, _, _, h in scored[:self.PROJECT_LIMIT]]
        elif query:
            scored = []
            for f in self._funcs:
                m = _fuzzy(f.name, query)
                if m is not None:
                    scored.append((m[0], m[1], f))
            scored.sort(key=lambda t: (-t[0], t[2].name))
            rows = [(None, f.addr, f.name, pos) for _, pos, f in scored[:self.LIMIT]]
        else:
            rows = [(None, f.addr, f.name, ()) for f in self._funcs[:self.LIMIT]]
        self._results = [(b, a, n) for b, a, n, _ in rows]
        ol = self.query_one(OptionList)
        ol.clear_options()
        opts = []
        for binary, addr, name, pos in rows:
            label = Text()
            if binary:
                label.append(f"{binary:<14.14} ", _S_LABEL)
            label.append(f"{addr:08X}  ", _S_ADDR)
            nm = Text(name)
            for p in pos:
                if p < len(name):
                    nm.stylize(_S_NAME_MATCH, p, p + 1)
            label.append_text(nm)
            opts.append(Option(label))
        ol.add_options(opts)
        if self._results:
            ol.highlighted = 0
        scope = "project" if self._project_scope else "this binary"
        cap = self.PROJECT_LIMIT if self._project_scope else self.LIMIT
        more = "+" if len(self._results) == cap else ""
        hint = "  (F2: this binary)" if self._project_scope else (
            "  (F2: whole project)" if self._index is not None else "")
        self.query_one("#pal-title", Static).update(
            f" symbols [{scope}]: {len(self._results)}{more}{hint}")

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
            b, a, _ = self._results[i]
            self.dismiss((b, a))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if 0 <= event.option_index < len(self._results):
            b, a, _ = self._results[event.option_index]
            self.dismiss((b, a))

    def action_close(self) -> None:
        self.dismiss(None)


def _str_display(text: str, limit: int = 200) -> str:
    """One-line, printable rendering of a string literal for the browser: escape
    the common control chars, drop the rest, and clip long bodies."""
    out = (text.replace("\\", "\\\\").replace("\n", "\\n")
               .replace("\r", "\\r").replace("\t", "\\t"))
    out = "".join(ch if ch.isprintable() else "." for ch in out)
    return out[:limit] + ("\u2026" if len(out) > limit else "")


class StringsPalette(ModalScreen):
    """Every string in the binary (IDA's Shift+F12), filterable; Enter jumps to
    it in the unified listing."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("down,ctrl+n", "cursor_down", show=False),
        Binding("up,ctrl+p", "cursor_up", show=False),
        Binding("f2", "scope", "This binary / whole project", show=False),
    ]
    LIMIT = 500
    #: Project scope saturates its cap (every binary contributes); keep the list
    #: short so arrowing stays snappy.
    PROJECT_LIMIT = 60

    def __init__(self, strings: list, index=None, binary=None) -> None:
        super().__init__()
        # Pre-render + pre-lower once: filtering runs on every keystroke and a
        # big binary has tens of thousands of strings.
        self._rows = [(s, d, d.lower())
                      for s in strings for d in (_str_display(s.text),)]
        self._index = index      # ProjectIndex, when this is a project
        self._binary = binary
        self._project_scope = False
        #: (binary|None, addr, display text) — binary is None for a local hit
        self._results: list[tuple] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="pal-box"):
            yield Static(" strings", id="pal-title", markup=False)
            yield Input(placeholder="filter strings\u2026  \u2191\u2193 select \u00b7 "
                                    "Enter jump \u00b7 Esc close", id="pal-input")
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

    def action_scope(self) -> None:
        if self._index is None:
            return  # not a project: nothing else to search
        self._project_scope = not self._project_scope
        self._apply(self.query_one("#pal-input", Input).value.strip())

    def _apply(self, query: str) -> None:
        q = query.lower()
        # rows: (binary|None, addr, length, display text, match offset)
        if self._project_scope and self._index is not None:
            from .index import KIND_STRING
            hits = self._index.search(query, kind=KIND_STRING,
                                      limit=self.PROJECT_LIMIT * 3) if query else []
            rows = []
            for h in hits:
                disp = _str_display(h.text)
                rows.append((h.binary, h.addr, len(h.text), disp,
                             disp.lower().find(q)))
            # the index already guarantees a match, so ranking only orders them:
            # earliest match, then shortest, with a stable (binary, addr) tiebreak
            # (a literal shared by two binaries would otherwise be unordered).
            rows.sort(key=lambda r: (r[4] if r[4] >= 0 else 1 << 30,
                                     r[2], r[0], r[1]))
            rows = rows[:self.PROJECT_LIMIT]
        else:
            rows = []
            for s, disp, low in self._rows:
                hit = low.find(q) if q else -1
                if q and hit < 0:
                    continue
                rows.append((None, s.addr, s.length, disp, hit))
                if len(rows) >= self.LIMIT:
                    break
        self._results = [(b, a, d) for b, a, _, d, _ in rows]
        ol = self.query_one(OptionList)
        ol.clear_options()
        opts = []
        for binary, addr, length, disp, hit in rows:
            label = Text()
            if binary:
                label.append(f"{binary:<14.14} ", _S_LABEL)
            label.append(f"{addr:08X}  ", _S_ADDR)
            label.append(f"{length:>5}  ", _S_DIM)
            body = Text(disp)
            if hit >= 0:
                body.stylize(_S_NAME_MATCH, hit, hit + len(q))
            label.append_text(body)
            opts.append(Option(label))
        ol.add_options(opts)
        if self._results:
            ol.highlighted = 0
        scope = "project" if self._project_scope else "this binary"
        cap = self.PROJECT_LIMIT if self._project_scope else self.LIMIT
        more = "+" if len(rows) == cap else ""
        hint = "  (F2: this binary)" if self._project_scope else (
            "  (F2: whole project)" if self._index is not None else "")
        self.query_one("#pal-title", Static).update(
            f" strings [{scope}]: {len(self._results)}{more} of {len(self._rows)}{hint}")

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
            b, a, _ = self._results[i]
            self.dismiss((b, a))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if 0 <= event.option_index < len(self._results):
            b, a, _ = self._results[event.option_index]
            self.dismiss((b, a))

    def action_close(self) -> None:
        self.dismiss(None)


#: The keyboard cheatsheet (F1). Grouped by task rather than by widget, which is
#: what makes it readable; keep it in step with the BINDINGS above it.
_HELP = (
    ("Navigate", (
        ("Enter", "follow the symbol under the cursor"),
        ("Esc", "back (navigation history)"),
        ("g", "goto address or symbol"),
        ("Ctrl+N", "find symbol (fuzzy)"),
        ("\"", "strings browser"),
        ("x", "cross-references to the symbol"),
        ("L", "continuous listing at the cursor"),
        ("Ctrl+O", "switch binary (projects)"),
    )),
    ("Views", (
        ("Tab / F5", "disassembly \u21c4 pseudocode"),
        ("s", "split view: listing + pseudocode"),
        ("Tab", "in split: switch the driving pane"),
        ("\\", "hex view"),
        ("o", "cycle the opcode-bytes column"),
        ("Ctrl+B", "show/hide the names pane"),
        ("Ctrl+T", "structs / types editor"),
        ("Ctrl+P", "command palette"),
    )),
    ("Move", (
        ("j / k", "down / up"),
        ("Ctrl+D / Ctrl+U", "half page down / up"),
        ("PgDn / PgUp", "page down / up"),
        ("Ctrl+Home / Ctrl+End", "top / bottom (G also)"),
        ("Home / End", "start / end of line"),
        ("Shift+Home", "start of the instruction / code"),
        ("h / l", "column left / right"),
        ("w / b", "word forward / back"),
    )),
    ("Edit", (
        ("n", "rename"),
        ("y", "set type (prototype, local or global)"),
        (";", "comment"),
        ("c", "make code"),
        ("p", "make function"),
        ("d", "make data"),
        ("a", "make string"),
        ("u", "undefine"),
        ("Ctrl+S", "save the database"),
    )),
    ("Search", (
        ("/", "search forward (repeat to continue)"),
        ("?", "search backward"),
        ("N", "previous match"),
        ("Ctrl+Y", "copy the current line"),
        ("F1", "this cheatsheet"),
        ("q", "quit"),
    )),
)


class QuitScreen(ModalScreen):
    """Asked before exiting with unsaved database changes. Dismisses with
    "save", "discard" or None (stay)."""

    BINDINGS = [
        Binding("s", "save", "Save & quit"),
        Binding("d", "discard", "Discard & quit"),
        Binding("escape,c", "cancel", "Cancel"),
    ]

    def __init__(self, labels: list[str]) -> None:
        super().__init__()
        self._labels = labels

    def compose(self) -> ComposeResult:
        what = (f"{len(self._labels)} databases have unsaved changes"
                if len(self._labels) > 1 else "unsaved changes")
        with Vertical(id="quit-box"):
            yield Static(f"\u26a0  {what}", id="quit-title")
            body = Text()
            for label in self._labels:
                body.append(f"  \u2022 {label}\n", _S_LABEL)
            yield Static(body, id="quit-list")
            yield Static("s  save & quit      d  discard & quit      Esc  cancel",
                         id="quit-help")

    def action_save(self) -> None:
        self.dismiss("save")

    def action_discard(self) -> None:
        self.dismiss("discard")

    def action_cancel(self) -> None:
        self.dismiss(None)


class HelpScreen(ModalScreen):
    """F1: the keyboard cheatsheet, replacing the permanent footer."""

    BINDINGS = [Binding("escape,f1,q,question_mark", "close", "Close")]

    #: widest cell content, +2 for the card's border, +2 for its padding
    _CARD_PAD = 4

    def compose(self) -> ComposeResult:
        # Fluid: as many columns as the terminal can hold. Textual CSS has no
        # media queries, so the split is computed here from the real width.
        avail = max(self.app.size.width - 6, 20)
        cols = self._columns(avail)
        per = -(-len(_HELP) // cols)  # ceil, so the columns stay balanced
        with Vertical(id="help-box"):
            yield Static(" keys", id="help-title", markup=False)
            # Still inside a scroll container, so a genuinely tiny terminal
            # degrades to scrolling rather than clipping — but spread across the
            # width it shouldn't come to that.
            with VerticalScroll(id="help-body"):
                with Horizontal(id="help-cols"):
                    for c in range(cols):
                        chunk = _HELP[c * per:(c + 1) * per]
                        if not chunk:
                            continue
                        with Vertical(classes="help-col"):
                            for title, rows in chunk:
                                card = Static(self._card(rows),
                                              classes="help-card", markup=False)
                                card.border_title = title
                                yield card
            yield Static("Esc / F1 to close", id="help-foot")

    @staticmethod
    def _section_widths() -> list[int]:
        """Rendered width of each section's card (keys right-aligned per card)."""
        out = []
        for _, rows in _HELP:
            kw = max(len(k) for k, _ in rows)
            out.append(max(kw + 2 + len(d) for _, d in rows) + HelpScreen._CARD_PAD)
        return out

    @classmethod
    def _columns(cls, avail: int) -> int:
        """Most columns that actually fit in ``avail``.

        Sizing off the widest section would let one long row (Move's
        "Ctrl+Home / Ctrl+End") inflate every column and cost a column that would
        otherwise fit. Each column hugs its own content, so measure the real
        layout: chunk the sections and sum the per-chunk maxima.
        """
        ws = cls._section_widths()
        n = len(ws)
        for cols in range(min(n, 4), 1, -1):
            per = -(-n // cols)
            chunks = [ws[c * per:(c + 1) * per] for c in range(cols)]
            total = sum(max(c) for c in chunks if c) + (cols - 1)
            if total <= avail:
                return cols
        return 1

    @staticmethod
    def _card(rows) -> Text:  # NB: not _render — that's a Widget internal
        """One section's keys. The key column is sized per section, so a card of
        short keys stays narrow instead of padding out to the global maximum."""
        width = max(len(k) for k, _ in rows)
        out = Text()
        for i, (key, desc) in enumerate(rows):
            if i:
                out.append("\n")
            out.append(f"{key:>{width}}", _S_MNEM)
            out.append(f"  {desc}", _S_INSN)
        return out

    def action_close(self) -> None:
        self.dismiss(None)


class RegWriteScreen(ModalScreen):
    """Registers, and the instruction that set each one.

    "Which instruction set this register to its current value?" is the question
    a trace exists to answer, and seeking backwards to it is a single keypress
    here rather than a manual walk. Forward is offered too, but backward is what
    people actually want — you notice a bad value after it has been used.
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("down,ctrl+n", "cursor_down", show=False),
        Binding("up,ctrl+p", "cursor_up", show=False),
        Binding("enter", "choose", show=False, priority=True),
        Binding("f", "choose_forward", show=False),
    ]

    def __init__(self, rows, idx: int) -> None:
        super().__init__()
        self._rows = rows          # (name, value, last_write, next_write)
        self._idx = idx

    def compose(self) -> ComposeResult:
        with Vertical(id="pal-box"):
            yield Static(f" registers at t={self._idx:,} \u2014 Enter seeks to the "
                         f"write, f seeks forward", id="pal-title", markup=False)
            yield OptionList(id="pal-list")

    def on_mount(self) -> None:
        ol = self.query_one(OptionList)
        opts = []
        for name, val, last, nxt in self._rows:
            label = Text()
            label.append(f" {name:>4} ", _S_MNEM)
            label.append(f"{val:#018x}  " if val > 0xFFFFFFFF else f"{val:#010x}  ",
                         _S_INSN)
            if last is None:
                label.append("never written in this trace", _S_DIM)
            elif last == self._idx:
                label.append("set by THIS instruction", _S_DATA)
            else:
                label.append(f"set at t={last:,}", _S_LABEL)
                label.append(f"  ({self._idx - last:,} steps back)", _S_DIM)
            if nxt is not None:
                label.append(f"   next t={nxt:,}", _S_DIM)
            opts.append(Option(label))
        ol.add_options(opts)
        ol.highlighted = 0
        ol.focus()

    def action_cursor_down(self) -> None:
        ol = self.query_one(OptionList)
        if ol.option_count:
            ol.highlighted = min((ol.highlighted or 0) + 1, ol.option_count - 1)

    def action_cursor_up(self) -> None:
        ol = self.query_one(OptionList)
        if ol.option_count:
            ol.highlighted = max((ol.highlighted or 0) - 1, 0)

    def _pick(self, forward: bool) -> None:
        i = self.query_one(OptionList).highlighted
        if i is None or not (0 <= i < len(self._rows)):
            self.dismiss(None)
            return
        _name, _val, last, nxt = self._rows[i]
        self.dismiss(nxt if forward else last)

    def action_choose(self) -> None:
        self._pick(False)

    def action_choose_forward(self) -> None:
        self._pick(True)

    def on_option_list_option_selected(self, event) -> None:  # type: ignore[no-untyped-def]
        self._pick(False)

    def action_close(self) -> None:
        self.dismiss(None)


class TraceDock(Vertical):
    """Registers and a timeline for the loaded execution trace, docked right.

    Persistent rather than a modal: a trace turns every other view into "state
    at time T", so the time and the registers are context you read WHILE looking
    at code, not something you open and dismiss.
    """

    def __init__(self) -> None:
        super().__init__(id="trace-dock")
        self.trace = None
        self.idx = 0

    def compose(self) -> ComposeResult:
        yield Static("", id="trace-head", markup=False)
        yield Static("", id="trace-regs", markup=False)
        yield Static("", id="trace-stack", markup=False)
        yield TraceTimeline(id="trace-timeline")

    def show(self, trace, idx: int) -> None:
        self.trace = trace
        self.idx = idx
        tl = self.query_one(TraceTimeline)
        tl.trace, tl.idx = trace, idx
        self.refresh_state()

    def refresh_state(self) -> None:
        t = self.trace
        if t is None:
            return
        n = max(t.length, 1)
        pct = (self.idx + 1) * 100.0 / n
        head = Text()
        head.append(f" {self.idx:,}", _S_MNEM)
        head.append(f" / {t.length - 1:,}  ", _S_DIM)
        head.append(f"{pct:5.1f}%\n", _S_ADDR)
        # Register values are machine state and stay as the trace recorded them,
        # but everything else on screen is in database addresses. Showing both
        # here explains the relationship once, where it's read, instead of
        # leaving "pc 0x2aed" next to "rip 0x7ffff6faaaed" to be puzzled over.
        head.append(f" pc {t.ip(self.idx):#x}", _S_LABEL)
        if t.slide:
            head.append(f"  (trace {t.raw_ip(self.idx):#x})", _S_DIM)
        self.query_one("#trace-head", Static).update(head)

        # Registers, with the ones THIS instruction wrote called out: that
        # difference is the entire reason a delta trace is readable.
        changed = t.changed(self.idx)
        body = Text()
        pc = t.pc_name
        for name in t.registers:
            v = t.register(name, self.idx)
            if v is None:
                continue
            hot = name in changed
            body.append(f" {name:>4} ", _S_MNEM if hot else _S_DIM)
            body.append(f"{v:#018x}\n" if v > 0xFFFFFFFF else f"{v:#010x}\n",
                        _S_DATA if hot else (_S_LABEL if name == pc else _S_INSN))
        self.query_one("#trace-regs", Static).update(body)
        self._render_stack(t)
        tl = self.query_one(TraceTimeline)
        tl.idx = self.idx
        tl.refresh()


    STACK_WORDS = 8

    def _render_stack(self, t) -> None:  # type: ignore[no-untyped-def]
        """The stack as of this instant, read out of the trace.

        This is where a trace's memory actually is: on two real traces, NONE of
        the accesses fell inside the image — every one was stack or heap. A
        memory view that could only address the image would have nothing to show.

        Bytes the trace never saw are printed as '??' rather than zeros. A trace
        knows what it observed and nothing else, and quietly rendering unseen
        memory as zero would invent facts.
        """
        sp_name = next((r for r in ("rsp", "esp", "sp") if r in t.reg_at), "")
        sp = t.register(sp_name, self.idx) if sp_name else None
        out = Text()
        if sp is None:
            self.query_one("#trace-stack", Static).update(out)
            return
        width = 8 if (t.info and "64" in (t.info.arch or "")) else 4
        out.append(f" stack ({sp_name})\n", _S_DIM)
        for k in range(self.STACK_WORDS):
            a = sp + k * width
            data, known = t.memory_raw(a, width, self.idx)
            out.append(" \u25b8" if k == 0 else "  ", _S_MNEM)
            out.append(f"{a:012x} ", _S_ADDR)
            if all(known):
                v = int.from_bytes(data, "little")
                out.append(f"{v:0{width * 2}x}\n", _S_DATA if k == 0 else _S_INSN)
            elif any(known):
                out.append("".join(f"{b:02x}" if known[i] else "??"
                                   for i, b in enumerate(data)) + "\n", _S_INSN)
            else:
                out.append("?" * (width * 2) + "\n", _S_SEP)
        self.query_one("#trace-stack", Static).update(out)


class TraceTimeline(Static):
    """The trace as a vertical bar: where you are, and where you've been.

    Tenet's timeline is a Qt widget you scroll and drag to zoom. A terminal
    column can't do that, but it can do the part that matters — show the shape
    of the trace and your position in it — with one row per N timestamps.
    """

    def __init__(self, **kw) -> None:
        super().__init__("", **kw)
        self.trace = None
        self.idx = 0

    def render(self) -> Text:
        t = self.trace
        out = Text()
        h = max(self.size.height - 1, 1)
        if t is None or not t.length:
            return out
        out.append(" timeline\n", _S_DIM)
        h = max(h - 1, 1)
        per = max(t.length / h, 1.0)
        here = int(self.idx / per)
        for row in range(h):
            if row == here:
                out.append(" \u25b6", _S_MNEM)
                out.append(f" {int(row * per):>10,}\n", _S_ADDR)
            else:
                out.append(" \u2502\n", _S_SEP if row % 5 else _S_ADDR)
        return out


class LoadOptionsScreen(ModalScreen):
    """Ask how to load a file no loader recognised.

    IDA's own answer to an unidentified file is a dialog; ours is this. Without
    it the fallback is x86 at address 0, which doesn't fail — it analyses to
    nothing, and you're left wondering why a firmware image has no functions.

    Returns ``{"processor": str, "base": int}``, or ``{}`` to load it the way
    IDA would have anyway (that IS the right answer sometimes: our sniff only
    recognises formats we're sure about, so it says "unknown" for things IDA
    can in fact handle).
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("down,ctrl+n", "cursor_down", show=False),
        Binding("up,ctrl+p", "cursor_up", show=False),
        Binding("enter", "choose", show=False, priority=True),
    ]

    def __init__(self, path: str, size: int = 0) -> None:
        super().__init__()
        self._path = path
        # NOT self._size: that is Textual's own backing field for outer_size, and
        # assigning an int to it crashes the layout with a bewildering
        # "'int' object has no attribute 'region'" from deep inside _set_dirty.
        self._nbytes = size
        self._results: list[tuple[str, str]] = []

    def compose(self) -> ComposeResult:
        from .formats import PROCESSORS
        self._all = list(PROCESSORS)
        with Vertical(id="pal-box"):
            yield Static(" unrecognised file \u2014 how should IDA load it?",
                         id="pal-title", markup=False)
            yield Static(f" {os.path.basename(self._path)}  ({self._nbytes:,} bytes) "
                         f"\u2014 no loader matched; without a processor IDA "
                         f"assumes x86 at 0", id="load-note", markup=False)
            yield Input(placeholder="filter processors\u2026", id="pal-input")
            yield OptionList(id="pal-list")
            yield Input(placeholder="load address, e.g. 0x8000000 (blank = 0)",
                        id="load-base")
            yield Static(" Enter accept \u00b7 Tab base address \u00b7 "
                         "Esc load as IDA would", id="load-help", markup=False)

    def on_mount(self) -> None:
        self._apply("")
        self.query_one("#pal-input", Input).focus()

    def focus_next(self, selector="*"):  # type: ignore[override]
        """Tab moves between the two things you TYPE into.

        DOM order would stop at the option list on the way, which is
        arrow-driven and has nothing to type — and the address you meant to
        enter goes into whichever box happened to have focus. Typing an address
        into the processor filter is then taken as a processor name, IDA rejects
        it, and the open fails; that is a bad enough outcome to be worth
        overriding Tab for.
        """
        inp = self.query_one("#pal-input", Input)
        base = self.query_one("#load-base", Input)
        (inp if self.focused is base else base).focus()
        return self.focused

    def focus_previous(self, selector="*"):  # type: ignore[override]
        return self.focus_next()

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        if event.input.id == "pal-input":
            self._apply(event.value.strip())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_choose()

    def _apply(self, query: str) -> None:
        q = query.lower()
        rows = [(name, desc) for name, desc in self._all
                if not q or q in name.lower() or q in desc.lower()]
        # An unlisted processor is still valid: IDA has 73 modules and this
        # offers 20, so a typed name that matches nothing is taken literally
        # rather than refused.
        if not rows and q:
            rows = [(query.strip(), "use this processor name as typed")]
        self._results = rows
        ol = self.query_one(OptionList)
        ol.clear_options()
        opts = []
        for name, desc in rows:
            label = Text()
            label.append(f"  {name:<12}", _S_LABEL)
            label.append(desc, _S_DIM)
            opts.append(Option(label))
        ol.add_options(opts)
        if rows:
            ol.highlighted = 0
        self.query_one("#pal-title", Static).update(
            f" unrecognised file \u2014 processor? ({len(rows)})")

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
        if i is None or not (0 <= i < len(self._results)):
            self.dismiss({})
            return
        raw = self.query_one("#load-base", Input).value.strip()
        base = 0
        if raw:
            try:
                base = int(raw, 0)
            except ValueError:
                self.query_one("#load-help", Static).update(
                    f" {raw!r} is not an address \u2014 try 0x8000000")
                self.query_one("#load-base", Input).focus()
                return
            if base % 16:
                # IDA's -b is in paragraphs, so an unaligned base can't be
                # expressed and would quietly load somewhere else.
                self.query_one("#load-help", Static).update(
                    f" {base:#x} must be 16-byte aligned")
                self.query_one("#load-base", Input).focus()
                return
        self.dismiss({"processor": self._results[i][0], "base": base})

    def action_close(self) -> None:
        self.dismiss({})


class ProjectPalette(ModalScreen):
    """The project's binaries; Enter switches to one. Shows which are resident
    (a live worker, so switching is instant) vs cold (needs an open)."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("down,ctrl+n", "cursor_down", show=False),
        Binding("up,ctrl+p", "cursor_up", show=False),
    ]

    def __init__(self, entries: list[dict]) -> None:
        super().__init__()
        self._entries = entries
        self._results: list[dict] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="pal-box"):
            yield Static(" binaries", id="pal-title", markup=False)
            yield Input(placeholder="filter binaries\u2026  \u2191\u2193 select \u00b7 "
                                    "Enter switch \u00b7 Esc close", id="pal-input")
            yield OptionList(id="pal-list")

    def on_mount(self) -> None:
        self._apply("")
        self.query_one("#pal-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._apply(event.value.strip())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_choose()

    def _apply(self, query: str) -> None:
        q = query.lower()
        rows = [e for e in self._entries
                if not q or q in e["label"].lower() or q in e["source"].lower()]
        self._results = rows
        ol = self.query_one(OptionList)
        ol.clear_options()
        opts = []
        for e in rows:
            label = Text()
            label.append("\u25b8 " if e["active"] else "  ",
                         _S_MNEM if e["active"] else _S_DIM)
            label.append(f"{e['label']:<22}", _S_LABEL)
            if e["resident"]:
                mb = e.get("memory_mb") or 0
                label.append(f"resident {mb:>4}MB  ", _S_MNEM)
            elif e["analysed"]:
                label.append("analysed        ", _S_DIM)
            else:
                label.append("not opened      ", _S_DIM)
            if e["pinned"]:
                label.append("pin ", _S_ADDR)
            label.append(e["source"], _S_DIM)
            opts.append(Option(label))
        ol.add_options(opts)
        if rows:
            # Land on the binary you're already in, so the switcher opens where
            # you are rather than at whatever sorts first.
            active = next((i for i, e in enumerate(rows) if e["active"]), 0)
            ol.highlighted = active
        self.query_one("#pal-title", Static).update(
            f" binaries: {len(rows)} of {len(self._entries)}")

    def action_cursor_down(self) -> None:
        ol = self.query_one(OptionList)
        if ol.option_count:
            ol.highlighted = min((ol.highlighted or 0) + 1, ol.option_count - 1)

    def action_cursor_up(self) -> None:
        ol = self.query_one(OptionList)
        if ol.option_count:
            ol.highlighted = max((ol.highlighted or 0) - 1, 0)

    def action_choose(self) -> None:
        i = self.query_one(OptionList).highlighted
        if i is not None and 0 <= i < len(self._results):
            self.dismiss(self._results[i]["label"])

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if 0 <= event.option_index < len(self._results):
            self.dismiss(self._results[event.option_index]["label"])

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

    def __init__(self, message: str, note: str = "") -> None:
        super().__init__()
        self._message = message
        self._note = note

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Static(self._message, id="confirm-msg", markup=False)
            if self._note:
                yield Static(self._note, id="confirm-note", markup=False)
            yield Static("[Enter/y] confirm      [Esc/n] cancel", id="confirm-help")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


_LOGO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logo.ans")
_logo_cache: object = False  # False == not yet loaded (None == absent/unreadable)


def _load_logo() -> "Text | None":
    """The ANSI-art splash logo (logo.ans) as a Rich Text, or None if missing.
    Loaded once; cursor show/hide escapes are stripped so Rich sees only SGR."""
    global _logo_cache
    if _logo_cache is not False:
        return _logo_cache  # type: ignore[return-value]
    try:
        with open(_LOGO_PATH, encoding="utf-8", errors="replace") as f:
            data = f.read()
        data = re.sub(r"\x1b\[\?25[lh]", "", data)  # drop cursor hide/show
        _logo_cache = Text.from_ansi(data.strip("\n"), no_wrap=True)
    except OSError:
        _logo_cache = None
    return _logo_cache  # type: ignore[return-value]


class LoadingScreen(ModalScreen):
    """Startup overlay shown while the binary is opened + analyzed, so a slow
    load (big binary) isn't just empty panes and dead air. The app updates the
    note line with progress and dismisses it once we land on a function."""

    BINDINGS = [Binding("escape", "hide", "Hide")]

    def __init__(self, title: str, note: str = "opening\u2026") -> None:
        super().__init__()
        self._title = title
        self._note = note

    def compose(self) -> ComposeResult:
        with Vertical(id="loading-box"):
            logo = _load_logo()
            # Only show the splash art when the terminal can fit it plus the
            # title/note/help + box chrome; otherwise fall back to a text-only
            # overlay so nothing important is clipped off a small screen.
            if logo is not None:
                sz = self.app.size
                n = len(logo.split("\n"))
                if sz.height >= n + 9 and sz.width >= 64:
                    # Align.center, not the box's align-horizontal: the 1fr
                    # title/note siblings make the child group span the full
                    # width, so container alignment has nothing left to centre.
                    yield Static(Align.center(logo), id="loading-logo")
            yield Static(f"\u23f3  loading  {self._title}", id="loading-title")
            yield Static(self._note, id="loading-note")
            yield Static("first open of a big binary can take a while  \u00b7  "
                         "Esc to hide", id="loading-help")

    def update_note(self, text: str) -> None:
        try:
            self.query_one("#loading-note", Static).update(text)
        except Exception:  # noqa: BLE001 -- not mounted yet / already gone
            pass

    def action_hide(self) -> None:
        self.dismiss()


class BusyScreen(ModalScreen):
    """A tiny blocking overlay for a short async step (e.g. gathering xrefs) so
    the user can't fire more actions into a half-finished operation. Esc cancels
    (dismisses with "cancel"); a programmatic dismiss carries no result."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="busy-box"):
            yield Static(self._message, id="busy-msg")
            yield Static("Esc to cancel", id="busy-help")

    def action_cancel(self) -> None:
        self.dismiss("cancel")


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
#: The app's own theme. Textual's default (textual-dark) paints every accent and
#: border in #ffa62b, a neon orange that fights the muted VS Code/Solarized
#: palette the code views already use (amber #b58900 for matches, #6a9955 green,
#: #264f78 blue). This keeps the chrome in the same family as the content:
#: desaturated blue-greys, amber for emphasis, blue reserved for focus.
IDATUI_THEME = Theme(
    name="idatui",
    dark=True,
    background="#12161c",   # deep blue-black, softer than pure black
    surface="#181d25",      # views
    panel="#212832",        # dialogs, status bar, gutters
    foreground="#d6d9de",
    primary="#5aa0d6",      # focus / links: the one cool accent
    secondary="#2f5d82",
    accent="#d0a215",       # the same amber as a search match — one meaning
    warning="#c9762f",      # burnt orange — distinct from accent, reads as care
    error="#ff5f5f",        # already used for failure text
    success="#6a9955",      # already used for comments
)


class IdaCommands(Provider):
    """Fills the Ctrl+P command palette with real ida-tui actions instead of the
    stock Textual system commands (change theme / take screenshot / …).

    App-level actions run directly; cursor-scoped ones (rename/xrefs/comment/…)
    are dispatched to the active code view via ``IdaTui._palette_action``."""

    def _commands(self):
        app = self.app
        va = app._palette_action  # dispatch to the focused code view
        return (
            ("Goto address / symbol…", "jump to an address or name (g)",
             app.action_goto),
            ("Find symbol…", "fuzzy function finder (Ctrl+N)", app.action_symbols),
            ("Strings…", "browse every string in the binary (\")",
             app.action_strings),
            ("Switch binary…", "another binary in the project (Ctrl+O)",
             app.action_switch_binary),
            ("Keyboard shortcuts", "the key cheatsheet (F1)", app.action_help),
            ("Follow symbol under cursor", "jump to the referenced symbol (Enter)",
             lambda: va("follow")),
            ("Show xrefs to symbol", "cross-references to the cursor symbol (x)",
             lambda: va("xrefs")),
            ("Back", "navigation history (Esc)", app.action_back),
            ("Toggle disassembly / pseudocode", "decompile / listing (F5, Tab)",
             app.action_toggle_view),
            ("Continuous listing here", "flat segment listing (L)",
             app.action_continuous_here),
            ("Hex view", "raw bytes at the cursor (\\)", app.action_hex),
            ("Split view (listing ⇄ pseudocode)",
             "side-by-side synced views (s)", app.action_toggle_split),
            ("Rename symbol…", "rename the symbol under the cursor (n)",
             lambda: va("rename")),
            ("Set type / prototype…", "retype the symbol under the cursor (y)",
             lambda: va("retype")),
            ("Add comment…", "comment at the cursor (;)", lambda: va("comment")),
            ("Define code", "make code at the cursor (c)", lambda: va("define_code")),
            ("Create function", "define a function at the cursor (p)",
             lambda: va("define_func")),
            ("Make data", "define a data item at the cursor (d)",
             lambda: va("make_data")),
            ("Make string", "define a string at the cursor (a)",
             lambda: va("make_string")),
            ("Undefine", "undefine the item at the cursor (u)",
             lambda: va("undefine")),
            ("Toggle opcode bytes", "cycle the opcode-bytes column (o)",
             lambda: va("toggle_opcodes")),
            ("Structs / types editor", "view + edit local types (Ctrl+T)",
             app.action_structs),
            ("Filter functions…", "glob-filter the function list (/)",
             app.action_filter),
            ("Toggle names pane", "function-list sidebar (Ctrl+B)",
             app.action_toggle_functions),
            ("Save database (.i64)", "persist changes (Ctrl+S)", app.action_save),
            ("Quit", "exit ida-tui (q)", app.action_quit),
        )

    async def discover(self):
        for title, help_text, cb in self._commands():
            yield DiscoveryHit(title, cb, help=help_text)

    async def search(self, query: str):
        matcher = self.matcher(query)
        for title, help_text, cb in self._commands():
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, matcher.highlight(title), cb, help=help_text)


class IdaTui(App):
    COMMANDS = {IdaCommands}  # replace the stock system-commands palette

    CSS = """
    Screen { layout: vertical; }
    #panes { height: 1fr; }
    #left { width: 30%; min-width: 42; max-width: 44; border-right: solid $panel; }
    #func-table { height: 1fr; }
    #func-filter { dock: top; }
    DecompView { width: 1fr; }
    ListingView { width: 1fr; padding: 0 1; }
    #panes.split ListingView { border-right: tall $panel-lighten-2; }
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
        background: $panel-darken-1;
    }
    QuitScreen { align: center middle; }
    #quit-box { width: 64; height: auto; border: thick $warning; background: $panel; }
    #quit-title { dock: top; height: 1; background: $warning; color: $background; text-style: bold; padding: 0 1; }
    #quit-list { height: auto; padding: 1 2 0 2; }
    #quit-help { height: 1; color: $text-muted; padding: 0 2; margin-top: 1; }
    HelpScreen { align: center middle; }
    #help-box { width: auto; max-width: 98%; height: auto; max-height: 90%;
                border: thick $accent; background: $panel; }
    #help-title { dock: top; height: 1; background: $accent; color: $background; text-style: bold; padding: 0 1; }
    #help-body { height: auto; max-height: 100%; width: auto; padding: 1 1; }
    #help-cols { height: auto; width: auto; }
    .help-col { height: auto; width: auto; margin-right: 1; }
    .help-card { height: auto; width: auto; padding: 0 1;
                 border: round $panel-lighten-2; }
    #help-foot { dock: bottom; height: 1; color: $text-muted; padding: 0 2; }
    XrefsScreen { align: center middle; }
    #xref-box { width: 84; max-height: 70%; height: auto; border: thick $accent; background: $panel; }
    #xref-title { dock: top; height: 1; background: $accent; color: $background; text-style: bold; padding: 0 1; }
    #xref-list { height: auto; max-height: 100%; }
    /* every #pal-box palette centres, not just the symbol one */
    SymbolPalette, StringsPalette, ProjectPalette,
    LoadOptionsScreen, RegWriteScreen { align: center middle; }
    /* Give the stock Ctrl+P command palette side padding instead of full width;
       the input + results inherit this width (results is an overlay, so pin it). */
    CommandPalette > Vertical { width: 80%; max-width: 120; }
    CommandPalette #--results { width: 100%; }
    #pal-box { width: 96; max-width: 92%; height: auto; max-height: 80%;
               border: thick $accent; background: $panel; }
    #pal-title { dock: top; height: 1; background: $accent; color: $background; text-style: bold; padding: 0 1; }
    #pal-input { border: none; height: 1; margin: 0 1; background: $panel; color: $text; }
    #pal-list { height: auto; max-height: 24; }
    #trace-dock { dock: right; width: 34; background: $surface; border-left: solid $panel; }
    #trace-head { height: 2; padding: 0 1; background: $panel; }
    #trace-regs { height: auto; padding: 1 0 0 0; }
    #trace-stack { height: auto; padding: 1 0 0 0; }
    #trace-timeline { height: 1fr; padding: 1 0 0 0; }
    #load-note { height: 2; padding: 1 1 0 1; color: $text-muted; }
    /* Cap the processor list so the ADDRESS FIELD is always on screen: with the
       palette default (24) the box outgrew the terminal and the field you need
       was clipped off the bottom, which read as "Tab does nothing". */
    LoadOptionsScreen #pal-list { max-height: 12; }
    #load-base { border: none; height: 1; margin: 1 1 0 1; background: $panel; color: $text; }
    #load-help { height: 1; padding: 0 1; color: $text-muted; }
    #confirm-note { height: auto; padding: 0 1; color: $text-muted; }
    StructEditor { align: center middle; }
    #se-box { width: 90%; height: 84%; border: thick $accent; background: $panel; }
    #se-panes { height: 1fr; }
    #se-left { width: 38; border-right: solid $accent; }
    #se-right { width: 1fr; }
    #se-title, #se-hint { height: 1; background: $accent; color: $background; text-style: bold; padding: 0 1; }
    #se-list { height: 1fr; }
    #se-edit { height: 1fr; border: none; }
    #se-status { height: 1; background: $panel-darken-2; color: $text-muted; padding: 0 1; }
    ConfirmScreen { align: center middle; }
    #confirm-box { width: 60; height: auto; border: thick $warning;
                   background: $panel; padding: 1 2; }
    #confirm-msg { height: auto; }
    #confirm-help { height: 1; color: $text-muted; margin-top: 1; }
    LoadingScreen { align: center middle; }
    #loading-box { width: 72; height: auto; border: thick $accent;
                   background: $panel; padding: 1 2; }
    #loading-logo { width: 100%; height: auto; margin-bottom: 1; }
    #loading-title { width: 1fr; height: 1; text-style: bold; }
    #loading-note { height: auto; color: $text-muted; margin-top: 1; }
    #loading-help { height: auto; color: $text-muted; margin-top: 1; }
    BusyScreen { align: center middle; }
    #busy-box { width: auto; min-width: 26; height: auto; border: thick $accent;
                background: $panel; padding: 1 2; }
    #busy-msg { height: 1; text-style: bold; }
    #busy-help { height: 1; color: $text-muted; margin-top: 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+n", "symbols", "Symbols"),
        Binding("ctrl+t", "structs", "Structs"),
        Binding("backslash", "hex", "Hex"),
        Binding("s", "toggle_split", "Split", show=False),
        Binding("quotation_mark,shift+f12", "strings", "Strings", show=False),
        Binding("ctrl+o", "switch_binary", "Binaries", show=False),
        Binding("ctrl+l", "load_options", "Reload as…", show=False),
        # Trace stepping. ] / [ move one instruction, } / { step over a
        # call by following the stack pointer.
        # Seeking, as opposed to stepping: jump to the next/previous time THIS
        # thing was touched, where "this thing" is whatever the focused view
        # addresses — an instruction in the code views, a byte in hex.
        Binding("greater_than_sign", "seek_next_hit", "Next hit", show=False),
        Binding("less_than_sign", "seek_prev_hit", "Prev hit", show=False),
        Binding("W", "seek_reg_write", "Reg writes", show=False),
        Binding("right_square_bracket", "step_fwd", "Step", show=False),
        Binding("left_square_bracket", "step_back", "Step back", show=False),
        Binding("right_curly_bracket", "step_over_fwd", "Step over", show=False),
        Binding("left_curly_bracket", "step_over_back", "Step over back", show=False),
        Binding("f1", "help", "Keys", show=False),
        Binding("g", "goto", "Goto"),
        Binding("slash", "filter", "Filter", show=False),
        Binding("ctrl+b", "toggle_functions", "Names", show=False),
        Binding("tab,shift+tab", "toggle_view", "Disasm/Pseudocode", priority=True),
        Binding("ctrl+s", "save", "Save"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, open_path: str | None = None, keepalive: bool = True,
                 rpc_path: str | None = None, ttl: int = 1800,
                 project=None, load_args: str = "", trace_path: str = "") -> None:
        super().__init__()
        # Project mode is additive: with no project this is the plain
        # single-binary app, unchanged.
        self._project = project
        self._pool = None
        self._binary: str | None = None       # active project binary (label)
        self._states: dict[str, BinaryState] = {}
        self._pending_restore = None          # entry to reopen after a switch
        self._goto_after_switch = None        # cross-binary search hit to land on
        self._hops: list[str] = []            # binaries a navigation crossed FROM
        self._load_for_label = None           # project binary the dialog is for
        self._no_functions = False            # analysis produced nothing at all
        self._flash: str | None = None        # message a pending reload must keep
        self._flash_until = 0.0               # ...until this monotonic time
        self._pending_switch = None           # switch waiting on that answer
        self._nav_seq = 0                     # bumped per navigation; drops stale ones
        # None = teardown wasn't an explicit quit (crash/kill): save defensively.
        # False = the user chose discard, or we already saved on the way out.
        self._save_on_exit: bool | None = None
        self._index = None                    # project-wide symbol/string index
        if project is not None:
            from .index import ProjectIndex
            from .pool import WorkerPool
            self._pool = WorkerPool(project, ttl=ttl)
            self._index = ProjectIndex(
                os.path.join(project.index_dir, "project.db"))
            self._binary = project.refs[0].label
            open_path = project.refs[0].staged
        self._open_path = open_path
        self._ttl = ttl
        self._load_args = load_args or ""   # IDA switches for a headerless blob
        self._title = (os.path.basename(open_path) if open_path else "")
        self._trace_path = trace_path or ""  # Tenet execution trace to explore
        self._trace = None                   # the loaded Trace, once analysed
        self._trail_map = []                 # decomp_map for _trail_map_ea
        self._trail_map_ea = None
        self._pending_trace_line = None      # step waiting on a re-decompile
        self._trail_line_of: dict[int, int] = {}   # ea -> pseudocode line
        self._trail_span = None                   # ea span of that function
        self._trail_eas: list[int] = []            # sorted keys of _trail_line_of
        self._t = 0                          # current timestamp in that trace
        self._do_keepalive = keepalive
        self._rpc_path = rpc_path
        self._rpc = None
        self.client: WorkerClient | None = None
        self.program: Program | None = None
        self._loading_screen: LoadingScreen | None = None
        self._ka = None
        self._nav: list[NavEntry] = []
        self._func_index = None  # the unfiltered FunctionIndex (source of truth)
        self._did_auto_land = False  # startup jump-to-main/picker fires once
        self._filter_term = ""
        self._pending_filter = ""
        self._filter_timer = None
        self._sort_col = 0        # 0=addr, 1=name, 2=size
        self._sort_reverse = False
        # ONE notion of "which pane you're in": _active, kept in step with focus
        # (on_descendant_focus does that while split). There used to be a second,
        # _pref, but it was only ever assigned "listing" — see _code_mode().
        self._active = "listing"  # currently shown view (in split: the focused pane)
        self._split = False       # side-by-side listing + pseudocode
        self._split_eamap: list[list[int]] = []  # split: decomp line -> instr EAs
        self._split_ea2line: dict[int, int] = {}  # split: instr EA -> decomp line
        self._split_range: tuple[int, int] | None = None  # decomp'd fn ea span
        self._hex_pending_ea: int | None = None
        self._cur: NavEntry | None = None
        self._pending_focus_name: str | None = None  # token to land the cursor on
        self._decomp_return: NavEntry | None = None  # listing to return to from F5
        self._busy_screen: BusyScreen | None = None
        self._xref_active = False  # an xref gather is in flight (blocks re-entry)
        self._conn_screen: LoadingScreen | None = None
        self._reconnecting = False  # a reconnect attempt is in flight
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
            # The unified continuous listing is the one code view. (DisasmModel
            # is still used by the domain to index a function's instructions.)
            lst = ListingView()
            yield lst
            yield DecompView()
            hx = HexView()
            hx.display = False
            yield hx
            # Docked right and only shown once a trace is loaded, so a normal
            # session looks exactly as it did.
            td = TraceDock()
            td.display = False
            yield td
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
        # markup=False: the status is plain text full of [listing]/[split]/[label]
        # markers and symbol names that may contain brackets. With Textual markup
        # on, a single-word marker parses as a style tag and is silently eaten —
        # which is why [listing] and [pseudocode] never actually rendered.
        yield Static("connecting\u2026", id="status", markup=False)

    def on_mount(self) -> None:
        self.register_theme(IDATUI_THEME)
        self.theme = IDATUI_THEME.name
        # Keep the hidden command input out of the focus chain until summoned.
        inp = self.query_one("#func-filter", Input)
        inp.can_focus = False
        # The names pane is an overlay now (Ctrl+N); focus the default code view
        # (pseudocode) so app bindings work before anything is opened.
        self.query_one(ListingView).focus()
        if self._rpc_path:
            self._start_rpc()
        # A file no loader recognises has to be described before it can be
        # opened, so ask BEFORE the worker starts — once IDA has made a database
        # the answer is baked in and changing it means deleting the .i64.
        if self._project is not None:
            ref = self._pending_load_ref()
            if ref is not None:
                self._ask_load_options(ref.source, label=ref.label)
                return
        elif self._should_ask_load_options():
            self._ask_load_options(self._open_path)
            return
        # Show a loading overlay immediately so a slow open/analysis (big binary)
        # isn't just dead air behind empty panes; dismissed once we land.
        self._loading_screen = LoadingScreen(self._loading_title())
        self.push_screen(self._loading_screen)
        self._connect()

    def _should_ask_load_options(self) -> bool:
        """Ask only when nobody has already answered, and only when it matters.

        Skipped when: options came from the command line or the project (the
        user already said); a database exists (the answer is recorded in it, and
        re-passing switches fails the open); or the file is a format IDA
        recognises, which is nearly always.
        """
        if not self._open_path:
            return False
        if self._load_args:
            return False
        from .formats import needs_load_options
        if os.path.exists(self._open_path + ".i64") or os.path.exists(
                os.path.splitext(self._open_path)[0] + ".i64"):
            return False
        return needs_load_options(self._open_path)

    def action_load_options(self) -> None:
        """Ctrl+L: re-open this binary with different load options.

        The database IDA already built has the old processor and base baked into
        it and takes precedence over any switches, so re-loading means throwing
        it away. That destroys names and comments, hence the confirmation — but
        for the case this exists for (a blob loaded as the wrong architecture,
        which analysed to nothing) there is nothing to lose and no other way
        forward.
        """
        if not self._can_reload():
            self._status("nothing to reload")
            return
        n = len(self._func_index) if self._func_index else 0
        note = ("this image has no functions, so nothing is lost"
                if n == 0 else
                f"discards the database for this binary \u2014 {n} "
                f"function{'s' if n != 1 else ''}, plus any names and comments "
                f"you've added")
        self.push_screen(ConfirmScreen("Reload with different options?", note),
                         self._on_reload_confirmed)

    def _on_reload_confirmed(self, yes) -> None:  # type: ignore[no-untyped-def]
        if not yes:
            return
        path, label = self._open_path, None
        if self._project is not None and self._binary is not None:
            ref = self._project.by_label(self._binary)
            if ref is not None:
                path, label = ref.source, ref.label
        # Drop the worker first: it holds the database open, and the .i64 can't
        # be removed (or rebuilt) underneath a live one.
        self._release_worker()
        self._drop_database()
        self._reset_for_reload()
        self._load_args = ""
        if label is not None and self._project is not None:
            self._project.set_load(label, processor="", base=0)
            i = self._project._refs.index(self._project.by_label(label))
            self._project._entries[i].pop("processor", None)
            self._project._entries[i].pop("base", None)
            self._project.save()
            self._pending_switch = None
        self._ask_load_options(path, label=label)

    def _release_worker(self) -> None:
        if self._pool is not None and self._binary is not None:
            try:
                self._pool.evict(self._binary, save=False)
            except Exception:  # noqa: BLE001
                pass
        elif self.client is not None:
            try:
                self.client.close()
            except Exception:  # noqa: BLE001
                pass
        self.client = None
        self.program = None

    def _drop_database(self) -> None:
        """Remove the .i64 (and any unpacked scratch) so the next open re-reads
        the raw image with new options."""
        base = self._open_path
        if self._project is not None and self._binary is not None:
            ref = self._project.by_label(self._binary)
            if ref is not None:
                base = ref.staged
        if not base:
            return
        for suffix in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
            for cand in (base + suffix, os.path.splitext(base)[0] + suffix):
                try:
                    os.remove(cand)
                except OSError:
                    pass

    def _reset_for_reload(self) -> None:
        self._no_functions = False
        self._func_index = None
        self._cur = None
        self._nav = []
        self._did_auto_land = False
        self._pending_restore = None
        self._split = False
        self.query_one(DecompView).loaded_ea = None

    def _retry_load_options(self) -> None:
        """Re-ask after IDA refused what we told it."""
        path, label = self._open_path, None
        if self._project is not None and self._binary is not None:
            ref = self._project.by_label(self._binary)
            if ref is not None:
                path, label = ref.source, ref.label
                # Clear the rejected answer or _pending_load_ref would see the
                # binary as already described and never ask again.
                self._project.set_load(label, processor="", base=0)
                self._project._entries[self._project._refs.index(ref)].pop(
                    "processor", None)
                self._project.save()
        self._load_args = ""
        if path:
            self._status("those load options were rejected \u2014 try again")
            self._ask_load_options(path, label=label)

    def _pending_load_ref(self, label: str | None = None):  # type: ignore[no-untyped-def]
        """The project binary about to be opened, if it needs describing.

        Checked against the SOURCE: staging may not have happened yet, and the
        question is about the bytes, not where they were copied to.
        """
        if self._project is None:
            return None
        label = label or self._binary or self._project.refs[0].label
        ref = self._project.by_label(label)
        if ref is None or ref.load_args:
            return None
        if os.path.exists(ref.db) or os.path.exists(
                os.path.splitext(ref.staged)[0] + ".i64"):
            return None    # already analysed: the .i64 records how
        from .formats import needs_load_options
        return ref if needs_load_options(ref.source) else None

    def _ask_load_options(self, path: str, label: str | None = None) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        self._load_for_label = label
        self.push_screen(LoadOptionsScreen(path, size), self._on_load_options)

    def _on_load_options(self, choice) -> None:  # type: ignore[no-untyped-def]
        from .formats import load_args
        choice = choice or {}
        label, self._load_for_label = self._load_for_label, None
        proc, base = choice.get("processor", ""), int(choice.get("base", 0) or 0)
        if proc:
            if label is not None and self._project is not None:
                # Persist it: the answer belongs to the binary, not to this run.
                self._project.set_load(label, proc, base)
            else:
                self._load_args = load_args(proc, base)
            self._status(f"loading as {proc} @ {base:#x}")
        if self._pending_switch is not None:
            label2, self._pending_switch = self._pending_switch, None
            self._switch_binary(label2)
            return
        self._loading_screen = LoadingScreen(self._loading_title())
        self.push_screen(self._loading_screen)
        self._connect()

    def _loading_title(self) -> str:
        return os.path.basename(self._open_path) if self._open_path else "database"

    def _dismiss_loading(self) -> None:
        ls = self._loading_screen
        self._loading_screen = None
        if ls is not None:
            try:
                ls.dismiss()
            except Exception:  # noqa: BLE001 -- already popped
                pass

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
    def _status(self, text: str, priority: bool = False) -> None:
        """Write the status bar. ``priority`` marks the RESULT of something the
        user did.

        An action's result is written, and then the reload it triggered writes
        its own idle status on top — cursor moved, filter re-applied, functions
        re-counted. I patched that at five separate call sites before admitting
        it's one problem: routine chatter must not outrank an answer. A priority
        message holds the bar briefly and is cleared by the next keypress, i.e.
        when the user has read it and moved on.
        """
        import time as _time
        if priority:
            self._flash = text
            self._flash_until = _time.monotonic() + 8.0
        elif self._flash and _time.monotonic() < self._flash_until:
            text = self._flash
        # Always say WHICH file this is. In project mode that's the binary's
        # label; otherwise the filename we opened. Cheap on purpose — _module()
        # asks the worker, and this runs on every status write.
        tag = self._binary or self._title
        if tag:
            text = f"[{tag}] {text}"
        # An image with no functions at all is nearly always a blob described
        # wrongly, and that stays true as you scroll around — so it belongs in
        # the status bar, not in a one-off message the next write clobbers.
        # It stops being true the moment a function exists, though: latching it
        # meant the warning survived defining one with `p` and kept telling you
        # the load was wrong when it no longer was.
        if self._no_functions and self._func_index is not None and len(self._func_index):
            self._no_functions = False
        if self._no_functions:
            text += "   \u2014 no functions: wrong processor/base? Ctrl+L to reload"
        try:
            self.query_one("#status", Static).update(text)
        except Exception:  # noqa: BLE001 -- status bar transiently unavailable
            pass
        if self._loading_screen is not None:  # mirror progress into the overlay
            self._loading_screen.update_note(text)

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

    # -- connection loss / recovery --------------------------------------- #
    def _handle_exception(self, error: BaseException) -> None:
        """Intercept a lost-connection error from any worker so the whole app
        doesn't die when the analysis server goes away (it can idle out, be
        killed, or the box can sleep). Everything else crashes as usual."""
        from textual.worker import WorkerFailed
        orig = error.error if isinstance(error, WorkerFailed) else error
        if isinstance(orig, IDAConnectionError):
            self._on_connection_lost()
            return
        super()._handle_exception(error)

    def _on_connection_lost(self) -> None:
        if self._reconnecting:
            return
        self._reconnecting = True
        self._conn_screen = LoadingScreen(
            "the analysis server", note="connection lost \u2014 reconnecting\u2026")
        self.push_screen(self._conn_screen)
        self._reconnect()

    def _conn_note(self, text: str) -> None:
        if self._conn_screen is not None:
            self._conn_screen.update_note(text)

    def _dismiss_conn(self) -> None:
        cs = self._conn_screen
        self._conn_screen = None
        if cs is not None:
            try:
                cs.dismiss()
            except Exception:  # noqa: BLE001 -- already popped (Esc)
                pass

    @work(thread=True, exclusive=True, group="reconnect")
    def _reconnect(self) -> None:
        # The worker died (segfault -> dropped socket). Respawn it: it re-opens
        # and re-analyzes the binary in a fresh process, then we rebuild.
        try:
            if self._open_path is None:
                self.app.call_from_thread(self._reconnect_failed,
                                          "no binary to reopen")
                return
            client = WorkerClient(self._open_path, ttl=self._ttl,
                                  load_args=self._load_args)
            client.connect(progress=lambda m: self.app.call_from_thread(
                self._conn_note, m))
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._reconnect_failed, str(e))
            return
        self.app.call_from_thread(self._after_reconnect, client, Program(client))

    def _after_reconnect(self, client: "WorkerClient", program: "Program") -> None:
        self.client = client
        self.program = program
        self._reconnecting = False
        self._dismiss_conn()
        self._status("reconnected \u2014 reloading\u2026")
        self._load_functions()  # rebuild the function index against the new client
        cur = self._cur
        if cur is not None:  # refresh the current view with the new program
            self._open_entry(cur, push=False)

    def _reconnect_failed(self, why: str) -> None:
        self._reconnecting = False
        self._conn_note(f"reconnect failed: {why}  \u2014  retry on next action, or 'q'")
        self._status(f"reconnect failed: {why}")

    # -- connection + initial load ---------------------------------------- #
    @work(thread=True, exclusive=True, group="connect")
    def _connect(self) -> None:
        try:
            client = self._open_worker_client()
            if client is None:
                return  # the opener already reported + dismissed the overlay
            module = client.health().get("module", "?")
            if self._do_keepalive:
                # Keep the session warm while we run; don't make it immortal, so
                # it's reclaimed after the TUI closes. (No-op for the worker.)
                self._ka = client.keepalive(interval=120.0).start()
            program = Program(client)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"connect failed: {e}")
            self.app.call_from_thread(self._dismiss_loading)
            # A load we described ourselves and IDA refused: offer the dialog
            # again rather than leaving an empty app with an error in the status
            # bar. Getting the processor wrong is an ordinary mistake and should
            # cost one more keypress, not a restart.
            if "load options" in str(e):
                self.app.call_from_thread(self._retry_load_options)
            return
        self.client = client
        self.program = program
        self.app.call_from_thread(self._status, f"{module} — loading functions…")
        self._load_functions()

    def _open_worker_client(self):  # type: ignore[no-untyped-def]
        """Our idalib-worker path: spawn the worker (it opens + analyzes the
        binary in its own process) and connect. Returns the client, or None."""
        from .worker_client import WorkerClient
        if self._pool is not None:  # project mode: the pool owns the workers
            label = self._binary or self._project.refs[0].label
            client = self._pool.get(label, progress=lambda m:
                                    self.app.call_from_thread(self._status, m))
            self._binary = label
            self._pool.set_active(label)
            self._open_path = self._project.by_label(label).staged
            self._title = os.path.basename(self._open_path)
            return client
        if not self._open_path:
            self.app.call_from_thread(
                self._status, "the worker backend needs a binary path")
            self.app.call_from_thread(self._dismiss_loading)
            return None
        base = os.path.basename(self._open_path)
        self.app.call_from_thread(
            self._status, f"starting worker — initial auto-analysis of {base}…")
        client = WorkerClient(self._open_path, ttl=self._ttl,
                              load_args=self._load_args)
        client.connect(progress=lambda m: self.app.call_from_thread(
            self._status, m))
        return client

    @work(thread=True, exclusive=True, group="load-funcs")
    def _load_functions(self) -> None:
        assert self.program is not None
        idx = self.program.functions()
        self._func_index = idx
        self.app.call_from_thread(lambda: self.query_one("#func-table", DataTable).clear())
        last = 0
        while not idx.complete:
            idx.load_next_page()
            rows = idx.window(last, len(idx) - last)
            last = len(idx)
            if rows:
                self.app.call_from_thread(self._append_rows, rows)
                self.app.call_from_thread(
                    self._status, f"{last} functions…"
                )
        # If a filter is active (typed during load), re-apply it over the full set.
        if self._filter_term:
            self.app.call_from_thread(self._apply_filter, self._filter_term)
        else:
            self.app.call_from_thread(
                self._status, f"{len(idx)} functions   (Ctrl+N: find symbol)")
        # Land somewhere useful instead of an empty pane: main() if present,
        # otherwise pop the fuzzy symbol picker.
        self.app.call_from_thread(self._auto_land)
        self._index_binary()  # project mode: keep the cross-binary index fresh
        if self._trace_path and self._trace is None:
            self._load_trace()   # needs the index above: rebasing reads it

    @work(thread=True, exclusive=True, group="prewarm")
    def _prewarm_provider(self) -> None:
        """Warm the binary this one leans on hardest, once we're idle.

        Not "the next in the list" — phase 3 tells us something better. The
        binary providing the most of this one's imports is where a follow is
        most likely to take you, so paying its startup now is the switch you
        would otherwise wait for. Refuses to evict anything (see pool.prewarm),
        so at a tight budget this simply does nothing.
        """
        if self._pool is None or self._index is None or self._binary is None:
            return
        try:
            imps, _ = self.program.linkage()
        except Exception:  # noqa: BLE001
            return
        if not imps:
            return
        from collections import Counter
        votes: Counter = Counter()
        for name in {i.name for i in imps}:
            for h in self._index.providers(name, exclude=self._binary):
                votes[h.binary] += 1
        resident = set(self._pool.resident())
        cand = next((b for b, _ in votes.most_common() if b not in resident), None)
        if cand is None:
            return
        n = votes[cand]
        try:
            if self._pool.prewarm(cand):
                self.app.call_from_thread(
                    self._status, f"pre-warmed {cand} (provides {n} imports)")
        except Exception:  # noqa: BLE001 -- speculative work must never surface
            pass

    @work(thread=True, exclusive=True, group="index")
    def _index_binary(self) -> None:
        """Fold this binary's symbols + strings into the project index, so it can
        be searched later even when its worker is gone."""
        if self._index is None or self._project is None or self._binary is None:
            return
        ref = self._project.by_label(self._binary)
        if ref is None or not self._index.is_stale(self._binary, ref.source):
            return
        from .index import KIND_EXPORT, KIND_FUNC, KIND_IMPORT, KIND_STRING
        idx = self._func_index
        entries = [(KIND_FUNC, f.addr, f.name) for f in (idx.all_loaded() if idx else [])]
        try:
            entries += [(KIND_STRING, s.addr, s.text)
                        for s in self.program.strings()]
        except Exception:  # noqa: BLE001 -- symbols alone are still worth indexing
            pass
        try:
            imps, exps = self.program.linkage()
            entries += [(KIND_IMPORT, i.addr, i.name) for i in imps]
            entries += [(KIND_EXPORT, e.addr, e.name) for e in exps]
        except Exception:  # noqa: BLE001 -- an old worker has no list_linkage
            pass
        try:
            n = self._index.reindex(self._binary, entries, source=ref.source)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"indexing failed: {e}")
            return
        self.app.call_from_thread(
            self._status, f"indexed {self._binary}: {n} symbols, strings + linkage")
        self._prewarm_provider()

    # -- initial landing --------------------------------------------------- #
    #: function names tried (in order) as the startup landing spot
    ENTRY_NAMES = ("main", "_main", "wmain", "WinMain", "wWinMain")

    def _auto_land(self) -> None:
        """On startup, once functions are loaded and nothing is open yet, jump to
        main() if it exists; else open the symbol picker so you're never staring
        at a blank pane. Runs once (guarded by ``_cur``) and never steals focus
        from a user who already navigated."""
        goto = self._goto_after_switch
        if goto is not None:  # arrived here from a project-wide search hit
            self._goto_after_switch = None
            self._did_auto_land = True
            self._dismiss_loading()
            self._goto_ea(goto, push=True)
            return
        entry = self._pending_restore
        if entry is not None:  # switched back to a binary we'd already explored
            self._pending_restore = None
            self._did_auto_land = True
            self._dismiss_loading()
            self._open_entry(entry, push=False)
            return
        if self._cur is not None or self._did_auto_land or self._func_index is None:
            return
        self._did_auto_land = True
        self._dismiss_loading()  # binary is up; hand the screen back to the views
        fn = self._entry_func()
        if fn is not None:
            self._open_function(fn.addr, fn.name)
        elif len(self._func_index):
            self.action_symbols()
        else:
            self._land_without_functions()

    def _land_without_functions(self) -> None:
        """Analysis found nothing. Show the bytes and say so.

        Falling through to the symbol picker here left two empty panes and
        "functions still loading…" — which is a lie, loading had finished. There
        is always something to look at: the segments exist even when IDA
        recognised no code in them, so open the listing at the start of the image.

        Zero functions is also the signal that a blob was described wrongly. It's
        exactly what a good image loaded as the wrong processor looks like, so
        the status says so rather than leaving you to guess.
        """
        start = None
        try:
            regions = self.program.file_regions()
            if regions:
                start = regions[0][0]
        except Exception:  # noqa: BLE001
            pass
        self._no_functions = self._can_reload()
        if start is None:
            self._status("no functions and no segments \u2014 nothing to show")
            return
        self._open_at(start, self.program.section_of(start) or "image",
                      cursor=0, push=True, is_region=True)

    def _can_reload(self) -> bool:
        """Whether we're able to re-open this binary with different options."""
        if self._project is not None and self._binary is not None:
            return True
        return bool(self._open_path)

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
            self._status(f"{total} functions")

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
        """Ctrl+N: fuzzy-find a symbol (Ctrl+A widens it to the whole project)."""
        idx = self._func_index
        funcs = idx.all_loaded() if idx is not None else []
        if not funcs:
            self._status("functions still loading…")
            return
        self.push_screen(SymbolPalette(funcs, index=self._index,
                                       binary=self._binary),
                         self._on_symbol_chosen)

    def _on_symbol_chosen(self, choice) -> None:  # type: ignore[no-untyped-def]
        if choice is None:
            return
        binary, addr = choice
        if binary and binary != self._binary:
            self._switch_then_goto(binary, addr)
            return
        f = self._func_index.by_addr(addr) if self._func_index else None
        self._open_function(addr, f.name if f else hex(addr))

    def _switch_then_goto(self, binary: str, addr: int) -> None:
        """A project-wide hit in another binary: switch to it, then jump there
        once its index has loaded.

        Records the hop so Esc can come back. Nav history is per-binary, so
        without this a cross-binary jump — a project search hit, or following an
        import into the library that implements it — is a one-way door: you
        arrive in a binary whose history is empty and nothing takes you back.
        """
        if self._binary is not None and binary != self._binary:
            self._hops.append(self._binary)
        self._goto_after_switch = addr
        self._switch_binary(binary)

    # -- projects: switching between the binaries of one target ------------ #
    # -- exit ---------------------------------------------------------------- #
    def _dirty_labels(self) -> list[str]:
        """Databases with edits that aren't on disk yet.

        A binary the pool has evicted was saved on the way out, so only the
        active one and other still-resident binaries can be dirty.
        """
        if self._pool is None:
            return [os.path.basename(self._open_path or "database")] if self._dirty else []
        out = [self._binary] if (self._dirty and self._binary) else []
        out += [label for label, st in self._states.items()
                if st.dirty and label != self._binary
                and self._pool.is_resident(label)]
        return out

    async def action_quit(self) -> None:
        """Never drop edits on the floor: ask before exiting when a database has
        unsaved changes (IDA/Ghidra behaviour)."""
        dirty = self._dirty_labels()
        if not dirty:
            self._save_on_exit = False  # nothing to write
            self.exit()
            return
        self.push_screen(QuitScreen(dirty), self._on_quit_choice)

    def _on_quit_choice(self, choice: str | None) -> None:
        if choice == "discard":
            self._save_on_exit = False
            self.exit()
        elif choice == "save":
            # Save with the overlay up: writing a big .i64 takes seconds, and
            # doing it during teardown would look like a hang with no UI left.
            self._loading_screen = LoadingScreen("saving", note="writing databases\u2026")
            self.push_screen(self._loading_screen)
            self._save_then_exit()
        # None: cancel, stay put

    @work(thread=True, exclusive=True, group="save-exit")
    def _save_then_exit(self) -> None:
        try:
            if self._pool is not None:
                self._pool.close_all(save=True)  # saves each resident worker
            elif self.program is not None:
                self.program.client.call("idb_save", timeout=600.0)
        except Exception as e:  # noqa: BLE001 -- still exit, but say so
            self.app.call_from_thread(self._status, f"save failed: {e}")
        self.app.call_from_thread(self._finish_exit)

    def _finish_exit(self) -> None:
        self._save_on_exit = False  # already written above
        self._dirty = False
        self.exit()

    def action_help(self) -> None:
        """F1: the keyboard cheatsheet (there's no permanent footer any more)."""
        if self._prompt_active():
            return
        if not isinstance(self.screen, HelpScreen):
            self.push_screen(HelpScreen())

    def action_switch_binary(self) -> None:
        """Ctrl+O: pick another binary from the project (Ghidra-style)."""
        if self._pool is None:
            self._status("not a project — open one with --project")
            return
        if self._prompt_active():
            return
        self.push_screen(ProjectPalette(self._pool.status()),
                         self._on_binary_chosen)

    def _on_binary_chosen(self, label: str | None) -> None:
        if label and label != self._binary:
            self._switch_binary(label)

    def _switch_binary(self, label: str) -> None:
        # A blob nobody has described yet has to be described before its worker
        # opens it — same as at boot, just reached by switching instead.
        ref = self._pending_load_ref(label)
        if ref is not None and self._load_for_label is None:
            self._pending_switch = label
            self._ask_load_options(ref.source, label=label)
            return
        # Snapshot what we're leaving so coming back restores the view, then let
        # the pool hand us a worker (spawning + evicting as the budget dictates).
        if self._binary is not None:
            self._states[self._binary] = BinaryState(
                label=self._binary, program=self.program,
                func_index=self._func_index, nav=list(self._nav), cur=self._cur,
                active=self._active, split=self._split,
                filter_term=self._filter_term, dirty=self._dirty)
        self._loading_screen = LoadingScreen(label, note="switching\u2026")
        self.push_screen(self._loading_screen)
        self._do_switch(label)

    @work(thread=True, exclusive=True, group="switch-binary")
    def _do_switch(self, label: str) -> None:
        assert self._pool is not None
        try:
            client = self._pool.get(label, progress=lambda m:
                                    self.app.call_from_thread(self._status, m))
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._switch_failed, label, str(e))
            return
        st = self._states.get(label)
        # The Program (and its caches) only survive while that worker does; a
        # binary that was evicted comes back with a fresh one. Either way the nav
        # history is just addresses, so it always survives.
        reuse = (st is not None and st.program is not None
                 and getattr(st.program, "client", None) is client)
        program = st.program if reuse else Program(client)
        self.app.call_from_thread(self._after_switch, label, client, program,
                                  st, reuse)

    def _after_switch(self, label, client, program, st, reuse) -> None:  # type: ignore[no-untyped-def]
        self.client = client
        self.program = program
        self._binary = label
        self._pool.set_active(label)
        self._open_path = self._project.by_label(label).staged
        self._title = os.path.basename(self._open_path)
        self._active = st.active if st else "listing"
        self._split = st.split if st else False
        self._filter_term = st.filter_term if st else ""
        self._dirty = st.dirty if st else False
        self._nav = list(st.nav) if st else []
        self._decomp_return = None
        self._split_eamap, self._split_ea2line, self._split_range = [], {}, None
        self.query_one(DecompView).loaded_ea = None  # belongs to the old binary
        if reuse and st.func_index is not None:
            self._cur = st.cur
            self._func_index = st.func_index
            self._apply_filter(self._filter_term)  # repopulate the names table
            self._dismiss_loading()
            if self._goto_after_switch is not None:
                addr, self._goto_after_switch = self._goto_after_switch, None
                self._goto_ea(addr, push=True)
            elif self._cur is not None:
                self._open_entry(self._cur, push=False)
            else:
                self._did_auto_land = False
                self._auto_land()
            return
        # Cold (first visit, or the worker was evicted): rebuild the index, then
        # land back where we were via _pending_restore.
        self._cur = None
        self._func_index = None
        self._pending_restore = st.cur if st else None
        # Landing is per-binary: without this the app-wide "already landed" flag
        # from the first binary would stop the new one landing at all (and leave
        # the switch overlay up forever).
        self._did_auto_land = False
        self._status("loading functions\u2026")
        self._load_functions()

    def _switch_failed(self, label: str, why: str) -> None:
        self._dismiss_loading()
        self._status(f"could not open {label}: {why}")

    def action_strings(self) -> None:
        """'\"' / Shift+F12: browse every string in the binary (filterable, F2
        widens to the whole project); Enter jumps to it in the unified listing."""
        if self.program is None:
            self._status("not connected yet")
            return
        if self._prompt_active():
            return
        self._status("collecting strings\u2026")
        self._load_strings()

    @work(thread=True, exclusive=True, group="strings")
    def _load_strings(self) -> None:
        assert self.program is not None
        try:
            items, err = self.program.strings(), None
        except Exception as e:  # noqa: BLE001 -- report, never kill the app
            items, err = [], str(e)
        self.app.call_from_thread(self._present_strings, items, err)

    def _present_strings(self, items: list, err: str | None) -> None:
        if err:
            self._status(f"strings failed: {err}")
            return
        if not items:
            self._status("no strings found (needs the list_strings tool)")
            return
        self._status(f"strings: {len(items)}")
        self.push_screen(StringsPalette(items, index=self._index,
                                        binary=self._binary),
                         self._on_string_chosen)

    def _on_string_chosen(self, choice) -> None:  # type: ignore[no-untyped-def]
        if choice is None:
            return
        binary, addr = choice
        if binary and binary != self._binary:
            self._switch_then_goto(binary, addr)
            return
        self._goto_ea(addr, push=True)  # land on the literal in the listing

    def on_descendant_focus(self, event) -> None:  # type: ignore[no-untyped-def]
        """Keep ``_active`` in step with focus while split.

        Tab moves both together, but focus also moves on its own — a click, or a
        pane focusing itself after a load — and then ``_active`` still names the
        pane you're NOT in. Everything downstream trusts ``_active``: follow
        resolves the word under that pane's cursor and pushes history for it, so
        Enter in the pseudocode would follow something from the listing and the
        next Esc got spent undoing it.
        """
        if not self._split:
            return
        w = self.focused
        mode = ("decomp" if isinstance(w, DecompView)
                else "listing" if isinstance(w, ListingView) else None)
        if mode is None or mode == self._active:
            return
        self._active = mode
        self._sync_split(mode)   # re-link the band from the new driver
        if not self.query_one(DecompView).loading:
            self._status_for_cur("split")  # never clobber "decompiling…"

    def action_toggle_view(self) -> None:
        """Tab: switch the code pane between disassembly and pseudocode (or leave
        the hex view back to the preferred code view)."""
        # Tab is a PRIORITY app binding, so it fires even while a modal is up and
        # nothing inside a dialog could ever be tabbed to. Hand it back to the
        # dialog: this is the only reason the load dialog's address field was
        # unreachable, and it was broken the same way in every other modal.
        if self.screen is not self.screen_stack[0]:
            try:
                self.screen.focus_next()
            except Exception:  # noqa: BLE001 -- screen with nothing focusable
                pass
            return
        if self._cur is None:
            return
        if self._split:
            # In split mode Tab/F5 just moves focus between the two panes.
            self._active = "decomp" if self._active == "listing" else "listing"
            (self.query_one(DecompView) if self._active == "decomp"
             else self.query_one(ListingView)).focus()
            self._sync_split(self._active)  # re-link from the new driver
            self._status_for_cur("split")
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
            # Raise the pseudocode pane + 'decompiling…' overlay NOW, before the
            # background decompile runs — otherwise the (cold) decompile happens in
            # _decomp_from_listing first and _show_active's re-decompile is cached,
            # so the overlay only flashes for an instant.
            dec = self.query_one(DecompView)
            self.query_one(ListingView).display = False
            self.query_one(HexView).display = False
            dec.display = True
            dec.loading = True
            dec.focus()
            self._status("decompiling\u2026")
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
                self._decomp_from_listing_failed,
                "F5 — cursor is not inside a defined function ('p' to make one)")
            return
        dec_idx = self._decomp_line_for(fn.addr, ea)
        self.app.call_from_thread(self._enter_decomp, fn.addr, fn.name, dec_idx)

    def _decomp_from_listing_failed(self, msg: str) -> None:
        # We optimistically raised the pseudocode overlay; drop back to the
        # listing since there's nothing to decompile here.
        self.query_one(DecompView).loading = False
        self._active = "listing"
        self._show_active()
        self._status(msg)

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

    def action_toggle_split(self) -> None:
        """Toggle the side-by-side listing ⇄ pseudocode view (Ghidra-style)."""
        if self._prompt_active():
            return  # a search/rename/… prompt owns the keyboard
        if self._cur is None or self.program is None:
            self._status("open a function first")
            return
        if not self._split and self.size.width < _SPLIT_MIN_WIDTH:
            self._status(f"terminal too narrow for split — need ≈{_SPLIT_MIN_WIDTH} "
                         f"cols (have {self.size.width})")
            return
        self._split = not self._split
        if self._active not in ("listing", "decomp"):
            self._active = "listing"
        if self._split:
            self._enter_split(self._cur.ea, self._cur.name)
        else:
            self._show_active()

    @work(thread=True, group="split")
    def _enter_split(self, ea: int, name: str) -> None:
        # Load the listing for the current function (bg) then reveal both panes.
        assert self.program is not None
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        self.app.call_from_thread(self._apply_enter_split, lm, ea, name, idx)

    def _apply_enter_split(self, lm, ea: int, name: str, idx: int) -> None:  # type: ignore[no-untyped-def]
        if not self._split:
            return  # toggled back off before the listing finished loading
        lst = self.query_one(ListingView)
        if lm is not None:
            lst.load(lm, name, cursor=idx, scroll_y=max(idx - _JUMP_CONTEXT, 0))
        self._show_active()  # split branch shows both + loads the decomp
        self._sync_split(self._active)  # crude link now
        self._load_split_map(ea)         # region map (async) if decomp is loaded

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
            self._nav_seq += 1  # invalidate any navigation still in flight
            self._nav.pop()
            # Say something immediately: going back can need a decompile, and
            # until it lands the panes still show where you were — with no
            # feedback Esc reads as a no-op.
            dest = self._nav[-1]
            self._status(f"\u25c2 back to {dest.name}\u2026")
            self._open_entry(dest, push=False)
        elif self._hops:
            # Local history is spent, but we got here from another binary.
            label = self._hops.pop()
            self._status(f"\u25c2 back to {label}\u2026")
            self._switch_binary(label)   # _states restores its nav and position
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
        if isinstance(view, ListingView):
            ea = view._cursor_ea()
            if ea is not None:
                # _next_ea() is the following item: follow uses it to skip the
                # ordinary fall-through edge, which is an indistinguishable
                # 'code' xref, and land on a call/jump's real target instead.
                self._follow_disasm(ea, word, view._next_ea())
        elif isinstance(view, DecompView) and view._texts:
            self._follow_decomp(view._texts[view.cursor], word,
                                view._line_ea(view.cursor))

    def on_xrefs_requested(self, msg: XrefsRequested) -> None:
        if self._xref_active:  # one gather at a time; ignore a second 'x'
            return
        view = msg.view
        word = view.word_under_cursor()
        if isinstance(view, ListingView):
            ea = view._cursor_ea()
            if ea is not None:
                # span = this instruction .. the next, to pre-select the dialog
                # entry for the site we invoked xrefs from.
                self._push_busy("finding xrefs\u2026")
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
            self._push_busy("finding xrefs\u2026")
            self._xrefs_decomp(view._texts[view.cursor], word, here, end)

    # -- blocking "busy" overlay for short async steps -------------------- #
    def _push_busy(self, message: str) -> None:
        self._xref_active = True
        self._busy_screen = BusyScreen(message)
        self.push_screen(self._busy_screen, self._on_busy_closed)

    def _on_busy_closed(self, result: object = None) -> None:
        self._busy_screen = None
        if result == "cancel":  # user hit Esc while we were still gathering
            self._xref_active = False

    def _dismiss_busy(self) -> None:
        bs = self._busy_screen
        if bs is not None:
            try:
                bs.dismiss()  # no result -> _on_busy_closed leaves the flag alone
            except Exception:  # noqa: BLE001 -- already popped
                pass

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
                self._do_navigate(self.program.resolve(word), push=True,
                                  focus_name=word)
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
        if self._follow_import(tgt.to):
            return
        self._do_navigate(tgt.to, push=True)

    def _import_stub(self, ea: int) -> str | None:
        """The import name at ``ea``, if ``ea`` is one of this binary's import
        stubs. That's the dead end phase 3 exists to open up: a call to strcmp
        reaches the PLT/extern entry and Hex-Rays has nothing to decompile,
        because the code lives in a library this binary only references."""
        try:
            imps, _ = self.program.linkage()
        except Exception:  # noqa: BLE001
            return None
        for i in imps:
            if i.addr == ea:
                return i.name
        return None

    def _cross_binary_impl(self, name: str) -> tuple[str, int] | None:
        """``(binary, addr)`` of a project binary that EXPORTS ``name``.

        Reads the on-disk index, so a provider resolves even when its worker was
        evicted — the whole reason the index exists.
        """
        if self._index is None or self._project is None or not name:
            return None
        try:
            hits = self._index.providers(name, exclude=self._binary)
        except Exception:  # noqa: BLE001
            return None
        return (hits[0].binary, hits[0].addr) if hits else None

    def _follow_import(self, ea: int) -> bool:
        """Follow an import stub into the binary that implements it. True when
        it was handled (caller must not also navigate locally)."""
        name = self._import_stub(ea)
        if not name:
            return False
        found = self._cross_binary_impl(name)
        if found is None:
            # Leave the local navigation alone: landing on the stub is still the
            # honest answer when nothing in the project provides the symbol.
            return False
        label, addr = found
        self.app.call_from_thread(
            self._status, f"{name} \u2192 {label}  (import resolved)")
        self.app.call_from_thread(self._switch_then_goto, label, addr)
        return True

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
        if self._follow_import(addr):
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
        else:  # nothing to xref -> still clear the busy overlay
            self.app.call_from_thread(self._present_xrefs, "xrefs", [], None, 0)

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
        try:
            return self._xrefs_present_inner(subj, subj_name, here_ea, here_end)
        except Exception as e:  # noqa: BLE001 -- never leave the busy overlay stuck
            self.app.call_from_thread(self._status, f"xrefs failed: {e}")
            self.app.call_from_thread(self._present_xrefs, "xrefs", [], None, 0)

    def _xrefs_present_inner(self, subj, subj_name, here_ea, here_end):  # type: ignore[no-untyped-def]
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
            kind = x.kind or x.type or "?"
            items.append((x.frm, f"{x.frm:08X}  {kind:<6}  {loc}"))
        preselect = self._xref_preselect(xr, here_ea, here_end)
        # Callers in OTHER project binaries. xrefs_to only ever sees this
        # database, so an exported function looks unused from the inside even
        # when half the project calls it — the import side of the linkage index
        # is the only place that knowledge exists.
        for label_b, addr_b, text_b in self._foreign_importers(subj, subj_name, fn):
            items.append(((label_b, addr_b), text_b))
        self.app.call_from_thread(self._present_xrefs, label, items, focus, preselect)

    def _foreign_importers(self, subj: int, subj_name, fn):  # type: ignore[no-untyped-def]
        """Project binaries that IMPORT the symbol at ``subj`` — the other half
        of the phase-3 join, read from the on-disk index so a caller shows up
        whether or not its worker is resident.

        Only for a symbol this binary actually exports: a local name that
        happens to collide with another binary's import isn't a caller of ours.
        """
        if self._index is None or self._project is None or self._binary is None:
            return []
        name = subj_name if self._looks_like_symbol(subj_name) else None
        if name is None and fn is not None and fn.addr == subj:
            name = fn.name
        if not name:
            return []
        from .domain import link_name
        name = link_name(name)
        try:
            _, exports = self.program.linkage()
        except Exception:  # noqa: BLE001
            return []
        if not any(e.name == name for e in exports):
            return []          # we don't export it; nobody imports it FROM US
        try:
            hits = self._index.importers(name, exclude=self._binary)
        except Exception:  # noqa: BLE001
            return []
        return [(h.binary, h.addr, f"{h.addr:08X}  import  [{h.binary}] {name}")
                for h in hits]

    def _present_xrefs(self, label: str, items: list[tuple[object, str]],
                       focus_name: str | None = None, preselect: int = 0) -> None:
        if not self._xref_active:
            return  # cancelled (Esc) while we were still gathering
        self._xref_active = False
        self._dismiss_busy()
        if not items:
            self._status(f"{label}: none")
            return
        self._xref_focus_name = focus_name
        self._status(f"{label}: {len(items)}")
        self.push_screen(XrefsScreen(label, items, preselect), self._on_xref_chosen)

    def _on_xref_chosen(self, addr) -> None:  # type: ignore[no-untyped-def]
        if addr is None:
            return
        if isinstance(addr, tuple):   # a caller in another project binary
            binary, ea = addr
            self._switch_then_goto(binary, ea)   # records a hop, so Esc returns
            return
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
        if isinstance(view, ListingView):
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
            # Snapshot the LIVE pseudocode position before forcing a recompile.
            # dec_scroll_y isn't tracked on every move, so without this the reload
            # falls into show()'s derive path (a bare scroll_to) and leaves a
            # stale frame until the next cursor move; capturing the real scroll
            # makes show() take the robust _apply_scroll path and repaint now.
            dec = self.query_one(DecompView)
            if cur.ea == dec.loaded_ea:
                cur.dec_cursor = dec.cursor
                cur.dec_cursor_x = dec.cursor_x
                cur.dec_scroll_y = round(dec.scroll_offset.y)
                cur.dec_scroll_x = round(dec.scroll_offset.x)
            dec.loaded_ea = None  # force re-decompile
            self._show_active()
        else:
            # Capture the LIVE position from the widget (the source of truth)
            # rather than trusting nav-entry tracking, which goes stale. Capture
            # it as ADDRESSES via the anchor: bump_names() discards the segment
            # model so the reload rebuilds it, and an edit that changes how many
            # rows an item takes makes the old indices point somewhere else.
            # Index capture is CORRECT here and an anchor is not: a rename or
            # comment doesn't change how many rows anything takes, and the model
            # this rebuilds is constructed empty — index_of_ea on it returns -1
            # until pages load, so an anchor would resolve to nothing while
            # costing an extra model build on the UI thread. Address anchoring is
            # for the edit paths that DO change row structure (see _do_edit_item).
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
        # 2) a symbol under the cursor: a function (retype its prototype) or a
        #    global/data item (retype the variable). Without the data case a
        #    global fell through to (3) and silently retyped the ENCLOSING
        #    function's prototype instead.
        if kind is None and self._looks_like_symbol(word):
            try:
                tgt = self.program.resolve(word)
            except Exception:  # noqa: BLE001
                tgt = None
            if tgt is not None:
                tft = self.program.func_types(tgt)
                if tft is not None:
                    kind, subject, prefill = "func", tgt, tft.prototype
                else:
                    dt = self.program.data_type(tgt)
                    if dt is not None and not dt.get("is_func"):
                        kind, subject = "data", tgt
                        prefill = dt.get("type") or self._guess_data_type(
                            dt.get("size") or 0)
        # 3) fall back to the current function itself
        if kind is None and ft is not None:
            kind, subject, prefill = "func", self._cur.ea, ft.prototype
        if kind is None:
            self.app.call_from_thread(self._status, "nothing to retype under the cursor")
            return
        self.app.call_from_thread(self._open_retype, view, kind, subject, word or "", prefill)

    @staticmethod
    def _guess_data_type(size: int) -> str:
        """A sensible prefill when a global carries no type yet."""
        return {1: "unsigned __int8", 2: "unsigned __int16",
                4: "unsigned __int32", 8: "unsigned __int64"}.get(
                    size, f"char[{size}]" if size > 0 else "void *")

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
        elif kind == "data":  # a global / data item referenced in the body
            err = self.program.set_data_type(subject, new)
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
    def _do_make_data(self, ea: int, type_decl: str,
                      anchor: ViewAnchor | None = None) -> None:  # worker context
        assert self.program is not None
        try:
            self.program.make_data(ea, type_decl)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"make data: {e}")
            return
        self.program.bump_items()
        anchor = anchor or ViewAnchor()
        anchor.flash = f"data ({type_decl}) @ {ea:#x}   (Ctrl+S to save)"
        name = self.program.region_label(ea)
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        _cur, top = self._anchor_rows(anchor, lm, ea)
        self.app.call_from_thread(
            self._open_at, ea, name, idx, False, -1, 0, True, None, top)
        self.app.call_from_thread(self._edit_done, anchor)

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
        view = msg.view
        ea = view._cursor_ea() if isinstance(view, ListingView) else None
        if ea is None:
            self._status("no address on this line to (re)define")
            return
        self._do_edit_item(msg.kind, ea, self._anchor())

    @work(thread=True, exclusive=True, group="edititem")
    def _do_edit_item(self, kind: str, ea: int,
                      anchor: ViewAnchor | None = None) -> None:  # worker context
        assert self.program is not None
        verb = {"code": "defined code", "func": "created function",
                "undef": "undefined", "string": "made string",
                "thumb": "switched decoding", "thumbscan": "scanned"}[kind]
        try:
            if kind == "code":
                # Keep going until something stops it: one instruction is rarely
                # what you want, and on a raw image it means pressing `c` once
                # per opcode for the length of a function.
                r = self.program.define_code_run(ea)
                n, why = int(r.get("count", 0)), r.get("stopped", "")
                if n == 0 and why == "defined":
                    # Already code/data here — a no-op, not a failure. Saying
                    # "failed to create instruction" for it would be a lie.
                    self.app.call_from_thread(
                        self._status, f"already defined @ {ea:#x}")
                    return
                if n == 0:
                    raise IDAToolError("define_code",
                                       f"@ {ea:#x}: Failed to create instruction")
                end = int(str(r.get("end", hex(ea))), 0)
                reason = {"undecodable": "hit bytes that don't decode",
                          "flow": "control flow ends here",
                          "defined": "ran into existing code/data",
                          "segment": "end of segment",
                          "limit": "instruction limit"}.get(why, why)
                verb = (f"defined {n} instruction{'s' if n != 1 else ''} "
                        f"({ea:#x}\u2013{end:#x}) \u2014 {reason}")
            elif kind == "thumbscan":
                # A vector table is a list of Thumb entry points that IDA won't
                # follow on a headerless image, because nothing tells it those
                # words are pointers. Scan from the cursor.
                anchor.refresh_functions = True
                r = self.program.thumb_scan(ea, ea + 0x400)
                n, applied = int(r.get("n", 0)), int(r.get("applied", 0))
                if not n:
                    verb = (f"no Thumb entry pointers in {ea:#x}\u2013{ea+0x400:#x}"
                            " (odd words pointing into the image)")
                else:
                    verb = (f"{n} Thumb entr{'y' if n == 1 else 'ies'} found, "
                            f"{applied} disassembled")
            elif kind == "thumb":
                # Switch the mode, then disassemble in it: flipping T and
                # leaving the bytes undefined shows nothing, and the reason you
                # flipped it was to read the code.
                r = self.program.set_thumb(ea)
                run = self.program.define_code_run(ea)
                n = int(run.get("count", 0))
                mode = "Thumb" if r.get("thumb") else "ARM"
                verb = f"{mode} @ {ea:#x}"
                if r.get("forced_32bit"):
                    verb += " (segment set to 32-bit; Thumb needs ARM32)"
                if r.get("db_64bit"):
                    # Disassembly will look right and F5 will never work.
                    verb += ("  \u26a0 this database is 64-bit, so Hex-Rays "
                             "won't decompile it \u2014 Ctrl+L and pick "
                             "arm:ARMv7-A")
                verb += (f" \u2014 {n} instruction{'s' if n != 1 else ''}"
                         if n else " \u2014 still doesn't decode")
                # falls through to the shared reload: same cache bump, same
                # anchor restore, same flash. That is the whole point of having
                # one path.
            elif kind == "func":
                anchor.refresh_functions = True
                r = self.program.define_func(ea)
                if r.get("start") and r.get("end"):
                    verb = (f"created function {r['start']}\u2013{r['end']}"
                            + (" (end worked out from the code)"
                               if r.get("how") == "explicit-end" else ""))
            elif kind == "string":
                s = self.program.make_string(ea)
                verb = f"made string ({s[:24]!r})" if s else verb
            else:
                # Undefining can destroy a function as easily as `p` creates one.
                anchor.refresh_functions = True
                self.program.undefine(ea)
        except Exception as e:  # noqa: BLE001 -- surface soft/hard tool errors
            self.app.call_from_thread(self._status, f"{kind}: {e}")
            return
        # Structure changed everywhere: drop all item/function/decomp caches.
        self.program.bump_items()
        # Re-resolve: a define_func upgrades the region to a real function view;
        # anything else re-reads the (still function-less) listing in place.
        anchor = anchor or ViewAnchor()
        anchor.flash = f"{verb} @ {ea:#x}   (Ctrl+S to save)"
        fn = self.program.function_of(ea)
        if fn is not None:
            model = self.program.disasm(fn.addr, fn.name)
            idx = 0 if ea == fn.addr else model.index_of_ea(ea)
            _cur, top = self._anchor_rows(anchor, model, ea)
            self.app.call_from_thread(
                self._open_at, fn.addr, fn.name, idx, False, -1, 0, False,
                None, top)
        else:
            name = self.program.region_label(ea)
            lm = self.program.listing(ea)
            idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
            _cur, top = self._anchor_rows(anchor, lm, ea)
            self.app.call_from_thread(
                self._open_at, ea, name, idx, False, -1, 0, True, None, top)
        self.app.call_from_thread(self._edit_done, anchor)

    def _edit_done(self, anchor: ViewAnchor) -> None:
        """One place where an edit's aftermath is settled.

        The reload this edit triggered will write its own status when it lands —
        after this — so the message is handed over as a flash rather than
        written and lost.
        """
        self._dirty = True
        if anchor.flash:
            self._status(anchor.flash, priority=True)
        if anchor.refresh_functions:
            # Creating (or destroying) a function changes the index that the
            # names pane, Ctrl+N and the "no functions" hint all read. Without
            # this, `p` gave you a function the rest of the app couldn't see.
            self._reindex_functions()

    def _load_trace(self) -> None:
        """Parse the trace and line it up with the database.

        Runs after the function index exists: rebasing needs the database's
        addresses, and without it nothing in the trace matches anything on
        screen (our echo trace runs at 0x7ffff6faa000; the database has that
        code at 0x2000).
        """
        from .trace import Trace
        path = self._trace_path
        try:
            def note(n):
                self.app.call_from_thread(
                    self._status, f"trace: {n:,} instructions\u2026")
            trace = Trace.load(path, progress=note)
        except OSError as e:
            self.app.call_from_thread(self._status, f"trace: {e}")
            return
        if not trace.length:
            self.app.call_from_thread(
                self._status, f"trace: {os.path.basename(path)} is empty")
            return
        idx = self._func_index
        addrs = [f.addr for f in idx.all_loaded()] if idx is not None else []
        slide = trace.rebase(addrs)
        trace.apply_slide(slide)
        hit = sum(1 for f in (idx.all_loaded() if idx else []) if trace.executions(f.addr))
        self.app.call_from_thread(self._trace_ready, trace, slide, hit)

    def _trace_ready(self, trace, slide: int, hit: int) -> None:
        self._trace = trace
        self._t = 0
        dock = self.query_one(TraceDock)
        dock.display = True
        dock.show(trace, 0)
        where = (f"rebased {slide:+#x}" if slide else "no rebase needed")
        self._status(f"trace: {trace.length:,} instructions, {hit} functions "
                     f"touched ({where})", priority=True)
        self._seek(0, follow=True)

    # -- trace navigation --------------------------------------------------- #
    def _seek(self, idx: int, follow: bool = True) -> None:
        """Move to timestamp ``idx``; ``follow`` takes the code view with it."""
        t = self._trace
        if t is None or not t.length:
            return
        self._t = max(0, min(int(idx), t.length - 1))
        self.query_one(TraceDock).show(t, self._t)
        self._paint_trail()
        if not follow:
            return
        pc = t.ip(self._t)
        if self._split and self._seek_split(pc):
            return
        # Stay in whichever view you're reading. Without prefer_decomp a step
        # from the pseudocode navigates to an address, which opens the listing —
        # so stepping through C threw you out of C on the first keypress.
        self._goto_ea(pc, push=False,
                      prefer_decomp=(self._active == "decomp"))

    def _seek_split(self, pc: int) -> bool:
        """Put BOTH panes on ``pc``. True if handled.

        Normal navigation moves one pane and gives the companion a band, never a
        cursor — that rule exists so the two can't chase each other. A trace step
        isn't navigation though: time is a single global position, and both views
        are showing the same instant, so both cursors belong on it.

        The scroll anchoring is unchanged: after placing the cursors, the usual
        _sync_split still bands the companion and aligns it to the driver's
        screen row, so the eye tracks straight across.
        """
        lst = self.query_one(ListingView)
        dec = self.query_one(DecompView)
        if lst.model is None:
            return False
        row = lst.model.ensure_ea(pc)
        if row is None or row < 0:
            return False        # not in this listing (other segment): full nav
        lst.cursor = row
        lst._scroll_cursor_into_view()

        # Has execution actually left the decompiled function? Ask the map the
        # trail painting keeps, which is keyed to what the decompiler currently
        # HOLDS. _split_range comes from the guarded async path and lags, so a
        # stale one made every step look like a function change: the decompiler
        # bounced main -> PLT stub -> main, each bounce costing a synchronous
        # 769-line map fetch on the UI thread.
        span = self._trail_span
        inside = (pc in self._trail_line_of
                  or (span is not None and span[0] <= pc <= span[1]))
        if not inside:
            self._pending_trace_line = pc
            self._resync_decomp_async(pc)
            return True
        self._place_decomp_at(pc)
        self._sync_split(self._active)
        return True

    def _place_decomp_at(self, pc: int) -> None:
        """Move the pseudocode cursor to the line covering ``pc``.

        Uses the map the trail painting already keeps (keyed to the decompiler's
        CURRENTLY loaded function), not the split view's _split_ea2line. That one
        is refreshed by a guarded async path — it drops a result if _cur moved
        while it was in flight — and a burst of steps moves _cur constantly, so
        during stepping it is frequently a map of the function you just left.
        """
        dec = self.query_one(DecompView)
        line = None
        if self._trail_map_ea == dec.loaded_ea and self._trail_line_of:
            # EXACT match only. The decompiler doesn't attribute every
            # instruction to a line (about half of main's aren't), and the
            # tempting fallback — the nearest mapped instruction at or before
            # the pc — is unsound: C lines are not monotonic in address, so
            # 0x24a8 early in main resolved to line 708, "sub_2040();", near the
            # end. A cursor that jumps to an unrelated statement is worse than
            # one that waits; the trail still marks where we are.
            line = self._trail_line_of.get(pc)
        if line is None:
            line = self._split_ea2line.get(pc)
        if line is None:
            line = dec.line_for_ea(pc)
        if line is not None:
            dec.goto(line, dec.cursor_x)

    @work(thread=True, exclusive=True, group="split-resync")
    def _resync_decomp_async(self, ea: int) -> None:
        self._resync_decomp(ea)

    def _paint_trail(self) -> None:
        """Push the execution trail into the code views.

        Recomputed per seek rather than per repaint: it's ~200 lookups, and a
        repaint happens far more often than a step.
        """
        t = self._trace
        if t is None:
            return
        try:
            hx = self.query_one(HexView)
            hx.trace, hx.trace_idx = t, self._t
            if hx.display:
                hx.refresh()
        except Exception:  # noqa: BLE001 -- not mounted yet
            pass
        trail = t.trail(self._t)
        try:
            lst = self.query_one(ListingView)
            lst.trail = trail
            lst.refresh()
        except Exception:  # noqa: BLE001 -- view not mounted yet
            pass
        self._paint_trail_decomp(trail)

    def _paint_trail_decomp(self, trail: dict) -> None:
        """Map the instruction trail onto pseudocode lines.

        This is the thing Tenet can't do: it paints disassembly, because that's
        where a trace's addresses live. We already have decomp_map (built for
        the split view) saying which instructions each pseudocode line covers,
        so the same trail lands on C.

        A line covers many instructions, so it takes the strongest kind present:
        'now' wins over 'past' wins over 'future' — if the instruction you are
        standing on is part of this line, this line is where you are.
        """
        try:
            dec = self.query_one(DecompView)
        except Exception:  # noqa: BLE001
            return
        ea = dec.loaded_ea
        if not dec.display or ea is None or self.program is None:
            dec.trail = {}
            return
        if self._trail_map_ea != ea:
            # One index, built once per decompiled function and shared with the
            # split view (_apply_split_map fills the same fields). decomp_map is
            # an RPC and stepping is interactive, so paying it per keystroke —
            # or twice, once for each of two parallel maps — would be felt.
            try:
                self._apply_split_map(ea, self.program.decomp_map(ea))
            except Exception:  # noqa: BLE001
                self._trail_map, self._trail_map_ea = [], ea
                self._trail_line_of, self._trail_eas = {}, []
                self._trail_span = None
        rank = {"future": 0, "past": 1, "now": 2}
        lines: dict[int, str] = {}
        for i, eas in enumerate(self._trail_map or []):
            best = None
            for a in eas:
                k = trail.get(a)
                if k is not None and (best is None or rank[k] > rank[best]):
                    best = k
            if best is not None:
                lines[i] = best
        dec.trail = lines
        dec.refresh()
        pend, self._pending_trace_line = self._pending_trace_line, None
        if pend is not None and self._split:
            # The function was still decompiling when the step happened; land
            # now that its line map exists.
            self._place_decomp_at(pend)
            self._sync_split(self._active)

    def _step(self, delta: int) -> None:
        if self._trace is None:
            self._status("no trace loaded (--trace FILE)")
            return
        self._seek(self._t + delta)

    def _seek_hit(self, direction: int) -> None:
        """Seek to the next/previous time the focused view's subject was touched.

        Two different questions with one pair of keys, because the answer to
        "which thing?" is already on screen: in a code view it's the instruction
        under the cursor ("when else did this run?"), in hex it's the byte under
        the cursor ("who else touched this?").
        """
        t = self._trace
        if t is None:
            self._status("no trace loaded (--trace FILE)")
            return
        if self._active == "hex":
            hx = self._try_view(HexView)
            va = hx.cursor_va() if hx is not None else None
            if va is None:
                return
            stamps = t.memory_accesses(va, 1)
            what = f"access to {va:#x}"
        else:
            view = self._active_code_view()
            if isinstance(view, DecompView):
                # A C line is not one address, so ask about the whole statement:
                # "when else did this line run?" is the question, and it's the
                # union of its instructions' executions. Falling back to the
                # line's single /*ea*/ marker would answer a narrower question
                # and often no question at all, since most lines have no marker.
                line = view.cursor
                eas = []
                if (self._trail_map_ea == view.loaded_ea
                        and 0 <= line < len(self._trail_map or [])):
                    eas = list(self._trail_map[line])
                if not eas:
                    one = view._line_ea(line)
                    eas = [one] if one is not None else []
                if not eas:
                    self._status("this line has no instructions to seek on",
                                 priority=True)
                    return
                stamps = sorted({x for e in eas for x in t.executions(e)})
                what = f"execution of C line {line + 1}"
            else:
                ea = view._cursor_ea() if view is not None else None
                if ea is None:
                    self._status("no address on this line", priority=True)
                    return
                stamps = list(t.executions(ea))
                what = f"execution of {ea:#x}"
        if not stamps:
            self._status(f"no {what} in this trace", priority=True)
            return
        import bisect as _b
        if direction > 0:
            i = _b.bisect_right(stamps, self._t)
        else:
            i = _b.bisect_left(stamps, self._t) - 1
        if not (0 <= i < len(stamps)):
            edge = "last" if direction > 0 else "first"
            self._status(f"already at the {edge} {what} "
                         f"({len(stamps)} in the trace)", priority=True)
            return
        self._seek(stamps[i])
        self._status(f"{what}: {i + 1} of {len(stamps)}  @ t={stamps[i]:,}",
                     priority=True)

    def action_seek_next_hit(self) -> None:
        self._seek_hit(1)

    def action_seek_prev_hit(self) -> None:
        self._seek_hit(-1)

    def action_seek_reg_write(self) -> None:
        """W: which instruction set each register to its current value."""
        t = self._trace
        if t is None:
            self._status("no trace loaded (--trace FILE)")
            return
        rows = []
        for name in t.registers:
            v = t.register(name, self._t)
            if v is None:
                continue
            rows.append((name, v, t.last_write(name, self._t),
                         t.next_write(name, self._t)))
        if rows:
            self.push_screen(RegWriteScreen(rows, self._t), self._on_reg_write_chosen)

    def _on_reg_write_chosen(self, idx) -> None:  # type: ignore[no-untyped-def]
        if idx is not None:
            self._seek(int(idx))

    def action_step_fwd(self) -> None:
        self._step(1)

    def action_step_back(self) -> None:
        self._step(-1)

    def _step_over(self, direction: int) -> None:
        """Step over a call by following the stack pointer.

        A call pushes, so the callee runs with SP BELOW where we started;
        stepping until SP comes back up lands after the call returns. Cheaper
        and more robust than recognising call instructions per architecture,
        which is what the mode makes it: if this instruction doesn't call
        anything, SP is already >= the start and it degenerates to one step.
        """
        t = self._trace
        if t is None:
            self._status("no trace loaded (--trace FILE)")
            return
        sp_name = "rsp" if "rsp" in t.reg_at else ("esp" if "esp" in t.reg_at else "sp")
        sp0 = t.register(sp_name, self._t)
        i = self._t + direction
        limit = 200000          # a runaway search must not hang the UI
        while 0 <= i < t.length and limit > 0:
            sp = t.register(sp_name, i)
            if sp0 is None or sp is None or sp >= sp0:
                break
            i += direction
            limit -= 1
        self._seek(max(0, min(i, t.length - 1)))

    def action_step_over_fwd(self) -> None:
        self._step_over(1)

    def action_step_over_back(self) -> None:
        self._step_over(-1)

    @work(thread=True, exclusive=True, group="load-funcs")
    def _reindex_functions(self) -> None:
        """Rebuild the function index in place after an edit changed it.

        Deliberately not _load_functions(): that one is the BOOT path — it
        clears the table, streams progress and then auto-lands, which would
        yank the view away from the function you just made.
        """
        if self.program is None:
            return
        idx = self.program.functions()
        idx.load_all()
        self._func_index = idx
        self.app.call_from_thread(self._after_reindex)

    def _after_reindex(self) -> None:
        idx = self._func_index
        if idx is None:
            return
        if len(idx):
            self._no_functions = False
        self._apply_filter(self._filter_term)   # repopulate the names pane

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
        # Which navigation this is. Decompiling below can take a while, and if
        # you press Esc (or jump again) in the meantime this result is stale —
        # applying it anyway silently undoes what you just did.
        seq = self._nav_seq
        fn = self.program.function_of(ea)
        # Jumping FROM the decompiler: stay in pseudocode when the target is a
        # decompilable function, landing on the line that matches ``ea``.
        if prefer_decomp and fn is not None:
            dec = self.program.decompile(fn.addr)
            if not dec.failed and dec.code:
                if ea == fn.addr:
                    # Jumping to the function itself: land on its name in the
                    # prototype (line 0), not column 0.
                    dec_idx = 0
                    col = self._decomp_col_for(fn.addr, 0, fn.name)
                else:
                    # A mid-function site (e.g. an xref jump to a call site):
                    # anchor on the address but snap to the nearest line that
                    # actually holds the referenced symbol (the marker line and
                    # the symbol's line can differ), landing on the token.
                    dec_idx, col = self._decomp_locate(fn.addr, ea,
                                                       focus_name or fn.name)
                self.app.call_from_thread(
                    self._open_decomp_entry, fn.addr, fn.name, dec_idx, col,
                    push, seq)
                return
        # Otherwise: everything opens the one continuous listing at ``ea``. A
        # function name is used for the status label; a region gets a segment
        # label. F5/Tab decompiles the function under the cursor from here.
        lm = self.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        name = fn.name if fn is not None else self.program.region_label(ea)
        self.app.call_from_thread(
            self._open_at, ea, name, idx, push, -1, 0, fn is None, focus_name)

    def _open_decomp_entry(self, fn_addr: int, fn_name: str, dec_idx: int,
                           dec_cursor_x: int, push: bool,
                           seq: int | None = None) -> None:
        """Open ``fn_addr`` in the decompiler as a real navigation (nav history
        aware), landing on pseudocode line ``dec_idx`` column ``dec_cursor_x``.

        ``seq`` is the navigation this result belongs to; if the user has
        navigated since (Esc, another jump), the result is stale and dropped —
        otherwise a slow decompile lands afterwards and undoes their Esc.
        """
        if seq is not None and seq != self._nav_seq:
            return
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
                    self._push_nav(src)   # never stack a second copy of a spot
            else:
                self._save_current_pos()
        self._decomp_return = None  # a real navigation abandons the F5 return
        entry = NavEntry(ea=fn_addr, name=fn_name, view="decomp",
                         dec_cursor=dec_idx, dec_cursor_x=dec_cursor_x)
        if push:
            self._push_nav(entry)
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

    def _decomp_locate(self, fn_addr: int, ea: int,
                       token: str | None) -> tuple[int, int]:
        """Best (line, column) for address ``ea`` in ``fn_addr``'s pseudocode.

        Anchors on the /*0xEA*/ marker line for ``ea``, but Hex-Rays can attribute
        an address to a line a step off from where the referenced symbol actually
        appears. So when ``token`` is given, snap to the whole-word occurrence of
        it NEAREST the anchor line (preferring the anchor line itself, then the
        line just below), which disambiguates repeated symbols by address."""
        assert self.program is not None
        try:
            dec = self.program.decompile(fn_addr)
        except Exception:  # noqa: BLE001
            return (0, 0)
        lines = (dec.code or "").splitlines()
        if not lines:
            return (0, 0)
        anchor = self._decomp_line_for(fn_addr, ea)
        anchor = anchor if anchor >= 0 else 0
        if not token:
            return (anchor, 0)
        pat = re.compile(rf"\b{re.escape(token)}\b")
        best: tuple[int, int] | None = None
        best_key: tuple[int, int] | None = None
        for i, ln in enumerate(lines):
            m = pat.search(_ADDR_MARK_STRIP_RE.sub("", ln))
            if not m:
                continue
            # rank: nearest to the anchor; tie -> the line at/after the anchor.
            key = (abs(i - anchor), 0 if i >= anchor else 1)
            if best_key is None or key < best_key:
                best_key, best = key, (i, m.start())
        return best if best is not None else (anchor, 0)

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

    @staticmethod
    def _same_spot(a: NavEntry, b: NavEntry) -> bool:
        """Same function, same view, same line — i.e. going from a to b is not a
        move, so it has no business being a step in the history."""
        if a.ea != b.ea or a.view != b.view:
            return False
        return (a.dec_cursor == b.dec_cursor if a.view == "decomp"
                else a.cursor == b.cursor)

    def _push_nav(self, entry: NavEntry) -> None:
        """Append to the nav stack unless that would duplicate where we already are.

        Opening the place you're standing on — the app auto-lands on main, then
        you pick main out of Ctrl+N — used to append an identical entry. The Esc
        it created popped the stack without changing anything on screen: a dead
        keypress, which is exactly what "back doesn't work" feels like. Replace
        the top instead, so the newer entry's metadata still wins.
        """
        top = self._nav[-1] if self._nav else None
        if top is not None and self._same_spot(top, entry):
            self._nav[-1] = entry
            return
        self._nav.append(entry)

    # -- view state across a model rebuild --------------------------------- #
    def _anchor(self, flash: str | None = None) -> ViewAnchor:
        """Capture where we're looking, BEFORE an edit rebuilds the model.

        Must run on the UI thread: it reads live widget state.
        """
        a = ViewAnchor(view=self._active, flash=flash)
        view = self._active_code_view()
        model = getattr(view, "model", None)
        if view is None or model is None:
            return a
        a.cursor_x = getattr(view, "cursor_x", 0)
        try:
            a.ea = view._cursor_ea()
        except Exception:  # noqa: BLE001
            a.ea = None
        top = round(view.scroll_offset.y)
        h = model.cached_line(top) or model.get(top)
        a.top_ea = getattr(h, "ea", None)
        return a

    @staticmethod
    def _anchor_rows(a: ViewAnchor, model, fallback_ea: int | None = None):
        """(cursor_row, top_row) for ``a`` in a freshly built ``model``.

        -1 means "no opinion" — the caller's own default wins.
        """
        if model is None:
            return (-1, -1)

        def row_of(ea):
            if ea is None:
                return -1
            try:
                i = model.index_of_ea(ea)
            except Exception:  # noqa: BLE001
                return -1
            return i if i >= 0 else -1

        cur = row_of(a.ea if a.ea is not None else fallback_ea)
        if cur < 0 and fallback_ea is not None:
            cur = row_of(fallback_ea)
        return (cur, row_of(a.top_ea))

    def _open_at(self, ea: int, name: str, cursor: int, push: bool,
                 dec_cursor: int = -1, dec_cursor_x: int = 0,
                 is_region: bool = False, focus_name: str | None = None,
                 scroll_y: int = -1) -> None:
        if push:
            self._save_current_pos()
        self._decomp_return = None  # a real navigation abandons the F5 return
        # Land the cursor on this token (e.g. the ref an xref jump targets) once
        # the row is loaded, instead of column 0.
        self._pending_focus_name = focus_name
        entry = NavEntry(ea=ea, name=name, cursor=cursor, is_region=is_region)
        if scroll_y >= 0:
            entry.scroll_y = scroll_y
        if dec_cursor >= 0:
            entry.dec_cursor = dec_cursor
            entry.dec_cursor_x = dec_cursor_x
        if push:
            self._push_nav(entry)
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
        # Any keypress means the result of the last edit has been read.
        self._flash = None
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
                self._do_make_data(ea, value, self._anchor())
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
        """The code pane the user is in — where focus belongs after a prompt closes.

        This used to pick on _pref, which was always "listing", so closing the
        goto prompt while reading pseudocode threw focus into the listing.
        """
        return self._active_code_view()

    def _active_code_view(self):  # type: ignore[no-untyped-def]
        """The currently-shown code widget (for reading the cursor address)."""
        if self._active in ("listing", "disasm"):
            return self.query_one(ListingView)
        if self._active == "decomp":
            return self.query_one(DecompView)
        return None

    def _palette_action(self, name: str) -> None:
        """Run a cursor-scoped code-view action (rename/xrefs/follow/…) picked from
        the command palette against the active code view."""
        view = self._active_code_view()
        if view is None:
            self._status("open a function first")
            return
        view.focus()
        fn = getattr(view, f"action_{name}", None)
        if fn is None:
            self._status(f"'{name}' isn't available in this view")
            return
        fn()

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
        focus = self._pending_focus_name  # one-shot: consume it here
        self._pending_focus_name = None
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
                cursor_x=entry.cursor_x, scroll_y=sy, focus=focus)
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
        if self._split and self._active in ("listing", "decomp"):
            # Side-by-side: listing (left) + pseudocode (right), one focused.
            hx.display = False
            lst.display = dec.display = True
            self.query_one("#panes").set_class(True, "split")
            busy = self._cur is not None and dec.loaded_ea != self._cur.ea
            if busy:
                dec.loading = True
                self._load_decomp(self._cur.ea, self._cur.name)
            else:
                dec.loading = False
            if grab:
                (dec if self._active == "decomp" else lst).focus()
            if busy and self._cur is not None:
                # Keep the in-flight message: the idle status used to overwrite
                # it, so travelling history in split showed nothing at all while
                # a decompile ran and Esc looked like a no-op.
                self._status(f"{self._cur.name} \u2014 decompiling\u2026")
            else:
                self._status_for_cur("split")
            return
        self._split = False  # a single-view target (hex, etc.) leaves split
        self.query_one("#panes").set_class(False, "split")
        lst.set_link(set())
        dec.set_link(None)
        self._split_eamap = []
        self._split_ea2line = {}
        self._split_range = None
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
                # Already showing this function: clear any overlay raised by the
                # F5-from-listing path (no re-decompile happens here, so nothing
                # else would).
                dec.loading = False
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
        self._active = self._code_mode()
        self._goto_ea(msg.va, push=True)

    def _status_for_cur(self, mode: str) -> None:
        if self._cur is not None:
            self._status(f"{self._cur.name}  @ {self._cur.ea:#x}   [{mode}]")

    @work(thread=True, exclusive=True, group="decomp")
    def _load_decomp(self, ea: int, name: str) -> None:
        assert self.program is not None
        dec = self.program.decompile(ea)
        why = ""
        if dec.failed:
            # Ask Hex-Rays why, in the same worker: the plain tool reports
            # "Decompilation failed at 0x0" and drops the only useful part.
            # "Decompile failed" with no reason is indistinguishable from a bug
            # in this app, and for the common cause (a 32-bit function in a
            # 64-bit database) the user cannot even guess the fix.
            why = self.program.decomp_error(ea)
        self.app.call_from_thread(self._apply_decomp, ea, name, dec, why)

    def _apply_decomp(self, ea: int, name: str, dec,  # type: ignore[no-untyped-def]
                      why: str = "") -> None:
        view = self.query_one(DecompView)
        view.loading = False
        if dec.failed:
            detail = f" \u2014 {why}" if why else ""
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
                # Hand the reason over as a flash BEFORE reopening: going back
                # to the listing reloads it, and the reload writes its own
                # status afterwards — which is precisely how "F5 does nothing"
                # looked like nothing at all.
                msg = f"{name}: cannot decompile{detail}"
                self._status(msg, priority=True)
                self._open_entry(ret, push=False)
                return
            self._active = "disasm"
            self._status(f"{name}: cannot decompile{detail}", priority=True)
            self._show_active()
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
        if self._split:
            self._sync_split(self._active)  # crude link now
            self._load_split_map(ea)        # then upgrade to the region map
            self._split_status()
        else:
            self._status(
                f"{name}  @ {ea:#x}   [pseudocode {len(dec.code or '')} chars]{note}")

    def _sync_split(self, source: str) -> None:
        """Split view: highlight (+ scroll into view) the companion pane's
        location for the focused pane's cursor. The companion only gets a band +
        scroll (its cursor never moves), so there is no echo/ping-pong. Uses the
        rich per-line ea map (decomp_map) when loaded, else the single marker."""
        if not self._split or self.program is None:
            return
        lst = self.query_one(ListingView)
        dec = self.query_one(DecompView)
        if source == "decomp":
            dec.set_link(None)  # the driver shows its own cursor, no band
            line, screen = self._split_anchor(dec)
            eas = (self._split_eamap[line]
                   if 0 <= line < len(self._split_eamap) else [])
            if not eas:  # fallback: the single /*ea*/ marker for the line
                one = dec._line_ea(line)
                eas = [one] if one is not None else []
            rows: set[int] = set()
            if lst.model is not None:
                for e in eas:
                    r = lst.model.ensure_ea(e)
                    if r is not None and r >= 0:
                        rows.add(r)
            lst.set_link(rows)
            if rows:
                # keep the linked region level with the driver's anchor row so
                # the eye tracks straight across the two panes
                lst.align(min(rows), screen)
        else:  # the listing drives
            lst.set_link(set())
            row, screen = self._split_anchor(lst)
            head = lst._head(row)
            ea = head.ea if head is not None else None
            if ea is None:
                dec.set_link(None)
                return
            rng = self._split_range
            if rng is not None and not (rng[0] <= ea <= rng[1]):
                # left the decompiled function — follow to whatever function is
                # under the anchor (the unified view spans many functions).
                self._resync_decomp(ea)
                return
            line = self._split_ea2line.get(ea)
            if line is None:  # fallback: nearest marker
                line = dec.line_for_ea(ea)
            if line is not None:
                dec.set_link(line)
                dec.align(line, screen)
            else:
                dec.set_link(None)

    @staticmethod
    def _split_anchor(view) -> tuple[int, int]:  # type: ignore[no-untyped-def]
        """(row, screen_row) the split sync anchors on: the driver's cursor while
        it's visible, else the top visible row. A wheel-scroll/scrollbar drag
        never moves the cursor, so anchoring on the viewport keeps the companion
        following once the cursor scrolls out of sight."""
        top = round(view.scroll_offset.y)
        if top <= view.cursor < top + view._visible_height():
            return view.cursor, view.cursor - top
        return top, 0

    def on_listing_view_scrolled(self, msg: "ListingView.Scrolled") -> None:
        if self._split and self._active == "listing":
            self._sync_split("listing")

    def on_decomp_view_scrolled(self, msg: "DecompView.Scrolled") -> None:
        if self._split and self._active == "decomp":
            self._sync_split("decomp")

    @work(thread=True, group="split-resync", exclusive=True)
    def _resync_decomp(self, ea: int) -> None:
        # The listing cursor crossed out of the decompiled function; find the
        # function it's in now (off the UI thread) and re-point the decomp pane.
        assert self.program is not None
        fn = self.program.function_of(ea)
        self.app.call_from_thread(self._apply_resync, fn)

    def _apply_resync(self, fn) -> None:  # type: ignore[no-untyped-def]
        if not self._split or self._cur is None:
            return
        dec = self.query_one(DecompView)
        if fn is None:
            dec.set_link(None)  # over data/undefined: keep the decomp, drop the band
            return
        self._cur.ea, self._cur.name = fn.addr, fn.name
        if dec.loaded_ea == fn.addr:  # already decompiled (scrolled back): just relink
            self._sync_split("listing")
            return
        dec.loading = True
        self._load_decomp(fn.addr, fn.name)  # -> _apply_decomp -> map -> re-sync

    def _split_status(self) -> None:
        """A split-aware status line reflecting the focused pane + the link."""
        if self._cur is None:
            return
        if self._active == "decomp":
            dec = self.query_one(DecompView)
            ea = dec._line_ea(dec.cursor)
            n = (len(self._split_eamap[dec.cursor])
                 if 0 <= dec.cursor < len(self._split_eamap) else 0)
            at = f" @ {ea:#x}" if ea is not None else ""
            rel = f" \u2194 {n} insn" if n else ""
            self._status(f"{self._cur.name}{at}   "
                         f"[split \u00b7 pseudocode line {dec.cursor + 1}{rel}]"
                         f"   (Tab/click: drive listing)")
        else:
            ea = self.query_one(ListingView)._cursor_ea()
            at = f" @ {ea:#x}" if ea is not None else ""
            self._status(f"{self._cur.name}{at}   [split \u00b7 listing]"
                         f"   (Tab/click: drive pseudocode)")

    def on_descendant_focus(self, event) -> None:  # type: ignore[no-untyped-def]
        """In split, focusing a pane (Tab or a mouse click) makes it the leading/
        driver pane, so the sync direction follows where you're actually working."""
        if not self._split:
            return
        w = event.control
        new = ("decomp" if isinstance(w, DecompView)
               else "listing" if isinstance(w, ListingView) else None)
        if new is not None and new != self._active:
            self._active = new
            self._sync_split(new)
            self._split_status()

    @work(thread=True, group="split-map")
    def _load_split_map(self, ea: int) -> None:
        # Fetch the rich per-line instruction map off the UI thread; sync stays
        # on the crude single-ea fallback until it lands.
        assert self.program is not None
        m = self.program.decomp_map(ea)
        self.app.call_from_thread(self._apply_split_map, ea, m)

    def _apply_split_map(self, ea: int, m: list) -> None:
        """Index the per-line instruction map for the decompiled function.

        Keyed to what the DECOMPILER holds, not to _cur, and not conditional on
        split being on. The old guard dropped the result whenever _cur had moved
        while the fetch was in flight — during trace stepping that is almost
        always — leaving the split view working from the map of the function you
        just left. _cur follows the cursor; this map describes the pseudocode on
        screen, and those are different things.
        """
        dec = self._try_view(DecompView)
        if dec is not None and dec.loaded_ea is not None and ea != dec.loaded_ea:
            return  # a stale fetch for a function we no longer show
        self._split_eamap = m
        self._split_ea2line = {}
        alleas = []
        for line, eas in enumerate(m):
            for e in eas:
                self._split_ea2line.setdefault(e, line)
                alleas.append(e)
        # ea span of the decompiled function: when the listing cursor leaves it,
        # _sync_split re-points the decomp to the function under the cursor.
        self._split_range = (min(alleas), max(alleas)) if alleas else None
        # ONE index, shared with the trace path: it used to keep a parallel copy
        # of exactly this, fetched separately and keyed differently, which is how
        # the two ended up describing different functions.
        self._trail_map, self._trail_map_ea = m, ea
        self._trail_line_of = dict(self._split_ea2line)
        self._trail_eas = sorted(self._trail_line_of)
        self._trail_span = self._split_range
        if self._split:
            self._sync_split(self._active)  # re-link with the region map

    def on_decomp_view_cursor_moved(self, msg: DecompView.CursorMoved) -> None:
        dv = self._try_view(DecompView)
        if self._nav and dv is not None:
            self._nav[-1].dec_cursor = msg.index
            self._nav[-1].dec_cursor_x = dv.cursor_x
        if self._split:
            if self._active == "decomp":
                self._sync_split("decomp")
            self._split_status()
            return
        if self._cur is not None:
            loc = f" @ {msg.ea:#x}" if msg.ea is not None else ""
            self._status(f"{self._cur.name}{loc}   [pseudocode line {msg.index}]")

    def _try_view(self, cls):  # type: ignore[no-untyped-def]
        """The code view, or None. App.query_one searches the TOP screen, so a
        cursor-moved message that lands while any modal is up (the loading
        overlay, a project switch) would otherwise raise NoMatches and kill the
        app from a message handler."""
        try:
            return self.query_one(cls)
        except Exception:  # noqa: BLE001 -- NoMatches: a modal owns the screen
            return None

    def on_listing_view_cursor_moved(self, msg: ListingView.CursorMoved) -> None:
        lst = self._try_view(ListingView)
        if self._nav and lst is not None:
            self._nav[-1].cursor = msg.index
            self._nav[-1].cursor_x = lst.cursor_x
            if msg.index >= 0:
                self._nav[-1].scroll_y = round(lst.scroll_offset.y)
        if self._split:
            if self._active == "listing":
                self._sync_split("listing")
            self._split_status()
            return
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
        if self._pool is not None:
            # _save_on_exit is False only when the user chose discard or we
            # already saved; an unexpected teardown still writes defensively.
            self._pool.close_all(save=self._save_on_exit is not False)
        elif self.client is not None:
            if self._save_on_exit is None and self._dirty:
                try:  # unexpected teardown with edits: don't drop them
                    self.client.call("idb_save", timeout=600.0)
                except Exception:  # noqa: BLE001
                    pass
            self.client.close()
