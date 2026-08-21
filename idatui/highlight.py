"""Pygments-based C highlighting for Hex-Rays pseudocode and the struct editor.

Textual's TextArea has no C/C++ tree-sitter grammar (its bundled languages are
python/rust/go/... only), so ``language="cpp"`` silently does nothing. Pygments
(already a Rich/Textual dependency) has a solid C lexer, so we tokenize once and
map tokens to Rich styles, producing per-line Segment lists the virtualized view
can cache and paint instantly.

The same tokenizer feeds two consumers, so one palette covers both:

* ``highlight_c`` -> Segment lists for the read-only pseudocode view.
* ``CTextArea``   -> an *editable* TextArea (the struct editor) highlighted by
  filling TextArea's own ``_highlights`` map, the hook tree-sitter would use.
"""

from __future__ import annotations

from pygments.lexers import CLexer
from pygments.token import Token
from rich.segment import Segment
from rich.style import Style
from textual.widgets import TextArea
from textual.widgets.text_area import TextAreaTheme

# Token -> (highlight name, style), checked in priority order (first
# hierarchical match wins). The names are what TextArea's theme maps to styles;
# the styles are what the pseudocode view paints directly.
#
# Same measured palette as the listing (see the theme notes): one hue = one
# meaning across BOTH panes, so a string is the same green and a symbol the same
# blue whether you're reading disassembly or pseudocode. Contrast ratios are
# against the app background #12161c; signal sits at 7:1+ and structure recedes
# to 3-4:1 so punctuation stops competing with the code.
#
# Control keywords take the brightest NEUTRAL rather than a hue, mirroring the
# mnemonic column: they're the skeleton you scan for, and a hue there would
# claim a meaning the rest of the palette already assigns.
_PALETTE: list[tuple[str, object, Style]] = [
    (
        "comment",
        Token.Comment,
        Style(color="#7c8b9e", italic=True),
    ),  # 5.2:1  commentary
    ("type", Token.Keyword.Type, Style(color="#93aee0")),  # 8.1:1  type info
    (
        "keyword",
        Token.Keyword,
        Style(color="#e8ecf2", bold=True),
    ),  # 15.3:1 control flow
    ("builtin", Token.Name.Builtin, Style(color="#93aee0")),  # 8.1:1  type info
    ("string", Token.Literal.String, Style(color="#9ece6a")),  # 9.9:1  strings
    ("number", Token.Literal.Number, Style(color="#d8a657")),  # 8.2:1  data/number
    ("operator", Token.Operator, Style(color="#c3cad3")),  # 11.0:1 body
    ("punctuation", Token.Punctuation, Style(color="#626c7a")),  # 3.4:1  structure
    ("name", Token.Name, Style(color="#7aa2f7")),  # 7.2:1  symbol names
]
_STYLES: list[tuple[object, Style]] = [(t, s) for _, t, s in _PALETTE]
_DEFAULT = Style(color="#c3cad3")  # 11.0:1 body
_DEFAULT_NAME = "text"

#: highlight name -> style, for TextArea themes (see ``CTextArea``).
SYNTAX_STYLES: dict[str, Style] = {name: style for name, _, style in _PALETTE}
SYNTAX_STYLES[_DEFAULT_NAME] = _DEFAULT

_lexer = CLexer(stripnl=False, ensurenl=False)


#: Resolved styles by token type. Pygments token types are interned singletons
#: and a whole decompilation only ever uses about eighteen of them, but
#: ``token in ttype`` is a hierarchy walk and _STYLES is scanned in order -- so
#: without this every token in the body pays up to nine of those walks. It was a
#: quarter of the time spent highlighting a function.
_STYLE_CACHE: dict[object, Style] = {}
_NAME_CACHE: dict[object, str] = {}


def _style_for(token) -> Style:
    style = _STYLE_CACHE.get(token)
    if style is None:
        style = _DEFAULT
        for ttype, candidate in _STYLES:
            if token in ttype:
                style = candidate
                break
        _STYLE_CACHE[token] = style
    return style


def _name_for(token) -> str:
    name = _NAME_CACHE.get(token)
    if name is None:
        name = _DEFAULT_NAME
        for candidate, ttype, _ in _PALETTE:
            if token in ttype:
                name = candidate
                break
        _NAME_CACHE[token] = name
    return name


def highlight_c(code: str) -> list[list[Segment]]:
    """Return one list of Segments per source line (no trailing newline segs)."""
    lines: list[list[Segment]] = [[]]
    for token, value in _lexer.get_tokens(code):
        if not value:
            continue
        style = _style_for(token)
        if "\n" not in value:  # the common case: a token inside one line
            lines[-1].append(Segment(value, style))
            continue
        parts = value.split("\n")
        for i, part in enumerate(parts):
            if i > 0:
                lines.append([])
            if part:
                lines[-1].append(Segment(part, style))
    # get_tokens tends to append a final empty line; drop a lone trailing blank.
    if len(lines) > 1 and not lines[-1]:
        lines.pop()
    return lines


def highlight_c_spans(code: str) -> dict[int, list[tuple[int, int, str]]]:
    """Return ``{row: [(start_byte, end_byte, highlight_name), ...]}`` for ``code``.

    The shape TextArea's ``_highlights`` map wants. Columns are **byte** offsets
    into the line, not character offsets -- that's the tree-sitter convention
    TextArea's renderer decodes with ``build_byte_to_codepoint_dict``, so a
    non-ASCII identifier or string would smear its styling one cell per extra
    byte if we handed it character offsets.
    """
    spans: dict[int, list[tuple[int, int, str]]] = {}
    row = 0
    col = 0
    for token, value in _lexer.get_tokens(code):
        if not value:
            continue
        name = _name_for(token)
        parts = value.split("\n")
        for i, part in enumerate(parts):
            if i:
                row += 1
                col = 0
            if not part:
                continue
            width = len(part) if part.isascii() else len(part.encode("utf-8"))
            if part.strip():  # whitespace carries no visible style
                spans.setdefault(row, []).append((col, col + width, name))
            col += width
    return spans


#: TextArea theme carrying our palette. Everything else (background, cursor,
#: selection) is deliberately left unset so it keeps falling back to the app's
#: CSS -- this theme only says how C tokens are coloured.
C_TEXTAREA_THEME = TextAreaTheme(name="idatui-c", syntax_styles=SYNTAX_STYLES)


class CTextArea(TextArea):
    """An editable TextArea that syntax-highlights C.

    ``language="cpp"`` is not available (no bundled grammar), so instead of a
    tree-sitter query we fill the very same ``_highlights`` map the tree-sitter
    path fills, from the Pygments lexer above. Everything downstream --
    per-line style application, the line cache, selection, the cursor -- is
    stock TextArea, and the colours match the pseudocode pane token for token.
    """

    #: Above this, re-lexing on every keystroke would cost more than the colour
    #: is worth. Struct definitions are a few hundred bytes; this is a guard,
    #: not a limit anyone should hit.
    MAX_HIGHLIGHT_CHARS = 200_000

    def __init__(self, text: str = "", **kwargs) -> None:
        super().__init__(text, **kwargs)
        self.register_theme(C_TEXTAREA_THEME)
        self.theme = C_TEXTAREA_THEME.name
        # __init__ built the document (and so the highlight map) before the
        # theme existed; redo it now that tokens can resolve to styles.
        self._build_highlight_map()

    def _build_highlight_map(self) -> None:
        """Lex the buffer and publish per-line highlight spans.

        Called by TextArea on every document change, so it must be cheap and it
        must never raise: a lexer hiccup should cost colour, not the editor.
        """
        self._line_cache.clear()
        highlights = self._highlights
        highlights.clear()
        text = self.document.text
        if not text or len(text) > self.MAX_HIGHLIGHT_CHARS:
            return
        try:
            spans = highlight_c_spans(text)
        except Exception:  # noqa: BLE001 - highlighting is never load-bearing
            return
        for row, row_spans in spans.items():
            highlights[row].extend(row_spans)
