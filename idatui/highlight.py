"""Pygments-based C highlighting for Hex-Rays pseudocode.

Textual's TextArea has no C/C++ tree-sitter grammar (its bundled languages are
python/rust/go/... only), so ``language="cpp"`` silently does nothing. Pygments
(already a Rich/Textual dependency) has a solid C lexer, so we tokenize once and
map tokens to Rich styles, producing per-line Segment lists the virtualized view
can cache and paint instantly.
"""

from __future__ import annotations

from rich.segment import Segment
from rich.style import Style
from pygments.lexers import CLexer
from pygments.token import Token

# Token -> style, checked in priority order (first hierarchical match wins).
# Palette roughly follows a dark IDE theme.
_STYLES: list[tuple[object, Style]] = [
    (Token.Comment, Style(color="grey54", italic=True)),
    (Token.Keyword.Type, Style(color="#4ec9b0")),          # __int64, char, ...
    (Token.Keyword, Style(color="#c586c0", bold=True)),    # if/else/return/goto
    (Token.Name.Builtin, Style(color="#4ec9b0")),
    (Token.Literal.String, Style(color="#ce9178")),        # "..."
    (Token.Literal.Number, Style(color="#b5cea8")),        # 0x10, 42
    (Token.Operator, Style(color="#d4d4d4")),
    (Token.Punctuation, Style(color="grey70")),
    (Token.Name, Style(color="#dcdcaa")),                  # identifiers / calls
]
_DEFAULT = Style(color="#d4d4d4")

_lexer = CLexer(stripnl=False, ensurenl=False)


def _style_for(token) -> Style:
    for ttype, style in _STYLES:
        if token in ttype:
            return style
    return _DEFAULT


def highlight_c(code: str) -> list[list[Segment]]:
    """Return one list of Segments per source line (no trailing newline segs)."""
    lines: list[list[Segment]] = [[]]
    for token, value in _lexer.get_tokens(code):
        if not value:
            continue
        style = _style_for(token)
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
