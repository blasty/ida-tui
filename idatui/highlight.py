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
_STYLES: list[tuple[object, Style]] = [
    (Token.Comment, Style(color="#7c8b9e", italic=True)),   # 5.2:1  commentary
    (Token.Keyword.Type, Style(color="#93aee0")),           # 8.1:1  type info
    (Token.Keyword, Style(color="#e8ecf2", bold=True)),     # 15.3:1 control flow
    (Token.Name.Builtin, Style(color="#93aee0")),           # 8.1:1  type info
    (Token.Literal.String, Style(color="#9ece6a")),         # 9.9:1  strings
    (Token.Literal.Number, Style(color="#d8a657")),         # 8.2:1  data/number
    (Token.Operator, Style(color="#c3cad3")),               # 11.0:1 body
    (Token.Punctuation, Style(color="#626c7a")),            # 3.4:1  structure
    (Token.Name, Style(color="#7aa2f7")),                   # 7.2:1  symbol names
]
_DEFAULT = Style(color="#c3cad3")                           # 11.0:1 body

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
