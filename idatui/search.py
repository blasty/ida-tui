"""What did the user mean by that query? (Ctrl+F.)

Database-wide search comes in two kinds -- **text** through the disassembly and
**bytes** through the image -- and asking people to pick a mode before they type
is a tax on every search. So the query decides, and the rule has to be
conservative in one specific direction: a hex-looking word is often real text
(``add``, ``dec``, ``dead``, ``beef``, ``cafe`` are all valid hex AND things you
would search for), while nobody types ``48 8b ?? c3`` meaning prose.

Hence: bytes only when the query is unambiguously a byte pattern -- several
whitespace/comma separated tokens that are all hex pairs or wildcards, or any
query containing a ``?``. Everything else is text, and the two explicit prefixes
(``hex:`` / ``text:``) settle any argument, as does F2 in the palette.

Pure: no IDA, no Textual, so ``tests/test_search.py`` runs it offline.
"""

from __future__ import annotations

import re

TEXT = "text"
BYTES = "bytes"

#: One token of a byte pattern: a hex pair, a wildcard nibble ("8?"), or a bare
#: "?" standing for a whole byte. IDA's find_bytes accepts all three.
_TOKEN = re.compile(r"^(?:[0-9A-Fa-f?]{2}|\?)$")

#: A quoted literal inside a pattern ('"Hello", 0'), which IDA also accepts.
_QUOTED = re.compile(r'"[^"]*"')


def looks_like_bytes(query: str) -> bool:
    """True when ``query`` can only sensibly be a byte pattern."""
    q = (query or "").strip()
    if not q:
        return False
    if _QUOTED.search(q):
        return True
    tokens = [t for t in re.split(r"[\s,]+", q) if t]
    if not all(_TOKEN.match(t) for t in tokens):
        return False
    # A single token is ambiguous ("ff" is also a word); a wildcard never is.
    return len(tokens) > 1 or "?" in q


def probably_meant_bytes(query: str) -> bool:
    """True for a query that is *shaped* like bytes but does not parse.

    ``48 zz c3`` is a typo in a byte pattern, and treating it as a text search
    answers "no match" -- the most misleading thing a search can say, because it
    is indistinguishable from "those bytes are not in this binary". Every token
    being byte-sized is the tell; ``add ff`` (a three-letter token) is not, and
    stays text.
    """
    tokens = [t for t in re.split(r"[\s,]+", (query or "").strip()) if t]
    if len(tokens) < 2 or any(len(t) > 2 for t in tokens):
        return False
    return any(_TOKEN.match(t) for t in tokens)


def classify(query: str, forced: str | None = None) -> tuple[str, str]:
    """Return ``(mode, cleaned_query)``.

    An explicit ``hex:``/``bytes:``/``text:`` prefix wins, then ``forced`` (the
    palette's F2), then the shape of the query.
    """
    q = (query or "").strip()
    low = q.lower()
    for prefix, mode in (("hex:", BYTES), ("bytes:", BYTES), ("text:", TEXT)):
        if low.startswith(prefix):
            return (mode, q[len(prefix) :].strip())
    if forced in (TEXT, BYTES):
        return (forced, q)
    if looks_like_bytes(q) or probably_meant_bytes(q):
        return (BYTES, q)
    return (TEXT, q)


def normalise_pattern(pattern: str) -> str:
    """Tidy a byte pattern for IDA: single spaces, commas as separators.

    ``48 8B?? C3``, ``48,8b,??,c3`` and ``48 8b ?? c3`` are the same search;
    people paste all three (the middle one out of a signature file).
    """
    q = (pattern or "").strip()
    if _QUOTED.search(q):
        return q  # a quoted literal owns its own spacing
    q = q.replace(",", " ")
    # "488B??C3" -- a bare hex run with no separators at all.
    if " " not in q and len(q) > 2 and len(q) % 2 == 0:
        q = " ".join(q[i : i + 2] for i in range(0, len(q), 2))
    return " ".join(q.split())


def pattern_problem(pattern: str) -> str | None:
    """A human explanation if this cannot be a byte pattern, else ``None``.

    Checked before the round trip, because IDA's own message for a bad pattern
    is empty about half the time.
    """
    q = normalise_pattern(pattern)
    if not q:
        return "type some bytes, e.g. 48 8b ?? c3"
    if _QUOTED.search(q):
        return None
    tokens = [t for t in q.split() if t]
    bad = [t for t in tokens if not _TOKEN.match(t)]
    if bad:
        return (
            f'{bad[0]!r} is not a byte: use hex pairs, ? wildcards or a "quoted string"'
        )
    return None
