#!/usr/bin/env python3
"""Query classification for Ctrl+F: is that text, or is it bytes?

The whole risk of a mode-guessing search is guessing wrong in the direction
that loses work: deciding a word like `dead` or `add` is a byte pattern, and
silently searching the image instead of the disassembly. These checks pin that
asymmetry down. Pure -- no IDA, no worker.
"""

#: pure: stdlib only.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.search import (  # noqa: E402
    BYTES,
    TEXT,
    classify,
    looks_like_bytes,
    normalise_pattern,
    pattern_problem,
    probably_meant_bytes,
)

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def main() -> int:
    # -- the asymmetry: hex-looking WORDS must stay text --------------------- #
    for word in ("add", "dead", "beef", "cafe", "ff", "0", "abcdef", "decode", "face"):
        check(
            f"{word!r} searches text, not bytes",
            classify(word)[0] == TEXT,
            classify(word),
        )

    # -- unambiguous byte patterns ------------------------------------------ #
    for pat in (
        "48 8b ?? c3",
        "B8 ? ? ? ? 90",
        "48,8b,05",
        "de ad be ef",
        "48 8? ?? 24",
        "??",
    ):
        check(f"{pat!r} searches bytes", classify(pat)[0] == BYTES, classify(pat))

    check("a quoted literal is a byte pattern", classify('"Hello", 0')[0] == BYTES)

    # A TYPO in a byte pattern must stay a byte pattern, so it can be refused
    # with a reason. Falling back to text answers "no match", which is
    # indistinguishable from "those bytes are not in this binary".
    check(
        "a typo'd byte pattern is still a byte pattern",
        classify("48 zz c3")[0] == BYTES,
        classify("48 zz c3"),
    )
    check("and it is refused by name", "'zz'" in (pattern_problem("48 zz c3") or ""))
    check(
        "but a word among bytes is prose",
        classify("add ff")[0] == TEXT and classify("mov rdi, rax")[0] == TEXT,
        classify("add ff"),
    )
    check("prose stays text", classify("mov rdi, rax")[0] == TEXT)
    check("a call target stays text", classify("call cs:__isoc99_scanf")[0] == TEXT)
    check(
        "an empty query is text (nothing to search yet)",
        classify("")[0] == TEXT and not looks_like_bytes(""),
    )

    # -- explicit wins over any guess --------------------------------------- #
    check("hex: forces bytes", classify("hex: dead") == (BYTES, "dead"))
    check("bytes: forces bytes too", classify("bytes:dead") == (BYTES, "dead"))
    check("text: forces text", classify("text: 48 8b c3") == (TEXT, "48 8b c3"))
    check(
        "F2's forced mode beats the shape",
        classify("dead", forced=BYTES) == (BYTES, "dead")
        and classify("48 8b c3", forced=TEXT) == (TEXT, "48 8b c3"),
    )
    check(
        "a prefix beats even the forced mode",
        classify("text:48 8b c3", forced=BYTES)[0] == TEXT,
    )

    # -- the shapes people paste -------------------------------------------- #
    check("commas become spaces", normalise_pattern("48,8b,05") == "48 8b 05")
    check(
        "a run with no separators is split into bytes",
        normalise_pattern("488B05C3") == "48 8B 05 C3",
    )
    check("whitespace is squeezed", normalise_pattern(" 48   8b\t05 ") == "48 8b 05")
    check(
        "a quoted literal keeps its own spacing",
        normalise_pattern('"Hello, world", 0') == '"Hello, world", 0',
    )

    # -- refusing a bad pattern with a reason -------------------------------- #
    check("an empty pattern says what to type", "48 8b" in (pattern_problem("") or ""))
    check(
        "a non-hex token is named",
        "'zz'" in (pattern_problem("48 zz c3") or ""),
        pattern_problem("48 zz c3"),
    )
    check(
        "a good pattern has no complaint",
        pattern_problem("48 8b ?? c3") is None and pattern_problem('"Hi", 0') is None,
    )
    check(
        "an odd-length run is refused rather than silently split",
        pattern_problem("488B0") is not None,
        pattern_problem("488B0"),
    )

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
