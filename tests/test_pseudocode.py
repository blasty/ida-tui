"""IDA-free regressions for pseudocode display text and address annotations."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.domain import split_pseudocode_line  # noqa: E402

NEEDS_IDA = False
PASS = FAIL = 0


def check(name, line, expected):
    global PASS, FAIL
    actual = split_pseudocode_line(line)
    if actual == expected:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}: {actual!r} != {expected!r}")


def main():
    check(
        "trailing annotation", "  return 42; /*0x401000*/", ("  return 42;", 0x401000)
    )
    source = '  printf("before /*0x1234*/ after", 42);'
    check("marker-shaped string survives", source + " /*0x401000*/", (source, 0x401000))
    check("string without annotation is not an anchor", source, (source, None))
    source = "  x = /*0x1234*/ y;"
    check(
        "inline source comment survives", source + " /*0x401000*/", (source, 0x401000)
    )
    source = "  return x; /*0x1234*/"
    check(
        "only the final annotation is removed",
        source + " /*0x401000*/",
        (source, 0x401000),
    )
    check(
        "non-address source comment",
        "  return x; /* explanation */",
        ("  return x; /* explanation */", None),
    )
    check(
        "annotation whitespace and hex casing", "  x;\t/* 0xAbCd */  ", ("  x;", 0xABCD)
    )
    check("address zero is valid", "x; /*0x0*/", ("x;", 0))
    check("blank line", "   ", ("", None))
    print(f"\n{PASS} passed, {FAIL} failed")
    return bool(FAIL)


if __name__ == "__main__":
    raise SystemExit(main())
