"""IDA-free regressions for the source-shipped listing tag parser."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

NEEDS_IDA = False
PASS = FAIL = 0
ON, OFF, ESC, INV = "\x01", "\x02", "\x03", "\x04"
ADDR, SEM = "\x28", "\x36"
INSN, REG, NUM, OPND = "\x05", "\x29", "\x0c", "\x40"


def load_parser(semantic_headers=True):
    # remote_tools is shipped as source and imports IDAPython at module scope.
    # Compile the actual parser, not a copy, with only its IDA surface faked.
    path = Path(__file__).resolve().parents[1] / "idatui" / "remote_tools.py"
    tree = ast.parse(path.read_text())
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_idatui_spans"
    )
    calls = []

    def skipcode(at):
        calls.append(at)
        if at[0] == INV:
            return 1
        if at.startswith(ON + ADDR):
            return 18
        if semantic_headers and at.startswith(ON + SEM):
            return 19 if at[2] == "\x03" else 3
        return 2

    ns = {
        "_re": re,
        "ida_lines": SimpleNamespace(
            COLOR_ADDR=0x28, COLOR_ADDR_SIZE=16, tag_skipcode=skipcode
        ),
        "_IDATUI_TAGS": {INSN: "insn", REG: "reg", NUM: "num"},
        "_IDATUI_OPND_TAGS": {OPND: 0},
        "_IDATUI_CTL": None,
        "_IDATUI_TAGINFO": None,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), ns)
    return ns["_idatui_spans"], calls


def tag(t, text):
    return ON + t + text + OFF + t


def check(name, actual, expected):
    global PASS, FAIL
    if actual == expected:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}: {actual!r} != {expected!r}")


def main():
    parse, calls = load_parser()
    check(
        "ordinary colours and operand coordinates",
        parse(
            tag(INSN, "mov")
            + "   "
            + tag(OPND, tag(REG, "eax") + ", " + tag(NUM, "42"))
        ),
        (
            [
                ["insn", "mov"],
                ["text", " "],
                ["reg", "eax"],
                ["text", ", "],
                ["num", "42"],
            ],
            [[4, 11, 0]],
        ),
    )
    # Semantic metadata can itself contain bytes that look like presentation
    # controls. The kernel's header length, not a two-byte regex, owns them.
    name = ON + SEM + "\x01" + "main" + OFF + SEM
    check(
        "semantic name preserves enclosing colour",
        parse(tag(INSN, "call " + name)),
        ([["insn", "call main"]], []),
    )
    typed = ON + SEM + "\x03" + "0123456789ABCDEF" + tag(REG, "MY_TYPE") + OFF + SEM
    check(
        "type-id payload is invisible and operand survives",
        parse(tag(OPND, typed + "+" + tag(NUM, "4"))),
        ([["reg", "MY_TYPE"], ["text", "+"], ["num", "4"]], [[0, 9, 0]]),
    )
    check(
        "address payload is invisible",
        parse(tag(REG, "a" + ON + ADDR + "0123456789ABCDEF" + "b")),
        ([["reg", "ab"]], []),
    )
    check(
        "inverse is a one-byte code, including at end",
        parse(tag(REG, "a" + INV + "b" + INV)),
        ([["reg", "ab"]], []),
    )
    check(
        "escaped controls are literal",
        parse("a" + ESC + ON + "b"),
        ([["text", "a" + ON + "b"]], []),
    )
    check("kernel skipcode is consulted", bool(calls), True)
    old_parse, _ = load_parser(semantic_headers=False)
    check(
        "headerless semantic group preserves enclosing colour",
        old_parse(tag(INSN, "call " + tag(SEM, "main"))),
        ([["insn", "call main"]], []),
    )
    check(
        "unknown presentation tags retain their text",
        parse(tag("\x7f", "unknown")),
        ([["text", "unknown"]], []),
    )
    check("empty line", parse(""), ([], []))
    print(f"\n{PASS} passed, {FAIL} failed")
    return bool(FAIL)


if __name__ == "__main__":
    raise SystemExit(main())
