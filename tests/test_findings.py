#!/usr/bin/env python3
"""The findings export: gathering and, mostly, RENDERING.

`idatui.findings.render` takes plain data and returns markdown, so all of the
interesting behaviour -- grouping, sorting, what an empty section says, and
whether hostile text can break out of a table cell or a code fence -- is
testable with no IDA, no worker and no binary. `gather` is covered against a
fake Program that answers like the real one, including by raising.
"""

#: pure: stdlib only.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.domain import Comment, NamedItem, Struct  # noqa: E402
from idatui.findings import (  # noqa: E402
    Findings,
    default_path,
    from_loader,
    gather,
    is_dummy,
    render,
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


def sample() -> Findings:
    return Findings(
        binary="echo",
        path="/tmp/echo",
        sections=[(0x1000, 0x2000, ".text"), (0x2000, 0x2100, ".data")],
        n_functions=128,
        comments=[
            Comment(
                addr=0x1100,
                text="length is attacker controlled",
                line="mov edi, [rbp+len]",
                func="parse",
                func_addr=0x1000,
            ),
            Comment(
                addr=0x1010,
                text="entry",
                line="push rbp",
                func="parse",
                func_addr=0x1000,
            ),
            Comment(
                addr=0x1000,
                text="parses the header",
                whole_func=True,
                func="parse",
                func_addr=0x1000,
            ),
            Comment(addr=0x2004, text="magic", line="dd 0DEADBEEFh"),
            # What the ELF loader writes into every database, through the very
            # same set_cmt a person uses.
            Comment(addr=0x4, text="File class: 64-bit", line="db 2", seg="LOAD"),
        ],
        names=[
            NamedItem(
                addr=0x1000,
                name="parse",
                is_func=True,
                size=0x120,
                proto="int __fastcall parse(char *)",
            ),
            NamedItem(addr=0x1200, name="sub_1200", is_func=True, size=0x30),
            NamedItem(addr=0x2004, name="hdr_magic", seg=".data"),
            NamedItem(addr=0x1400, name="memcpy", is_func=True, size=0x40),
            NamedItem(addr=0x390, name="elf_gnu_hash_nbuckets", seg="LOAD"),
        ],
        types=[
            (
                Struct(name="hdr", size=0x10, is_union=False, members=3, ordinal=42),
                "struct hdr\n{\n  int magic;\n};\n",
            ),
            (
                Struct(
                    name="Elf64_Dyn", size=0x10, is_union=False, members=2, ordinal=3
                ),
                "struct Elf64_Dyn\n{\n  int d_tag;\n};\n",
            ),
        ],
        linked={"memcpy"},
        stripped=True,
    )


def main() -> int:
    doc = render(sample())

    check("the report names the binary", doc.startswith("# Findings — echo"), doc[:40])
    # 1 function, not 3: sub_1200 is IDA's invention and memcpy is the linker's.
    check(
        "the summary counts only what a person contributed",
        "1 named functions · 1 named data · 4 comments · 2 local types" in doc,
        doc.splitlines()[2] if len(doc.splitlines()) > 2 else "",
    )

    # A name IDA invented is not a finding, and neither is one the linker gave.
    check("dummy names are excluded", "sub_1200" not in doc)
    check("imported names are excluded", "`memcpy`" not in doc)
    check("real names survive", "`parse`" in doc and "`hdr_magic`" in doc)

    # The loader annotates every database it makes; none of it is a finding.
    check("the loader's own comments are left out", "File class" not in doc)
    check("the loader's own names are left out", "elf_gnu_hash" not in doc)
    check(
        "but the report says how many it dropped",
        "4 annotations left out as the loader's own" in doc,  # 1 comment + 3 names
        [l for l in doc.splitlines() if "left out" in l],
    )
    check(
        "from_loader knows both shapes",
        from_loader("LOAD")
        and from_loader("", "elf_gnu_hash_x")
        and not from_loader(".text", "parse"),
    )
    check(
        "is_dummy knows the shapes IDA invents",
        all(is_dummy(n) for n in ("sub_1234", "loc_A0", "unk_4000", "j_free"))
        and not any(is_dummy(n) for n in ("parse", "sub_parse", "main", "")),
        "",
    )

    # Comments lead, grouped by function, address-ordered within a group.
    check(
        "comments come before the name tables",
        doc.index("## Comments") < doc.index("## Named functions"),
    )
    body = doc[doc.index("## Comments") : doc.index("## Named functions")]
    check("comments are grouped under their function", "### `parse`" in body)
    check(
        "a commentless region is grouped separately", "### outside any function" in body
    )
    check(
        "comments are ordered by address inside a group",
        body.index("0x1010") < body.index("0x1100"),
    )
    check(
        "a function comment says that is what it is",
        "*whole function*: parses the header" in body,
    )
    check(
        "an instruction comment carries the line it annotates",
        "`mov edi, [rbp+len]`" in body,
    )

    # Types: newest ordinal first, because that is the one you just wrote.
    types = doc[doc.index("## Local types") :]
    check("your newest type is first", types.index("hdr") < types.index("Elf64_Dyn"))
    check("type source is fenced as C", "```c\nstruct hdr" in types)

    # Escaping.
    hostile = Findings(
        binary="x",
        comments=[
            Comment(addr=1, text="a | b", line="mov | rax"),
        ],
        names=[NamedItem(addr=2, name="a|b")],
    )
    hdoc = render(hostile)
    check("a pipe cannot break a table row", "a\\|b" in hdoc, hdoc)
    check("a pipe in a comment is escaped too", "a \\| b" in hdoc)

    # The empty database must still produce a document that says something.
    empty = render(Findings(binary="nothing"))
    check(
        "an empty report is still a document",
        empty.startswith("# Findings — nothing") and "## Comments" in empty,
    )
    check("and it says why it is empty", "Comments are the part" in empty)
    check("an empty report has no dangling type section", "## Local types" not in empty)

    # Provenance must be stated, not implied. Without a journal the report is a
    # scan and says so; with one it is exactly what idatui recorded doing.
    scanned = render(
        Findings(
            binary="x",
            stripped=False,
            names=[NamedItem(addr=1, name="main", is_func=True)],
        )
    )
    check(
        "a scanned report admits it cannot know who wrote what",
        "**source**: a scan of the database" in scanned
        and "include its work as well as yours" in scanned,
    )
    check(
        "and warns when the binary brought its own symbols",
        "include ones it shipped with" in scanned,
    )

    j = sample()
    j.recorded = {0x1100, 0x1000}
    j.n_recorded = 7
    jdoc = render(j)
    check(
        "a journalled report says so",
        "idatui's edit journal" in jdoc and "7 recorded edits" in jdoc,
        "",
    )
    jbody = jdoc[jdoc.index("## Comments") : jdoc.index("## Named functions")]
    check(
        "and lists only the comments it recorded",
        "length is attacker controlled" in jbody and "0x2004" not in jbody,
        jbody,
    )
    check(
        "a journalled report drops names it did not record",
        "`parse`" in jdoc and "hdr_magic" not in jdoc,
    )

    # -- gather ------------------------------------------------------------- #
    class FakeProgram:
        def sections(self):
            return [(0x1000, 0x2000, ".text")]

        def annotations(self, limit=4000):
            return (
                [Comment(addr=1, text="hi")],
                [NamedItem(addr=1, name="parse", is_func=True)],
            )

        def linkage(self):
            return ([], [])

        def functions(self):
            raise RuntimeError("index unavailable")

        def list_structs(self):
            raise RuntimeError("no types")

        def struct_source(self, name):
            return ""

    f = gather(FakeProgram(), "/tmp/echo")
    check("gather reads the annotations", len(f.comments) == 1 and len(f.names) == 1)
    check("gather takes the binary name from the path", f.binary == "echo", f.binary)
    check(
        "a failing backend degrades the report instead of raising",
        f.n_functions == 0 and f.types == [] and "# Findings" in render(f),
    )

    check(
        "the default path sits beside the binary",
        default_path("/tmp/echo") == "/tmp/echo.findings.md",
    )

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
