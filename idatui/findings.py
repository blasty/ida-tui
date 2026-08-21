"""Export a reverse-engineering session as a markdown report.

The output of an RE session is not the database, it is what you *learned* --
and that lives scattered across comments, names and types inside a `.i64` that
only IDA can read. This turns it into one document you can paste into an
advisory, a writeup or a ticket.

Two halves, deliberately separated:

* :func:`gather` talks to a :class:`~idatui.domain.Program` (the only part that
  needs IDA) and returns a plain :class:`Findings`.
* :func:`render` turns a :class:`Findings` into markdown and knows nothing about
  IDA, so the formatting -- grouping, sorting, escaping, the empty cases -- is
  tested offline in ``tests/test_findings.py``.

**On authorship.** IDA records "this address has a real name" but not *who*
named it, so a stripped binary's report is exactly your renames while a binary
with symbols also lists the ones it shipped with. The report says which case it
is rather than claiming credit; comments and types have no such ambiguity.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field


@dataclass
class Findings:
    """Everything the report can show, already fetched. Plain data on purpose."""

    binary: str = ""
    path: str = ""
    #: (start, end, name) segments, for the overview
    sections: list[tuple[int, int, str]] = field(default_factory=list)
    n_functions: int = 0
    #: idatui.domain.Comment
    comments: list = field(default_factory=list)
    #: idatui.domain.NamedItem
    names: list = field(default_factory=list)
    #: (idatui.domain.Struct, source or "")
    types: list[tuple[object, str]] = field(default_factory=list)
    #: names IDA supplied from imports/exports -- excluded from "named", since
    #: they are the linker's work, not anyone's finding
    linked: set[str] = field(default_factory=set)
    stripped: bool = True
    truncated: bool = False
    #: annotations dropped as the loader's own work, reported as a count
    skipped_loader: int = 0
    #: Addresses idatui recorded itself editing (idatui/journal.py). When this
    #: is non-empty the report is EXACT -- it is what you did, not what the
    #: database happens to contain. Empty means nobody journalled this database
    #: (worked on in the IDA GUI, or before this feature), and the report falls
    #: back to filtering by shape, which it says out loud.
    recorded: set[int] = field(default_factory=set)
    #: type names the journal saw declared, for the same reason
    recorded_types: set[str] = field(default_factory=set)
    n_recorded: int = 0
    generated_at: float = field(default_factory=time.time)


#: Segments the *loader* owns rather than the program: the ELF/PE header and
#: friends. IDA annotates those itself -- "File format: \x7FELF", "File class:
#: 64-bit", `elf_gnu_hash_nbuckets` -- through the very same set_cmt/set_name
#: calls a person uses, and the database does not record who called them. So a
#: report that trusted `has_user_name` alone opened with forty lines of ELF
#: header trivia. Anything here is the file describing itself; it is reported as
#: a count, never as a finding.
_LOADER_SEGS = frozenset({"LOAD", "HEADER", "MEMORY", "UNDEF", "abs", "extern"})

#: Same idea for names the loader derives from format structures.
_LOADER_NAME = re.compile(r"^(?:elf|pe|macho|coff|dos)_", re.I)


def from_loader(seg: str, name: str = "") -> bool:
    """True if this annotation is the file format describing itself."""
    return (seg or "") in _LOADER_SEGS or bool(_LOADER_NAME.match(name or ""))


#: IDA's *analyzer* also writes comments, with `set_cmt`, and the database keeps
#: no record that they are its own -- verified: `get_cmt` at a switch returns
#: "switch jump" with exactly the flags a hand-written comment has. These are
#: its stereotyped shapes, which no one types by accident.
_ANALYZER = re.compile(
    r"^(?:switch \d+ cases?|switch jump|jumptable [0-9A-Fa-f]+\b.*|"
    r"indirect table for switch.*|jump table for switch.*)$",
    re.I,
)

#: The other family is argument hints (`s1`, `locale`, `domainname`), which IDA
#: copies from the callee's prototype onto each argument-setup instruction. They
#: have no distinguishing shape -- but they REPEAT, once per call site, while a
#: note you wrote is yours alone. Three occurrences of one whitespace-free text
#: is the threshold; anything filtered is counted in the report, never dropped
#: in silence.
_HINT_REPEATS = 3


def analyzer_texts(comments) -> set[str]:
    """The comment texts in ``comments`` that look like IDA's own work."""
    counts: dict[str, int] = {}
    for c in comments:
        text = (c.text or "").strip()
        if text and not text.split()[1:]:  # a single whitespace-free token
            counts[text] = counts.get(text, 0) + 1
    out = {t for t, n in counts.items() if n >= _HINT_REPEATS}
    out |= {
        (c.text or "").strip()
        for c in comments
        if _ANALYZER.match((c.text or "").strip())
    }
    return out


#: Names IDA invents when nobody has said otherwise. An address carrying one of
#: these has not been understood by anybody, so it is not a finding.
_DUMMY = re.compile(
    r"^(?:(?:sub|loc|locret|off|seg|asc|byte|word|dword|qword|xmmword|ymmword|"
    r"flt|dbl|tbyte|stru|algn|unk|nullsub|def|jpt|jsub)_[0-9A-Fa-f]+"
    # j_strlen: a thunk name IDA derives from its target, not from a person.
    r"|j_\w+)$"
)


def is_dummy(name: str) -> bool:
    """True for an IDA-generated placeholder name (``sub_1234``, ``loc_A0``…)."""
    return bool(_DUMMY.match(name or ""))


def gather(
    program, path: str = "", *, limit: int = 4000, types: bool = True, journal=None
) -> Findings:
    """Collect a :class:`Findings` from a live :class:`Program`.

    ``path`` is the binary the app opened -- ``Program`` speaks to a database
    and does not know the file name the user would recognise.

    Every step is individually guarded: a report that is missing its types
    section is worth far more than an exception at the end of a long session.
    """
    out = Findings()
    out.path = path or ""
    out.binary = os.path.basename(out.path) if out.path else ""
    if journal is not None:
        try:
            out.recorded = journal.addresses()
            out.recorded_types = {
                e.get("d", "")
                for e in journal.entries
                if e.get("k") == "type" and e.get("d")
            }
            out.n_recorded = len(journal)
        except Exception:  # noqa: BLE001
            out.recorded, out.recorded_types, out.n_recorded = set(), set(), 0
    try:
        out.sections = list(program.sections())
    except Exception:  # noqa: BLE001
        out.sections = []
    try:
        comments, names = program.annotations(limit=limit)
    except Exception:  # noqa: BLE001
        comments, names = [], []
    out.comments, out.names = list(comments), list(names)
    try:
        imports, exports = program.linkage()
        out.linked = {i.name for i in imports} | {e.name for e in exports}
    except Exception:  # noqa: BLE001
        out.linked = set()
    try:
        idx = program.functions()
        idx.load_all()
        out.n_functions = len(idx)
        # "Stripped" is a judgement about the report, not about the ELF: if
        # almost every function is still sub_XXXX, a real name IS a finding.
        named = sum(1 for f in idx.all_loaded() if not is_dummy(f.name))
        out.stripped = named <= max(4, out.n_functions // 20)
    except Exception:  # noqa: BLE001
        pass
    if types:
        try:
            for st in program.list_structs():
                try:
                    src = program.struct_source(st.name)
                except Exception:  # noqa: BLE001
                    src = ""
                out.types.append((st, src))
        except Exception:  # noqa: BLE001
            out.types = []
    return out


def _esc(text: str) -> str:
    """Make one line safe inside a markdown TABLE cell."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _fence(text: str) -> str:
    """Fence body text so a comment containing backticks cannot break out."""
    ticks = "`" * max(
        3, max((len(m) for m in re.findall(r"`+", text or "")), default=0) + 1
    )
    return f"{ticks}\n{(text or '').rstrip()}\n{ticks}"


def _user_names(f: Findings) -> list:
    """The names worth reporting.

    With a journal, that is exactly the addresses we recorded renaming. Without
    one, it is a judgement: a real name, not the linker's, not the loader's.
    """
    names = [
        n
        for n in f.names
        if not is_dummy(n.name)
        and n.name not in f.linked
        and not from_loader(n.seg, n.name)
    ]
    if f.recorded:
        return [n for n in names if n.addr in f.recorded]
    return names


def _user_types(f: Findings) -> list:
    """The types worth reporting. A database is seeded with the type libraries
    IDA loaded, so with a journal we show only the ones declared here; without
    one, all of them, newest ordinal first (yours are the newest)."""
    if f.recorded or f.recorded_types:
        return [t for t in f.types if getattr(t[0], "name", "") in f.recorded_types]
    return list(f.types)


def _user_comments(f: Findings) -> list:
    """The comments a person wrote: not the loader's, not the analyzer's, and
    not the same comment reported twice."""
    auto = analyzer_texts(f.comments)
    out, seen = [], set()
    for c in f.comments:
        text = (c.text or "").strip()
        if not text or from_loader(c.seg) or text in auto:
            continue
        if f.recorded and c.addr not in f.recorded:
            continue
        # A comment on a function's first instruction comes back BOTH as an
        # instruction comment and as the function comment; report it once.
        key = (c.addr, text)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def render(f: Findings) -> str:
    """Render a :class:`Findings` as a markdown document."""
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.generated_at))
    names = sorted(_user_names(f), key=lambda n: n.addr)
    funcs = [n for n in names if n.is_func]
    data = [n for n in names if not n.is_func]
    comments = sorted(_user_comments(f), key=lambda c: (c.func_addr or c.addr, c.addr))
    dropped = (len(f.comments) - len(comments)) + (len(f.names) - len(names))
    types = _user_types(f)

    L: list[str] = []
    title = f.binary or "database"
    L.append(f"# Findings — {title}")
    L.append("")
    L.append(
        f"*{len(funcs)} named functions · {len(data)} named data · "
        f"{len(comments)} comments · {len(types)} local types — "
        f"exported {when} by idatui*"
    )
    L.append("")
    if f.path:
        L.append(f"- **binary**: `{f.path}`")
    if f.n_functions:
        L.append(f"- **functions**: {f.n_functions}")
    if f.sections:
        segs = ", ".join(f"`{nm}` {s:#x}–{e:#x}" for s, e, nm in f.sections[:8])
        more = f" (+{len(f.sections) - 8} more)" if len(f.sections) > 8 else ""
        L.append(f"- **segments**: {segs}{more}")
    if f.recorded or f.recorded_types:
        n_at = len(f.recorded)
        L.append(
            f"- **source**: idatui's edit journal — {f.n_recorded} recorded "
            f"edits across {n_at} address{'' if n_at == 1 else 'es'}. "
            "Everything below is work done here, not the analyzer's."
        )
    else:
        L.append(
            "- **source**: a scan of the database. Nothing in a `.i64` "
            "records *who* wrote a comment or a name — IDA's own analyzer "
            "uses the same calls — so this is filtered by shape and may "
            "include its work as well as yours."
        )
        if not f.stripped:
            L.append(
                "- **note**: this binary has its own symbols, so the names "
                "below include ones it shipped with."
            )
    if dropped and (f.recorded or f.recorded_types):
        L.append(
            f"- **note**: {dropped} other annotations in this database "
            "were not made here (the analyzer's, the loader's, the "
            "linker's) and are left out."
        )
    elif dropped:
        L.append(
            f"- **note**: {dropped} annotations left out as the loader's "
            "own (file headers, dummy names, imports)."
        )
    if f.truncated:
        L.append("- **note**: the scan hit its limit; this report is partial.")
    L.append("")

    # -- comments: the actual reasoning, so they lead ----------------------- #
    L.append("## Comments")
    L.append("")
    if not comments:
        L.append(
            "*None. (Comments are the part of a database nobody else can "
            "reconstruct — they are worth writing.)*"
        )
        L.append("")
    else:
        by_func: dict[str, list] = {}
        for c in comments:
            by_func.setdefault(c.func or "", []).append(c)
        for fn in sorted(by_func, key=lambda k: (k == "", k)):
            rows = by_func[fn]
            head = f"### `{fn}`" if fn else "### outside any function"
            if fn and rows[0].func_addr is not None:
                head += f"  ({rows[0].func_addr:#x})"
            L.append(head)
            L.append("")
            for c in rows:
                if c.whole_func:
                    L.append(f"- **{c.addr:#x}** — *whole function*: {_esc(c.text)}")
                elif c.line:
                    L.append(f"- **{c.addr:#x}** `{_esc(c.line)}`  \n  {_esc(c.text)}")
                else:
                    L.append(f"- **{c.addr:#x}** — {_esc(c.text)}")
            L.append("")

    # -- names -------------------------------------------------------------- #
    L.append("## Named functions")
    L.append("")
    if not funcs:
        L.append("*None.*")
        L.append("")
    else:
        L.append("| address | name | size | prototype |")
        L.append("|---|---|---|---|")
        for n in funcs:
            proto = f"`{_esc(n.proto)}`" if n.proto else ""
            L.append(f"| `{n.addr:#x}` | `{_esc(n.name)}` | {n.size:#x} | {proto} |")
        L.append("")
    if data:
        L.append("## Named data")
        L.append("")
        L.append("| address | name | segment |")
        L.append("|---|---|---|")
        for n in data:
            L.append(f"| `{n.addr:#x}` | `{_esc(n.name)}` | {_esc(n.seg)} |")
        L.append("")

    # -- types -------------------------------------------------------------- #
    if types:
        L.append("## Local types")
        L.append("")
        if not (f.recorded or f.recorded_types):
            L.append(
                "*Newest first. A database is seeded with types from the "
                "libraries IDA loaded, so the ones you defined are the "
                "ones with the highest ordinals — at the top of this "
                "list.*"
            )
            L.append("")
        ordered = sorted(types, key=lambda t: -getattr(t[0], "ordinal", 0))
        for st, src in ordered:
            kw = "union" if getattr(st, "is_union", False) else "struct"
            L.append(
                f"### `{kw} {st.name}`  "
                f"({getattr(st, 'size', 0):#x} bytes, "
                f"{getattr(st, 'members', 0)} fields)"
            )
            L.append("")
            if src:
                L.append("```c")
                L.append(src.rstrip())
                L.append("```")
                L.append("")
    return "\n".join(L).rstrip() + "\n"


def default_path(program_path: str) -> str:
    """Where a report lands if nobody says otherwise: beside the binary."""
    base = program_path or "findings"
    return f"{base}.findings.md"


def export(
    program,
    binary_path: str = "",
    out_path: str | None = None,
    *,
    limit: int = 4000,
    types: bool = True,
    journal=None,
) -> tuple[str, Findings]:
    """Gather, render and WRITE the report. Returns ``(path, findings)``."""
    f = gather(program, binary_path, limit=limit, types=types, journal=journal)
    out = out_path or default_path(f.path)
    out = os.path.abspath(os.path.expanduser(out))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render(f))
    return out, f
