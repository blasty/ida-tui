"""The IDAPython ida-tui runs inside the Code Mode sandbox.

Two features have no ida-domain surface at all and are carried over VERBATIM
from the tools ida-tui was developed against (`server/patch_server.py`'s
injected BODY, which the Code Mode port deletes):

* `heads` -- the continuous listing. ida-domain enumerates defined heads and
  renders plain disassembly; the listing also needs coalesced undefined runs,
  IDA colour-tag spans, PER-OPERAND EXTENTS, function banners, code labels and
  expanded struct members, plus the digest/`expect` protocol the paging layer
  uses to skip re-sending a page that has not changed.
* `op_format` / `pc_nums` / `pc_num_format` -- `o`/`O`. IDA's operand types and
  Hex-Rays' per-(ea, opnum) numforms are separate sets, and neither is exposed.

Keeping the originals rather than paraphrasing them is deliberate: this is the
most performance-tuned and most behaviour-sensitive code in the project (the
span walker is a single regex pass because a per-character loop was the most
expensive thing the listing did, and the cycle only offers stops that change
what you see). A re-implementation drifts from it silently.

This file is SOURCE SHIPPED AS TEXT to the database process; it is never
imported here, because the ida_* modules do not exist in the TUI's interpreter.
`codemode_client` reads it and prepends it to the relevant snippets. Keep it
self-contained: no relative imports, nothing beyond what Code Mode provides.
"""
# ruff: noqa
import re as _re

# IDAPython, imported ONCE at module scope.
#
# This file is never imported by the client -- codemode_client reads it as
# TEXT and installs it as a module inside the database process -- so the
# no-IDA house rule that keeps idatui importable without IDA does not apply
# here, and these need not be function-local.
#
# It is worth real time: a function-local `import` still costs a sys.modules
# lookup per call (0.124us measured in the database process) and
# _idatui_head_row did three per LISTING ROW -- 3.2ms on a 500-row page,
# which the background grower pays 455 times to stream one bash.
#
# ida_hexrays is deliberately NOT here: it is licence-dependent, and a
# module-level import would break this whole library for someone without the
# decompiler instead of failing only when they decompile.
import ida_bytes
import ida_funcs
import ida_lines
import ida_nalt
import ida_name
import ida_offset
import ida_segment
import ida_typeinf
import ida_ua
import idaapi

from typing import Annotated  # the extracted tool signatures still carry these


class IDAError(Exception):
    """The MCP host's error type; the tools raise/catch it by name."""


def parse_address(addr):
    """ida_pro_mcp.utils.parse_address: hex/decimal string, int, or a symbol."""
    if isinstance(addr, int):
        return addr
    try:
        return int(addr, 0)
    except ValueError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, str(addr).strip())
        if ea != idaapi.BADADDR:
            return ea
        raise IDAError(f"Not found: {addr!r}")


#: Byte-identical to ida_pro_mcp.utils._STRING_OR_SPACES_RE: the pseudocode
#: column coordinates the client holds depend on collapsing exactly the same way.
_IDATUI_STRING_OR_SPACES_RE = _re.compile(
    r'"(?:[^"\\]|\\.)*"'  # double-quoted string
    r"|'(?:[^'\\]|\\.)*'"  # single-quoted string / char
    r"|[ \t]{2,}"  # run of 2+ whitespace (outside strings)
)


def compact_whitespace(line: str) -> str:
    """ida_pro_mcp.utils.compact_whitespace: collapse runs of 2+ spaces/tabs to
    one, preserving string literals."""
    stripped = line.lstrip(" \t")
    if not stripped:
        return line
    lead = line[: len(line) - len(stripped)]

    def _repl(m):
        s = m.group()
        if s[0] in ('"', "'"):
            return s  # preserve string content
        return " "

    return lead + _IDATUI_STRING_OR_SPACES_RE.sub(_repl, stripped)


# NOTE: an identical, UNDECORATED copy of _idatui_head_row/_idatui_line_parts
# used to sit here, shadowed by the real ones below. If you find one again:
# keep the copy carrying @lru_cache. Deleting that one instead is a silent
# ~2.7x regression on every listing row (10.4us -> 3.9us is the cache).
def _idatui_head_row(ea, flags=None):
    """One flat-listing row for the head at ``ea``: kind (code/data/unknown),
    byte size, rendered text, and any symbol name.

    ``flags`` lets a caller that already asked for them say so -- the walk in
    ``heads`` used to fetch them three times per head (here, in _is_unknown from
    _advance, and again from _rows_for).
    """

    f = ida_bytes.get_flags(ea) if flags is None else flags
    if ida_bytes.is_code(f):
        kind = "code"
    elif ida_bytes.is_data(f):
        kind = "data"
    else:
        kind = "unknown"
    line = ida_lines.generate_disasm_line(ea, 0)
    text, spans, ops = _idatui_line_parts(line) if line else ("", None, None)
    row = {
        "ea": hex(ea),
        "kind": kind,
        "size": int(ida_bytes.get_item_size(ea)),
        "text": text,
    }
    if spans is not None:
        row["spans"] = spans
        # Where each operand sits in `text`. Comes out of the same tag walk
        # (free), and is what lets the client show WHICH literal a keypress
        # would reformat before you press it.
        if ops:
            row["ops"] = ops
    nm = ida_name.get_ea_name(ea)
    if nm:
        row["name"] = nm
    return row


import functools as _idatui_functools


import os as _idatui_os


_IDATUI_LINE_CACHE = int(_idatui_os.environ.get("IDATUI_LINE_CACHE") or 65536)


@_idatui_functools.lru_cache(maxsize=_IDATUI_LINE_CACHE)
def _idatui_line_parts(line):
    """``(text, spans, ops)`` for one tagged disassembly line -- memoised.

    A function of the tagged line and nothing else, so the same line always
    gives the same answer: a rename changes the line, which changes the key.
    And listings repeat themselves hard -- 196k lines of bash are 53k distinct
    ones, so a 16k-entry cache serves ~70% of them and takes the per-line cost
    from 10.4us to 3.9us. This is the most expensive thing the backend does per
    listing row, and a jump to an address near the end of a big binary walks
    hundreds of thousands of them.

    ``spans`` is None when the tag walk and the plain text disagree about what
    the line says (then the text wins and the row renders unhighlighted).

    The returned lists are SHARED between every row that has the same line;
    treat them as read-only. Pickle notices the sharing too, so a page of
    repetitive disassembly also serialises smaller.
    """
    text = " ".join(ida_lines.tag_remove(line).split())  # collapse the padding
    spans, ops = _idatui_spans(line)
    # Built from the SAME line as `text`, then whitespace-collapsed identically,
    # so the two can never disagree about what the row says.
    joined = "".join([t for _k, t in spans])
    if " ".join(joined.split()) != text:
        return (text, None, None)
    return (text, spans, ops)


_IDATUI_SPAN_KINDS = {
    "insn": ("SCOLOR_INSN", "SCOLOR_KEYWORD", "SCOLOR_ASMDIR", "SCOLOR_MACRO"),
    "reg": ("SCOLOR_REG",),
    "num": ("SCOLOR_NUMBER", "SCOLOR_CHAR", "SCOLOR_BINPREF"),
    "str": ("SCOLOR_STRING",),
    # NB the real constant names: DATNAME/CODNAME, not "DNAME". Guessing here
    # fails silently — an unmapped tag renders as plain body text, so symbols
    # just quietly aren't blue and nothing tells you why.
    "name": ("SCOLOR_DATNAME", "SCOLOR_CODNAME", "SCOLOR_LOCNAME",
             "SCOLOR_IMPNAME", "SCOLOR_DEMNAME", "SCOLOR_LIBNAME",
             "SCOLOR_CNAME", "SCOLOR_DNAME",
             "SCOLOR_CREF", "SCOLOR_DREF", "SCOLOR_CREFTAIL", "SCOLOR_DREFTAIL"),
    "seg": ("SCOLOR_SEGNAME",),
    "cmt": ("SCOLOR_AUTOCMT", "SCOLOR_REGCMT", "SCOLOR_RPTCMT", "SCOLOR_VOIDOP"),
    "punct": ("SCOLOR_SYMBOL", "SCOLOR_ALTOP", "SCOLOR_HIDNAME"),
    "err": ("SCOLOR_ERROR",),
}


def _idatui_tag_map():
    """{tag character: kind}, built once from whatever this IDA actually has."""
    out = {}
    for kind, names in _IDATUI_SPAN_KINDS.items():
        for n in names:
            v = getattr(ida_lines, n, None)
            if isinstance(v, str) and v:
                out[v[0]] = kind
            elif isinstance(v, int):
                out[chr(v)] = kind
    return out


_IDATUI_TAGS = None


_IDATUI_OPND_TAGS = None


_IDATUI_CTL = None   # re: a tag = one of three control chars plus its argument


_IDATUI_TAGINFO = None


def _idatui_opnd_tag_map():
    """{tag character: operand index}. IDA wraps each operand of a disassembly
    line in COLOR_OPND1..8, so the line already says where operand N starts and
    ends -- no need to re-render operands with print_operand to find out (and
    the two agree exactly; checked over thousands of instructions)."""
    out = {}
    for i in range(1, 9):
        v = getattr(ida_lines, "COLOR_OPND%d" % i, None)
        if isinstance(v, int):
            out[chr(v)] = i - 1
        elif isinstance(v, str) and v:
            out[v[0]] = i - 1
    return out


def _idatui_spans(line):
    """(spans, ops) for a tagged disasm line.

    ``spans`` is [[kind, text], ...] with colour tags resolved; ``ops`` is
    [[start, end, n], ...], the extent of each operand in the SAME (collapsed)
    coordinates the row's ``text`` uses -- which is what lets a cursor column
    name the operand it is standing on.

    Unknown tags become 'text' rather than being dropped: a processor module can
    emit a colour we don't classify, and losing the characters would corrupt the
    line."""
    global _IDATUI_TAGS, _IDATUI_OPND_TAGS, _IDATUI_CTL, _IDATUI_TAGINFO
    if _IDATUI_TAGS is None:
        _IDATUI_TAGS = _idatui_tag_map()
    if _IDATUI_OPND_TAGS is None:
        _IDATUI_OPND_TAGS = _idatui_opnd_tag_map()
    if _IDATUI_CTL is None:
        import re as _re
        # One capturing split gives [text, tag, text, tag, ..., text] in a
        # single C pass. A per-character python loop over the line used to be
        # the most expensive thing the `heads` tool did, and a line is ~54
        # characters but only ~13 tags -- everything between two tags is already
        # exactly one span's worth of text.
        _IDATUI_CTL = _re.compile("([\\x01\\x02\\x03](?s:.))")
    if _IDATUI_TAGINFO is None:
        _IDATUI_TAGINFO = {
            tag: (_IDATUI_TAGS.get(tag, "text"), _IDATUI_OPND_TAGS.get(tag))
            for tag in set(_IDATUI_TAGS) | set(_IDATUI_OPND_TAGS)}
    taginfo = _IDATUI_TAGINFO
    plain_tag = ("text", None)
    on, off, esc = "\x01", "\x02", "\x03"
    addr_tag = chr(getattr(ida_lines, "COLOR_ADDR", 0x28))
    addr_len = int(getattr(ida_lines, "COLOR_ADDR_SIZE", 16))
    parts = _IDATUI_CTL.split(line)
    spans, stack = [], []            # stack entries: (kind, operand index|None)
    kind, opnd = "text", None        # state the current run of text belongs to
    pend = ""
    skip = 0                         # characters of an address payload still due
    i, n = 0, len(parts)
    while i < n:
        txt = parts[i]
        i += 1
        if skip:
            if len(txt) <= skip:
                skip -= len(txt)
                txt = ""
            else:
                txt = txt[skip:]
                skip = 0
        if txt:
            pend += txt
        if i >= n:
            break
        pair = parts[i]
        i += 1
        if skip:                     # a tag INSIDE an address payload: 2 chars
            skip = skip - 2 if skip > 2 else 0
            continue
        ch = pair[0]
        if ch == esc:                # escaped literal: keep the char it guards
            pend += pair[1]
            continue
        tag = pair[1]
        if ch == on and tag == addr_tag:
            # An embedded target address, not display text: 16 hex digits that
            # must not reach the screen. Deliberately NOT a span boundary.
            skip = addr_len
            continue
        if pend:
            spans.append([kind, pend, opnd])
            pend = ""
        if ch == on:
            stack.append((kind, opnd))
            kind, o = taginfo.get(tag, plain_tag)
            if o is not None:
                opnd = o     # operands nest: an inner colour keeps the operand
        elif stack:
            kind, opnd = stack.pop()
        else:
            kind, opnd = "text", None
    if pend:
        spans.append([kind, pend, opnd])
    # Collapse IDA's column padding EXACTLY as the plain text does. A run of
    # spaces can straddle two spans, so the leading space of a span is dropped
    # when the previous one ended in space — otherwise the spans and `text`
    # disagree about the line and the row silently loses its highlighting.
    # ``" ".join(txt.split())`` splits on exactly what str.isspace() calls
    # whitespace, which is what the character walk this replaces tested.
    out, prev_space = [], False
    for kind, txt, opnd in spans:
        core = " ".join(txt.split())
        if core == txt:
            # Nothing to collapse and no edge whitespace -- which is the common
            # case ("mov", "rax", ", ") and skips both isspace() probes below.
            prev_space = False
            out.append([kind, txt, opnd])
            continue
        if not core:                 # the span is nothing but padding
            if not prev_space:
                prev_space = True
                out.append([kind, " ", opnd])
            continue
        acc = core
        if txt[0].isspace() and not prev_space:
            acc = " " + acc
        if txt[-1].isspace():
            acc += " "
        prev_space = acc[-1] == " "
        out.append([kind, acc, opnd])
    while out and out[0][1] == " ":
        out.pop(0)
    while out and out[-1][1] == " ":
        out.pop()
    if out and out[0][1].startswith(" "):
        out[0][1] = out[0][1].lstrip()
    if out and out[-1][1].endswith(" "):
        out[-1][1] = out[-1][1].rstrip()
    out = [s for s in out if s[1]]
    # Operand extents, in the coordinates of the collapsed text these spans
    # spell out. Adjacent spans of the same operand merge, so an operand like
    # ``[rbp+var_40]`` (five differently-coloured tokens) comes back as ONE
    # range -- which is the thing a cursor is inside of, and the thing a format
    # change applies to.
    ops, pos, cur, start = [], 0, None, 0
    for _kind, txt, opnd in out:
        if opnd != cur:
            if cur is not None and pos > start:
                ops.append([start, pos, cur])
            cur, start = opnd, pos
        pos += len(txt)
    if cur is not None and pos > start:
        ops.append([start, pos, cur])
    text = "".join(t for _k, t, _o in out)
    trimmed = []
    for lo, hi, k in ops:                 # don't let a range own trailing space
        while hi > lo and text[hi - 1].isspace():
            hi -= 1
        while lo < hi and text[lo].isspace():
            lo += 1
        if hi > lo:
            trimmed.append([lo, hi, k])
    return [[k, t] for k, t, _o in out], trimmed


def _idatui_rows_digest(rows):
    """A value that changes whenever any of ``rows`` would render differently.

    Covers everything a client keeps off a row: address, kind, size, the plain
    text, the symbol name and the colour spans (which is what makes it exact
    rather than a heuristic -- two lines can collapse to the same text and still
    be coloured differently).

    Uses the interpreter's own ``hash``, deliberately. It never has to mean
    anything outside this process: the client stores what a page hashed to when
    it loaded it and hands the same number back to ask whether the page still
    hashes to that. One worker, one process, one hash seed.
    """
    acc = 0
    # The per-line render is memoised, so one spans list is shared by every row
    # that says the same thing -- about 45% of them within a page. Hash each
    # distinct list once and key that by identity, rather than rebuilding a
    # tuple of tuples per row (which is the exact cost that was measured and
    # removed from the client side for the same reason).
    seen = {}
    for r in rows:
        sp = r.get("spans")
        if sp is None:
            sh = None
        else:
            key = id(sp)
            sh = seen.get(key)
            if sh is None:
                sh = seen[key] = hash(tuple(map(tuple, sp)))
        acc = hash((acc, r.get("ea"), r.get("kind"), r.get("size"),
                    r.get("text"), r.get("name"), sh))
    return acc


def _idatui_unknown_row(ea, size):
    """One collapsed row for a run of ``size`` undefined bytes starting at
    ``ea``. A single byte is rendered normally (shows its value); a longer run
    collapses to ``db N dup(?)`` so a big .bss/gap doesn't explode into millions
    of one-byte rows."""

    if size <= 1:
        return _idatui_head_row(ea)
    row = {"ea": hex(ea), "kind": "unknown", "size": int(size),
           "text": f"db {size} dup(?)"}
    nm = ida_name.get_ea_name(ea)
    if nm:
        row["name"] = nm
    return row


def _idatui_struct_member_rows(ea):
    """Indented member rows for a struct-typed data item at ``ea`` (expansion),
    or [] if it isn't a struct. Top-level fields only."""

    tif = ida_typeinf.tinfo_t()
    if not (ida_nalt.get_tinfo(tif, ea) and tif.is_udt()):
        return []
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return []
    rows = []
    for m in udt:
        off = m.begin() // 8
        try:
            mtype = m.type._print() or ""
        except Exception:
            mtype = ""
        try:
            sz = int(m.type.get_size())
            if sz == idaapi.BADSIZE:
                sz = 0
        except Exception:
            sz = 0
        name = m.name or ""
        text = f"+{off:X} {name}" + (f" {mtype}" if mtype else "")
        rows.append({"ea": hex(ea + off), "kind": "member", "size": sz,
                     "text": text})
    return rows


def _idatui_func_header_rows(ea):
    """IDA-style subroutine banner rows shown just before a function's entry."""

    name = ida_funcs.get_func_name(ea) or "sub_%X" % ea
    bar = "=" * 15 + " S U B R O U T I N E " + "=" * 15
    return [
        {"ea": hex(ea), "kind": "sep", "size": 0, "text": ""},
        {"ea": hex(ea), "kind": "sep", "size": 0, "text": "; " + bar},
        {"ea": hex(ea), "kind": "funchdr", "size": 0,
         "text": name + " proc", "name": name},
    ]


def _idatui_func_footer_rows(ea, func):
    """End-of-function marker shown just after a function's last item."""

    name = ida_funcs.get_func_name(func.start_ea) or "sub_%X" % func.start_ea
    return [
        {"ea": hex(ea), "kind": "funchdr", "size": 0,
         "text": name + " endp", "name": name},
        {"ea": hex(ea), "kind": "sep", "size": 0, "text": "; " + "-" * 60},
    ]


def heads(
    addr: Annotated[str, "Start address or name to walk from"],
    count: Annotated[int, "Max heads to return (default 200, max 2000)"] = 200,
    offset: Annotated[int, "Skip first N heads from addr (default 0)"] = 0,
    end: Annotated[str, "Optional exclusive end address; default = segment end"] = "",
    back: Annotated[bool, "Walk backwards: return the count heads ENDING just before addr, in forward order"] = False,
    annotate: Annotated[bool, "Emit IDA-style function boundary banner rows (kind sep/funchdr)"] = False,
    expect: Annotated[str, "Digest a caller already holds: the rows are omitted when they still hash to it"] = "",
) -> dict:
    """Walk item heads from ``addr`` as a flat listing: every head is rendered
    (code OR data OR undefined) via generate_disasm_line and stepped with
    next_head/prev_head. Unlike ``disasm`` (code-only, bails at the first data
    byte) this shows db/dw/dd/... lines for data and undefined regions — IDA's
    real disassembly view. Address-paged: page forward by re-calling with
    ``addr`` = the returned cursor.next; page up with ``back=true``."""

    count = 2000 if count > 2000 else (1 if count < 1 else count)
    offset = max(int(offset), 0)
    try:
        start = parse_address(addr)
    except Exception as e:
        return {"addr": str(addr), "error": str(e), "heads": [], "cursor": {"done": True}}
    seg = ida_segment.getseg(start)
    if not seg:
        return {"addr": str(addr), "error": "no segment", "heads": [], "cursor": {"done": True}}
    lo, hi = seg.start_ea, seg.end_ea
    if end:
        try:
            hi = min(hi, parse_address(end))
        except Exception:
            pass

    rows = []
    if back:
        # Collect up to (count+offset) heads strictly before `start`, then take
        # the window closest to `start`, returned in forward order.
        walk = []
        cur = ida_bytes.prev_head(start, lo)
        while cur != idaapi.BADADDR and cur >= lo and len(walk) < count + offset:
            walk.append(cur)
            cur = ida_bytes.prev_head(cur, lo)
        walk.reverse()
        chosen = walk[: len(walk) - offset] if offset else walk
        chosen = chosen[-count:]
        rows = [_idatui_head_row(e) for e in chosen]
        first = chosen[0] if chosen else start
        pea = ida_bytes.prev_head(first, lo)
        cursor = {"done": True} if pea == idaapi.BADADDR or pea < lo else {"prev": hex(pea)}
        return {"addr": str(addr), "heads": rows, "cursor": cursor}

    # Walk by item END (not next_head): next_head SKIPS undefined bytes, but a
    # flat listing must show them (IDA renders undefined as `db ?` lines, and
    # navigating to an unmarked address must land ON it). Defined items advance
    # by get_item_end; a run of undefined bytes is COLLAPSED into one row (its
    # end found in O(1) via next_head, which skips undefined) so a large .bss or
    # gap doesn't explode into millions of one-byte rows.
    def _is_unknown_f(f):
        return not (ida_bytes.is_code(f) or ida_bytes.is_data(f))

    def _run_end(e):
        """End (exclusive) of the undefined run starting at ``e``."""
        nh = ida_bytes.next_head(e, hi)
        return nh if (nh != idaapi.BADADDR and e < nh <= hi) else hi

    def _advance(e, f):
        if _is_unknown_f(f):
            return _run_end(e)
        nxt = ida_bytes.get_item_end(e)
        return nxt if nxt > e else e + 1

    # The function the walk is currently inside, reused while it stays inside.
    # get_func is ~0.5us and the walk asks per head; a head is nearly always in
    # the same function as the one before it. Only ever consulted when ``e``
    # falls in [start_ea, end_ea), so a tail chunk elsewhere cannot be
    # misattributed -- checked against get_func over 437k heads of
    # bash/ls_ttl/echo with zero disagreements.
    fn_cache = [None]

    def _func_at(e):
        cur = fn_cache[0]
        if cur is not None and cur.start_ea <= e < cur.end_ea:
            return cur
        cur = idaapi.get_func(e)
        fn_cache[0] = cur
        return cur

    def _rows_for(e, f):
        if _is_unknown_f(f):
            return [_idatui_unknown_row(e, _run_end(e) - e)]
        func = _func_at(e) if annotate else None
        at_start = func is not None and func.start_ea == e
        out = []
        if at_start:
            out.extend(_idatui_func_header_rows(e))
        row = _idatui_head_row(e, f)
        if at_start:
            row = dict(row)
            row["name"] = None  # the name is shown on the proc header line
        elif annotate and row.get("kind") == "code" and row.get("name"):
            # A code label (loc_XXX/jump target) gets its OWN line at depth 0,
            # like IDA; strip it from the instruction row below.
            nm = row["name"]
            out.append({"ea": hex(e), "kind": "label", "size": 0,
                        "text": nm + ":", "name": nm})
            row = dict(row)
            row["name"] = None
        out.append(row)
        if row.get("kind") == "data":
            out.extend(_idatui_struct_member_rows(e))  # expand struct fields
        if func is not None and ida_bytes.get_item_end(e) >= func.end_ea:
            out.extend(_idatui_func_footer_rows(e, func))
        return out

    ea = ida_bytes.get_item_head(start)
    get_flags = ida_bytes.get_flags
    for _ in range(offset):
        if ea >= hi or ea == idaapi.BADADDR:
            break
        ea = _advance(ea, get_flags(ea))
    more = False
    while ea != idaapi.BADADDR and ea < hi:
        if len(rows) >= count:
            more = True
            break
        f = get_flags(ea)            # once per head, not once per consumer
        rows.extend(_rows_for(ea, f))  # a struct head expands into member rows
        ea = _advance(ea, f)
    cursor = {"next": hex(ea)} if more else {"done": True}
    dig = _idatui_rows_digest(rows)
    out = {"addr": str(addr), "cursor": cursor, "digest": dig, "count": len(rows)}
    # ``expect`` says "I already hold a page that hashed to this". The rows are
    # built either way -- generate_disasm_line is the floor and there is no way
    # to know a line is unchanged without rendering it -- but pickling several
    # hundred rows with their colour spans, unpickling them and rebuilding Heads
    # is about 40% of what a page costs, and after a rename almost every page
    # comes back identical.
    #
    # It carries the expected value rather than being a yes/no "digest mode" so
    # that a page which HAS changed still costs one round trip: asking first and
    # fetching afterwards made every changed page two.
    if not (expect and str(dig) == expect):
        out["heads"] = rows
    return out


_IDATUI_FMT_CYCLE = ("hex", "dec", "bin", "char", "offset", "default")


_IDATUI_FMT_SETTABLE = ("hex", "dec", "oct", "bin", "char", "offset", "seg",
                        "float", "stack", "default")


def _idatui_fmt_nibbles():
    """{format name: IDA operand-type nibble}. Built on call, not at import:
    this module is injected into a file that is imported before a database is
    open."""
    return {
        "default": ida_bytes.FF_N_VOID, "hex": ida_bytes.FF_N_NUMH,
        "dec": ida_bytes.FF_N_NUMD, "char": ida_bytes.FF_N_CHAR,
        "seg": ida_bytes.FF_N_SEG, "offset": ida_bytes.FF_N_OFF,
        "bin": ida_bytes.FF_N_NUMB, "oct": ida_bytes.FF_N_NUMO,
        "enum": ida_bytes.FF_N_ENUM, "forced": ida_bytes.FF_N_FOP,
        "stroff": ida_bytes.FF_N_STRO, "stack": ida_bytes.FF_N_STK,
        "float": ida_bytes.FF_N_FLT, "custom": ida_bytes.FF_N_CUST,
    }


def _idatui_fmt_name(nib):
    for name, v in _idatui_fmt_nibbles().items():
        if v == nib:
            return name
    return "default"


def _idatui_op_fmt(ea, n):
    """The format operand ``n`` of the item at ``ea`` is currently displayed in.

    Reads the nibble IDA keeps per operand rather than guessing from the text --
    ``1`` renders identically in hex and decimal, so the rendered line cannot
    answer this."""
    F = ida_bytes.get_flags(ea)
    nib = (F >> ida_bytes.get_operand_type_shift(int(n))) & 0xF
    return _idatui_fmt_name(nib)


def _idatui_op_value(ea, n):
    """(value, byte width) of operand ``n``, or (None, 0) if it hasn't got one.

    The value is what decides which formats are OFFERED: a character constant
    for 0x38A9 or an offset to an unmapped address are stops worth skipping."""

    F = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(F):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None, 0
        try:
            op = insn.ops[int(n)]
        except Exception:
            return None, 0
        if op.type == ida_ua.o_void:
            return None, 0
        v = op.value if op.type == ida_ua.o_imm else op.addr
        try:
            size = int(ida_ua.get_dtype_size(op.dtype))
        except Exception:
            size = 0
        return int(v), size
    size = int(ida_bytes.get_item_size(ea))
    read = {1: ida_bytes.get_byte, 2: ida_bytes.get_word,
            4: ida_bytes.get_dword, 8: ida_bytes.get_qword}.get(size)
    if read is None:
        return None, size
    try:
        return int(read(ea)), size
    except Exception:
        return None, size


def _idatui_printable(v):
    """Whether ``v`` would actually render as a character constant. IDA accepts
    op_chr on anything and then prints the number anyway, so a cycle that offers
    'char' for 0x18 has a stop where nothing visibly happens."""
    if v is None or v < 0 or v > 0xFFFFFFFF:
        return False
    bs, x = [], int(v)
    while True:
        bs.append(x & 0xFF)
        x >>= 8
        if not x:
            break
    return all(0x20 <= b <= 0x7E or b in (9, 10, 13) for b in bs)


def _idatui_offset_worth(v):
    """Whether 'offset' is worth OFFERING as a cycle stop for value ``v``.

    Making an offset is not free: IDA invents a dummy name at the target
    (``off_18``) and that name STAYS once you cycle past it. So the ring only
    stops there when the target is already something you could name -- a symbol,
    a function, or an item something else references. In a PIE at base 0 half
    the small constants in a function are 'mapped' (they land in the ELF
    header); ``sub rsp, 18h`` is not a reference and must not offer to become
    one on the way past.

    An explicit request still converts anything mapped: that's a decision, not a
    keypress that happened to land here. After it, the target HAS a name, so the
    ring includes the stop from then on."""

    return bool(v and ida_bytes.is_mapped(v) and ida_name.get_ea_name(v))


def _idatui_op_candidates(ea):
    """Operand indices at ``ea`` whose display format is worth changing.

    Immediates and displacements -- the literals. Deliberately NOT:

    * branch targets (o_near/o_far), or every jump on the listing would offer to
      become a bare number, on a view you navigate by label;
    * memory references (o_mem), e.g. x86-64's RIP-relative ``lea rdi, name``.
      IDA prints those from the reference, not from the operand's number format,
      so setting one is accepted and changes nothing on screen -- a keypress
      that appears to do nothing is worse than one that says it can't.

    An explicit ``n`` still reaches them; this is what a bare cursor picks."""

    F = ida_bytes.get_flags(ea)
    if ida_bytes.is_data(F):
        return [0]              # a data item's value is operand 0
    if not ida_bytes.is_code(F):
        return []               # undefined bytes: IDA refuses a format outright
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return []
    want = (ida_ua.o_imm, ida_ua.o_displ)
    out = []
    for i in range(len(insn.ops)):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        if op.type in want:
            out.append(i)
    return out


def _idatui_op_spans(ea, text):
    """[(start, end, n)] -- where each operand sits inside ``text`` (the
    whitespace-collapsed line the TUI shows), so a cursor column can name the
    operand it is standing on.

    Read out of IDA's own COLOR_OPND markers on the line, which is both free
    (the line is generated anyway) and exact. print_operand is kept as a
    fallback for a processor module that emits no operand markers -- it agrees
    with the tags where both exist, but it re-renders every operand to say so.
    """

    line = ida_lines.generate_disasm_line(ea, 0)
    if line:
        _spans, ops = _idatui_spans(line)
        if ops:
            return [tuple(o) for o in ops]

    out, pos = [], 0
    for n in range(8):
        try:
            raw = ida_ua.print_operand(ea, n)
        except Exception:
            raw = None
        if not raw:
            continue
        op = " ".join(ida_lines.tag_remove(raw).split())
        if not op:
            continue
        i = text.find(op, pos)
        if i < 0:                      # duplicated operand text (mov eax, eax)
            i = text.find(op)
        if i < 0:
            continue
        out.append((i, i + len(op), n))
        pos = i + len(op)
    return out


def _idatui_line_text(ea):
    line = ida_lines.generate_disasm_line(ea, 0)
    return " ".join(ida_lines.tag_remove(line).split()) if line else ""


def _idatui_op_text(ea, text, n):
    """How operand ``n`` reads on the line, for a message that names it."""
    for lo, hi, i in _idatui_op_spans(ea, text):
        if i == int(n):
            return text[lo:hi].strip()
    return ""


def _idatui_apply_fmt(ea, n, fmt):
    """Set operand ``n``'s display format. Returns (ok, error)."""

    n = int(n)
    if fmt == "default":
        return bool(ida_bytes.clr_op_type(ea, n)), ""
    if fmt == "offset":
        base = ida_offset.calc_offset_base(ea, n)
        if base in (idaapi.BADADDR, None) or base < 0:
            base = 0
        return bool(ida_offset.op_plain_offset(ea, n, base)), ""
    fn = {"hex": ida_bytes.op_hex, "dec": ida_bytes.op_dec,
          "oct": ida_bytes.op_oct, "bin": ida_bytes.op_bin,
          "char": ida_bytes.op_chr, "seg": ida_bytes.op_seg,
          "float": ida_bytes.op_flt, "stack": ida_bytes.op_stkvar}.get(fmt)
    if fn is None:
        return False, (f"can't set {fmt!r} from a name alone"
                       if fmt in _idatui_fmt_nibbles() else
                       f"unknown format {fmt!r}")
    return bool(fn(ea, n)), ""


def op_format(
    addr: Annotated[str, "Address of the instruction or data item"],
    mode: Annotated[str, "cycle | back | show | hex | dec | oct | bin | char | offset | stack | default"] = "cycle",
    col: Annotated[int, "Cursor column inside the rendered line (-1: first literal)"] = -1,
    n: Annotated[int, "Operand index; -1 derives it from ``col``"] = -1,
) -> dict:
    """Change how a literal is DISPLAYED (IDA's 'o' family): hex, decimal,
    binary, character, or an offset to the address it names.

    The value in the bytes never changes -- only the representation IDA renders
    and remembers. ``cycle``/``back`` step the stops that make sense for THIS
    operand: 'char' is skipped unless the value prints as one, 'offset' unless
    the target is already named, so no press is ever a no-op you have to press
    again. ``show`` reports without changing anything.

    A format the ring can't hold (a stack variable, an enum) is reported in
    ``warn`` on the way out, with what to do about it -- ``mode`` takes any of
    the names above outright, which is also how you put one back.

    Which operand: ``n`` if given, else the one under ``col`` (a column in the
    whitespace-collapsed line, as ``heads`` renders it), else the first literal
    on the line."""

    try:
        ea = ida_bytes.get_item_head(parse_address(addr))
    except Exception as e:
        return {"addr": str(addr), "error": str(e)}

    before = _idatui_line_text(ea)
    cands = _idatui_op_candidates(ea)
    n = int(n)
    if n < 0:
        n = -1
        if int(col) >= 0:
            for lo, hi, i in _idatui_op_spans(ea, before):
                if not (lo <= int(col) < hi):
                    continue
                if i in cands:
                    n = i
                    break
                # The cursor IS on an operand, just not one with a format. The
                # client highlights what the cursor is on, so quietly moving to
                # a different operand would make that highlight a lie -- say
                # which one can be changed instead.
                where = before[lo:hi].strip()
                alt = (f"; the literal on this line is operand {cands[0]} "
                       f"({_idatui_op_text(ea, before, cands[0])})"
                       if cands else "")
                return {"addr": hex(ea), "n": i, "text": before,
                        "error": f"operand {i} ({where}) has no format to "
                                 f"change{alt}"}
        if n < 0:
            if not cands:
                F = ida_bytes.get_flags(ea)
                why = ("no literal on this line to reformat"
                       if ida_bytes.is_code(F) or ida_bytes.is_data(F) else
                       "undefined bytes have no format to change -- define "
                       "them first ('d' makes data, 'c' makes code)")
                return {"addr": hex(ea), "text": before, "error": why}
            n = cands[0]

    cur = _idatui_op_fmt(ea, n)
    value, width = _idatui_op_value(ea, n)
    mapped = value is not None and value != 0 and ida_bytes.is_mapped(value)
    # The ring is a property of the OPERAND, not of what you last pressed: every
    # stop is one that changes what you see for this value, and it is the same
    # ring at every step, so a lap always comes home.
    choices = [f for f in _IDATUI_FMT_CYCLE
               if (f != "char" or _idatui_printable(value))
               and (f != "offset" or _idatui_offset_worth(value))]
    # A stack variable is deliberately NOT a stop: ``[rbp+var_40]`` is a frame
    # member, not a way of writing a number, and IDA's own "is this a stack
    # variable" test isn't exposed to Python here (calc_stkvar_struc_offset
    # happily answers for ``[r14+8]`` too, which would put a bogus stop in the
    # ring). Leaving one is reported instead, with the command that undoes it.
    lossy = cur not in choices and cur != "default"

    mode = str(mode or "cycle").lower()
    if mode == "show":
        return {"addr": hex(ea), "n": n, "format": cur, "prev": cur,
                "choices": choices, "text": before, "before": before,
                "value": None if value is None else hex(value),
                "width": width, "applied": False}
    if mode in ("cycle", "back"):
        step = 1 if mode == "cycle" else -1
        if cur in choices:
            want = choices[(choices.index(cur) + step) % len(choices)]
        else:
            # Standing on a format the ring can't hold (an enum names a type a
            # nibble doesn't record): enter the ring at its end, don't skip a
            # stop working out where we "would have" been.
            want = choices[0] if step > 0 else choices[-1]
    else:
        want = mode
        if want not in _idatui_fmt_nibbles():
            return {"addr": hex(ea), "n": n, "text": before,
                    "error": f"unknown format {mode!r}; one of "
                             + ", ".join(_IDATUI_FMT_SETTABLE)}
        if want == "offset" and not mapped:
            return {"addr": hex(ea), "n": n, "text": before, "format": cur,
                    "error": (f"{'0x%x' % value if value is not None else 'this operand'}"
                              " isn't a mapped address -- an offset to it would"
                              " invent a name for nothing")}

    ok, err = _idatui_apply_fmt(ea, n, want)
    if err:
        return {"addr": hex(ea), "n": n, "text": before, "format": cur,
                "error": err}
    got = _idatui_op_fmt(ea, n)
    out = {"addr": hex(ea), "n": n, "prev": cur, "format": got,
           "requested": want, "applied": bool(ok), "choices": choices,
           "before": before, "text": _idatui_line_text(ea),
           "value": None if value is None else hex(value), "width": width}
    if not ok:
        out["error"] = f"IDA refused {want} on operand {n}"
    elif lossy:
        out["warn"] = (
            f"operand {n} was {cur} and the ring has no stop there -- "
            + (f"'{cur}' sets it again" if cur in _IDATUI_FMT_SETTABLE else
               f"{cur} names a type this can't put back, reassign it by hand"))
    return out


_IDATUI_PC_FMT_CYCLE = ("hex", "dec", "oct", "char", "default")


def _idatui_compact(line):
    """The ida-pro-mcp whitespace collapse the pseudocode is served through, so
    a column in what the client SHOWS can be mapped back to Hex-Rays' line.

    DEVIATION FROM THE EXTRACTED ORIGINAL, deliberately: this used to be
    ``from ida_pro_mcp.ida_mcp.utils import compact_whitespace`` inside a
    try/except, with a plain ``[ \\t]{2,}`` regex as the fallback. Under Code
    Mode ida_pro_mcp is not installed in the database process, so BOTH halves
    of that were wrong:

    * the import failed on every call, and a failed import is never cached, so
      each one re-searched the whole of sys.path -- 422 failures per pc_nums
      call, which was the majority of its runtime;
    * the fallback collapses runs of spaces INSIDE STRING LITERALS, which the
      real function preserves. Pseudocode columns are served in these
      coordinates, so a line containing a string with two spaces would have put
      every literal's mark, and every reformat, on the wrong column.

    The module-level shim above is byte-identical to the original regex, so
    call it directly.
    """
    return compact_whitespace(line)


def _idatui_compact_col(plain, compact, col):
    """The inverse of ``_idatui_uncompact_col``: a column in Hex-Rays' own line,
    expressed in the collapsed line the client shows."""
    j = 0
    for i in range(min(int(col), len(plain))):
        if j < len(compact) and plain[i] == compact[j]:
            j += 1
    return j


def _idatui_uncompact_col(plain, compact, col):
    """Map a column in the collapsed line back to the same character in the
    original. The transform only ever DELETES spaces, so walking both in step
    and skipping what vanished is exact."""
    i = 0
    for j in range(min(int(col), len(compact))):
        c = compact[j]
        while i < len(plain) and plain[i] != c:
            i += 1
        i += 1
    return min(i, max(len(plain) - 1, 0))


_IDATUI_LIT_CHARS = frozenset("0123456789abcdefABCDEFxXuUlL")


def _idatui_lit_extent(plain, x):
    """The [start, end) of the literal token containing column ``x``.

    Hex-Rays says WHICH item a column belongs to, but not how wide the printed
    literal is -- and it attributes neighbouring punctuation to the same item,
    so ``if ( a1 > 1 )`` reports the closing paren as part of the number. The
    identity comes from the ctree; the extent is the run of literal characters
    around the column, which cannot reach a ``)`` or a space."""
    if x >= len(plain):
        return None
    if plain[x] == "'":                       # a character constant: '-'
        end = plain.find("'", x + 1)
        return (x, end + 1) if end > x else None
    lo = plain.rfind("'", 0, x)
    if lo >= 0 and plain.find("'", x) > x and "'" in plain[lo:x] and \
            plain[lo:x].count("'") == 1 and " " not in plain[lo:x]:
        return (lo, plain.find("'", x) + 1)   # inside 'c'
    if plain[x] not in _IDATUI_LIT_CHARS:
        return None
    lo = x
    while lo > 0 and plain[lo - 1] in _IDATUI_LIT_CHARS:
        lo -= 1
    hi = x
    while hi < len(plain) and plain[hi] in _IDATUI_LIT_CHARS:
        hi += 1
    if lo > 0 and plain[lo - 1] == "-":       # a unary minus is part of it
        lo -= 1
    return (lo, hi)


def _idatui_pc_nums(cf, sl):
    """Every number literal on one pseudocode line, as
    [{x0, x1, ea, opnum, value, nbytes, fmt}].

    Asks Hex-Rays what each column belongs to rather than pattern-matching the
    text: a regex over ``v6 = a1 - 1;`` has to guess which of those characters
    are a literal, and ``v11`` looks like one."""
    import ida_hexrays

    plain = ida_lines.tag_remove(sl.line)
    out = []
    x = 0
    while x < len(plain):
        ch = plain[x]
        if ch not in _IDATUI_LIT_CHARS and ch != "'":
            x += 1
            continue
        head, item, tail = (ida_hexrays.ctree_item_t() for _ in range(3))
        if not cf.get_line_item(sl.line, x, True, head, item, tail):
            x += 1
            continue
        if item.citype != ida_hexrays.VDI_EXPR:
            x += 1
            continue
        e = item.e
        if e.op != ida_hexrays.cot_num:
            x += 1
            continue
        extent = _idatui_lit_extent(plain, x)
        if extent is None:
            x += 1
            continue
        nf = e.n.nf
        opnum = ord(nf.opnum) if isinstance(nf.opnum, str) else int(nf.opnum)
        nbytes = (ord(nf.org_nbytes) if isinstance(nf.org_nbytes, str)
                  else int(nf.org_nbytes))
        ea = int(e.ea)
        if ea == idaapi.BADADDR:
            x = extent[1]
            continue                      # synthesised: nothing to key on
        nib = (nf.flags >> ida_bytes.get_operand_type_shift(opnum)) & 0xF
        # Whether this format is the USER's or Hex-Rays' own guess. The nibble
        # can't say: an untouched number reads back as whatever it happens to
        # be printed as, and cycling from there would skip that stop forever
        # (default already looks like it) and never come back to it.
        loc = ida_hexrays.operand_locator_t(ea, opnum)
        user = (ida_hexrays.user_numforms_find(cf.numforms, loc)
                != ida_hexrays.user_numforms_end(cf.numforms))
        out.append({"x0": extent[0], "x1": extent[1], "ea": ea,
                    "opnum": opnum, "value": int(e.n._value),
                    "nbytes": nbytes, "user": user,
                    "fmt": _idatui_fmt_name(nib) if user else "default",
                    "shown": _idatui_fmt_name(nib)})
        x = extent[1]                     # past this literal, not into it
    return out


def pc_nums(
    addr: Annotated[str, "Function address (or any address inside it)"],
) -> dict:
    """Every number literal in a function's pseudocode, as
    [{line, x0, x1, ea, opnum, value, fmt, user}].

    One call per decompilation, so a client can show WHICH literal the cursor is
    on (and reformat exactly that one) without a round trip per cursor move.
    Columns are in the same collapsed coordinates the decompile tool serves its
    text in, i.e. what the client actually displays."""
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        return {"addr": str(addr), "error": "no decompiler", "nums": []}
    try:
        f = idaapi.get_func(parse_address(addr))
    except Exception as e:
        return {"addr": str(addr), "error": str(e), "nums": []}
    if f is None:
        return {"addr": str(addr), "error": "no function here", "nums": []}
    try:
        cf = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"addr": hex(f.start_ea), "error": f"decompile failed: {e}",
                "nums": []}
    if cf is None:
        return {"addr": hex(f.start_ea), "error": "decompilation failed",
                "nums": []}
    sv = cf.get_pseudocode()
    out = []
    for i in range(len(sv)):
        plain = ida_lines.tag_remove(sv[i].line)
        compact = _idatui_compact(plain)
        for rec in _idatui_pc_nums(cf, sv[i]):
            out.append({
                "line": i,
                "x0": _idatui_compact_col(plain, compact, rec["x0"]),
                "x1": _idatui_compact_col(plain, compact, rec["x1"]),
                "ea": hex(rec["ea"]), "opnum": rec["opnum"],
                "value": hex(rec["value"]), "fmt": rec["fmt"],
                "shown": rec["shown"], "user": bool(rec["user"]),
            })
    return {"addr": hex(f.start_ea), "nums": out, "lines": len(sv)}


def pc_num_format(
    addr: Annotated[str, "Function address (or any address inside it)"],
    mode: Annotated[str, "cycle | back | show | hex | dec | oct | char | default"] = "cycle",
    line: Annotated[int, "0-based pseudocode line index"] = -1,
    col: Annotated[int, "Cursor column in the DISPLAYED line (-1: first literal)"] = -1,
    ea: Annotated[str, "Address of the number instead of line/col"] = "",
    opnum: Annotated[int, "Operand number, with ``ea``"] = -1,
) -> dict:
    """Change how a number is displayed in the DECOMPILATION (Hex-Rays keeps its
    own number formats, per (address, operand), independent of the listing).

    Same stops as ``op_format`` minus the two C can't express: binary (no such
    literal -- IDA takes the format and prints decimal anyway) and offset (it
    makes the function stop decompiling). Returns the re-rendered line, and
    marks the function dirty so the next decompile is the new text."""
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        return {"addr": str(addr), "error": "no decompiler"}
    try:
        f = idaapi.get_func(parse_address(addr))
    except Exception as e:
        return {"addr": str(addr), "error": str(e)}
    if f is None:
        return {"addr": str(addr), "error": "no function here"}
    try:
        cf = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"addr": hex(f.start_ea), "error": f"decompile failed: {e}"}
    if cf is None:
        return {"addr": hex(f.start_ea), "error": "decompilation failed"}

    sv = cf.get_pseudocode()
    line = int(line)
    target = None
    if ea:
        try:
            want_ea = parse_address(ea)
        except Exception as e:
            return {"addr": hex(f.start_ea), "error": str(e)}
        for i in range(len(sv)):
            for rec in _idatui_pc_nums(cf, sv[i]):
                if rec["ea"] == want_ea and (int(opnum) < 0
                                             or rec["opnum"] == int(opnum)):
                    target, line = rec, i
                    break
            if target:
                break
    elif 0 <= line < len(sv):
        nums = _idatui_pc_nums(cf, sv[line])
        if nums:
            if int(col) >= 0:
                plain = ida_lines.tag_remove(sv[line].line)
                x = _idatui_uncompact_col(plain, _idatui_compact(plain), int(col))
                target = next((r for r in nums if r["x0"] <= x < r["x1"]), None)
            target = target or nums[0]
    else:
        return {"addr": hex(f.start_ea),
                "error": f"line {line} is outside the {len(sv)}-line decompilation"}
    if target is None:
        return {"addr": hex(f.start_ea), "line": line,
                "text": (ida_lines.tag_remove(sv[line].line).strip()
                         if 0 <= line < len(sv) else ""),
                "error": "no number literal on this line"}

    cur, value = target["fmt"], target["value"]
    choices = [c for c in _IDATUI_PC_FMT_CYCLE
               if c != "char" or _idatui_printable(value)]
    # Same rule as the listing: one ring per literal, every step. A format the
    # ring can't hold (an enum set in the GUI) is reported on the way out
    # instead of being kept for one lap and then lost.
    lossy = cur not in choices and cur != "default"
    out = {"addr": hex(f.start_ea), "ea": hex(target["ea"]),
           "opnum": target["opnum"], "line": line, "prev": cur,
           "format": cur, "shown": target["shown"], "choices": choices,
           "value": hex(value),
           "before": ida_lines.tag_remove(sv[line].line).strip()}

    mode = str(mode or "cycle").lower()
    if mode == "show":
        out["text"] = out["before"]
        out["applied"] = False
        return out
    if mode in ("cycle", "back"):
        step = 1 if mode == "cycle" else -1
        if cur in choices:
            want = choices[(choices.index(cur) + step) % len(choices)]
        else:
            want = choices[0] if step > 0 else choices[-1]
    else:
        want = mode
        if want in ("bin", "offset", "stack", "seg", "float"):
            out["error"] = (f"Hex-Rays has no {want} format for a number "
                            f"-- set it on the listing instead")
            out["text"] = out["before"]
            return out
        if want not in ("hex", "dec", "oct", "char", "default"):
            out["error"] = (f"unknown format {mode!r}; one of hex, dec, oct, "
                            f"char, default")
            out["text"] = out["before"]
            return out

    loc = ida_hexrays.operand_locator_t(target["ea"], target["opnum"])
    it = ida_hexrays.user_numforms_find(cf.numforms, loc)
    if it != ida_hexrays.user_numforms_end(cf.numforms):
        # std::map::insert is a no-op on an existing key, so a format already
        # set here would silently win over the new one.
        ida_hexrays.user_numforms_erase(cf.numforms, it)
    if want != "default":
        nf = ida_hexrays.number_format_t(target["opnum"])
        nf.flags = ida_bytes.get_operand_flag(_idatui_fmt_nibbles()[want],
                                              target["opnum"])
        try:
            nf.org_nbytes = target["nbytes"]
        except Exception:
            pass
        ida_hexrays.user_numforms_insert(cf.numforms, loc, nf)
    cf.save_user_numforms()
    try:
        ida_hexrays.mark_cfunc_dirty(f.start_ea)
    except Exception:
        pass

    out["format"] = want
    out["applied"] = True
    if lossy:
        out["warn"] = (f"this number was {cur}, which names a type a radix "
                       f"can't put back -- reassign it in IDA")
    try:
        cf2 = ida_hexrays.decompile(f.start_ea,
                                    flags=ida_hexrays.DECOMP_NO_CACHE)
        sv2 = cf2.get_pseudocode() if cf2 is not None else None
        out["text"] = (ida_lines.tag_remove(sv2[line].line).strip()
                       if sv2 is not None and line < len(sv2) else out["before"])
    except Exception as e:
        out["text"] = out["before"]
        out["warn"] = f"re-render failed: {e}"
    return out


def decompile(addr, include_addresses=True):
    """Pseudocode for the function at ``addr``, plus the objects it references.

    Faithful to the tool ida-tui was written against, and in particular to its
    COST: the per-line address anchor comes from ONE ``get_line_item`` at column
    0 per line. The Code Mode port asked for the full per-column line map (what
    ``decomp_map`` is for) purely to fill in that anchor, which is thousands of
    ``get_line_item``+``dstr()`` calls per function instead of one per line, and
    made every pseudocode open cost the same as opening the split view.

    Text is whitespace-collapsed exactly as the client displays it, because
    ``pc_nums`` reports literal columns in those coordinates.
    """
    import ida_hexrays

    try:
        ea = parse_address(addr)
    except Exception as e:
        return {"addr": str(addr), "code": None, "error": str(e)}
    fn = idaapi.get_func(ea)
    if fn is None:
        return {"addr": str(addr), "code": None, "error": f"no function at {ea:#x}"}
    if not ida_hexrays.init_hexrays_plugin():
        return {"addr": hex(int(fn.start_ea)), "code": None, "error": "no decompiler"}
    failure = ida_hexrays.hexrays_failure_t()
    try:
        cfunc = ida_hexrays.decompile_func(fn, failure)
    except Exception as e:
        return {"addr": hex(int(fn.start_ea)), "code": None,
                "error": f"Decompilation failed at {ea:#x}: {e}"}
    if cfunc is None:
        return {"addr": hex(int(fn.start_ea)), "code": None,
                "error": failure.desc() or f"Decompilation failed at {ea:#x}"}

    lines = []
    for sl in cfunc.get_pseudocode():
        head = ida_hexrays.ctree_item_t()
        item = ida_hexrays.ctree_item_t()
        tail = ida_hexrays.ctree_item_t()
        line_ea = None
        if include_addresses and cfunc.get_line_item(sl.line, 0, False, head, item, tail):
            parts = (item.dstr() or "").split(": ")
            if len(parts) == 2:
                try:
                    line_ea = int(parts[0], 16)
                except ValueError:
                    line_ea = None
        text = compact_whitespace(ida_lines.tag_remove(sl.line))
        lines.append(f"{text} /*{line_ea:#x}*/" if line_ea is not None else text)

    refs, seen = [], set()

    class _RefVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                target = int(e.obj_ea)
                if target != idaapi.BADADDR and target not in seen:
                    seen.add(target)
                    try:
                        raw = ida_bytes.get_strlit_contents(target, -1, 0)
                        text = raw.decode("utf-8", "replace") if raw else None
                    except Exception:
                        text = None
                    refs.append({"addr": hex(target),
                                 "name": ida_name.get_name(target) or "",
                                 "string": text})
            return 0

    try:
        _RefVisitor().apply_to(cfunc.body, None)
    except Exception:
        pass
    return {"addr": hex(int(fn.start_ea)), "code": "\n".join(lines), "refs": refs}


def decomp_map(
    addr: Annotated[str, "Function address or name"],
) -> dict:
    """Per-pseudocode-line instruction coverage for the split view's region
    highlight: for each line, the set of EAs the decompiler attributes to it,
    swept across the line's columns via get_line_item. Shape:
    {addr, lines:[{ea: primary|None, eas:[hex,...]}, ...]}."""
    import ida_hexrays
    try:
        ea = int(str(addr), 16)
    except ValueError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, str(addr).strip())
    func = idaapi.get_func(ea)
    if not func:
        return {"error": f"no function at {addr}"}
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:  # noqa: BLE001
        return {"error": f"decompile failed: {e}"}
    if cfunc is None:
        return {"error": "decompile failed"}
    # Three things this loop must not do, each measured on real functions (the 25
    # largest of bash went 68.3s -> 6.5s; echo's 60 largest 5.4s -> 0.6s, with
    # byte-identical output):
    #
    #  * allocate ctree_item_t's per COLUMN. They are SWIG objects and this is
    #    the innermost loop; one per call is enough, and head/tail are never
    #    read, so don't ask for them at all.
    #  * sweep the TAGGED length. ``x`` is a screen column but ``sl.line`` still
    #    carries IDA's colour tags, so a 23-column line was swept 124 times.
    #  * call dstr() per column. It formats a whole 'EA: description' string --
    #    24us a call, which is 79% of this tool. Comparing against the PREVIOUS
    #    column's item id is not enough: items interleave, so `foo(a, b)` flips
    #    call -> arg -> call -> arg and every flip re-formats an item already
    #    seen (106 594 calls for 15 417 lines of bash). Memoise id -> ea for the
    #    whole function instead: obj_id is unique within a cfunc, so the same id
    #    always yields the same string, and the result is deduped by ``seen``
    #    anyway. Items with no ctree node (it is None) have no id to key on and
    #    still pay per occurrence.
    item = ida_hexrays.ctree_item_t()
    tag_remove = ida_lines.tag_remove
    get_line_item = cfunc.get_line_item
    ea_of_id = {}
    lines = []
    for sl in cfunc.get_pseudocode():
        line = sl.line
        eas, seen = [], set()
        prev_id = None
        for x in range(len(tag_remove(line)) + 1):
            if not get_line_item(line, x, False, None, item, None):
                continue
            it = item.it
            if it is not None:
                oid = it.obj_id
                if oid == prev_id:
                    continue
                prev_id = oid
                if oid in ea_of_id:
                    e = ea_of_id[oid]
                    if e is not None and e not in seen:
                        seen.add(e)
                        eas.append(hex(e))
                    continue
            else:
                oid = None
                prev_id = None
            # Match the /*ea*/ marker's source (decompile_function_safe): the
            # item's dstr() is 'EA: description'; get_ea() reports a different ea.
            e = None
            dstr = item.dstr()
            if dstr:
                parts = dstr.split(": ", 1)
                if len(parts) == 2:
                    try:
                        e = int(parts[0], 16)
                    except ValueError:
                        e = None
            if oid is not None:
                ea_of_id[oid] = e
            if e is not None and e not in seen:
                seen.add(e)
                eas.append(hex(e))
        lines.append({"ea": eas[0] if eas else None, "eas": eas})
    return {"addr": hex(func.start_ea), "lines": lines}
