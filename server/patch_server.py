#!/usr/bin/env python3
"""Inject idatui's extra ida-pro-mcp tools into the installed server package.

DEPRECATED along with the ida-pro-mcp transport: the default backend is now the
idalib worker (idatui/worker.py), which registers these same tools in-process and
needs no patching. Kept only for `--backend mcp`; slated for removal.

ida-pro-mcp lacks a few tools idatui needs. Rather than vendor/fork the server,
we keep the tool source here and inject it (idempotently) into the installed
``api_types.py``. That module is imported by every worker
(``python -m ida_pro_mcp.idalib_server``), so the tools register themselves via
``@tool`` on the shared ``MCP_SERVER`` — no server code is forked, and re-running
this (spawn.sh does, on every start) re-applies it after a reinstall/upgrade.

Injected tools:
  * ``del_type``      — delete a named local type (struct editor CRUD).
  * ``func_types``    — structured decompiler types for a function (prototype +
                        local variables), so clients don't parse pseudocode text.
  * ``set_lvar_type`` — set a decompiler local variable's type; works on auto/
                        register vars too (the stock set_type only updates lvars
                        that already have user-saved info).

The block between the BEGIN/END markers is *replaced* on each run, so editing
BODY here and restarting the supervisor updates the tools.

Run with the *same* interpreter the server uses (the idalib-mcp entry point's
``/usr/bin/python``), so it patches the file the workers actually import.
Changing a tool needs a supervisor restart so workers respawn.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

BEGIN = "# >>> idatui-ext: begin (auto-injected by server/patch_server.py) >>>"
END = "# <<< idatui-ext: end <<<"

# Appended to ida_pro_mcp/ida_mcp/api_types.py, which already imports
# ``Annotated``, ``tool``, ``idasync``, ``ida_typeinf``, ``parse_address`` and
# ``_parse_type_tinfo``.
BODY = '''
def _idatui_lv_get(x):
    return x() if callable(x) else x


@tool
@idasync
def resolve_names(
    queries: Annotated[list, "Symbol name(s) to resolve to their OWN address"],
) -> list:
    """Resolve named locations (functions, labels like loc_/locret_, data) to the
    exact address the NAME denotes, via get_name_ea. Unlike lookup_funcs, a
    mid-function label resolves to the label's address, not the containing
    function's entry."""
    import idaapi
    qs = queries if isinstance(queries, list) else [queries]
    out = []
    for q in qs:
        q = str(q).strip()
        ea = idaapi.get_name_ea(idaapi.BADADDR, q)
        out.append({"query": q, "ea": (hex(ea) if ea != idaapi.BADADDR else None)})
    return out


@tool
@idasync
def del_type(
    name: Annotated[str, "Local type name to delete (struct/union/enum/typedef)"],
) -> dict:
    """Delete a named local type from the local type library."""
    til = ida_typeinf.get_idati()
    ok = ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE)
    if not ok:
        return {"name": name, "error": f"Type '{name}' not found or could not be deleted"}
    return {"name": name, "deleted": True}


@tool
@idasync
def func_types(
    addr: Annotated[str, "Function address or name"],
) -> dict:
    """Structured decompiler types for a function: its prototype plus each local
    variable (name/type/is_arg). Lets clients read/edit types without parsing
    pseudocode text."""
    import ida_hexrays
    import idaapi

    def _tstr(tif):
        try:
            s = tif.dstr()
            if s:
                return s
        except Exception:
            pass
        return str(tif)

    ea = parse_address(addr)
    f = idaapi.get_func(ea)
    if not f:
        return {"addr": str(addr), "error": "no function at address"}
    try:
        cf = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"addr": hex(f.start_ea), "error": f"decompile failed: {e}"}
    if cf is None:
        return {"addr": hex(f.start_ea), "error": "decompilation failed"}
    name = idaapi.get_func_name(f.start_ea) or ""
    try:
        proto = ida_typeinf.print_tinfo(
            "", 0, 0, ida_typeinf.PRTYPE_1LINE, cf.type, name, "")
    except Exception:
        proto = ""
    lvars = []
    for lv in cf.get_lvars():
        try:
            ty = _tstr(_idatui_lv_get(lv.type))
        except Exception:
            ty = ""
        lvars.append({
            "name": _idatui_lv_get(lv.name),
            "type": ty,
            "is_arg": bool(_idatui_lv_get(lv.is_arg_var)),
        })
    return {
        "addr": hex(f.start_ea),
        "name": name,
        "prototype": (proto or "").strip(),
        "lvars": lvars,
    }


@tool
@idasync
def set_lvar_type(
    addr: Annotated[str, "Function address or name"],
    variable: Annotated[str, "Local variable name"],
    type: Annotated[str, "New C type for the variable"],
) -> dict:
    """Set a decompiler local variable's type. Handles auto/register vars (unlike
    set_type, which only updates lvars that already have user-saved info)."""
    import ida_hexrays
    import idaapi

    ea = parse_address(addr)
    f = idaapi.get_func(ea)
    if not f:
        return {"error": "no function at address"}
    try:
        cf = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"error": f"decompile failed: {e}"}
    if cf is None:
        return {"error": "decompilation failed"}
    target = None
    for lv in cf.get_lvars():
        if _idatui_lv_get(lv.name) == variable:
            target = lv
            break
    if target is None:
        return {"error": f"local variable {variable!r} not found"}
    try:
        tif = _parse_type_tinfo(type)
    except Exception as e:
        return {"error": f"bad type {type!r}: {e}"}
    lsi = ida_hexrays.lvar_saved_info_t()
    try:
        lsi.ll = target
    except Exception:
        try:
            lsi.ll.location = _idatui_lv_get(target.location)
            lsi.ll.defea = target.defea
        except Exception as e:
            return {"error": f"could not locate variable: {e}"}
    lsi.type = tif
    ok = bool(ida_hexrays.modify_user_lvar_info(
        f.start_ea, ida_hexrays.MLI_TYPE, lsi))
    return {"addr": hex(f.start_ea), "variable": variable, "type": type, "ok": ok}


@tool
@idasync
def file_regions() -> dict:
    """Loaded segments mapped to their raw file offsets (get_fileregion_offset),
    so clients can convert a virtual address to an on-disk file offset without a
    format-specific header parser. file_off is -1 for non-file-backed segments
    (e.g. .bss)."""
    import ida_segment
    import idaapi

    out = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        try:
            fo = int(idaapi.get_fileregion_offset(seg.start_ea))
        except Exception:
            fo = -1
        if fo < 0 or fo >= (1 << 48):
            fo = -1
        try:
            nm = ida_segment.get_segm_name(seg) or ""
        except Exception:
            nm = ""
        out.append({"start": hex(seg.start_ea), "end": hex(seg.end_ea),
                    "file_off": fo, "name": nm})
        seg = ida_segment.get_next_seg(seg.start_ea)
    return {"regions": out}


@tool
@idasync
def make_string(
    addr: Annotated[str, "Address of the string start"],
    length: Annotated[int, "Length in bytes (0 = auto-detect to the terminator)"] = 0,
    kind: Annotated[str, "String kind: c | c16 | c32 | pascal"] = "c",
) -> dict:
    """Create a string literal at ``addr`` (IDA's 'A'). ``length`` 0 auto-detects
    to the terminator. Undefines any items in the way first, like the UI does.
    Returns the created byte size and the decoded contents."""
    import ida_bytes
    import ida_nalt

    ea = parse_address(addr)
    strtype = {
        "c": ida_nalt.STRTYPE_C,
        "c16": ida_nalt.STRTYPE_C_16,
        "c32": ida_nalt.STRTYPE_C_32,
        "pascal": ida_nalt.STRTYPE_PASCAL,
    }.get(str(kind).lower(), ida_nalt.STRTYPE_C)
    n = max(int(length), 0)
    # Free any existing item(s) so create_strlit can carve the literal.
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, n if n > 0 else 1)
    ok = bool(ida_bytes.create_strlit(ea, n, strtype))
    if not ok:
        return {"addr": addr, "ok": False, "error": "create_strlit failed"}
    size = int(ida_bytes.get_item_size(ea))
    try:
        raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
        text = raw.decode("utf-8", "replace") if raw else ""
    except Exception:
        text = ""
    return {"addr": addr, "ok": True, "size": size, "text": text}


@tool
@idasync
def read_raw(
    addr: Annotated[str, "Start address (hex or name)"],
    size: Annotated[int, "Number of bytes to read"],
) -> dict:
    """Read ``size`` bytes at ``addr`` as ONE contiguous lowercase hex string
    (no per-byte '0x'/spaces). The hot path for the hex view and disasm opcode
    bytes.

    Fast: does a single bulk ``ida_bytes.get_bytes`` (C-speed) instead of the
    per-byte read_bytes_bss_safe loop (2 IDA calls/byte). Unloaded bytes come
    back from IDA as the 0xFF sentinel, so we only re-check is_loaded for the
    (usually sparse) 0xFF bytes and zero the genuinely-unloaded ones — matching
    get_bytes' bss semantics without paying per-byte for the whole range.

    Encoding is compact hex (~2.5x smaller than get_bytes' '0x..'-with-spaces)
    and, unlike get_bytes, does not truncate on large reads."""
    import ida_bytes

    ea = parse_address(addr)
    n = max(int(size), 0)
    if n == 0:
        return {"addr": addr, "hex": "", "n": 0}
    raw = ida_bytes.get_bytes(ea, n)
    if raw is None or len(raw) < n:  # nothing (or not all) mapped
        base = bytearray(raw or b"")
        base.extend(b"\\xff" * (n - len(base)))
        raw = bytes(base)
    ba = bytearray(raw)
    # Only unloaded bytes read as 0xFF; correct just those to 0 (bss => zero).
    i = ba.find(0xFF)
    while i != -1:
        if not ida_bytes.is_loaded(ea + i):
            ba[i] = 0
        i = ba.find(0xFF, i + 1)
    return {"addr": addr, "hex": bytes(ba).hex(), "n": len(ba)}


def _idatui_head_row(ea):
    """One flat-listing row for the head at ``ea``: kind (code/data/unknown),
    byte size, rendered text, and any symbol name."""
    import ida_bytes
    import ida_lines
    import ida_name

    f = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(f):
        kind = "code"
    elif ida_bytes.is_data(f):
        kind = "data"
    else:
        kind = "unknown"
    line = ida_lines.generate_disasm_line(ea, 0)
    text = ida_lines.tag_remove(line) if line else ""
    text = " ".join(text.split())  # collapse IDA's column padding
    row = {
        "ea": hex(ea),
        "kind": kind,
        "size": int(ida_bytes.get_item_size(ea)),
        "text": text,
    }
    if line:
        # Keep IDA's own token classification for syntax highlighting. Built from
        # the SAME line as `text`, then whitespace-collapsed identically so the
        # two never disagree about what the row says.
        spans = _idatui_spans(line)
        joined = "".join(t for _k, t in spans)
        if " ".join(joined.split()) == text:
            row["spans"] = spans
    nm = ida_name.get_ea_name(ea)
    if nm:
        row["name"] = nm
    return row


#: IDA colour tag -> the semantic kind the TUI styles. IDA already classifies
#: every token in a disassembly line, for every processor it supports, so there
#: is nothing to lex: generate_disasm_line emits \x01<tag>text\x02<tag> and the
#: tag says what the text IS. A pygments assembly lexer would be a worse guess at
#: this and would need one dialect per architecture.
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
    import ida_lines
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


def _idatui_spans(line):
    """A tagged disasm line as [[kind, text], ...], colour tags resolved.

    Unknown tags become 'text' rather than being dropped: a processor module can
    emit a colour we don't classify, and losing the characters would corrupt the
    line."""
    global _IDATUI_TAGS
    import ida_lines
    if _IDATUI_TAGS is None:
        _IDATUI_TAGS = _idatui_tag_map()
    on, off, esc = "\x01", "\x02", "\x03"
    addr_tag = chr(getattr(ida_lines, "COLOR_ADDR", 0x28))
    addr_len = int(getattr(ida_lines, "COLOR_ADDR_SIZE", 16))
    spans, stack, buf = [], [], []
    i, n = 0, len(line)

    def flush():
        if buf:
            spans.append([stack[-1] if stack else "text", "".join(buf)])
            del buf[:]

    while i < n:
        ch = line[i]
        if ch == on and i + 1 < n:
            tag = line[i + 1]
            if tag == addr_tag:
                # An embedded target address, not display text: 16 hex digits
                # that must not reach the screen.
                i += 2 + addr_len
                continue
            flush()
            stack.append(_IDATUI_TAGS.get(tag, "text"))
            i += 2
            continue
        if ch == off and i + 1 < n:
            flush()
            if stack:
                stack.pop()
            i += 2
            continue
        if ch == esc and i + 1 < n:      # escaped literal
            buf.append(line[i + 1])
            i += 2
            continue
        buf.append(ch)
        i += 1
    flush()
    # Collapse IDA's column padding EXACTLY as the plain text does. A run of
    # spaces can straddle two spans, so this walks characters rather than
    # collapsing each span on its own — otherwise the spans and `text` disagree
    # about the line and the row silently loses its highlighting.
    out, prev_space = [], False
    for kind, txt in spans:
        acc = []
        for ch in txt:
            if ch.isspace():
                if prev_space:
                    continue
                acc.append(" ")
                prev_space = True
            else:
                acc.append(ch)
                prev_space = False
        if acc:
            out.append([kind, "".join(acc)])
    while out and out[0][1] == " ":
        out.pop(0)
    while out and out[-1][1] == " ":
        out.pop()
    if out and out[0][1].startswith(" "):
        out[0][1] = out[0][1].lstrip()
    if out and out[-1][1].endswith(" "):
        out[-1][1] = out[-1][1].rstrip()
    return [[k, t] for k, t in out if t]


def _idatui_unknown_row(ea, size):
    """One collapsed row for a run of ``size`` undefined bytes starting at
    ``ea``. A single byte is rendered normally (shows its value); a longer run
    collapses to ``db N dup(?)`` so a big .bss/gap doesn't explode into millions
    of one-byte rows."""
    import ida_name

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
    import ida_nalt
    import ida_typeinf
    import idaapi

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
    import ida_funcs

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
    import ida_funcs

    name = ida_funcs.get_func_name(func.start_ea) or "sub_%X" % func.start_ea
    return [
        {"ea": hex(ea), "kind": "funchdr", "size": 0,
         "text": name + " endp", "name": name},
        {"ea": hex(ea), "kind": "sep", "size": 0, "text": "; " + "-" * 60},
    ]


@tool
@idasync
def heads(
    addr: Annotated[str, "Start address or name to walk from"],
    count: Annotated[int, "Max heads to return (default 200, max 2000)"] = 200,
    offset: Annotated[int, "Skip first N heads from addr (default 0)"] = 0,
    end: Annotated[str, "Optional exclusive end address; default = segment end"] = "",
    back: Annotated[bool, "Walk backwards: return the count heads ENDING just before addr, in forward order"] = False,
    annotate: Annotated[bool, "Emit IDA-style function boundary banner rows (kind sep/funchdr)"] = False,
) -> dict:
    """Walk item heads from ``addr`` as a flat listing: every head is rendered
    (code OR data OR undefined) via generate_disasm_line and stepped with
    next_head/prev_head. Unlike ``disasm`` (code-only, bails at the first data
    byte) this shows db/dw/dd/... lines for data and undefined regions — IDA's
    real disassembly view. Address-paged: page forward by re-calling with
    ``addr`` = the returned cursor.next; page up with ``back=true``."""
    import ida_bytes
    import ida_segment
    import idaapi

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
    def _is_unknown(e):
        f = ida_bytes.get_flags(e)
        return not (ida_bytes.is_code(f) or ida_bytes.is_data(f))

    def _run_end(e):
        """End (exclusive) of the undefined run starting at ``e``."""
        nh = ida_bytes.next_head(e, hi)
        return nh if (nh != idaapi.BADADDR and e < nh <= hi) else hi

    def _advance(e):
        if _is_unknown(e):
            return _run_end(e)
        nxt = ida_bytes.get_item_end(e)
        return nxt if nxt > e else e + 1

    def _rows_for(e):
        if _is_unknown(e):
            return [_idatui_unknown_row(e, _run_end(e) - e)]
        func = idaapi.get_func(e) if annotate else None
        at_start = func is not None and func.start_ea == e
        out = []
        if at_start:
            out.extend(_idatui_func_header_rows(e))
        row = _idatui_head_row(e)
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
    for _ in range(offset):
        if ea >= hi or ea == idaapi.BADADDR:
            break
        ea = _advance(ea)
    more = False
    while ea != idaapi.BADADDR and ea < hi:
        if len(rows) >= count:
            more = True
            break
        rows.extend(_rows_for(ea))  # a struct head expands into member rows
        ea = _advance(ea)
    cursor = {"next": hex(ea)} if more else {"done": True}
    return {"addr": str(addr), "heads": rows, "cursor": cursor}


@tool
@idasync
def xref_types(
    queries: Annotated[list, "[{addr, direction:'to'|'from'|'both', include_fn, dedup, count}]"],
) -> dict:
    """Like xref_query, but every row carries a fine-grained ``kind`` derived from
    the IDA xref type \u2014 call/jump/flow for code, read/write/offset/text/info for
    data \u2014 alongside the coarse ``type`` (code/data). Feeds the xref dialog's
    r/w/call badges. Same query/envelope shape as xref_query."""
    import idaapi, idautils, ida_funcs, ida_bytes, ida_xref
    code_kind = {ida_xref.fl_CF: "call", ida_xref.fl_CN: "call",
                 ida_xref.fl_JF: "jump", ida_xref.fl_JN: "jump",
                 ida_xref.fl_F: "flow"}
    data_kind = {ida_xref.dr_O: "offset", ida_xref.dr_W: "write",
                 ida_xref.dr_R: "read", ida_xref.dr_T: "text", ida_xref.dr_I: "info"}

    def _kind(xr):
        table = code_kind if xr.iscode else data_kind
        return table.get(xr.type, "code" if xr.iscode else "data")

    def _fn(ea):
        f = ida_funcs.get_func(ea)
        if not f:
            return None
        return {"addr": hex(f.start_ea), "name": ida_funcs.get_func_name(f.start_ea)}

    def _resolve(raw):
        raw = str(raw).strip()
        try:
            return int(raw, 16)  # handles '0x2490' and '2490'
        except ValueError:
            return idaapi.get_name_ea(idaapi.BADADDR, raw)

    qs = queries if isinstance(queries, list) else [queries]
    result = []
    for q in qs:
        q = q if isinstance(q, dict) else {"addr": q}
        raw = str(q.get("addr", "")).strip()
        direction = str(q.get("direction", "to") or "to").lower()
        include_fn = bool(q.get("include_fn", True))
        dedup = bool(q.get("dedup", True))
        try:
            count = int(q.get("count", 2000) or 2000)
        except (TypeError, ValueError):
            count = 2000
        target = _resolve(raw)
        rows = []
        if target is not None and target != idaapi.BADADDR and ida_bytes.is_mapped(target):
            if direction in ("to", "both"):
                for xr in idautils.XrefsTo(target, 0):
                    row = {"direction": "to", "addr": hex(xr.frm), "from": hex(xr.frm),
                           "to": hex(target), "type": "code" if xr.iscode else "data",
                           "kind": _kind(xr)}
                    if include_fn:
                        row["fn"] = _fn(xr.frm)
                    rows.append(row)
            if direction in ("from", "both"):
                for xr in idautils.XrefsFrom(target, 0):
                    row = {"direction": "from", "addr": hex(xr.to), "from": hex(target),
                           "to": hex(xr.to), "type": "code" if xr.iscode else "data",
                           "kind": _kind(xr)}
                    if include_fn:
                        row["fn"] = _fn(xr.to)
                    rows.append(row)
            if dedup:
                seen = set()
                deduped = []
                for r in rows:
                    k = (r["direction"], r["from"], r["to"], r["kind"])
                    if k in seen:
                        continue
                    seen.add(k)
                    deduped.append(r)
                rows = deduped
            rows = rows[:count]
        result.append({"query": raw, "data": rows, "next_offset": None})
    return {"result": result}


@tool
@idasync
def data_type(
    addr: Annotated[str, "Address or name of a data item / global"],
) -> dict:
    """The current C type of a data item, for prefilling a retype prompt:
    {addr, name, type, size, is_func}. ``type`` is empty when the item is
    untyped; ``is_func`` distinguishes a global from a function so the caller
    knows which flavour of set_type to use."""
    import idaapi
    import ida_bytes
    import ida_name
    import idc
    raw = str(addr).strip()
    try:
        ea = int(raw, 16)
    except ValueError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, raw)
    if ea == idaapi.BADADDR or not ida_bytes.is_mapped(ea):
        return {"addr": raw, "error": f"not a mapped address: {raw}"}
    return {
        "addr": hex(ea),
        "name": ida_name.get_name(ea) or "",
        "type": idc.get_type(ea) or "",
        "size": int(ida_bytes.get_item_size(ea) or 0),
        "is_func": bool(idaapi.get_func(ea)),
    }


@tool
@idasync
def decomp_map(
    addr: Annotated[str, "Function address or name"],
) -> dict:
    """Per-pseudocode-line instruction coverage for the split view's region
    highlight: for each line, the set of EAs the decompiler attributes to it,
    swept across the line's columns via get_line_item. Shape:
    {addr, lines:[{ea: primary|None, eas:[hex,...]}, ...]}."""
    import ida_hexrays
    import idaapi
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
    lines = []
    for sl in cfunc.get_pseudocode():
        line = sl.line
        eas, seen = [], set()
        for x in range(len(line) + 1):
            head = ida_hexrays.ctree_item_t()
            item = ida_hexrays.ctree_item_t()
            tail = ida_hexrays.ctree_item_t()
            if not cfunc.get_line_item(line, x, False, head, item, tail):
                continue
            # Match the /*ea*/ marker's source (decompile_function_safe): the
            # item's dstr() is 'EA: description'; get_ea() reports a different ea.
            dstr = item.dstr()
            if not dstr:
                continue
            parts = dstr.split(": ", 1)
            if len(parts) != 2:
                continue
            try:
                e = int(parts[0], 16)
            except ValueError:
                continue
            if e not in seen:
                seen.add(e)
                eas.append(hex(e))
        lines.append({"ea": eas[0] if eas else None, "eas": eas})
    return {"addr": hex(func.start_ea), "lines": lines}


_idatui_strings_cache = {}


def _idatui_build_strings(min_len):
    """[(ea, text, length, typename)] for every string IDA found, cached by
    min_len (rebuilding the list is O(n) and the browser pages through it)."""
    import idautils
    import ida_nalt
    hit = _idatui_strings_cache.get(min_len)
    if hit is not None:
        return hit
    tnames = {}
    for nm, lbl in (("STRTYPE_C", "C"), ("STRTYPE_C_16", "utf16"),
                    ("STRTYPE_C_32", "utf32"), ("STRTYPE_PASCAL", "pascal")):
        v = getattr(ida_nalt, nm, None)
        if v is not None:
            tnames[v & 0xFF] = lbl
    items = []
    for s in idautils.Strings():
        if s is None:
            continue
        try:
            text = str(s)
        except Exception:  # noqa: BLE001 -- undecodable literal
            continue
        if len(text) < min_len:
            continue
        st = getattr(s, "strtype", 0) & 0xFF
        items.append((s.ea, text, getattr(s, "length", len(text)),
                      tnames.get(st, "t%d" % st)))
    _idatui_strings_cache[min_len] = items
    return items


@tool
@idasync
def list_strings(
    offset: Annotated[int, "Start index into the strings list"] = 0,
    count: Annotated[int, "Max strings to return (page size)"] = 2000,
    min_len: Annotated[int, "Minimum string length to include"] = 4,
    refresh: Annotated[bool, "Rebuild the cached strings list"] = False,
) -> dict:
    """Every string literal IDA found in the binary (IDA's Shift+F12 window),
    paginated: {strings:[{addr,text,len,type}], total, next_offset}. Feeds the
    TUI's strings browser."""
    try:
        min_len = max(int(min_len), 1)
    except (TypeError, ValueError):
        min_len = 4
    try:
        offset = max(int(offset), 0)
    except (TypeError, ValueError):
        offset = 0
    try:
        count = max(int(count), 1)
    except (TypeError, ValueError):
        count = 2000
    if refresh:
        _idatui_strings_cache.pop(min_len, None)
    items = _idatui_build_strings(min_len)
    page = items[offset:offset + count]
    return {
        "strings": [{"addr": hex(ea), "text": text, "len": ln, "type": ty}
                    for (ea, text, ln, ty) in page],
        "total": len(items),
        "next_offset": offset + len(page),
    }

@tool
@idasync
def list_linkage(
    kind: Annotated[str, "'import', 'export' or 'both'"] = "both",
) -> dict:
    """What this binary imports from, and exports to, other modules:
    {imports:[{addr,name,module}], exports:[{addr,name,ordinal}]}. Feeds the
    project-wide import/export join, which resolves a PLT stub in one binary to
    the real implementation in another."""
    import idaapi
    import idautils
    import ida_nalt
    want = str(kind or "both").lower()
    imports = []
    exports = []
    if want in ("import", "both"):
        n = ida_nalt.get_import_module_qty()
        for i in range(n):
            mod = ida_nalt.get_import_module_name(i) or ""

            def _cb(ea, name, ordinal, _mod=mod):
                # An ordinal-only import has no name; skip rather than invent one.
                if name:
                    imports.append({"addr": hex(ea), "name": name, "module": _mod})
                return True

            ida_nalt.enum_import_names(i, _cb)
    if want in ("export", "both"):
        for index, ordinal, ea, name in idautils.Entries():
            if name:
                exports.append({"addr": hex(ea), "name": name,
                                "ordinal": int(ordinal)})
    return {"imports": imports, "exports": exports,
            "n_imports": len(imports), "n_exports": len(exports)}

@tool
@idasync
def define_code_run(
    addr: Annotated[str, "Address to start disassembling from"],
    limit: Annotated[int, "Max instructions to create (safety stop)"] = 20000,
) -> dict:
    """Disassemble CONSECUTIVELY from ``addr`` until something stops it, the way
    IDA's 'c' does — one instruction is rarely what you want when carving a raw
    image. Returns {start,end,count,stopped} where ``stopped`` says why:
    'undecodable' (bytes aren't an instruction), 'flow' (the last instruction
    doesn't fall through, e.g. RET/B), 'defined' (ran into existing code/data),
    'segment' (hit the end) or 'limit'.

    Runs in-process: doing this from the client would be one round trip per
    instruction, which is minutes on a real firmware image."""
    import ida_bytes
    import ida_idp
    import ida_segment
    import ida_ua
    import idaapi

    try:
        ea = parse_address(addr)
    except Exception as e:
        return {"addr": str(addr), "error": str(e), "count": 0}

    seg = ida_segment.getseg(ea)
    if not seg:
        return {"addr": str(addr), "error": "no segment", "count": 0}
    hi = seg.end_ea
    try:
        limit = max(1, min(int(limit), 200000))
    except (TypeError, ValueError):
        limit = 20000

    start, count, stopped = ea, 0, "limit"
    while count < limit:
        if ea >= hi:
            stopped = "segment"
            break
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_data(flags):
            # Already defined: stop rather than clobber. Undefining someone's
            # existing work to keep a speculative run going is not a trade the
            # user asked for.
            stopped = "defined"
            break
        n = ida_ua.create_insn(ea)
        if n <= 0:
            stopped = "undecodable"
            break
        count += 1
        # Stop where control flow stops. Past a RET the next bytes are usually
        # padding or a new function's data, and running on turns a clean carve
        # into a mess that has to be undone by hand.
        #
        # Ask ida_idp.is_ret_insn, NOT the canonical feature bits: on AArch64
        # get_canon_feature() returns 0 for RET, so a CF_STOP test silently never
        # fires and the run walks straight through the end of the routine.
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) > 0:
            try:
                is_ret = ida_idp.is_ret_insn(insn)
            except Exception:
                is_ret = False
            if is_ret or (insn.get_canon_feature() & idaapi.CF_STOP):
                ea += n
                stopped = "flow"
                break
        ea += n

    return {"start": hex(start), "end": hex(ea), "count": count,
            "stopped": stopped}

@tool
@idasync
def set_thumb(
    addr: Annotated[str, "Address to change the ARM decoding mode at"],
    mode: Annotated[str, "'toggle', 'on' (Thumb) or 'off' (ARM)"] = "toggle",
    end: Annotated[str, "Optional exclusive end address (default: this item)"] = "",
) -> dict:
    """Switch ARM/Thumb decoding at ``addr`` (IDA's T segment register).

    Thumb is not a property of the bytes, it's a mode the CPU is in, so a raw
    image gives IDA no way to know: at a Thumb entry point it decodes 16-bit
    instructions as 32-bit ARM and produces confident nonsense
    (``push {r3,lr}`` reads as ``SVCLT 0xBF00``).

    Also forces the segment to 32-bit when turning Thumb ON. Thumb does not
    exist in AArch64, and a headerless blob loaded with -parm defaults to
    64-bit — so setting T alone changes nothing and looks broken. Asking for
    Thumb IS asking for ARM32."""
    import ida_bytes
    import ida_idp
    import ida_segment
    import ida_segregs

    try:
        ea = parse_address(addr)
    except Exception as e:
        return {"addr": str(addr), "error": str(e)}
    treg = ida_idp.str2reg("T")
    if treg is None or treg < 0:
        return {"addr": hex(ea), "error": "no T register (not an ARM database)"}
    seg = ida_segment.getseg(ea)
    if not seg:
        return {"addr": hex(ea), "error": "no segment"}

    import ida_ida
    db64 = ida_ida.inf_get_app_bitness() == 64
    cur = ida_segregs.get_sreg(ea, treg)
    cur = 0 if cur in (None, 0xFFFFFFFF, -1) else int(cur)
    want = {"on": 1, "off": 0}.get(str(mode).lower(), 0 if cur else 1)

    changed_bits = False
    if want and seg.bitness != 1:
        ida_segment.set_segm_addressing(seg, 1)
        changed_bits = True

    try:
        stop = parse_address(end) if end else 0
    except Exception:
        stop = 0
    size = max(int(stop) - ea, 0) or max(ida_bytes.get_item_size(ea), 2)
    # The bytes are currently decoded in the OLD mode; leaving that item defined
    # pins the wrong instruction length and the new mode has nothing to apply to.
    ida_bytes.del_items(ea, 0, size)
    ok = bool(ida_segregs.split_sreg_range(ea, treg, want, ida_segregs.SR_user))
    now = ida_segregs.get_sreg(ea, treg)
    return {"addr": hex(ea), "thumb": bool(now), "was": bool(cur), "ok": ok,
            "bitness": ida_segment.getseg(ea).bitness,
            "forced_32bit": changed_bits,
            # The DATABASE's bitness is fixed at load and can't be corrected
            # here (setting it post-hoc makes the decompiler INTERR). In a
            # 64-bit database a 32-bit function disassembles but Hex-Rays
            # refuses it outright, so say so instead of leaving the user to
            # discover that F5 does nothing.
            "db_64bit": bool(db64 and want)}

@tool
@idasync
def define_func_run(
    addr: Annotated[str, "Entry point of the function to create"],
) -> dict:
    """Create a function at ``addr``, working out its end if IDA can't.

    ida_funcs.add_func(ea) asks IDA to find the end itself, and on hand-carved
    code it often can't — a run that ends in a tail call, or whose last
    instruction isn't recognised as a return, simply fails with no reason given.
    You then have a disassembled routine that refuses to become a function, and
    F5 has nothing to work with.

    So: try IDA's way, and if that fails, use the end of the contiguous
    instruction run starting at ``addr``."""
    import ida_bytes
    import ida_funcs
    import ida_segment
    import idaapi

    try:
        ea = parse_address(addr)
    except Exception as e:
        return {"addr": str(addr), "error": str(e), "ok": False}
    fn = idaapi.get_func(ea)
    if fn is not None and fn.start_ea == ea:
        return {"addr": hex(ea), "ok": True, "start": hex(fn.start_ea),
                "end": hex(fn.end_ea), "how": "existed"}
    if ida_funcs.add_func(ea):
        f = idaapi.get_func(ea)
        return {"addr": hex(ea), "ok": True, "start": hex(f.start_ea),
                "end": hex(f.end_ea), "how": "auto"}

    seg = ida_segment.getseg(ea)
    hi = seg.end_ea if seg else ea
    end = ea
    while end < hi and ida_bytes.is_code(ida_bytes.get_flags(end)):
        nxt = ida_bytes.get_item_end(end)
        if nxt <= end:
            break
        end = nxt
    if end <= ea:
        return {"addr": hex(ea), "ok": False,
                "error": "no code here to make a function from"}
    if not ida_funcs.add_func(ea, end):
        return {"addr": hex(ea), "ok": False,
                "error": f"IDA refused a function at {ea:#x}..{end:#x}"}
    f = idaapi.get_func(ea)
    return {"addr": hex(ea), "ok": True, "start": hex(f.start_ea),
            "end": hex(f.end_ea), "how": "explicit-end"}

@tool
@idasync
def decomp_error(
    addr: Annotated[str, "Address of the function that failed to decompile"],
) -> dict:
    """Why Hex-Rays refused this function, in its own words.

    The plain decompile tool reports "Decompilation failed at 0x0" and drops the
    reason, which is the only useful part. Hex-Rays fills in a hexrays_failure_t
    saying things like "only 64-bit functions can be decompiled in the current
    database" — that one is unfixable in place (the database's bitness is set at
    load), so a user who can't see it has no way to know they must reload."""
    import ida_funcs
    import ida_hexrays
    import ida_ida

    try:
        ea = parse_address(addr)
    except Exception as e:
        return {"addr": str(addr), "error": str(e)}
    out = {"addr": hex(ea), "bitness": ida_ida.inf_get_app_bitness()}
    fn = ida_funcs.get_func(ea)
    if fn is None:
        out["reason"] = "no function here"
        return out
    try:
        if not ida_hexrays.init_hexrays_plugin():
            out["reason"] = "the decompiler is not available for this processor"
            return out
        hf = ida_hexrays.hexrays_failure_t()
        cf = ida_hexrays.decompile_func(fn, hf)
        if cf is not None:
            out["reason"] = ""      # it decompiles now
            return out
        out["reason"] = hf.desc() or f"error {hf.code}"
        out["code"] = int(hf.code)
        out["errea"] = hex(hf.errea)
    except Exception as e:  # noqa: BLE001
        out["reason"] = f"{type(e).__name__}: {e}"
    return out
'''

SNIPPET = f"{BEGIN}\n{BODY.strip()}\n{END}\n"


def api_types_path() -> pathlib.Path | None:
    """Locate ida_pro_mcp/ida_mcp/api_types.py without importing it (importing the
    submodule would pull in IDA, which isn't available outside a worker)."""
    spec = importlib.util.find_spec("ida_pro_mcp")  # top-level pkg is IDA-free
    if spec is None or not spec.submodule_search_locations:
        return None
    p = pathlib.Path(spec.submodule_search_locations[0]) / "ida_mcp" / "api_types.py"
    return p if p.exists() else None


def main() -> int:
    path = api_types_path()
    if path is None:
        print("idatui: ida_pro_mcp not found; skipping tool injection", file=sys.stderr)
        return 0
    text = path.read_text()
    if BEGIN in text and END in text:  # replace the existing block in place
        pre = text[: text.index(BEGIN)].rstrip()
        post = text[text.index(END) + len(END):].lstrip("\n")
        new = pre + "\n\n" + SNIPPET + ("\n" + post if post else "")
    else:
        new = text.rstrip() + "\n\n" + SNIPPET
    if new == text:
        return 0
    try:
        path.write_text(new)
    except OSError as e:
        print(f"idatui: could not patch {path}: {e}", file=sys.stderr)
        return 1
    print(f"idatui: injected/updated idatui-ext tools in {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
