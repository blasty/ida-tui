#!/usr/bin/env python3
"""Inject idatui's extra ida-pro-mcp tools into the installed server package.

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
    nm = ida_name.get_ea_name(ea)
    if nm:
        row["name"] = nm
    return row


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
