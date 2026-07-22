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
        out.append({"start": hex(seg.start_ea), "end": hex(seg.end_ea), "file_off": fo})
        seg = ida_segment.get_next_seg(seg.start_ea)
    return {"regions": out}


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


@tool
@idasync
def heads(
    addr: Annotated[str, "Start address or name to walk from"],
    count: Annotated[int, "Max heads to return (default 200, max 2000)"] = 200,
    offset: Annotated[int, "Skip first N heads from addr (default 0)"] = 0,
    end: Annotated[str, "Optional exclusive end address; default = segment end"] = "",
    back: Annotated[bool, "Walk backwards: return the count heads ENDING just before addr, in forward order"] = False,
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

    ea = ida_bytes.get_item_head(start)
    for _ in range(offset):
        if ea >= hi or ea == idaapi.BADADDR:
            break
        ea = ida_bytes.next_head(ea, hi)
    more = False
    while ea != idaapi.BADADDR and ea < hi:
        if len(rows) >= count:
            more = True
            break
        rows.append(_idatui_head_row(ea))
        ea = ida_bytes.next_head(ea, hi)
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
