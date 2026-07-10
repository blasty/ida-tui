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
