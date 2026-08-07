"""Client adapter from ida-tui's domain operations to IDA Code Mode.

``DatabaseHandle`` is the lifecycle boundary: it discovers an already-registered
GUI database, reuses a shared managed idalib worker, or starts one when needed.
The TUI never owns or terminates an IDA process.  Closing this client releases
only its lease.

The Code Mode transport intentionally exposes one broad operation,
``execute_python``.  ``CodeModeClient.invoke`` turns the small, address-centric
operations needed by the paging layer into self-contained snippets.  The
snippets prefer the public ``ida-domain`` ``db`` object.  A handful of features
that ida-domain does not currently expose (IDA-coloured listing rows, creating
instructions, ARM T-state, and detailed Hex-Rays line maps/failures) use the
IDAPython modules that Code Mode deliberately makes importable.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import threading
import time
from pathlib import Path
from textwrap import dedent
from typing import Any

from .errors import IDAConnectionError, IDATimeoutError, IDAToolError, Session

# ida_codemode is imported EAGERLY-IF-PRESENT but never at hard import cost.
#
# The paging/graph/trace layers and their offline test suites must keep importing
# `idatui` on a machine with no IDA and no Code Mode installed -- that is the
# house rule the stdlib-only worker client used to satisfy for free, and
# `tests/run.py --fast` (257 checks, any python3) depends on it. A hard top-level
# import here makes the whole package unimportable, so the failure is deferred to
# the first operation that genuinely needs the library.
_CODEMODE_ERROR: Exception | None = None
try:
    from ida_codemode.client import (
        ClientError,
        DatabaseHandle,
        InstanceDisconnectedError,
        RemoteError,
    )
    from ida_codemode.registry import (
        REGISTRY_DIR,
        FileLock,
        RegistryEntry,
        canonical_path,
        idb_key,
        scan_instances,
    )
    from ida_codemode.resolver import IdbBusy, expected_idb_path
except ImportError as _exc:  # library absent: usable only for offline layers
    _CODEMODE_ERROR = _exc
    # Bound to None rather than left undefined so the names stay patchable: the
    # offline contract tests inject a fake DatabaseHandle here.
    ClientError = InstanceDisconnectedError = RemoteError = None  # type: ignore[assignment,misc]
    DatabaseHandle = RegistryEntry = FileLock = None  # type: ignore[assignment,misc]
    REGISTRY_DIR = canonical_path = idb_key = scan_instances = None  # type: ignore[assignment]
    IdbBusy = expected_idb_path = None  # type: ignore[assignment]


def _require_codemode() -> None:
    """Raise an actionable error when the Code Mode library is missing.

    Gated on the binding, not on the original import result, so a test that
    injects a fake ``DatabaseHandle`` exercises the real adapter logic.
    """
    if DatabaseHandle is None:
        raise IDAConnectionError(
            "ida-codemode-mcp is not installed in this environment "
            f"({_CODEMODE_ERROR}). Install it (e.g. `uv sync`, or "
            "`pip install -e ../ida-codemode-mcp`) so ida-tui can lease a "
            "database.") from _CODEMODE_ERROR


def database_owner(idb_path: str, staged_path: str | None = None):
    """The registry entry that owns ``idb_path``/``staged_path``, else None.

    Returns None when the Code Mode library is absent: with no library there is
    no client in this environment that could be holding the database, and the
    IDA-free layers (project staging) must keep working. Registry errors that
    happen WITH the library installed still propagate -- those mean "we could
    not determine ownership", which is not the same as "nobody owns it".
    """
    if DatabaseHandle is None:
        return None
    expected_key = idb_key(idb_path)
    staged = canonical_path(staged_path) if staged_path else None
    for item in scan_instances(timeout=0.5):
        entry = item.entry
        if entry.idb_key == expected_key:
            return entry
        if staged and entry.exe_path and canonical_path(entry.exe_path) == staged:
            return entry
    return None


def registered_database(path: str, output_database: str | None = None) -> bool:
    """Whether a live/lock-held Code Mode instance owns this target."""
    _require_codemode()
    source = canonical_path(path)
    expected = canonical_path(output_database) if output_database else expected_idb_path(source)
    expected_key = idb_key(expected)
    for instance in scan_instances(timeout=0.5):
        entry = instance.entry
        if entry.idb_key == expected_key:
            return True
        if not output_database and entry.backend == "gui" and entry.exe_path:
            if canonical_path(entry.exe_path) == source:
                return True
    return False


class _NoopKeepAlive:
    """Compatibility shim: the DatabaseHandle's SSE lease is the heartbeat."""

    def __init__(self) -> None:
        self.beats = self.failures = 0

    def start(self) -> "_NoopKeepAlive":
        return self

    def stop(self) -> None:
        pass


def _parse_load_args(value: str) -> tuple[str | None, int | None, str | None]:
    """Translate ida-tui's legacy first-open switches to Code Mode options.

    Code Mode has typed options for processor, natural loading address and file
    type.  It deliberately has no arbitrary command-line escape hatch; reject
    switches we cannot represent instead of silently loading a blob wrongly.
    """
    processor: str | None = None
    loading_address: int | None = None
    file_type: str | None = None
    unsupported: list[str] = []
    try:
        words = shlex.split(value or "", posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"invalid IDA load options: {exc}") from exc
    for word in words:
        if word.startswith("-p") and len(word) > 2:
            processor = word[2:]
        elif word.startswith("-b") and len(word) > 2:
            try:
                # IDA's -b is in 16-byte paragraphs. DatabaseHandle expects the
                # natural address, which is the safer public API.
                loading_address = int(word[2:], 16) << 4
            except ValueError as exc:
                raise ValueError(f"invalid IDA loading address: {word!r}") from exc
        elif word.startswith("-T") and len(word) > 2:
            file_type = word[2:]
        else:
            unsupported.append(word)
    if unsupported:
        joined = " ".join(unsupported)
        raise ValueError(
            "ida-codemode cannot represent arbitrary IDA load options: "
            f"{joined!r}; use processor/base/file type options instead"
        )
    return processor, loading_address, file_type


def _script(args: dict[str, Any], body: str) -> str:
    """Bind JSON arguments without interpolating user text into Python code."""
    encoded = json.dumps(args, ensure_ascii=False, separators=(",", ":"))
    return f"import json\na = json.loads({encoded!r})\n{dedent(body).strip()}\n"


_OPERATIONS: dict[str, str] = {
    "list_funcs": r'''
import fnmatch
queries = a.get("queries") or [{}]
q = queries[0]
offset, count = max(0, int(q.get("offset", 0))), max(1, int(q.get("count", 500)))
pattern = str(q.get("filter") or "").lower()
if pattern and not any(ch in pattern for ch in "*?["): pattern = "*" + pattern + "*"
rows = []
for fn in db.functions.get_all():
    name = db.functions.get_name(fn) or f"sub_{int(fn.start_ea):X}"
    if pattern and not fnmatch.fnmatchcase(name.lower(), pattern): continue
    rows.append({"addr": hex(int(fn.start_ea)), "name": name,
                 "size": int(fn.end_ea) - int(fn.start_ea)})
page = rows[offset:offset + count]
result = {"result": [{"data": page, "next_offset": offset + len(page), "total": len(rows)}]}
result
''',
    "disasm": r'''
ea = int(str(a["addr"]), 16)
fn = db.functions.get_at(ea)
if fn is None:
    result = {"instructions": [], "total_instructions": 0, "instruction_count": 0}
else:
    instructions = list(db.functions.get_instructions(fn))
    limit = max(1, int(a.get("max_instructions", len(instructions) or 1)))
    rows = [{"addr": hex(int(insn.ea)), "instruction": db.instructions.get_disassembly(insn)}
            for insn in instructions[:limit]]
    result = {"instructions": rows, "total_instructions": len(instructions),
              "instruction_count": len(instructions)}
result
''',
    "file_regions": r'''
import idaapi
rows = []
for seg in db.segments.get_all():
    try: file_off = int(idaapi.get_fileregion_offset(seg.start_ea))
    except Exception: file_off = -1
    if file_off < 0 or file_off >= (1 << 48): file_off = -1
    rows.append({"start": hex(int(seg.start_ea)), "end": hex(int(seg.end_ea)),
                 "file_off": file_off, "name": db.segments.get_name(seg) or ""})
result = {"regions": rows}
result
''',
    "read_raw": r'''
import ida_bytes
ea, size = int(str(a["addr"]), 16), max(0, int(a["size"]))
raw = ida_bytes.get_bytes(ea, size) or b""
raw = raw[:size] + b"\xff" * max(0, size - len(raw))
data = bytearray(raw)
for index, value in enumerate(data):
    if value == 0xFF and not ida_bytes.is_loaded(ea + index): data[index] = 0
result = {"addr": a["addr"], "hex": bytes(data).hex(), "n": len(data)}
result
''',
    "get_bytes": r'''
rows = []
for region in a.get("regions", []):
    ea, size = int(str(region["addr"]), 16), int(region["size"])
    raw = db.bytes.get_bytes_at(ea, size) or b""
    rows.append({"addr": region["addr"], "data": " ".join(f"{b:02x}" for b in raw)})
result = {"result": rows}
result
''',
    "search_structs": r'''
needle = str(a.get("filter") or "").lower()
rows = []
for tif in db.types.get_all():
    name = tif.get_type_name() or ""
    if not name or needle not in name.lower() or not tif.is_udt(): continue
    members = list(db.types.get_udt_members(tif))
    rows.append({"name": name, "size": int(tif.get_size()), "is_union": bool(tif.is_union()),
                 "cardinality": len(members), "ordinal": int(tif.get_ordinal())})
result = {"result": rows}
result
''',
    "type_inspect": r'''
rows = []
for query in a.get("queries", []):
    name = str(query.get("name") or "")
    tif = db.types.get_by_name(name)
    if tif is None:
        rows.append({"name": name, "error": "type not found"}); continue
    members = [{"name": m.name, "type": m.type.dstr() or str(m.type),
                "offset": int(m.offset), "size": int(m.size)}
               for m in db.types.get_udt_members(tif)] if tif.is_udt() else []
    rows.append({"name": name, "size": int(tif.get_size()), "is_union": bool(tif.is_union()),
                 "members": members})
result = {"result": rows}
result
''',
    "declare_type": r'''
import ida_typeinf
decls = a.get("decls", "")
if isinstance(decls, str): decls = [decls]
rows = []
for declaration in decls:
    try:
        errors = int(db.types.parse_declarations(ida_typeinf.get_idati(), declaration))
        rows.append({"ok": errors == 0, **({} if errors == 0 else {"error": f"{errors} parse error(s)"})})
    except Exception as exc:
        rows.append({"ok": False, "error": str(exc)})
result = {"result": rows}
result
''',
    "del_type": r'''
import ida_typeinf
name = str(a["name"])
ok = bool(ida_typeinf.del_named_type(ida_typeinf.get_idati(), name, ida_typeinf.NTF_TYPE))
result = {"name": name, "deleted": ok, **({} if ok else {"error": f"Type {name!r} not found or could not be deleted"})}
result
''',
    "func_types": r'''
import ida_typeinf
ea = int(str(a["addr"]), 16)
fn = db.functions.get_at(ea)
if fn is None:
    result = {"addr": a["addr"], "error": "no function at address"}
else:
    pseudo = db.pseudocode.decompile(fn)
    name = db.functions.get_name(fn) or ""
    tif = pseudo.get_func_type()
    try: prototype = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, "") if tif else ""
    except Exception: prototype = tif.dstr() if tif else ""
    lvars = [{"name": var.name, "type": var.type_info.dstr() if var.type_info else "",
              "is_arg": bool(var.is_arg)} for var in pseudo.local_variables]
    result = {"addr": hex(int(fn.start_ea)), "name": name,
              "prototype": (prototype or "").strip(), "lvars": lvars}
result
''',
    "set_lvar_type": r'''
import ida_typeinf
ea, variable, declaration = int(str(a["addr"]), 16), str(a["variable"]), str(a["type"])
fn = db.functions.get_at(ea)
if fn is None:
    result = {"error": "no function at address"}
else:
    pseudo = db.pseudocode.decompile(fn)
    var = pseudo.find_local_variable(variable)
    if var is None:
        result = {"error": f"local variable {variable!r} not found"}
    else:
        try:
            tif = db.types.parse_one_declaration(ida_typeinf.get_idati(), declaration)
            accepted = bool(var.set_type(tif))
            saved = bool(pseudo.save_local_variable_info(var, save_type=True)) if accepted else False
            result = {"addr": hex(int(fn.start_ea)), "variable": variable,
                      "type": declaration, "ok": accepted and saved}
        except Exception as exc:
            result = {"error": f"bad type {declaration!r}: {exc}"}
result
''',
    "set_type": r'''
from ida_domain.types import TypeApplyFlags
rows = []
for edit in a.get("edits", []):
    ea = int(str(edit["addr"]), 16)
    declaration = str(edit.get("signature") or edit.get("type") or "")
    try:
        ok = bool(db.types.apply_declaration_at(ea, declaration, TypeApplyFlags.DEFINITE))
        rows.append({"addr": hex(ea), "ok": ok, **({} if ok else {"error": "IDA rejected the type"})})
    except Exception as exc:
        rows.append({"addr": hex(ea), "ok": False, "error": str(exc)})
result = {"result": rows}
result
''',
    "data_type": r'''
ea = int(str(a["addr"]), 16)
try:
    tif = db.types.get_at(ea)
    fn = db.functions.get_at(ea)
    result = {"addr": hex(ea), "name": db.names.get_at(ea) or "",
              "type": tif.dstr() if tif else "", "size": int(db.heads.size(ea)) if db.heads.is_head(ea) else 0,
              "is_func": bool(fn)}
except Exception as exc:
    result = {"addr": hex(ea), "error": str(exc)}
result
''',
    "force_recompile": r'''
import ida_hexrays
rows = []
for item in a.get("items", []):
    ea = int(str(item["addr"]), 16)
    ida_hexrays.mark_cfunc_dirty(ea, False)
    rows.append({"addr": hex(ea), "ok": True})
result = {"result": rows}
result
''',
    "undefine": r'''
import ida_bytes
rows = []
for item in a.get("items", []):
    ea = int(str(item["addr"]), 16)
    size = max(1, int(item.get("size") or ida_bytes.get_item_size(ea) or 1))
    ok = bool(ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size))
    rows.append({"addr": hex(ea), "ok": ok, **({} if ok else {"error": "delete items failed"})})
result = {"result": rows}
result
''',
    "define_code": r'''
import ida_ua
rows = []
for item in a.get("items", []):
    ea = int(str(item["addr"]), 16); size = int(ida_ua.create_insn(ea))
    rows.append({"addr": hex(ea), "ok": size > 0, "size": size,
                 **({} if size > 0 else {"error": "instruction did not decode"})})
result = {"result": rows}
result
''',
    "define_func": r'''
rows = []
for item in a.get("items", []):
    ea = int(str(item["addr"]), 16); ok = bool(db.functions.create(ea))
    rows.append({"addr": hex(ea), "ok": ok, **({} if ok else {"error": "IDA refused the function"})})
result = {"result": rows}
result
''',
    "make_data": r'''
import ida_bytes, ida_idaapi, ida_typeinf
from ida_domain.types import TypeApplyFlags
rows = []
for item in a.get("items", []):
    ea, declaration = int(str(item["addr"]), 16), str(item["type"])
    try:
        tif = db.types.parse_one_declaration(ida_typeinf.get_idati(), declaration)
        size = max(1, int(tif.get_size()))
        saved_names = [(addr, name) for addr, name in db.names.get_all()
                       if ea <= int(addr) < ea + size]
        ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES,
                            max(size, int(ida_bytes.get_item_size(ea) or 1)))
        created = bool(ida_bytes.create_data(ea, ida_bytes.FF_BYTE, size, ida_idaapi.BADADDR))
        ok = created and bool(db.types.apply_at(tif, ea, TypeApplyFlags.DEFINITE))
        for address, name in saved_names:
            db.names.set_name(int(address), name)
        if ok and item.get("name"): ok = bool(db.names.set_name(ea, str(item["name"])))
        rows.append({"addr": hex(ea), "ok": ok, "size": size,
                     **({} if ok else {"error": "IDA rejected the data type"})})
    except Exception as exc:
        rows.append({"addr": hex(ea), "ok": False, "error": str(exc)})
result = {"result": rows}
result
''',
    "make_string": r'''
from ida_domain.strings import StringType
ea, length = int(str(a["addr"]), 16), max(0, int(a.get("length", 0)))
kind = {"c": StringType.C, "c16": StringType.C_16, "c32": StringType.C_32,
        "pascal": StringType.PASCAL}.get(str(a.get("kind", "c")).lower(), StringType.C)
import ida_bytes
try:
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, length if length > 0 else 1)
except Exception:
    pass
try:
    ok = bool(db.bytes.create_string_at(ea, length or None, kind))
    text = db.bytes.get_string_at(ea) or "" if ok else ""
    result = {"addr": hex(ea), "ok": ok, "size": int(db.heads.size(ea)) if ok else 0, "text": text}
except Exception as exc:
    result = {"addr": hex(ea), "ok": False, "error": str(exc)}
result
''',
    "list_strings": r'''
from ida_domain.strings import StringListConfig
offset, count, min_len = max(0, int(a.get("offset", 0))), max(1, int(a.get("count", 2000))), max(1, int(a.get("min_len", 4)))
if offset == 0 or a.get("refresh"):
    from ida_domain.strings import StringType
    db.strings.rebuild(StringListConfig(string_types=list(StringType), min_len=min_len,
                                        only_ascii_7bit=False))
items = list(db.strings.get_all())
page = items[offset:offset + count]
rows = []
for item in page:
    try: text = str(item)
    except Exception: text = item.contents.decode("utf-8", "replace") if item.contents else ""
    rows.append({"addr": hex(int(item.address)), "text": text, "len": int(item.length), "type": item.type.name})
result = {"strings": rows, "total": len(items), "next_offset": offset + len(rows)}
result
''',
    "list_linkage": r'''
imports = [{"addr": hex(int(item.address)), "name": item.name, "module": item.module_name}
           for item in db.imports.get_all_imports() if item.name]
exports = [{"addr": hex(int(item.address)), "name": item.name, "ordinal": int(item.ordinal)}
           for item in db.entries.get_all() if item.name]
result = {"imports": imports, "exports": exports,
          "n_imports": len(imports), "n_exports": len(exports)}
result
''',
    "lookup_funcs": r'''
rows = []
for query in a.get("queries", []):
    raw = str(query)
    try: ea = int(raw, 16)
    except ValueError:
        fn = db.functions.get_by_name(raw); ea = int(fn.start_ea) if fn else None
    else: fn = db.functions.get_at(ea)
    if fn is None:
        rows.append({"query": raw, "fn": None})
    else:
        rows.append({"query": raw, "fn": {"addr": hex(int(fn.start_ea)),
                     "name": db.functions.get_name(fn) or f"sub_{int(fn.start_ea):X}",
                     "size": int(fn.end_ea) - int(fn.start_ea)}})
result = {"result": rows}
result
''',
    "resolve_names": r'''
import ida_idaapi, ida_name
rows = []
for query in a.get("queries", []):
    name = str(query).strip(); ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    rows.append({"query": name, "ea": hex(int(ea)) if ea != ida_idaapi.BADADDR else None})
result = {"result": rows}
result
''',
    # Ours: the coarse code/data type plus a fine `kind` (call/jump/flow,
    # read/write/offset/text/info) that the xref dialog draws its badges from.
    # Deliberately NOT sorted -- the dialog lists xrefs in IDA's own order.
    "xref_types": r'''
import idaapi, idautils, ida_bytes, ida_funcs, ida_xref
code_kind = {ida_xref.fl_CF: "call", ida_xref.fl_CN: "call", ida_xref.fl_JF: "jump",
             ida_xref.fl_JN: "jump", ida_xref.fl_F: "flow"}
data_kind = {ida_xref.dr_O: "offset", ida_xref.dr_W: "write", ida_xref.dr_R: "read",
             ida_xref.dr_T: "text", ida_xref.dr_I: "info"}
def _kind(xr):
    return (code_kind if xr.iscode else data_kind).get(xr.type, "code" if xr.iscode else "data")
def _fn(ea):
    f = ida_funcs.get_func(ea)
    return {"addr": hex(int(f.start_ea)), "name": ida_funcs.get_func_name(f.start_ea) or ""} if f else None
queries = a.get("queries") or []
all_results = []
for query in queries:
    query = query if isinstance(query, dict) else {"addr": query}
    raw = str(query.get("addr", "")).strip()
    direction = str(query.get("direction", "to") or "to").lower()
    include_fn = bool(query.get("include_fn", True))
    dedup = bool(query.get("dedup", True))
    try: count = int(query.get("count", 2000) or 2000)
    except (TypeError, ValueError): count = 2000
    try: target = int(raw, 16)
    except ValueError: target = idaapi.get_name_ea(idaapi.BADADDR, raw)
    rows = []
    if target is not None and target != idaapi.BADADDR and ida_bytes.is_mapped(target):
        if direction in ("to", "both"):
            for xr in idautils.XrefsTo(target, 0):
                row = {"direction": "to", "addr": hex(int(xr.frm)), "from": hex(int(xr.frm)),
                       "to": hex(int(target)), "type": "code" if xr.iscode else "data", "kind": _kind(xr)}
                if include_fn: row["fn"] = _fn(xr.frm)
                rows.append(row)
        if direction in ("from", "both"):
            for xr in idautils.XrefsFrom(target, 0):
                row = {"direction": "from", "addr": hex(int(xr.to)), "from": hex(int(target)),
                       "to": hex(int(xr.to)), "type": "code" if xr.iscode else "data", "kind": _kind(xr)}
                if include_fn: row["fn"] = _fn(xr.to)
                rows.append(row)
        if dedup:
            seen, deduped = set(), []
            for r in rows:
                k = (r["direction"], r["from"], r["to"], r["kind"])
                if k in seen: continue
                seen.add(k); deduped.append(r)
            rows = deduped
        rows = rows[:count]
    all_results.append({"query": raw, "data": rows, "next_offset": None})
result = {"result": all_results}
result
''',
    # Mirrors the tool ida-tui was written against, ORDER INCLUDED. The rows are
    # sorted by the far-end address and deduped by default, and the pseudocode
    # follow's address fallback silently depends on it: at a call site the raw
    # IDA order yields the ordinary-flow xref (the next instruction) first, so an
    # unsorted result makes "follow the call" land on the following line instead.
    "xref_query": r'''
import idaapi, idautils, ida_bytes, ida_funcs
def _fn(ea):
    f = ida_funcs.get_func(ea)
    return {"addr": hex(int(f.start_ea)), "name": ida_funcs.get_func_name(f.start_ea) or ""} if f else None
queries = a.get("queries") or []
all_results = []
for query in queries:
    raw = str(query.get("addr", "")).strip()
    direction = str(query.get("direction", "both") or "both").lower()
    if direction not in ("to", "from", "both"): direction = "both"
    xref_type = str(query.get("xref_type", "any") or "any").lower()
    if xref_type not in ("any", "code", "data"): xref_type = "any"
    include_fn = bool(query.get("include_fn", True))
    dedup = bool(query.get("dedup", True))
    sort_by = str(query.get("sort_by", "addr") or "addr")
    descending = bool(query.get("descending", False))
    try: offset = max(0, int(query.get("offset", 0) or 0))
    except (TypeError, ValueError): offset = 0
    try: count = max(0, min(int(query.get("count", 200) or 200), 5000))
    except (TypeError, ValueError): count = 200
    try:
        try: target = int(raw, 16)
        except ValueError:
            target = idaapi.get_name_ea(idaapi.BADADDR, raw)
            if target == idaapi.BADADDR: raise ValueError(f"Failed to resolve address/name: {raw}")
        if not ida_bytes.is_mapped(target): raise ValueError(f"Address not mapped: {raw}")
        rows = []
        if direction in ("to", "both"):
            for xr in idautils.XrefsTo(target, 0):
                kind = "code" if xr.iscode else "data"
                if xref_type != "any" and kind != xref_type: continue
                row = {"direction": "to", "addr": hex(int(xr.frm)), "from": hex(int(xr.frm)),
                       "to": hex(int(target)), "type": kind}
                if include_fn: row["fn"] = _fn(xr.frm)
                rows.append(row)
        if direction in ("from", "both"):
            for xr in idautils.XrefsFrom(target, 0):
                kind = "code" if xr.iscode else "data"
                if xref_type != "any" and kind != xref_type: continue
                row = {"direction": "from", "addr": hex(int(xr.to)), "from": hex(int(target)),
                       "to": hex(int(xr.to)), "type": kind}
                if include_fn: row["fn"] = _fn(xr.to)
                rows.append(row)
        if dedup:
            seen, deduped = set(), []
            for row in rows:
                key = (row["direction"], row["from"], row["to"], row["type"])
                if key in seen: continue
                seen.add(key); deduped.append(row)
            rows = deduped
        if sort_by == "type":
            rows.sort(key=lambda r: (str(r.get("type", "")), int(str(r["addr"]), 16)), reverse=descending)
        else:
            rows.sort(key=lambda r: int(str(r["addr"]), 16), reverse=descending)
        page = rows[offset:offset + count] if count else rows[offset:]
        nxt = offset + len(page)
        all_results.append({"target": raw, "resolved_addr": hex(int(target)), "direction": direction,
                            "xref_type": xref_type, "data": page,
                            "next_offset": nxt if nxt < len(rows) else None,
                            "total": len(rows), "error": None})
    except Exception as exc:
        all_results.append({"target": raw, "resolved_addr": None, "direction": direction,
                            "xref_type": xref_type, "data": [], "next_offset": None,
                            "total": 0, "error": str(exc)})
result = {"result": all_results}
result
''',
    # A comment must land in BOTH views, and the pseudocode half is not a
    # simple set: db.comments.set_at() alone leaves the pseudocode unchanged.
    # Hex-Rays comments are anchored to a ctree location (treeloc_t), and an
    # anchor the ctree does not actually own is dropped as an "orphan" -- so the
    # itp slot has to be searched until one sticks, exactly as IDA's own UI does.
    # Without it a comment silently never appears in the decompilation.
    "set_comments": r'''
import idaapi, idc, ida_hexrays
rows = []
for item in a.get("items", []):
    addr_s = str(item.get("addr", ""))
    text = str(item.get("comment") or "")
    try:
        ea = int(addr_s, 16)
        if not idaapi.set_cmt(ea, text, False):
            rows.append({"addr": addr_s,
                         "error": f"Failed to set disassembly comment at {hex(ea)}"})
            continue
        if not ida_hexrays.init_hexrays_plugin():
            rows.append({"addr": addr_s}); continue
        try:
            cfunc = ida_hexrays.decompile(ea)
        except Exception:
            cfunc = None
        if cfunc is None:
            rows.append({"addr": addr_s}); continue
        if ea == cfunc.entry_ea:
            # The signature line carries no ctree item: it is a function comment.
            idc.set_func_cmt(ea, text, True)
            cfunc.refresh_func_ctext()
            rows.append({"addr": addr_s}); continue
        eamap = cfunc.get_eamap()
        if ea not in eamap:
            rows.append({"addr": addr_s,
                         "error": f"Failed to set decompiler comment at {hex(ea)}"})
            continue
        nearest_ea = eamap[ea][0].ea
        if cfunc.has_orphan_cmts():
            cfunc.del_orphan_cmts(); cfunc.save_user_cmts()
        tl = idaapi.treeloc_t(); tl.ea = nearest_ea
        placed = False
        for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, text)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            if not cfunc.has_orphan_cmts():
                placed = True; break
            cfunc.del_orphan_cmts(); cfunc.save_user_cmts()
        rows.append({"addr": addr_s} if placed else
                    {"addr": addr_s,
                     "error": f"Failed to set decompiler comment at {hex(ea)}"})
    except Exception as exc:
        rows.append({"addr": addr_s, "error": str(exc)})
result = {"result": rows}
result
''',
    # Every category takes EITHER one edit or a LIST of them, and the answer is
    # one row per edit. The port accepted only a single dict, so any batch path
    # (rpc rename_many applying a whole symbol file, which is the entire point of
    # that verb) died with "list indices must be integers or slices, not str" and
    # reported the failure against addr=null. Mirrors the real tool: conflict
    # detection before the write, dry_run/allow_overwrite/stop_on_error, per-row
    # addr/old/name, and a summary counting EDITS rather than categories.
    "rename": r'''
import idaapi, ida_hexrays, ida_name
batch = a.get("batch") or {}
dry_run = bool(batch.get("dry_run", False))
allow_overwrite = bool(batch.get("allow_overwrite", False))
stop_on_error = bool(batch.get("stop_on_error", False))

def _items(value):
    if value is None: return []
    if isinstance(value, dict): return [value]
    if isinstance(value, list): return [i for i in value if isinstance(i, dict)]
    return []

def _set_name_checked(ea, new):
    conflict = idaapi.get_name_ea(idaapi.BADADDR, new)
    if conflict != idaapi.BADADDR and conflict != ea and not allow_overwrite:
        return False, f"can't rename at {hex(ea)} as {new!r}: name already used at {hex(conflict)}"
    if dry_run:
        return True, None
    flags = idaapi.SN_CHECK
    if allow_overwrite: flags |= int(getattr(idaapi, "SN_FORCE", 0))
    if not idaapi.set_name(ea, new, flags):
        return False, (f"Rename failed at {hex(ea)}: IDA rejected name {new!r} "
                       "(invalid identifier or internal conflict)")
    return True, None

def _refresh_ctext(fn_addr):
    # A renamed function must invalidate Hex-Rays' cache, which is per function
    # and persisted in the .i64: without this the pseudocode keeps calling the
    # old name forever while every other readback reports the new one.
    if not ida_hexrays.init_hexrays_plugin(): return
    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_func(fn_addr, failure, ida_hexrays.DECOMP_WARNINGS)
    if cfunc: cfunc.refresh_func_ctext()

out = {}; ok_count = failed = 0; halted = False
for category in ("func", "data", "local", "stack"):
    if category not in batch: continue
    rows = []
    for edit in _items(batch.get(category)):
        try:
            if category == "func":
                addr_text = edit.get("addr") or edit.get("func_addr") or edit.get("func")
                new = edit.get("name") or edit.get("new") or edit.get("new_name")
                if not addr_text or not new:
                    row = {"addr": addr_text, "name": new,
                           "error": "Function rename requires addr + name"}
                else:
                    ea = int(str(addr_text), 16)
                    fn = idaapi.get_func(ea)
                    if fn is None:
                        row = {"addr": addr_text, "name": new, "error": "Function not found"}
                    else:
                        old = idaapi.get_name(fn.start_ea) or None
                        ok, err = _set_name_checked(fn.start_ea, str(new))
                        row = {"addr": addr_text, "old": old, "name": str(new)}
                        if err: row["error"] = err
                        if dry_run: row["dry_run"] = True
                        if ok and not dry_run: _refresh_ctext(fn.start_ea)
            elif category == "data":
                addr_text = edit.get("addr")
                old = edit.get("old") or edit.get("old_name")
                new = edit.get("new") or edit.get("new_name") or edit.get("name")
                if not new and new != "":
                    row = {"old": old, "new": None,
                           "error": "Global rename requires target and new name"}
                else:
                    if addr_text is not None:
                        ea = int(str(addr_text), 16)
                        old = old or (idaapi.get_name(ea) or None)
                    else:
                        ea = idaapi.get_name_ea(idaapi.BADADDR, str(old or ""))
                    if ea == idaapi.BADADDR:
                        row = {"old": old, "new": str(new), "error": f"Global {old!r} not found"}
                    else:
                        # An empty new name CLEARS the label; that is a real
                        # request (tests revert with it), not a missing argument.
                        if str(new) == "":
                            ok = bool(ida_name.set_name(ea, "", idaapi.SN_CHECK))
                            err = None if ok else f"Failed to clear the name at {hex(ea)}"
                        else:
                            ok, err = _set_name_checked(ea, str(new))
                        row = {"addr": hex(ea), "old": old, "new": str(new)}
                        if err: row["error"] = err
                        if dry_run: row["dry_run"] = True
            else:
                fa, old, new = edit.get("func_addr"), edit.get("old"), edit.get("new")
                if not fa or not old or not new:
                    row = {"old": old, "new": new,
                           "error": f"{category} rename requires func_addr + old + new"}
                else:
                    ea = int(str(fa), 16)
                    pseudo = db.pseudocode.decompile(ea)
                    var = pseudo.find_local_variable(str(old))
                    if var is None:
                        row = {"func_addr": fa, "old": old, "new": new,
                               "error": f"no local {old!r} in that function"}
                    elif dry_run:
                        row = {"func_addr": fa, "old": old, "new": new, "dry_run": True}
                    else:
                        var.set_user_name(str(new))
                        ok = bool(pseudo.save_local_variable_info(var, save_name=True))
                        row = {"func_addr": fa, "old": old, "new": new}
                        if not ok: row["error"] = "IDA rejected the local variable name"
        except Exception as exc:
            row = {"addr": edit.get("addr"), "error": str(exc)}
        rows.append(row)
        if row.get("error"): failed += 1
        else: ok_count += 1
        if row.get("error") and stop_on_error:
            halted = True; break
    out[category] = rows
    if halted: break
out["summary"] = {"ok": ok_count, "failed": failed}
if dry_run: out["summary"]["dry_run"] = True
if halted: out["summary"]["halted"] = True
result = out
result
''',
}


_OPERATIONS["define_code_run"] = r'''
import ida_bytes, ida_idp, ida_segment, ida_ua, idaapi
ea, limit = int(str(a["addr"]), 16), max(1, min(int(a.get("limit", 20000)), 200000))
seg = ida_segment.getseg(ea)
if seg is None:
    result = {"addr": a["addr"], "error": "no segment", "count": 0}
else:
    start, count, stopped, hi = ea, 0, "limit", int(seg.end_ea)
    while count < limit:
        if ea >= hi: stopped = "segment"; break
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_data(flags): stopped = "defined"; break
        size = int(ida_ua.create_insn(ea))
        if size <= 0: stopped = "undecodable"; break
        count += 1
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) > 0:
            try: is_ret = bool(ida_idp.is_ret_insn(insn))
            except Exception: is_ret = False
            if is_ret or (insn.get_canon_feature() & idaapi.CF_STOP):
                ea += size; stopped = "flow"; break
        ea += size
    result = {"start": hex(start), "end": hex(ea), "count": count, "stopped": stopped}
result
'''


_OPERATIONS["define_func_run"] = r'''
import ida_bytes, ida_funcs, ida_segment
ea = int(str(a["addr"]), 16)
fn = db.functions.get_at(ea)
if fn is not None and int(fn.start_ea) == ea:
    result = {"addr": hex(ea), "ok": True, "start": hex(ea), "end": hex(int(fn.end_ea)), "how": "existed"}
else:
    automatic = bool(db.functions.create(ea))
    if not automatic:
        seg = db.segments.get_at(ea); end = ea; hi = int(seg.end_ea) if seg else ea
        while end < hi and ida_bytes.is_code(ida_bytes.get_flags(end)):
            nxt = int(ida_bytes.get_item_end(end))
            if nxt <= end: break
            end = nxt
        ok = bool(end > ea and ida_funcs.add_func(ea, end))
    else: ok = True
    fn = db.functions.get_at(ea)
    result = ({"addr": hex(ea), "ok": True, "start": hex(int(fn.start_ea)),
               "end": hex(int(fn.end_ea)), "how": "auto" if automatic else "explicit-end"}
              if ok and fn is not None else
              {"addr": hex(ea), "ok": False, "error": f"IDA refused a function at {ea:#x}"})
result
'''


_OPERATIONS["set_thumb"] = r'''
import ida_bytes, ida_ida, ida_idp, ida_segment, ida_segregs
ea = int(str(a["addr"]), 16); treg = ida_idp.str2reg("T")
seg = ida_segment.getseg(ea)
if treg is None or treg < 0:
    result = {"addr": hex(ea), "error": "no T register (not an ARM database)"}
elif seg is None:
    result = {"addr": hex(ea), "error": "no segment"}
else:
    current = ida_segregs.get_sreg(ea, treg)
    current = 0 if current in (None, 0xFFFFFFFF, -1) else int(current)
    want = {"on": 1, "off": 0}.get(str(a.get("mode", "toggle")).lower(), 0 if current else 1)
    changed = False
    if want and seg.bitness != 1:
        ida_segment.set_segm_addressing(seg, 1); changed = True
    size = max(int(ida_bytes.get_item_size(ea)), 2)
    ida_bytes.del_items(ea, 0, size)
    ok = bool(ida_segregs.split_sreg_range(ea, treg, want, ida_segregs.SR_user))
    now = ida_segregs.get_sreg(ea, treg)
    result = {"addr": hex(ea), "thumb": bool(now), "was": bool(current), "ok": ok,
              "bitness": ida_segment.getseg(ea).bitness, "forced_32bit": changed,
              "db_64bit": bool(ida_ida.inf_get_app_bitness() == 64 and want)}
result
'''


_OPERATIONS["thumb_scan"] = r'''
import ida_bytes, ida_funcs, ida_idp, ida_segment, ida_segregs, ida_ua
lo, hi = int(str(a["start"]), 16), int(str(a["end"]), 16)
apply, limit = bool(a.get("apply", True)), int(a.get("limit", 512))
treg = ida_idp.str2reg("T"); found = []; applied = 0; cursor = lo
while cursor + 4 <= hi and len(found) < limit:
    at = cursor; value = int(ida_bytes.get_dword(cursor)); cursor += 4
    if not value & 1: continue
    target = value & ~1; seg = ida_segment.getseg(target)
    if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC or seg.perm == 0): continue
    flags = ida_bytes.get_flags(target)
    if ida_bytes.is_data(flags): continue
    item = {"at": hex(at), "value": hex(value), "target": hex(target),
            "was_code": bool(ida_bytes.is_code(flags))}; found.append(item)
    if not apply: continue
    if treg is not None and treg >= 0: ida_segregs.split_sreg_range(target, treg, 1, ida_segregs.SR_user)
    if not ida_bytes.is_code(ida_bytes.get_flags(target)):
        ida_bytes.del_items(target, 0, 2)
        if ida_ua.create_insn(target) <= 0: item["decoded"] = False; continue
    item["decoded"] = True; item["function"] = bool(db.functions.get_at(target) or db.functions.create(target)); applied += 1
result = {"start": hex(lo), "end": hex(hi), "found": found, "applied": applied, "n": len(found)}
result
'''


_OPERATIONS["decomp_error"] = r'''
import ida_hexrays, ida_ida
ea = int(str(a["addr"]), 16); fn = db.functions.get_at(ea)
result = {"addr": hex(ea), "bitness": ida_ida.inf_get_app_bitness()}
if fn is None:
    result["reason"] = "no function here"
else:
    try:
        failure = ida_hexrays.hexrays_failure_t(); cfunc = ida_hexrays.decompile_func(fn, failure)
        if cfunc is not None: result["reason"] = ""
        else:
            result.update({"reason": failure.desc() or f"error {failure.code}",
                           "code": int(failure.code), "errea": hex(int(failure.errea))})
    except Exception as exc: result["reason"] = f"{type(exc).__name__}: {exc}"
result
'''

# `heads` and the operand-format tools are the port's IDAPython island: the
# continuous listing's presentation model (undefined runs, colour spans, operand
# extents, banners, struct members, the digest protocol) and IDA/Hex-Rays number
# formats have no ida-domain surface. Rather than paraphrase ~1100 lines of
# performance-tuned, behaviour-sensitive code into string literals, they stay
# real, diffable source in idatui/remote_tools.py and are shipped to the database
# process as text. Read once at import; the file ships beside this module.
_REMOTE_LIB = (Path(__file__).with_name("remote_tools.py")).read_text(encoding="utf-8")

#: Versioned by content, so editing remote_tools.py re-installs it instead of
#: silently running the copy a long-lived worker already has.
_REMOTE_MODULE = "_idatui_remote_" + hashlib.sha1(
    _REMOTE_LIB.encode("utf-8")).hexdigest()[:12]

#: Sent back when the database process has not got the library yet; the client
#: installs it and retries once. Amortised, a worker receives it exactly once.
_NEED_LIB = "__idatui_needs_remote_lib__"

#: Installs the library as a real module in the database process. Persisting it
#: in sys.modules is what makes the module-level caches (the tag maps, and the
#: line-render lru_cache the listing's throughput depends on) survive between
#: calls -- execute_python builds a fresh namespace every time, so a library
#: exec'd inline is rebuilt, and its caches thrown away, on every single call.
_INSTALL_LIB = f'''
import sys, types
_m = types.ModuleType({_REMOTE_MODULE!r})
exec(compile(a["source"], {_REMOTE_MODULE!r}, "exec"), _m.__dict__)
sys.modules[{_REMOTE_MODULE!r}] = _m
result = True
result
'''


def _remote_op(call: str) -> str:
    """A snippet that calls one of the carried-over tools by its real signature.

    Costs one short request: the library is imported from the database process's
    own sys.modules, not shipped again.
    """
    return (f"import sys\n"
            f"_m = sys.modules.get({_REMOTE_MODULE!r})\n"
            f"result = {{{_NEED_LIB!r}: True}} if _m is None else _m.{call}\n"
            f"result\n")


_OPERATIONS["op_format"] = _remote_op(
    'op_format(addr=a["addr"], mode=a.get("mode", "cycle"),'
    ' col=int(a.get("col", -1)), n=int(a.get("n", -1)))')
_OPERATIONS["pc_nums"] = _remote_op('pc_nums(addr=a["addr"])')
_OPERATIONS["decompile"] = _remote_op(
    'decompile(addr=a["addr"],'
    ' include_addresses=bool(a.get("include_addresses", True)))')
_OPERATIONS["decomp_map"] = _remote_op('decomp_map(addr=a["addr"])')
_OPERATIONS["pc_num_format"] = _remote_op(
    'pc_num_format(addr=a["addr"], mode=a.get("mode", "cycle"),'
    ' line=int(a.get("line", -1)), col=int(a.get("col", -1)),'
    ' ea=a.get("ea", ""), opnum=int(a.get("opnum", -1)))')

# The listing walker itself. Replaces the port's re-implementation, which
# rendered no per-operand extents (so no keypress could say which literal it
# would reformat) and had no digest/expect support (so every page was re-sent
# after any edit), and whose span walk was the per-character loop our own
# version had already been rewritten to avoid.
_HEADS = _remote_op(
    'heads(addr=a["addr"], count=int(a.get("count", 200)),'
    ' offset=int(a.get("offset", 0)), end=a.get("end", ""),'
    ' back=bool(a.get("back", False)), annotate=bool(a.get("annotate", False)),'
    ' expect=a.get("expect", ""))')


# The graph view's only backend call. Blocks are address RANGES, never text:
# the client re-renders them with `heads`, so boxes reuse the exact listing rows
# (colours, operand marks, trail painting) instead of growing a second renderer.
#
# ida-domain exposes no basic-block/edge-kind surface, so this stays on ida_gdl.
_OPERATIONS["flowchart"] = r'''
import ida_funcs, ida_gdl
ea = int(str(a["addr"]), 16)
fn = ida_funcs.get_func(ea)
if fn is None:
    result = {"addr": hex(ea), "error": "no function at that address", "blocks": []}
else:
    fc = ida_gdl.FlowChart(fn, flags=ida_gdl.FC_PREDS)
    index, order = {}, []
    for bb in fc:
        index[bb.start_ea] = len(order)
        order.append(bb)
    blocks = []
    for bb in order:
        sl = [s for s in bb.succs() if s.start_ea in index]
        succs = []
        for s in sl:
            # Edge kind is what the graph view colours by: an n-way dispatch is
            # "switch", a successor that is literally the next address falls
            # through, anything else is a taken branch.
            if len(sl) > 2: kind = "switch"
            elif s.start_ea == bb.end_ea: kind = "fall"
            else: kind = "jump"
            succs.append([index[s.start_ea], kind])
        blocks.append({"id": index[bb.start_ea], "start": hex(int(bb.start_ea)),
                       "end": hex(int(bb.end_ea)), "succs": succs})
    result = {"addr": hex(ea),
              "func": {"addr": hex(int(fn.start_ea)), "end": hex(int(fn.end_ea)),
                       "name": ida_funcs.get_func_name(fn.start_ea) or ""},
              "entry": index.get(fn.start_ea, 0), "blocks": blocks}
result
'''

# Only ever reached as domain.py's fallback when file_regions yields nothing.
_OPERATIONS["survey_binary"] = r'''
segments = []
for seg in db.segments.get_all():
    segments.append({"start": hex(int(seg.start_ea)), "end": hex(int(seg.end_ea)),
                     "name": db.segments.get_name(seg) or ""})
result = {"segments": segments}
result
'''


class CodeModeClient:
    """A leased GUI/idalib database accessed through ``ida_codemode``."""

    def __init__(
        self,
        binary_path: str,
        *,
        ttl: int = 0,
        load_args: str = "",
        processor: str | None = None,
        loading_address: int | None = None,
        file_type: str | None = None,
        output_database: str | None = None,
        spawn: bool = True,
        new_database: bool = False,
    ) -> None:
        del ttl  # managed-worker lifetime is lease-based, not idle-TTL based
        self._path = os.path.abspath(os.path.expanduser(binary_path))
        parsed_processor, parsed_address, parsed_file_type = _parse_load_args(load_args)
        self._processor = processor or parsed_processor
        self._loading_address = loading_address if loading_address is not None else parsed_address
        self._file_type = file_type or parsed_file_type
        self._output_database = output_database
        self._spawn = spawn
        self._new_database = new_database
        self._handle: DatabaseHandle | None = None
        self._last_entry: RegistryEntry | None = None
        self._connect_lock = threading.Lock()

    def connect(self, timeout: float = 1800.0, progress=None) -> "CodeModeClient":
        _require_codemode()
        with self._connect_lock:
            if self._handle is not None and self._handle.connected:
                return self
            if progress:
                progress(f"discovering Code Mode database for {os.path.basename(self._path)}…")
            try:
                # A Ctrl+L reload releases its current managed-worker lease, but
                # that worker remains registered during Code Mode's final-lease
                # grace period. Retry only that known handoff window. A GUI or
                # another long-lived client remains busy and yields a clear
                # failure rather than being modified underneath its owner.
                deadline = time.monotonic() + min(timeout, 60.0)
                while True:
                    try:
                        handle = DatabaseHandle.open(
                            self._path,
                            spawn=self._spawn,
                            timeout=max(0.1, timeout),
                            output_database=self._output_database,
                            processor=self._processor,
                            # DatabaseHandle calls this image_base and wants the
                            # natural (16-byte aligned) address; it does the
                            # conversion to IDA's paragraph-based -b itself.
                            image_base=self._loading_address,
                            file_type=self._file_type,
                            new_database=self._new_database,
                        )
                        break
                    except IdbBusy:
                        if not self._new_database or time.monotonic() >= deadline:
                            raise
                        if progress:
                            progress("waiting for the previous Code Mode lease to close…")
                        # Remember the record before managed shutdown withdraws
                        # its JSON. The lifetime lock remains held until IDA has
                        # actually closed the IDB; waiting on it avoids racing a
                        # replacement worker into the old process's file lock.
                        expected = canonical_path(
                            self._output_database or expected_idb_path(self._path)
                        )
                        owners = [item.entry for item in scan_instances(timeout=0.5)
                                  if item.entry.idb_key == idb_key(expected)]
                        if owners:
                            self._wait_for_entry_release(
                                owners[0], max(0.0, deadline - time.monotonic())
                            )
                        else:
                            time.sleep(0.2)
                if progress:
                    backend = handle.entry.backend
                    progress(f"attached to {backend} database; waiting for auto-analysis…")
                handle.wait_autoanalysis(timeout=timeout)
            except Exception as exc:  # normalize the dependency's transport errors
                raise self._connection_error(exc) from exc
            self._handle = handle
            self._last_entry = handle.entry
            return self

    @staticmethod
    def _connection_error(exc: BaseException) -> IDAConnectionError:
        return IDAConnectionError(str(exc) or type(exc).__name__)

    @property
    def connected(self) -> bool:
        return self._handle is not None and self._handle.connected

    @property
    def pid(self) -> int | None:
        return self._handle.entry.pid if self._handle is not None else None

    @property
    def backend(self) -> str | None:
        return self._handle.entry.backend if self._handle is not None else None

    def execute_python(self, code: str, *, timeout: float | None = None) -> Any:
        if not self.connected:
            self.connect()
        handle = self._handle
        if handle is None:
            raise IDAConnectionError("Code Mode database is not connected")
        try:
            response = handle.execute_python(code, timeout=timeout)
        except RemoteError as exc:
            details = exc.details or {}
            message = str(exc)
            if details.get("traceback"):
                message += f"\n{details['traceback']}"
            if exc.code == "operation_timeout":
                raise IDATimeoutError(message) from exc
            raise IDAToolError("execute_python", message) from exc
        except (InstanceDisconnectedError, ClientError) as exc:
            raise self._connection_error(exc) from exc
        if not isinstance(response, dict) or "result" not in response:
            raise IDAToolError("execute_python", "Code Mode returned an invalid execution result")
        return response["result"]

    def invoke(self, operation: str, *, timeout: float | None = None, **args) -> Any:
        """Execute one TUI domain operation through Code Mode."""
        if operation in ("idb_save", "save"):
            return self.save_database()
        if operation in ("server_health", "ping", "health", "state"):
            return self.health()
        body = _HEADS if operation == "heads" else _OPERATIONS.get(operation)
        if body is None:
            raise IDAToolError(operation, f"unknown ida-tui Code Mode operation: {operation}")
        try:
            answer = self.execute_python(_script(args, body), timeout=timeout)
            if isinstance(answer, dict) and answer.get(_NEED_LIB):
                # First call against this database process (or a restarted one).
                self.execute_python(_script({"source": _REMOTE_LIB}, _INSTALL_LIB),
                                    timeout=timeout)
                answer = self.execute_python(_script(args, body), timeout=timeout)
            return answer
        except IDAToolError as exc:
            if exc.tool == "execute_python":
                raise IDAToolError(operation, exc.message) from exc
            raise

    # Temporary source compatibility for external drivers/tests that used the
    # old WorkerClient. Application code uses the accurately named invoke().
    call = invoke

    def save_database(self) -> dict[str, Any]:
        if not self.connected:
            self.connect()
        handle = self._handle
        if handle is None:
            raise IDAConnectionError("Code Mode database is not connected")
        try:
            return handle.save_database()
        except RemoteError as exc:
            raise IDAToolError("save_database", str(exc)) from exc
        except (InstanceDisconnectedError, ClientError) as exc:
            raise self._connection_error(exc) from exc

    def health(self) -> dict[str, Any]:
        if not self.connected:
            self.connect()
        assert self._handle is not None
        entry = self._handle.entry
        module = os.path.basename(entry.exe_path or entry.idb_path or self._path)
        return {
            "ok": self._handle.connected,
            "module": module,
            "backend": entry.backend,
            "record_id": entry.record_id,
            "input_path": entry.exe_path,
            "idb_path": entry.idb_path,
        }

    def keepalive(self, interval: float = 120.0) -> _NoopKeepAlive:
        del interval
        return _NoopKeepAlive()

    def resolve_db(self) -> str:
        if not self.connected:
            self.connect()
        assert self._handle is not None
        return self._handle.entry.record_id

    def set_db(self, db: str | None) -> None:
        del db  # one handle is permanently bound to one registered database

    def list_sessions(self) -> list[Session]:
        if not self.connected:
            self.connect()
        assert self._handle is not None
        entry = self._handle.entry
        path = entry.exe_path or entry.idb_path or self._path
        return [Session(session_id=entry.record_id, filename=os.path.basename(path),
                        input_path=path, is_active=True)]

    def close(self, grace: float = 0.0) -> None:
        del grace
        with self._connect_lock:
            handle, self._handle = self._handle, None
        if handle is not None:
            self._last_entry = handle.entry
            handle.close()  # release our lease; never close a GUI/other client's DB

    @staticmethod
    def _wait_for_entry_release(entry: "RegistryEntry", timeout: float) -> bool:
        _require_codemode()
        path = REGISTRY_DIR / f"{entry.record_id}.lock"
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            lock = FileLock(path)
            try:
                if lock.try_acquire():
                    return True
            except OSError:
                pass
            finally:
                lock.close()
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.1, deadline - time.monotonic()))

    def wait_released(self, timeout: float = 45.0) -> bool:
        """Wait until a managed instance releases its lifetime lock.

        Normal application shutdown must not wait: another client may retain the
        worker. This is an explicit test/maintenance helper for deleting a
        temporary IDB safely after this client closes. GUI instances return
        ``False`` immediately because clients never own their lifetime.
        """
        entry = self._last_entry
        if entry is None or entry.backend != "idalib":
            return False
        return self._wait_for_entry_release(entry, timeout)

    def __enter__(self) -> "CodeModeClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()
