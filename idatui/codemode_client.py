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

import json
import os
import shlex
import threading
import time
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


# Rich flat-listing generation is the largest ida-domain gap in this port.
# ida-domain can enumerate heads and render plain disassembly, but it does not
# expose undefined runs, IDA colour spans, function banners, or expanded UDT
# members. Keep that IDAPython-only logic isolated in this one operation.
_HEADS = r'''
import ida_bytes, ida_funcs, ida_idaapi, ida_lines, ida_name, ida_nalt, ida_segment, ida_typeinf
start = int(str(a["addr"]), 16)
count = max(1, min(int(a.get("count", 200)), 2000))
offset = max(0, int(a.get("offset", 0)))
annotate = bool(a.get("annotate", False))
seg = db.segments.get_at(start)
if seg is None:
    result = {"addr": a["addr"], "error": "no segment", "heads": [], "cursor": {"done": True}}
else:
    lo, hi = int(seg.start_ea), int(seg.end_ea)
    if a.get("end"):
        hi = min(hi, int(str(a["end"]), 16))

    span_names = {
        "insn": ("SCOLOR_INSN", "SCOLOR_KEYWORD", "SCOLOR_ASMDIR", "SCOLOR_MACRO"),
        "reg": ("SCOLOR_REG",),
        "num": ("SCOLOR_NUMBER", "SCOLOR_CHAR", "SCOLOR_BINPREF"),
        "str": ("SCOLOR_STRING",),
        "name": ("SCOLOR_DATNAME", "SCOLOR_CODNAME", "SCOLOR_LOCNAME", "SCOLOR_IMPNAME",
                 "SCOLOR_DEMNAME", "SCOLOR_LIBNAME", "SCOLOR_CNAME", "SCOLOR_DNAME",
                 "SCOLOR_CREF", "SCOLOR_DREF", "SCOLOR_CREFTAIL", "SCOLOR_DREFTAIL"),
        "seg": ("SCOLOR_SEGNAME",),
        "cmt": ("SCOLOR_AUTOCMT", "SCOLOR_REGCMT", "SCOLOR_RPTCMT", "SCOLOR_VOIDOP"),
        "punct": ("SCOLOR_SYMBOL", "SCOLOR_ALTOP", "SCOLOR_HIDNAME"),
        "err": ("SCOLOR_ERROR",),
    }
    tag_kinds = {}
    for kind, names in span_names.items():
        for name in names:
            value = getattr(ida_lines, name, None)
            if isinstance(value, str) and value:
                tag_kinds[value[0]] = kind
            elif isinstance(value, int):
                tag_kinds[chr(value)] = kind

    def spans(tagged):
        on, off, esc = "\x01", "\x02", "\x03"
        addr_tag = chr(getattr(ida_lines, "COLOR_ADDR", 0x28))
        addr_len = int(getattr(ida_lines, "COLOR_ADDR_SIZE", 16))
        out, stack, buf = [], [], []
        def flush():
            if buf:
                out.append([stack[-1] if stack else "text", "".join(buf)])
                buf.clear()
        i = 0
        while i < len(tagged):
            ch = tagged[i]
            if ch == on and i + 1 < len(tagged):
                tag = tagged[i + 1]
                if tag == addr_tag:
                    i += 2 + addr_len
                    continue
                flush(); stack.append(tag_kinds.get(tag, "text")); i += 2; continue
            if ch == off and i + 1 < len(tagged):
                flush()
                if stack: stack.pop()
                i += 2; continue
            if ch == esc and i + 1 < len(tagged):
                buf.append(tagged[i + 1]); i += 2; continue
            buf.append(ch); i += 1
        flush()
        collapsed, previous_space = [], False
        for kind, text in out:
            acc = []
            for ch in text:
                if ch.isspace():
                    if previous_space: continue
                    acc.append(" "); previous_space = True
                else:
                    acc.append(ch); previous_space = False
            if acc: collapsed.append([kind, "".join(acc)])
        if collapsed:
            collapsed[0][1] = collapsed[0][1].lstrip()
            collapsed[-1][1] = collapsed[-1][1].rstrip()
        return [[kind, text] for kind, text in collapsed if text]

    def row(ea):
        flags = ida_bytes.get_flags(ea)
        kind = "code" if ida_bytes.is_code(flags) else ("data" if ida_bytes.is_data(flags) else "unknown")
        tagged = ida_lines.generate_disasm_line(ea, 0) or ""
        text = " ".join(ida_lines.tag_remove(tagged).split()) if tagged else ""
        item = {"ea": hex(ea), "kind": kind, "size": int(ida_bytes.get_item_size(ea)), "text": text}
        if tagged:
            rich = spans(tagged)
            if " ".join("".join(x[1] for x in rich).split()) == text:
                item["spans"] = rich
        name = ida_name.get_ea_name(ea)
        if name: item["name"] = name
        return item

    def unknown_row(ea, size):
        if size <= 1: return row(ea)
        item = {"ea": hex(ea), "kind": "unknown", "size": int(size), "text": f"db {size} dup(?)"}
        name = ida_name.get_ea_name(ea)
        if name: item["name"] = name
        return item

    def members(ea):
        tif = db.types.get_at(ea)
        if tif is None or not tif.is_udt(): return []
        answer = []
        for member in db.types.get_udt_members(tif):
            type_text = member.type.dstr() or ""
            text = f"+{member.offset:X} {member.name}" + (f" {type_text}" if type_text else "")
            answer.append({"ea": hex(ea + member.offset), "kind": "member",
                           "size": int(member.size), "text": text})
        return answer

    def is_unknown(ea):
        flags = ida_bytes.get_flags(ea)
        return not (ida_bytes.is_code(flags) or ida_bytes.is_data(flags))
    def run_end(ea):
        nxt = ida_bytes.next_head(ea, hi)
        return nxt if nxt != ida_idaapi.BADADDR and ea < nxt <= hi else hi
    def advance(ea):
        if is_unknown(ea): return run_end(ea)
        nxt = ida_bytes.get_item_end(ea)
        return nxt if nxt > ea else ea + 1
    def rows_for(ea):
        if is_unknown(ea): return [unknown_row(ea, run_end(ea) - ea)]
        fn = db.functions.get_at(ea) if annotate else None
        at_start = fn is not None and int(fn.start_ea) == ea
        answer = []
        if at_start:
            name = db.functions.get_name(fn) or f"sub_{ea:X}"
            answer += [
                {"ea": hex(ea), "kind": "sep", "size": 0, "text": ""},
                {"ea": hex(ea), "kind": "sep", "size": 0,
                 "text": "; " + "=" * 15 + " S U B R O U T I N E " + "=" * 15},
                {"ea": hex(ea), "kind": "funchdr", "size": 0,
                 "text": name + " proc", "name": name},
            ]
        item = row(ea)
        if at_start:
            item["name"] = None
        elif annotate and item["kind"] == "code" and item.get("name"):
            name = item["name"]
            answer.append({"ea": hex(ea), "kind": "label", "size": 0,
                           "text": name + ":", "name": name})
            item["name"] = None
        answer.append(item)
        if item["kind"] == "data": answer += members(ea)
        if fn is not None and ida_bytes.get_item_end(ea) >= int(fn.end_ea):
            name = db.functions.get_name(fn) or f"sub_{int(fn.start_ea):X}"
            answer += [
                {"ea": hex(ea), "kind": "funchdr", "size": 0,
                 "text": name + " endp", "name": name},
                {"ea": hex(ea), "kind": "sep", "size": 0, "text": "; " + "-" * 60},
            ]
        return answer

    ea = ida_bytes.get_item_head(start)
    if ea == ida_idaapi.BADADDR: ea = start
    for _ in range(offset):
        if ea >= hi: break
        ea = advance(ea)
    rows = []
    more = False
    while ea != ida_idaapi.BADADDR and ea < hi:
        if len(rows) >= count:
            more = True; break
        rows += rows_for(ea)
        ea = advance(ea)
    result = {"addr": a["addr"], "heads": rows,
              "cursor": {"next": hex(ea)} if more else {"done": True}}
result
'''


_DECOMP_MAP_HELPER = r'''
def line_map(cfunc):
    import ida_hexrays
    answer = []
    for sl in cfunc.get_pseudocode():
        tagged, eas, seen = sl.line, [], set()
        for x in range(len(tagged) + 1):
            head = ida_hexrays.ctree_item_t(); item = ida_hexrays.ctree_item_t(); tail = ida_hexrays.ctree_item_t()
            if not cfunc.get_line_item(tagged, x, False, head, item, tail): continue
            text = item.dstr() or ""
            try: ea = int(text.split(": ", 1)[0], 16)
            except (ValueError, IndexError): continue
            if ea not in seen: seen.add(ea); eas.append(ea)
        answer.append(eas)
    return answer
'''


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
    "xref_types": r'''
queries = a.get("queries") or []
all_results = []
for query in queries:
    ea, direction = int(str(query["addr"]), 16), str(query.get("direction", "both"))
    refs = []
    if direction in ("to", "both"): refs += list(db.xrefs.to_ea(ea))
    if direction in ("from", "both"): refs += list(db.xrefs.from_ea(ea))
    rows, seen = [], set()
    for ref in refs:
        key = (int(ref.from_ea), int(ref.to_ea), int(ref.type))
        if query.get("dedup") and key in seen: continue
        seen.add(key)
        fn = db.functions.get_at(int(ref.from_ea))
        kind = ("call" if ref.is_call else "jump" if ref.is_jump else "flow" if ref.is_flow
                else "read" if ref.is_read else "write" if ref.is_write else ref.type.name.lower())
        row = {"from": hex(int(ref.from_ea)), "to": hex(int(ref.to_ea)),
               "type": "code" if ref.is_code else "data", "kind": kind}
        if query.get("include_fn") and fn is not None:
            row["fn"] = {"addr": hex(int(fn.start_ea)), "name": db.functions.get_name(fn) or ""}
        rows.append(row)
        if len(rows) >= int(query.get("count", 2000)): break
    all_results.append({"data": rows})
result = {"result": all_results}
result
''',
    "xref_query": r'''
queries = a.get("queries") or []
all_results = []
for query in queries:
    ea, direction = int(str(query["addr"]), 16), str(query.get("direction", "both"))
    refs = []
    if direction in ("to", "both"): refs += list(db.xrefs.to_ea(ea))
    if direction in ("from", "both"): refs += list(db.xrefs.from_ea(ea))
    rows = []
    for ref in refs[:int(query.get("count", 2000))]:
        fn = db.functions.get_at(int(ref.from_ea))
        row = {"from": hex(int(ref.from_ea)), "to": hex(int(ref.to_ea)),
               "type": "code" if ref.is_code else "data"}
        if query.get("include_fn") and fn is not None:
            row["fn"] = {"addr": hex(int(fn.start_ea)), "name": db.functions.get_name(fn) or ""}
        rows.append(row)
    all_results.append({"data": rows})
result = {"result": all_results}
result
''',
    "set_comments": r'''
rows = []
for item in a.get("items", []):
    ea, text = int(str(item["addr"]), 16), str(item.get("comment") or "")
    try:
        if text: ok = bool(db.comments.set_at(ea, text))
        else: db.comments.delete_at(ea); ok = True
        rows.append({"addr": hex(ea), "ok": ok})
    except Exception as exc:
        rows.append({"addr": hex(ea), "ok": False, "error": str(exc)})
result = {"result": rows}
result
''',
    "rename": r'''
import ida_idaapi, ida_name, ida_typeinf
batch = a.get("batch") or {}
out = {}; ok_count = failed = 0
for category, edit in batch.items():
    try:
        if category == "func":
            ea, new = int(str(edit["addr"]), 16), str(edit["name"])
            fn = db.functions.get_at(ea); ok = bool(fn and db.functions.set_name(fn, new))
        elif category == "data":
            new = str(edit.get("new") or "")
            if edit.get("addr") is not None: ea = int(str(edit["addr"]), 16)
            else: ea = int(ida_name.get_name_ea(ida_idaapi.BADADDR, str(edit.get("old") or "")))
            ok = bool(db.names.set_name(ea, new))
        elif category in ("local", "stack"):
            ea, old, new = int(str(edit["func_addr"]), 16), str(edit["old"]), str(edit["new"])
            pseudo = db.pseudocode.decompile(ea); var = pseudo.find_local_variable(old)
            if var is None: ok = False
            else:
                var.set_user_name(new)
                ok = bool(pseudo.save_local_variable_info(var, save_name=True))
        else:
            raise ValueError(f"unsupported rename category: {category}")
        row = {"ok": ok, **({} if ok else {"error": "IDA rejected the name"})}
    except Exception as exc:
        row = {"ok": False, "error": str(exc)}
    out[category] = [row]
    if row["ok"]: ok_count += 1
    else: failed += 1
out["summary"] = {"ok": ok_count, "failed": failed}
result = out
result
''',
}


_OPERATIONS["decompile"] = _DECOMP_MAP_HELPER + r'''
ea = int(str(a["addr"]), 16)
fn = db.functions.get_at(ea)
if fn is None:
    result = {"error": f"no function at {ea:#x}"}
else:
    pseudo = db.pseudocode.decompile(fn)
    mapping = line_map(pseudo.raw_cfunc)
    plain = pseudo.to_text()
    marked = [line + (f" /*0x{eas[0]:X}*/" if eas else "")
              for line, eas in zip(plain, mapping)]
    import ida_name
    refs, seen = [], set()
    for expr in pseudo.find_objects():
        target = int(expr.obj_ea)
        if target in seen or not (db.is_valid_ea(target) or db.is_private_ea(target)): continue
        seen.add(target)
        name = expr.obj_name or ida_name.get_name(target) or ""
        try: string = db.bytes.get_string_at(target) if db.is_valid_ea(target) else None
        except Exception: string = None
        refs.append({"addr": hex(target), "name": name, "string": string})
    result = {"addr": hex(int(fn.start_ea)), "code": "\n".join(marked), "refs": refs}
result
'''

_OPERATIONS["decomp_map"] = _DECOMP_MAP_HELPER + r'''
ea = int(str(a["addr"]), 16)
fn = db.functions.get_at(ea)
if fn is None:
    result = {"error": f"no function at {ea:#x}"}
else:
    pseudo = db.pseudocode.decompile(fn)
    mapping = line_map(pseudo.raw_cfunc)
    result = {"addr": hex(int(fn.start_ea)),
              "lines": [{"ea": hex(eas[0]) if eas else None,
                         "eas": [hex(item) for item in eas]} for eas in mapping]}
result
'''

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
                            loading_address=self._loading_address,
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
            return self.execute_python(_script(args, body), timeout=timeout)
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
