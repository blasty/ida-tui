"""Typed remote operations executed through ida-nexus."""

from __future__ import annotations
# ruff: noqa

import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ida_domain import Database


def operation_label() -> str:
    """Display attribution for the current call; ready for per-user context."""
    return "IDA TUI"


def data_type(db: Database, **a: Any) -> Any:
    ea = int(str(a["addr"]), 16)
    try:
        tif = db.types.get_at(ea)
        fn = db.functions.get_at(ea)
        result = {
            "addr": hex(ea),
            "name": db.names.get_at(ea) or "",
            "type": tif.dstr() if tif else "",
            "size": int(db.heads.size(ea)) if db.heads.is_head(ea) else 0,
            "is_func": bool(fn),
        }
    except Exception as exc:
        result = {"addr": hex(ea), "error": str(exc)}
    return result


def declare_type(db: Database, **a: Any) -> Any:
    import ida_typeinf

    decls = a.get("decls", "")
    if isinstance(decls, str):
        decls = [decls]
    rows = []
    for declaration in decls:
        try:
            errors = int(
                db.types.parse_declarations(ida_typeinf.get_idati(), declaration)
            )
            rows.append(
                {
                    "ok": errors == 0,
                    **({} if errors == 0 else {"error": f"{errors} parse error(s)"}),
                }
            )
        except Exception as exc:
            rows.append({"ok": False, "error": str(exc)})
    result = {"result": rows}
    return result


def decomp_error(db: Database, **a: Any) -> Any:
    import ida_hexrays, ida_ida

    ea = int(str(a["addr"]), 16)
    fn = db.functions.get_at(ea)
    result = {"addr": hex(ea), "bitness": ida_ida.inf_get_app_bitness()}
    if fn is None:
        result["reason"] = "no function here"
    else:
        try:
            failure = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile_func(fn, failure)
            if cfunc is not None:
                result["reason"] = ""
            else:
                result.update(
                    {
                        "reason": failure.desc() or f"error {failure.code}",
                        "code": int(failure.code),
                        "errea": hex(int(failure.errea)),
                    }
                )
        except Exception as exc:
            result["reason"] = f"{type(exc).__name__}: {exc}"
    return result


def define_code(db: Database, **a: Any) -> Any:
    import ida_ua

    rows = []
    for item in a.get("items", []):
        ea = int(str(item["addr"]), 16)
        size = int(ida_ua.create_insn(ea))
        rows.append(
            {
                "addr": hex(ea),
                "ok": size > 0,
                "size": size,
                **({} if size > 0 else {"error": "instruction did not decode"}),
            }
        )
    result = {"result": rows}
    return result


def define_code_run(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_idp, ida_segment, ida_ua, idaapi

    ea, limit = int(str(a["addr"]), 16), max(1, min(int(a.get("limit", 20000)), 200000))
    seg = ida_segment.getseg(ea)
    if seg is None:
        result = {"addr": a["addr"], "error": "no segment", "count": 0}
    else:
        start, count, stopped, hi = ea, 0, "limit", int(seg.end_ea)
        while count < limit:
            if ea >= hi:
                stopped = "segment"
                break
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_code(flags) or ida_bytes.is_data(flags):
                stopped = "defined"
                break
            size = int(ida_ua.create_insn(ea))
            if size <= 0:
                stopped = "undecodable"
                break
            count += 1
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                try:
                    is_ret = bool(ida_idp.is_ret_insn(insn))
                except Exception:
                    is_ret = False
                if is_ret or (insn.get_canon_feature() & idaapi.CF_STOP):
                    ea += size
                    stopped = "flow"
                    break
            ea += size
        result = {
            "start": hex(start),
            "end": hex(ea),
            "count": count,
            "stopped": stopped,
        }
    return result


def define_func(db: Database, **a: Any) -> Any:
    rows = []
    for item in a.get("items", []):
        ea = int(str(item["addr"]), 16)
        ok = bool(db.functions.create(ea))
        rows.append(
            {
                "addr": hex(ea),
                "ok": ok,
                **({} if ok else {"error": "IDA refused the function"}),
            }
        )
    result = {"result": rows}
    return result


def define_func_run(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_funcs, ida_segment

    ea = int(str(a["addr"]), 16)
    fn = db.functions.get_at(ea)
    if fn is not None and int(fn.start_ea) == ea:
        result = {
            "addr": hex(ea),
            "ok": True,
            "start": hex(ea),
            "end": hex(int(fn.end_ea)),
            "how": "existed",
        }
    else:
        automatic = bool(db.functions.create(ea))
        if not automatic:
            seg = db.segments.get_at(ea)
            end = ea
            hi = int(seg.end_ea) if seg else ea
            while end < hi and ida_bytes.is_code(ida_bytes.get_flags(end)):
                nxt = int(ida_bytes.get_item_end(end))
                if nxt <= end:
                    break
                end = nxt
            ok = bool(end > ea and ida_funcs.add_func(ea, end))
        else:
            ok = True
        fn = db.functions.get_at(ea)
        result = (
            {
                "addr": hex(ea),
                "ok": True,
                "start": hex(int(fn.start_ea)),
                "end": hex(int(fn.end_ea)),
                "how": "auto" if automatic else "explicit-end",
            }
            if ok and fn is not None
            else {
                "addr": hex(ea),
                "ok": False,
                "error": f"IDA refused a function at {ea:#x}",
            }
        )
    return result


def del_type(db: Database, **a: Any) -> Any:
    import ida_typeinf

    name = str(a["name"])
    ok = bool(
        ida_typeinf.del_named_type(ida_typeinf.get_idati(), name, ida_typeinf.NTF_TYPE)
    )
    result = {
        "name": name,
        "deleted": ok,
        **({} if ok else {"error": f"Type {name!r} not found or could not be deleted"}),
    }
    return result


def disasm(db: Database, **a: Any) -> Any:
    ea = int(str(a["addr"]), 16)
    fn = db.functions.get_at(ea)
    if fn is None:
        result = {"instructions": [], "total_instructions": 0, "instruction_count": 0}
    else:
        instructions = list(db.functions.get_instructions(fn))
        limit = max(1, int(a.get("max_instructions", len(instructions) or 1)))
        rows = [
            {
                "addr": hex(int(insn.ea)),
                "instruction": db.instructions.get_disassembly(insn),
            }
            for insn in instructions[:limit]
        ]
        result = {
            "instructions": rows,
            "total_instructions": len(instructions),
            "instruction_count": len(instructions),
        }
    return result


def file_regions(db: Database, **a: Any) -> Any:
    import idaapi

    rows = []
    for seg in db.segments.get_all():
        try:
            file_off = int(idaapi.get_fileregion_offset(seg.start_ea))
        except Exception:
            file_off = -1
        if file_off < 0 or file_off >= (1 << 48):
            file_off = -1
        rows.append(
            {
                "start": hex(int(seg.start_ea)),
                "end": hex(int(seg.end_ea)),
                "file_off": file_off,
                "name": db.segments.get_name(seg) or "",
            }
        )
    result = {"regions": rows}
    return result


def flowchart(db: Database, **a: Any) -> Any:
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
                if len(sl) > 2:
                    kind = "switch"
                elif s.start_ea == bb.end_ea:
                    kind = "fall"
                else:
                    kind = "jump"
                succs.append([index[s.start_ea], kind])
            blocks.append(
                {
                    "id": index[bb.start_ea],
                    "start": hex(int(bb.start_ea)),
                    "end": hex(int(bb.end_ea)),
                    "succs": succs,
                }
            )
        result = {
            "addr": hex(ea),
            "func": {
                "addr": hex(int(fn.start_ea)),
                "end": hex(int(fn.end_ea)),
                "name": ida_funcs.get_func_name(fn.start_ea) or "",
            },
            "entry": index.get(fn.start_ea, 0),
            "blocks": blocks,
        }
    return result


def force_recompile(db: Database, **a: Any) -> Any:
    import ida_hexrays

    rows = []
    for item in a.get("items", []):
        ea = int(str(item["addr"]), 16)
        ida_hexrays.mark_cfunc_dirty(ea, False)
        rows.append({"addr": hex(ea), "ok": True})
    result = {"result": rows}
    return result


def func_types(db: Database, **a: Any) -> Any:
    import ida_typeinf

    ea = int(str(a["addr"]), 16)
    fn = db.functions.get_at(ea)
    if fn is None:
        result = {"addr": a["addr"], "error": "no function at address"}
    else:
        pseudo = db.pseudocode.decompile(fn)
        name = db.functions.get_name(fn) or ""
        tif = pseudo.get_func_type()
        try:
            prototype = (
                ida_typeinf.print_tinfo(
                    "", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, ""
                )
                if tif
                else ""
            )
        except Exception:
            prototype = tif.dstr() if tif else ""
        lvars = [
            {
                "name": var.name,
                "type": var.type_info.dstr() if var.type_info else "",
                "is_arg": bool(var.is_arg),
            }
            for var in pseudo.local_variables
        ]
        result = {
            "addr": hex(int(fn.start_ea)),
            "name": name,
            "prototype": (prototype or "").strip(),
            "lvars": lvars,
        }
    return result


def get_bytes(db: Database, **a: Any) -> Any:
    rows = []
    for region in a.get("regions", []):
        ea, size = int(str(region["addr"]), 16), int(region["size"])
        raw = db.bytes.get_bytes_at(ea, size) or b""
        rows.append({"addr": region["addr"], "data": " ".join(f"{b:02x}" for b in raw)})
    result = {"result": rows}
    return result


def journal_get(db: Database, **a: Any) -> Any:
    import ida_netnode

    n = ida_netnode.netnode(a.get("node", "$ idatui.journal"))
    blob = n.getblob(0, "I") if ida_netnode.exist(n) else None
    result = {"data": blob.decode("utf-8", "replace") if blob else ""}
    return result


def journal_put(db: Database, **a: Any) -> Any:
    import ida_netnode

    n = ida_netnode.netnode(a.get("node", "$ idatui.journal"), 0, True)
    payload = (a.get("data") or "").encode("utf-8")
    n.setblob(payload, 0, "I")
    result = {"ok": True, "bytes": len(payload)}
    return result


def list_annotations(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_funcs, ida_lines, ida_nalt, ida_name
    import ida_segment, ida_typeinf, idautils

    limit = max(1, int(a.get("limit", 4000)))
    max_scan = max(1000, int(a.get("max_scan", 2000000)))
    comments, names = [], []
    scanned = 0

    def _line(ea):
        try:
            txt = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
        except Exception:
            txt = ""
        return " ".join((txt or "").split())

    for ea, nm in idautils.Names():
        if len(names) >= limit:
            break
        if not nm or not ida_bytes.has_user_name(ida_bytes.get_flags(ea)):
            continue
        fn = ida_funcs.get_func(ea)
        is_fn = fn is not None and int(fn.start_ea) == int(ea)
        proto = None
        if is_fn:
            try:
                ti = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(ti, ea):
                    proto = str(ti)
            except Exception:
                proto = None
        seg = ida_segment.getseg(ea)
        names.append(
            {
                "addr": hex(int(ea)),
                "name": nm,
                "func": is_fn,
                "size": (int(fn.end_ea - fn.start_ea) if is_fn else 0),
                "proto": proto,
                "seg": (ida_segment.get_segm_name(seg) if seg else ""),
            }
        )

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None or len(comments) >= limit or scanned >= max_scan:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            scanned += 1
            if len(comments) >= limit or scanned >= max_scan:
                break
            if not ida_bytes.has_cmt(ida_bytes.get_flags(ea)):
                continue
            for rep in (False, True):
                text = ida_bytes.get_cmt(ea, rep)
                if text:
                    fn = ida_funcs.get_func(ea)
                    comments.append(
                        {
                            "addr": hex(int(ea)),
                            "text": text,
                            "repeatable": rep,
                            "line": _line(ea),
                            "seg": ida_segment.get_segm_name(seg),
                            "func": (
                                ida_funcs.get_func_name(fn.start_ea) if fn else None
                            ),
                            "func_addr": (hex(int(fn.start_ea)) if fn else None),
                        }
                    )

    # Whole-function comments are not on the byte flags, so the scan cannot see them.
    for fn_ea in idautils.Functions():
        fn = ida_funcs.get_func(fn_ea)
        if fn is None or len(comments) >= limit:
            continue
        for rep in (False, True):
            text = ida_funcs.get_func_cmt(fn, rep)
            if text:
                seg = ida_segment.getseg(fn_ea)
                comments.append(
                    {
                        "addr": hex(int(fn_ea)),
                        "text": text,
                        "repeatable": rep,
                        "line": "",
                        "whole_func": True,
                        "seg": (ida_segment.get_segm_name(seg) if seg else ""),
                        "func": ida_funcs.get_func_name(fn_ea),
                        "func_addr": hex(int(fn_ea)),
                    }
                )
    result = {
        "comments": comments,
        "names": names,
        "scanned": scanned,
        "truncated": (
            len(comments) >= limit or len(names) >= limit or scanned >= max_scan
        ),
    }
    return result


def list_funcs(db: Database, **a: Any) -> Any:
    import fnmatch

    queries = a.get("queries") or [{}]
    q = queries[0]
    offset, count = max(0, int(q.get("offset", 0))), max(1, int(q.get("count", 500)))
    pattern = str(q.get("filter") or "").lower()
    if pattern and not any(ch in pattern for ch in "*?["):
        pattern = "*" + pattern + "*"
    rows = []
    for fn in db.functions.get_all():
        name = db.functions.get_name(fn) or f"sub_{int(fn.start_ea):X}"
        if pattern and not fnmatch.fnmatchcase(name.lower(), pattern):
            continue
        rows.append(
            {
                "addr": hex(int(fn.start_ea)),
                "name": name,
                "size": int(fn.end_ea) - int(fn.start_ea),
            }
        )
    page = rows[offset : offset + count]
    result = {
        "result": [
            {"data": page, "next_offset": offset + len(page), "total": len(rows)}
        ]
    }
    return result


def list_linkage(db: Database, **a: Any) -> Any:
    imports = [
        {"addr": hex(int(item.address)), "name": item.name, "module": item.module_name}
        for item in db.imports.get_all_imports()
        if item.name
    ]
    exports = [
        {
            "addr": hex(int(item.address)),
            "name": item.name,
            "ordinal": int(item.ordinal),
        }
        for item in db.entries.get_all()
        if item.name
    ]
    result = {
        "imports": imports,
        "exports": exports,
        "n_imports": len(imports),
        "n_exports": len(exports),
    }
    return result


def list_strings(db: Database, **a: Any) -> Any:
    from ida_domain.strings import StringListConfig

    offset, count, min_len = (
        max(0, int(a.get("offset", 0))),
        max(1, int(a.get("count", 2000))),
        max(1, int(a.get("min_len", 4))),
    )
    if offset == 0 or a.get("refresh"):
        from ida_domain.strings import StringType

        db.strings.rebuild(
            StringListConfig(
                string_types=list(StringType), min_len=min_len, only_ascii_7bit=False
            )
        )
    items = list(db.strings.get_all())
    page = items[offset : offset + count]
    rows = []
    for item in page:
        try:
            text = str(item)
        except Exception:
            text = item.contents.decode("utf-8", "replace") if item.contents else ""
        rows.append(
            {
                "addr": hex(int(item.address)),
                "text": text,
                "len": int(item.length),
                "type": item.type.name,
            }
        )
    result = {"strings": rows, "total": len(items), "next_offset": offset + len(rows)}
    return result


def lookup_funcs(db: Database, **a: Any) -> Any:
    rows = []
    for query in a.get("queries", []):
        raw = str(query)
        try:
            ea = int(raw, 16)
        except ValueError:
            fn = db.functions.get_by_name(raw)
            ea = int(fn.start_ea) if fn else None
        else:
            fn = db.functions.get_at(ea)
        if fn is None:
            rows.append({"query": raw, "fn": None})
        else:
            rows.append(
                {
                    "query": raw,
                    "fn": {
                        "addr": hex(int(fn.start_ea)),
                        "name": db.functions.get_name(fn)
                        or f"sub_{int(fn.start_ea):X}",
                        "size": int(fn.end_ea) - int(fn.start_ea),
                    },
                }
            )
    result = {"result": rows}
    return result


def make_data(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_idaapi, ida_typeinf
    from ida_domain.types import TypeApplyFlags

    rows = []
    for item in a.get("items", []):
        ea, declaration = int(str(item["addr"]), 16), str(item["type"])
        try:
            tif = db.types.parse_one_declaration(ida_typeinf.get_idati(), declaration)
            size = max(1, int(tif.get_size()))
            saved_names = [
                (addr, name)
                for addr, name in db.names.get_all()
                if ea <= int(addr) < ea + size
            ]
            ida_bytes.del_items(
                ea,
                ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES,
                max(size, int(ida_bytes.get_item_size(ea) or 1)),
            )
            created = bool(
                ida_bytes.create_data(ea, ida_bytes.FF_BYTE, size, ida_idaapi.BADADDR)
            )
            ok = created and bool(db.types.apply_at(tif, ea, TypeApplyFlags.DEFINITE))
            for address, name in saved_names:
                db.names.set_name(int(address), name)
            if ok and item.get("name"):
                ok = bool(db.names.set_name(ea, str(item["name"])))
            rows.append(
                {
                    "addr": hex(ea),
                    "ok": ok,
                    "size": size,
                    **({} if ok else {"error": "IDA rejected the data type"}),
                }
            )
        except Exception as exc:
            rows.append({"addr": hex(ea), "ok": False, "error": str(exc)})
    result = {"result": rows}
    return result


def make_string(db: Database, **a: Any) -> Any:
    from ida_domain.strings import StringType

    ea, length = int(str(a["addr"]), 16), max(0, int(a.get("length", 0)))
    kind = {
        "c": StringType.C,
        "c16": StringType.C_16,
        "c32": StringType.C_32,
        "pascal": StringType.PASCAL,
    }.get(str(a.get("kind", "c")).lower(), StringType.C)
    import ida_bytes

    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, length if length > 0 else 1)
    except Exception:
        pass
    try:
        ok = bool(db.bytes.create_string_at(ea, length or None, kind))
        text = db.bytes.get_string_at(ea) or "" if ok else ""
        result = {
            "addr": hex(ea),
            "ok": ok,
            "size": int(db.heads.size(ea)) if ok else 0,
            "text": text,
        }
    except Exception as exc:
        result = {"addr": hex(ea), "ok": False, "error": str(exc)}
    return result


def read_raw(db: Database, **a: Any) -> Any:
    import ida_bytes

    ea, size = int(str(a["addr"]), 16), max(0, int(a["size"]))
    raw = ida_bytes.get_bytes(ea, size) or b""
    raw = raw[:size] + b"\xff" * max(0, size - len(raw))
    data = bytearray(raw)
    for index, value in enumerate(data):
        if value == 0xFF and not ida_bytes.is_loaded(ea + index):
            data[index] = 0
    result = {"addr": a["addr"], "hex": bytes(data).hex(), "n": len(data)}
    return result


def rename(db: Database, **a: Any) -> Any:
    import idaapi, ida_hexrays, ida_name

    batch = a.get("batch") or {}
    dry_run = bool(batch.get("dry_run", False))
    allow_overwrite = bool(batch.get("allow_overwrite", False))
    stop_on_error = bool(batch.get("stop_on_error", False))

    def _items(value):
        if value is None:
            return []
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list):
            return [i for i in value if isinstance(i, dict)]
        return []

    def _set_name_checked(ea, new):
        conflict = idaapi.get_name_ea(idaapi.BADADDR, new)
        if conflict != idaapi.BADADDR and conflict != ea and not allow_overwrite:
            return (
                False,
                f"can't rename at {hex(ea)} as {new!r}: name already used at {hex(conflict)}",
            )
        if dry_run:
            return True, None
        flags = idaapi.SN_CHECK
        if allow_overwrite:
            flags |= int(getattr(idaapi, "SN_FORCE", 0))
        if not idaapi.set_name(ea, new, flags):
            return False, (
                f"Rename failed at {hex(ea)}: IDA rejected name {new!r} "
                "(invalid identifier or internal conflict)"
            )
        return True, None

    def _refresh_ctext(fn_addr):
        # A renamed function must invalidate Hex-Rays' cache, which is per function
        # and persisted in the .i64: without this the pseudocode keeps calling the
        # old name forever while every other readback reports the new one.
        if not ida_hexrays.init_hexrays_plugin():
            return
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(
            fn_addr, failure, ida_hexrays.DECOMP_WARNINGS
        )
        if cfunc:
            cfunc.refresh_func_ctext()

    out = {}
    ok_count = failed = 0
    halted = False
    for category in ("func", "data", "local", "stack"):
        if category not in batch:
            continue
        rows = []
        for edit in _items(batch.get(category)):
            try:
                if category == "func":
                    addr_text = (
                        edit.get("addr") or edit.get("func_addr") or edit.get("func")
                    )
                    new = edit.get("name") or edit.get("new") or edit.get("new_name")
                    if not addr_text or not new:
                        row = {
                            "addr": addr_text,
                            "name": new,
                            "error": "Function rename requires addr + name",
                        }
                    else:
                        ea = int(str(addr_text), 16)
                        fn = idaapi.get_func(ea)
                        if fn is None:
                            row = {
                                "addr": addr_text,
                                "name": new,
                                "error": "Function not found",
                            }
                        else:
                            old = idaapi.get_name(fn.start_ea) or None
                            ok, err = _set_name_checked(fn.start_ea, str(new))
                            row = {"addr": addr_text, "old": old, "name": str(new)}
                            if err:
                                row["error"] = err
                            if dry_run:
                                row["dry_run"] = True
                            if ok and not dry_run:
                                _refresh_ctext(fn.start_ea)
                elif category == "data":
                    addr_text = edit.get("addr")
                    old = edit.get("old") or edit.get("old_name")
                    new = edit.get("new") or edit.get("new_name") or edit.get("name")
                    if not new and new != "":
                        row = {
                            "old": old,
                            "new": None,
                            "error": "Global rename requires target and new name",
                        }
                    else:
                        if addr_text is not None:
                            ea = int(str(addr_text), 16)
                            old = old or (idaapi.get_name(ea) or None)
                        else:
                            ea = idaapi.get_name_ea(idaapi.BADADDR, str(old or ""))
                        if ea == idaapi.BADADDR:
                            row = {
                                "old": old,
                                "new": str(new),
                                "error": f"Global {old!r} not found",
                            }
                        else:
                            # An empty new name CLEARS the label; that is a real
                            # request (tests revert with it), not a missing argument.
                            if str(new) == "":
                                ok = bool(ida_name.set_name(ea, "", idaapi.SN_CHECK))
                                err = (
                                    None
                                    if ok
                                    else f"Failed to clear the name at {hex(ea)}"
                                )
                            else:
                                ok, err = _set_name_checked(ea, str(new))
                            row = {"addr": hex(ea), "old": old, "new": str(new)}
                            if err:
                                row["error"] = err
                            if dry_run:
                                row["dry_run"] = True
                else:
                    fa, old, new = (
                        edit.get("func_addr"),
                        edit.get("old"),
                        edit.get("new"),
                    )
                    if not fa or not old or not new:
                        row = {
                            "old": old,
                            "new": new,
                            "error": f"{category} rename requires func_addr + old + new",
                        }
                    else:
                        ea = int(str(fa), 16)
                        pseudo = db.pseudocode.decompile(ea)
                        var = pseudo.find_local_variable(str(old))
                        if var is None:
                            row = {
                                "func_addr": fa,
                                "old": old,
                                "new": new,
                                "error": f"no local {old!r} in that function",
                            }
                        elif dry_run:
                            row = {
                                "func_addr": fa,
                                "old": old,
                                "new": new,
                                "dry_run": True,
                            }
                        else:
                            var.set_user_name(str(new))
                            ok = bool(
                                pseudo.save_local_variable_info(var, save_name=True)
                            )
                            row = {"func_addr": fa, "old": old, "new": new}
                            if not ok:
                                row["error"] = "IDA rejected the local variable name"
            except Exception as exc:
                row = {"addr": edit.get("addr"), "error": str(exc)}
            rows.append(row)
            if row.get("error"):
                failed += 1
            else:
                ok_count += 1
            if row.get("error") and stop_on_error:
                halted = True
                break
        out[category] = rows
        if halted:
            break
    out["summary"] = {"ok": ok_count, "failed": failed}
    if dry_run:
        out["summary"]["dry_run"] = True
    if halted:
        out["summary"]["halted"] = True
    result = out
    return result


def resolve_names(db: Database, **a: Any) -> Any:
    import ida_idaapi, ida_name

    rows = []
    for query in a.get("queries", []):
        name = str(query).strip()
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        rows.append(
            {"query": name, "ea": hex(int(ea)) if ea != ida_idaapi.BADADDR else None}
        )
    result = {"result": rows}
    return result


def search_bytes(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_funcs, ida_idaapi, ida_lines, ida_segment

    pat = str(a.get("pattern", "")).strip()
    limit = max(1, int(a.get("limit", 500)))
    lo = int(a.get("start", 0))
    hi = int(a.get("end", 0)) or ida_idaapi.BADADDR
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    if a.get("case"):
        flags |= ida_bytes.BIN_SEARCH_CASE
    rows, err, ea = [], None, lo
    while len(rows) < limit:
        try:
            hit = ida_bytes.find_bytes(pat, range_start=ea, range_end=hi, flags=flags)
        except Exception as exc:
            err = str(exc) or exc.__class__.__name__
            break
        if hit is None or hit == ida_idaapi.BADADDR:
            break
        head = ida_bytes.get_item_head(hit)
        fn = ida_funcs.get_func(hit)
        seg = ida_segment.getseg(hit)
        try:
            line = (
                ida_lines.generate_disasm_line(head, ida_lines.GENDSM_REMOVE_TAGS) or ""
            )
        except Exception:
            line = ""
        rows.append(
            {
                "addr": hex(int(hit)),
                "head": hex(int(head)),
                "line": " ".join(line.split()),
                "func": (ida_funcs.get_func_name(fn.start_ea) if fn else None),
                "func_addr": (hex(int(fn.start_ea)) if fn else None),
                "seg": (ida_segment.get_segm_name(seg) if seg else ""),
            }
        )
        ea = int(hit) + 1
    result = {"hits": rows, "error": err, "truncated": len(rows) >= limit}
    return result


def search_structs(db: Database, **a: Any) -> Any:
    needle = str(a.get("filter") or "").lower()
    rows = []
    for tif in db.types.get_all():
        name = tif.get_type_name() or ""
        if not name or needle not in name.lower() or not tif.is_udt():
            continue
        members = list(db.types.get_udt_members(tif))
        rows.append(
            {
                "name": name,
                "size": int(tif.get_size()),
                "is_union": bool(tif.is_union()),
                "cardinality": len(members),
                "ordinal": int(tif.get_ordinal()),
            }
        )
    result = {"result": rows}
    return result


def search_text(db: Database, **a: Any) -> Any:
    import ida_lines, ida_funcs, ida_segment, idautils
    import re as _re

    q = str(a.get("query", ""))
    limit = max(1, int(a.get("limit", 500)))
    max_scan = max(1000, int(a.get("max_scan", 3000000)))
    ci = (not a.get("case")) and q.islower()  # smartcase, like the in-view search
    rx, err = None, None
    if a.get("regex"):
        try:
            rx = _re.compile(q, _re.I if ci else 0)
        except Exception as exc:
            err = "bad regex: " + str(exc)
    needle = q.lower() if ci else q
    rows, scanned = [], 0
    if err is None and q:
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None or len(rows) >= limit or scanned >= max_scan:
                continue
            for ea in idautils.Heads(seg.start_ea, seg.end_ea):
                scanned += 1
                if len(rows) >= limit or scanned >= max_scan:
                    break
                try:
                    line = (
                        ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
                        or ""
                    )
                except Exception:
                    continue
                # Match what the user SEES, not IDA's column padding: nobody types
                # "call" + four spaces + "cs:getenv_ptr".
                line = " ".join(line.split())
                hay = line.lower() if ci else line
                if rx.search(line) if rx is not None else (needle in hay):
                    fn = ida_funcs.get_func(ea)
                    rows.append(
                        {
                            "addr": hex(int(ea)),
                            "head": hex(int(ea)),
                            "line": line,
                            "func": (
                                ida_funcs.get_func_name(fn.start_ea) if fn else None
                            ),
                            "func_addr": (hex(int(fn.start_ea)) if fn else None),
                            "seg": ida_segment.get_segm_name(seg),
                        }
                    )
    result = {
        "hits": rows,
        "error": err,
        "scanned": scanned,
        "truncated": len(rows) >= limit or scanned >= max_scan,
    }
    return result


def set_comments(db: Database, **a: Any) -> Any:
    import idaapi, idc, ida_hexrays

    rows = []
    for item in a.get("items", []):
        addr_s = str(item.get("addr", ""))
        text = str(item.get("comment") or "")
        try:
            ea = int(addr_s, 16)
            if not idaapi.set_cmt(ea, text, False):
                rows.append(
                    {
                        "addr": addr_s,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue
            if not ida_hexrays.init_hexrays_plugin():
                rows.append({"addr": addr_s})
                continue
            try:
                cfunc = ida_hexrays.decompile(ea)
            except Exception:
                cfunc = None
            if cfunc is None:
                rows.append({"addr": addr_s})
                continue
            if ea == cfunc.entry_ea:
                # The signature line carries no ctree item: it is a function comment.
                idc.set_func_cmt(ea, text, True)
                cfunc.refresh_func_ctext()
                rows.append({"addr": addr_s})
                continue
            eamap = cfunc.get_eamap()
            if ea not in eamap:
                rows.append(
                    {
                        "addr": addr_s,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea
            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            placed = False
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, text)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    placed = True
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            rows.append(
                {"addr": addr_s}
                if placed
                else {
                    "addr": addr_s,
                    "error": f"Failed to set decompiler comment at {hex(ea)}",
                }
            )
        except Exception as exc:
            rows.append({"addr": addr_s, "error": str(exc)})
    result = {"result": rows}
    return result


def set_lvar_type(db: Database, **a: Any) -> Any:
    import ida_typeinf

    ea, variable, declaration = (
        int(str(a["addr"]), 16),
        str(a["variable"]),
        str(a["type"]),
    )
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
                tif = db.types.parse_one_declaration(
                    ida_typeinf.get_idati(), declaration
                )
                accepted = bool(var.set_type(tif))
                saved = (
                    bool(pseudo.save_local_variable_info(var, save_type=True))
                    if accepted
                    else False
                )
                result = {
                    "addr": hex(int(fn.start_ea)),
                    "variable": variable,
                    "type": declaration,
                    "ok": accepted and saved,
                }
            except Exception as exc:
                result = {"error": f"bad type {declaration!r}: {exc}"}
    return result


def set_thumb(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_ida, ida_idp, ida_segment, ida_segregs

    ea = int(str(a["addr"]), 16)
    treg = ida_idp.str2reg("T")
    seg = ida_segment.getseg(ea)
    if treg is None or treg < 0:
        result = {"addr": hex(ea), "error": "no T register (not an ARM database)"}
    elif seg is None:
        result = {"addr": hex(ea), "error": "no segment"}
    else:
        current = ida_segregs.get_sreg(ea, treg)
        current = 0 if current in (None, 0xFFFFFFFF, -1) else int(current)
        want = {"on": 1, "off": 0}.get(
            str(a.get("mode", "toggle")).lower(), 0 if current else 1
        )
        changed = False
        if want and seg.bitness != 1:
            ida_segment.set_segm_addressing(seg, 1)
            changed = True
        size = max(int(ida_bytes.get_item_size(ea)), 2)
        ida_bytes.del_items(ea, 0, size)
        ok = bool(ida_segregs.split_sreg_range(ea, treg, want, ida_segregs.SR_user))
        now = ida_segregs.get_sreg(ea, treg)
        result = {
            "addr": hex(ea),
            "thumb": bool(now),
            "was": bool(current),
            "ok": ok,
            "bitness": ida_segment.getseg(ea).bitness,
            "forced_32bit": changed,
            "db_64bit": bool(ida_ida.inf_get_app_bitness() == 64 and want),
        }
    return result


def set_type(db: Database, **a: Any) -> Any:
    from ida_domain.types import TypeApplyFlags

    rows = []
    for edit in a.get("edits", []):
        ea = int(str(edit["addr"]), 16)
        declaration = str(edit.get("signature") or edit.get("type") or "")
        try:
            ok = bool(
                db.types.apply_declaration_at(ea, declaration, TypeApplyFlags.DEFINITE)
            )
            rows.append(
                {
                    "addr": hex(ea),
                    "ok": ok,
                    **({} if ok else {"error": "IDA rejected the type"}),
                }
            )
        except Exception as exc:
            rows.append({"addr": hex(ea), "ok": False, "error": str(exc)})
    result = {"result": rows}
    return result


def survey_binary(db: Database, **a: Any) -> Any:
    segments = []
    for seg in db.segments.get_all():
        segments.append(
            {
                "start": hex(int(seg.start_ea)),
                "end": hex(int(seg.end_ea)),
                "name": db.segments.get_name(seg) or "",
            }
        )
    result = {"segments": segments}
    return result


def thumb_scan(db: Database, **a: Any) -> Any:
    import ida_bytes, ida_funcs, ida_idp, ida_segment, ida_segregs, ida_ua

    lo, hi = int(str(a["start"]), 16), int(str(a["end"]), 16)
    apply, limit = bool(a.get("apply", True)), int(a.get("limit", 512))
    treg = ida_idp.str2reg("T")
    found = []
    applied = 0
    cursor = lo
    while cursor + 4 <= hi and len(found) < limit:
        at = cursor
        value = int(ida_bytes.get_dword(cursor))
        cursor += 4
        if not value & 1:
            continue
        target = value & ~1
        seg = ida_segment.getseg(target)
        if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC or seg.perm == 0):
            continue
        flags = ida_bytes.get_flags(target)
        if ida_bytes.is_data(flags):
            continue
        item = {
            "at": hex(at),
            "value": hex(value),
            "target": hex(target),
            "was_code": bool(ida_bytes.is_code(flags)),
        }
        found.append(item)
        if not apply:
            continue
        if treg is not None and treg >= 0:
            ida_segregs.split_sreg_range(target, treg, 1, ida_segregs.SR_user)
        if not ida_bytes.is_code(ida_bytes.get_flags(target)):
            ida_bytes.del_items(target, 0, 2)
            if ida_ua.create_insn(target) <= 0:
                item["decoded"] = False
                continue
        item["decoded"] = True
        item["function"] = bool(
            db.functions.get_at(target) or db.functions.create(target)
        )
        applied += 1
    result = {
        "start": hex(lo),
        "end": hex(hi),
        "found": found,
        "applied": applied,
        "n": len(found),
    }
    return result


def type_inspect(db: Database, **a: Any) -> Any:
    rows = []
    for query in a.get("queries", []):
        name = str(query.get("name") or "")
        tif = db.types.get_by_name(name)
        if tif is None:
            rows.append({"name": name, "error": "type not found"})
            continue
        members = (
            [
                {
                    "name": m.name,
                    "type": m.type.dstr() or str(m.type),
                    "offset": int(m.offset),
                    "size": int(m.size),
                }
                for m in db.types.get_udt_members(tif)
            ]
            if tif.is_udt()
            else []
        )
        rows.append(
            {
                "name": name,
                "size": int(tif.get_size()),
                "is_union": bool(tif.is_union()),
                "members": members,
            }
        )
    result = {"result": rows}
    return result


def undefine(db: Database, **a: Any) -> Any:
    import ida_bytes

    rows = []
    for item in a.get("items", []):
        ea = int(str(item["addr"]), 16)
        size = max(1, int(item.get("size") or ida_bytes.get_item_size(ea) or 1))
        ok = bool(ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size))
        rows.append(
            {
                "addr": hex(ea),
                "ok": ok,
                **({} if ok else {"error": "delete items failed"}),
            }
        )
    result = {"result": rows}
    return result


def xref_query(db: Database, **a: Any) -> Any:
    import idaapi, idautils, ida_bytes, ida_funcs

    def _fn(ea):
        f = ida_funcs.get_func(ea)
        return (
            {
                "addr": hex(int(f.start_ea)),
                "name": ida_funcs.get_func_name(f.start_ea) or "",
            }
            if f
            else None
        )

    queries = a.get("queries") or []
    all_results = []
    for query in queries:
        raw = str(query.get("addr", "")).strip()
        direction = str(query.get("direction", "both") or "both").lower()
        if direction not in ("to", "from", "both"):
            direction = "both"
        xref_type = str(query.get("xref_type", "any") or "any").lower()
        if xref_type not in ("any", "code", "data"):
            xref_type = "any"
        include_fn = bool(query.get("include_fn", True))
        dedup = bool(query.get("dedup", True))
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        try:
            offset = max(0, int(query.get("offset", 0) or 0))
        except (TypeError, ValueError):
            offset = 0
        try:
            count = max(0, min(int(query.get("count", 200) or 200), 5000))
        except (TypeError, ValueError):
            count = 200
        try:
            try:
                target = int(raw, 16)
            except ValueError:
                target = idaapi.get_name_ea(idaapi.BADADDR, raw)
                if target == idaapi.BADADDR:
                    raise ValueError(f"Failed to resolve address/name: {raw}")
            if not ida_bytes.is_mapped(target):
                raise ValueError(f"Address not mapped: {raw}")
            rows = []
            if direction in ("to", "both"):
                for xr in idautils.XrefsTo(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "to",
                        "addr": hex(int(xr.frm)),
                        "from": hex(int(xr.frm)),
                        "to": hex(int(target)),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = _fn(xr.frm)
                    rows.append(row)
            if direction in ("from", "both"):
                for xr in idautils.XrefsFrom(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "from",
                        "addr": hex(int(xr.to)),
                        "from": hex(int(target)),
                        "to": hex(int(xr.to)),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = _fn(xr.to)
                    rows.append(row)
            if dedup:
                seen, deduped = set(), []
                for row in rows:
                    key = (row["direction"], row["from"], row["to"], row["type"])
                    if key in seen:
                        continue
                    seen.add(key)
                    deduped.append(row)
                rows = deduped
            if sort_by == "type":
                rows.sort(
                    key=lambda r: (str(r.get("type", "")), int(str(r["addr"]), 16)),
                    reverse=descending,
                )
            else:
                rows.sort(key=lambda r: int(str(r["addr"]), 16), reverse=descending)
            page = rows[offset : offset + count] if count else rows[offset:]
            nxt = offset + len(page)
            all_results.append(
                {
                    "target": raw,
                    "resolved_addr": hex(int(target)),
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": page,
                    "next_offset": nxt if nxt < len(rows) else None,
                    "total": len(rows),
                    "error": None,
                }
            )
        except Exception as exc:
            all_results.append(
                {
                    "target": raw,
                    "resolved_addr": None,
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": str(exc),
                }
            )
    result = {"result": all_results}
    return result


def xref_types(db: Database, **a: Any) -> Any:
    import idaapi, idautils, ida_bytes, ida_funcs, ida_xref

    code_kind = {
        ida_xref.fl_CF: "call",
        ida_xref.fl_CN: "call",
        ida_xref.fl_JF: "jump",
        ida_xref.fl_JN: "jump",
        ida_xref.fl_F: "flow",
    }
    data_kind = {
        ida_xref.dr_O: "offset",
        ida_xref.dr_W: "write",
        ida_xref.dr_R: "read",
        ida_xref.dr_T: "text",
        ida_xref.dr_I: "info",
    }

    def _kind(xr):
        return (code_kind if xr.iscode else data_kind).get(
            xr.type, "code" if xr.iscode else "data"
        )

    def _fn(ea):
        f = ida_funcs.get_func(ea)
        return (
            {
                "addr": hex(int(f.start_ea)),
                "name": ida_funcs.get_func_name(f.start_ea) or "",
            }
            if f
            else None
        )

    queries = a.get("queries") or []
    all_results = []
    for query in queries:
        query = query if isinstance(query, dict) else {"addr": query}
        raw = str(query.get("addr", "")).strip()
        direction = str(query.get("direction", "to") or "to").lower()
        include_fn = bool(query.get("include_fn", True))
        dedup = bool(query.get("dedup", True))
        try:
            count = int(query.get("count", 2000) or 2000)
        except (TypeError, ValueError):
            count = 2000
        try:
            target = int(raw, 16)
        except ValueError:
            target = idaapi.get_name_ea(idaapi.BADADDR, raw)
        rows = []
        if (
            target is not None
            and target != idaapi.BADADDR
            and ida_bytes.is_mapped(target)
        ):
            if direction in ("to", "both"):
                for xr in idautils.XrefsTo(target, 0):
                    row = {
                        "direction": "to",
                        "addr": hex(int(xr.frm)),
                        "from": hex(int(xr.frm)),
                        "to": hex(int(target)),
                        "type": "code" if xr.iscode else "data",
                        "kind": _kind(xr),
                    }
                    if include_fn:
                        row["fn"] = _fn(xr.frm)
                    rows.append(row)
            if direction in ("from", "both"):
                for xr in idautils.XrefsFrom(target, 0):
                    row = {
                        "direction": "from",
                        "addr": hex(int(xr.to)),
                        "from": hex(int(target)),
                        "to": hex(int(xr.to)),
                        "type": "code" if xr.iscode else "data",
                        "kind": _kind(xr),
                    }
                    if include_fn:
                        row["fn"] = _fn(xr.to)
                    rows.append(row)
            if dedup:
                seen, deduped = set(), []
                for r in rows:
                    k = (r["direction"], r["from"], r["to"], r["kind"])
                    if k in seen:
                        continue
                    seen.add(k)
                    deduped.append(r)
                rows = deduped
            rows = rows[:count]
        all_results.append({"query": raw, "data": rows, "next_offset": None})
    result = {"result": all_results}
    return result


def op_format(addr: str, mode: str = "cycle", col: int = -1, n: int = -1) -> dict: ...


def pc_nums(addr: str) -> dict: ...


def decompile(addr, include_addresses=True) -> dict: ...


def decomp_map(addr: str) -> dict: ...


def pc_num_format(
    addr: str,
    mode: str = "cycle",
    line: int = -1,
    col: int = -1,
    ea: str = "",
    opnum: int = -1,
) -> dict: ...


def segment_index(
    addr: str,
    end: str = "",
    page_rows: int = 500,
    detail: bool = False,
) -> dict: ...


def heads(
    addr: str,
    count: int = 200,
    offset: int = 0,
    end: str = "",
    back: bool = False,
    annotate: bool = False,
    expect: str = "",
    text: bool = True,
) -> dict: ...


def profile_remote(operation: str, args: dict[str, Any], reps: int = 5) -> dict: ...


OPERATIONS: dict[str, Callable[..., Any]] = {
    "data_type": data_type,
    "declare_type": declare_type,
    "decomp_error": decomp_error,
    "define_code": define_code,
    "define_code_run": define_code_run,
    "define_func": define_func,
    "define_func_run": define_func_run,
    "del_type": del_type,
    "disasm": disasm,
    "file_regions": file_regions,
    "flowchart": flowchart,
    "force_recompile": force_recompile,
    "func_types": func_types,
    "get_bytes": get_bytes,
    "heads": heads,
    "journal_get": journal_get,
    "journal_put": journal_put,
    "list_annotations": list_annotations,
    "list_funcs": list_funcs,
    "list_linkage": list_linkage,
    "list_strings": list_strings,
    "lookup_funcs": lookup_funcs,
    "make_data": make_data,
    "make_string": make_string,
    "op_format": op_format,
    "pc_nums": pc_nums,
    "decompile": decompile,
    "decomp_map": decomp_map,
    "pc_num_format": pc_num_format,
    "profile_remote": profile_remote,
    "read_raw": read_raw,
    "rename": rename,
    "resolve_names": resolve_names,
    "search_bytes": search_bytes,
    "search_structs": search_structs,
    "search_text": search_text,
    "segment_index": segment_index,
    "set_comments": set_comments,
    "set_lvar_type": set_lvar_type,
    "set_thumb": set_thumb,
    "set_type": set_type,
    "survey_binary": survey_binary,
    "thumb_scan": thumb_scan,
    "type_inspect": type_inspect,
    "undefine": undefine,
    "xref_query": xref_query,
    "xref_types": xref_types,
}

_MODULE_DECLARATIONS = frozenset(
    (
        heads,
        segment_index,
        op_format,
        pc_nums,
        decompile,
        decomp_map,
        pc_num_format,
        profile_remote,
    )
)
_BOUND: dict[Callable[..., Any], Any] | None = None
_BIND_LOCK = threading.Lock()


def _bindings() -> dict[Callable[..., Any], Any]:
    global _BOUND
    with _BIND_LOCK:
        if _BOUND is not None:
            return _BOUND
        from ida_nexus import RemoteModule

        operations_module = RemoteModule(
            Path(__file__), operation_label=operation_label, codec="json"
        )
        tools_module = RemoteModule(
            Path(__file__).with_name("remote_tools.py"),
            operation_label=operation_label,
            codec="json",
        )
        bound: dict[Callable[..., Any], Any] = {}
        for declaration in OPERATIONS.values():
            if declaration in _MODULE_DECLARATIONS:
                bound[declaration] = tools_module.function(
                    declaration,
                    timeout=15.0 if declaration is decompile else None,
                )
            else:
                bound[declaration] = operations_module.function(declaration)
        _BOUND = bound
        return bound


def bind(function: Callable[..., Any]) -> Any:
    """Return the lazily constructed remote callable for one declaration."""
    return _bindings()[function]
