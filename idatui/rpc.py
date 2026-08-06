"""In-process RPC server: puppeteer the live TUI over a unix socket.

The TUI renders normally in its terminal (what a viewer/livestream sees); this
listener runs on the *same* asyncio loop, so handlers touch the UI directly with
no thread marshalling. Every injected key produces the identical on-screen effect
a human keyboard would — that's the whole point (drive it "as if a user").

Protocol: newline-delimited JSON, one request/response per line.
  ->  {"id": 1, "method": "keys", "params": {"keys": ["g","m","a","i","n","enter"]}}
  <-  {"id": 1, "result": {...}}                 (or {"id":1,"error":{"message":..}})

Anyone who can r/w the socket can drive the app (no auth by design; the socket is
mode 0600, local only).

Method tiers:
  raw          keys, text            — inject keystrokes (max fidelity)
  introspect   state, view, screen, functions
  (semantic verbs — open/goto/rename/... — layer on top in a later pass.)
"""
from __future__ import annotations

import asyncio
import io
import json
import os
from typing import Any

from rich.console import Console

from ._sync import drain, settle
from .app import DecompView, GraphView, HexView, ListingView

PROTO_VERSION = 1
TYPE_DELAY_MS = 35  # default per-char delay for high-level typed ops (aesthetic)

# Verbs that dereference app.program — refused with a clear error before load.
_PROGRAM_METHODS = {
    "goto", "open", "rename", "comment", "retype", "follow", "xrefs", "symbols",
    "structs", "search", "select", "save", "hex", "toggle_view",
    "pseudocode", "disassembly", "xrefs_to", "xrefs_from", "resolve",
    "define", "rename_many", "opfmt", "graph",
}

# Self-documenting method table (returned by the 'methods' verb).
METHODS = {
    "ping": "-> {ok,proto,module,ready,functions,complete}",
    "methods": "-> this table",
    "quit": "gracefully exit the TUI",
    "state": "-> full state snapshot",
    "view": "{lines?} -> visible code-pane lines (disasm/decomp)",
    "screen": "{format?=text|html|svg} -> {width,height,text} full render",
    "functions": "{filter?,limit?=50} -> [{ea,name,size}]",
    "pseudocode": "{target?} -> full decompiled body",
    "disassembly": "{target?,max?=2000} -> {total,lines:[{ea,text}]}",
    "xrefs_to": "{target,limit?=200} -> [{frm,to,type,fn_addr,fn_name}]",
    "xrefs_from": "{target,limit?=200} -> callees/refs; function-scoped for a "
                  "function (decomp refs), address-scoped for a 0xADDR",
    "resolve": "{name} -> {ea}",
    "keys": "{keys:[str],settle?,timeout?} raw key injection (supports 'wait:<ms>')",
    "text": "{text,delay_ms?,settle?} type a literal string into the focused input",
    "goto/open": "{target,delay_ms?} g-prompt to a name or 0xADDR",
    "rename": "{name,word?,delay_ms?} rename the token under (or 'word') the cursor",
    "comment": "{text} comment the current line (use \\n for newlines)",
    "retype": "{proto,word?,delay_ms?} set the prototype/type under the cursor",
    "follow": "{word?} follow the reference under (or 'word') the cursor",
    "cursor_on": "{word,line?,occurrence?=1} place the cursor on a token",
    "back": "pop the nav stack",
    "toggle_view": "disasm <-> pseudocode",
    "hex": "hex view",
    "graph": "{action?=show|open|close|toggle|zoom|block|entry|succ|pred,"
             "target?,blocks?} the control-flow graph: 'show' reports its "
             "structure (blocks, edges, cursor) without touching it; the others "
             "drive it. 'block' takes target=<id|0xADDR>",
    "xrefs": "open the xref picker",
    "symbols": "{query?} open the symbol palette",
    "structs": "open the struct editor",
    "search": "{term,direction?=1} incremental search in the code view",
    "select": "{index?} choose the highlighted/nth item in the open modal",
    "save": "persist the .i64 (Ctrl+S)",
    "trace": "{seek|goto|step,over?} navigate the execution trace (seek '!50' = percent)",
    "binaries": "-> project binaries {label,active,resident,indexed} (project mode)",
    "switch": "{binary,addr?} make another project binary active (addr also jumps)",
    "close": "dismiss a modal (Escape)",
    "move": "{dir,n?=1} fast movement (down/up/.../pagedown)",
    "cursor": "{line?,col?} set the code-pane cursor directly",
    "define": "{kind:code|func|undef|thumb|thumbscan|data|string,target?} "
              "(re)define bytes at target — the raw-image workflow",
    "rename_many": "{items:[{addr,name}] | file:JSON} bulk-apply a symbol file "
                   "in ONE call (no typing, no navigation)",
    "opfmt": "{mode?=cycle|back|show|hex|dec|oct|bin|char|offset|stack|"
             "default,target?,word?,line?,col?} how the literal under the cursor is "
             "DISPLAYED (IDA's 'o'); works on the listing and on pseudocode "
             "numbers. 'show' reports the format and the stops without editing",
}

#: `opfmt` modes that have a real key on the code views. Driving the key keeps
#: the pane honest (a viewer sees the same thing a human would do); the named
#: formats have no key, so those go through the view's action directly.
_OPFMT_KEYS = {"cycle": "o", "back": "O"}
_OPFMT_MODES = ("cycle", "back", "show", "hex", "dec", "oct", "bin", "char",
                "offset", "stack", "default")

# `define` kinds -> the ListingView key that runs them. Driving the real key
# keeps the pane honest (a viewer sees the same thing a human would do) and
# reuses the app's own edit worker, which reports what actually happened.
_DEFINE_KEYS = {
    "code": "c",          # make code (runs until flow/undecodable)
    "func": "p",          # make function
    "undef": "u",
    "thumb": "t",         # flip ARM/Thumb at the cursor, then disassemble
    "thumbscan": "T",     # find Thumb entry pointers in a vector table
    "data": "d",
    "string": "a",
}

# Movement keys — driven fast (no typed delay) so the pane still visibly moves.
_MOVE_KEYS = {
    "down": "j", "up": "k", "left": "h", "right": "l",
    "word": "w", "wordback": "b", "bol": "0", "eol": "dollar_sign",
    "top": "home", "bottom": "G",
    "halfdown": "ctrl+d", "halfup": "ctrl+u",
    "pagedown": "pagedown", "pageup": "pageup",
}


# --------------------------------------------------------------------------- #
# State introspection
# --------------------------------------------------------------------------- #
def _active_widget(app):
    """The currently *shown* code widget (mirrors app._active)."""
    if app._active == "hex":
        return app.query_one(HexView)
    if app._active == "graph":
        return app.query_one(GraphView)
    if app._active in ("listing", "disasm"):
        return app.query_one(ListingView)
    return app.query_one(DecompView)


def graph_info(app, blocks: bool = True) -> dict[str, Any]:
    """Structured view of the control-flow graph: what a driver actually wants,
    rather than the box-drawing characters it is rendered as."""
    gv = app.query_one(GraphView)
    if gv.fc is None or gv.lay is None:
        return {"open": app._active == "graph", "loaded": False,
                "note": "press space (or graph {action:'open'}) on a function"}
    lay, fc = gv.lay, gv.fc
    out: dict[str, Any] = {
        "open": app._active == "graph",
        "loaded": True,
        "func": {"name": fc.name, "ea": fc.func_ea, "entry": fc.entry},
        "zoom": gv.ZOOMS[gv._zoom],
        "canvas": {"w": lay.width, "h": lay.height},
        "stats": dict(lay.stats),
        "cursor": {"block": gv.cursor_node, "row": gv.cursor_row,
                   "ea": gv._cursor_ea(), "word": gv.word_under_cursor()},
    }
    if blocks:
        rows = []
        for n in lay.nodes:
            b = gv._blocks.get(n.id)
            rows.append({
                "id": n.id,
                "start": b.start if b else None,
                "end": b.end if b else None,
                "insns": len(b.rows) if b else 0,
                "rank": n.rank,
                "box": {"x": n.x, "y": n.y, "w": n.w, "h": n.h},
                "succs": [{"id": i, "kind": k} for i, k in lay.succ.get(n.id, [])],
                "preds": [{"id": i, "kind": k} for i, k in lay.pred.get(n.id, [])],
                "selfloop": bool(b and any(d == n.id for d, _ in b.succs)),
            })
        out["blocks"] = rows
    return out


_MODALS = ("XrefsScreen", "SymbolPalette", "StructEditor", "ConfirmScreen")

#: ``drive raw`` (and any k=v CLI) hands every param through as a *string*.
#: Handlers that did ``int(...)`` coped; the ones that compared directly blew up
#: with e.g. "'<' not supported between instances of 'int' and 'str'". Coerce the
#: known-numeric names once, centrally, instead of at every call site.
_INT_PARAMS = ("lines", "limit", "max", "n", "index", "line", "col",
               "occurrence", "delay_ms", "direction", "addr", "count")
_FLOAT_PARAMS = ("timeout",)


def _coerce_params(params: dict[str, Any]) -> dict[str, Any]:
    out = dict(params)
    for k in _INT_PARAMS:
        v = out.get(k)
        if isinstance(v, str) and v.strip():
            try:
                out[k] = int(v, 0)
            except ValueError:
                pass
    for k in _FLOAT_PARAMS:
        v = out.get(k)
        if isinstance(v, str) and v.strip():
            try:
                out[k] = float(v)
            except ValueError:
                pass
    return out


def _modal_snapshot(app) -> dict[str, Any] | None:
    """Describe the top modal screen, if any, enough to drive it."""
    scr = app.screen
    name = type(scr).__name__
    if name not in _MODALS:
        return None  # the base app Screen is not a modal
    info: dict[str, Any] = {"kind": name}
    items = getattr(scr, "_items", None)
    if isinstance(items, list):
        try:
            from textual.widgets import OptionList
            hl = scr.query_one(OptionList).highlighted
        except Exception:  # noqa: BLE001
            hl = None
        info["highlighted"] = hl
        info["items"] = [
            {"ea": (it[0] if isinstance(it[0], int) else None),
             "label": str(it[1]) if len(it) > 1 else str(it)}
            for it in items[:64]
        ]
    return info


def _cursor_info(app, w) -> dict[str, Any]:
    if isinstance(w, HexView):
        return {"kind": "hex", "va": (w.cursor_va() if w.model else None),
                "byte": w.cursor}
    if isinstance(w, GraphView):
        # The graph cursor is (block, row), not a line index -- reporting it as
        # one would make a driver's `cursor line=` land somewhere arbitrary.
        return {"kind": "graph", "ea": w._cursor_ea(), "block": w.cursor_node,
                "row": w.cursor_row, "col": w.cursor_x,
                "word": w.word_under_cursor(), "text": w._line_plain()}
    # disasm / decomp share the ColumnCursor surface
    word = None
    try:
        word = w.word_under_cursor()
    except Exception:  # noqa: BLE001
        pass
    ea = None
    try:
        ea = app._line_ea_for(w)
    except Exception:  # noqa: BLE001
        pass
    return {"kind": app._active, "line": w.cursor, "col": w.cursor_x,
            "word": word, "ea": ea, "total": getattr(w, "total", None),
            "scroll_y": round(w.scroll_offset.y)}


def _where(app) -> str:
    """Short 'name @ 0xea' for error messages that need to say where we ended up."""
    cur = getattr(app, "_cur", None)
    if cur is None:
        return "nowhere"
    return f"{getattr(cur, 'name', '?')} @ {getattr(cur, 'ea', 0):#x}"


def _readiness(app) -> dict[str, Any]:
    """Whether the app is drivable yet, and how far function-loading has got.
    (Cheap: no network — never call client.health() here.)"""
    idx = app._func_index
    n = len(idx.all_loaded()) if idx is not None else 0
    return {
        "ready": app.program is not None and idx is not None and n > 0,
        "functions": n,
        "complete": bool(idx is not None and idx.complete),
    }


def snapshot(app) -> dict[str, Any]:
    """A structured view of everything an agent needs to decide the next move."""
    cur = app._cur
    w = _active_widget(app)
    st = ""
    try:
        st = str(app.query_one("#status").render())
    except Exception:  # noqa: BLE001
        pass
    return {
        "active": app._active,
        "pref": app._code_mode(),   # kept for wire compat; a constant now
        "function": ({"ea": cur.ea, "name": cur.name} if cur else None),
        "cursor": _cursor_info(app, w),
        "status": st,
        "filter": app._filter_term,
        "binary": app._binary,      # None outside project mode
        "nav_depth": len(app._nav),
        "hops": list(getattr(app, "_hops", [])),
        "dirty": bool(app._dirty),
        "modal": _modal_snapshot(app),
        **_readiness(app),
    }


def view_lines(app, lines: int | None = None) -> dict[str, Any]:
    """The visible text of the active code pane, cursor-marked. (disasm/decomp;
    for hex use screen())."""
    w = _active_widget(app)
    if isinstance(w, HexView):
        return {"active": "hex", "note": "use screen() for the hex grid",
                "cursor": _cursor_info(app, w)}
    if isinstance(w, GraphView):
        return {"active": "graph", "note": "use graph() for structure, "
                                           "screen() for the drawing",
                "cursor": _cursor_info(app, w),
                "graph": graph_info(app, blocks=False)}
    top = round(w.scroll_offset.y)
    height = w.size.height or 40
    n = min(lines or height, max(w.total - top, 0))
    out = []
    for r in range(n):
        idx = top + r
        plain = w._line_plain(idx)
        out.append({"i": idx, "cur": idx == w.cursor,
                    "text": plain if plain is not None else ""})
    return {"active": app._active, "top": top, "total": w.total,
            "cursor": _cursor_info(app, w), "lines": out}


def screen_text(app, fmt: str = "text") -> dict[str, Any]:
    """Render the whole screen exactly as shown. ``fmt``: 'text' (plain, default),
    'html' or 'svg' (colored — handy for an out-of-band web viewer)."""
    width, height = app.size
    console = Console(width=width, height=height or 40, file=io.StringIO(),
                      force_terminal=True, color_system="truecolor", record=True,
                      legacy_windows=False, safe_box=False)
    render = app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens, simplify=False)
    console.print(render)
    out: dict[str, Any] = {"width": width, "height": height, "format": fmt}
    if fmt == "html":
        out["text"] = console.export_html(inline_styles=True)
    elif fmt == "svg":
        out["text"] = console.export_svg(title=app.title)
    else:
        out["text"] = console.export_text(styles=False)
    return out


def place_cursor(w, line=None, col=None) -> None:
    """Move a code view's cursor and BRING IT INTO VIEW.

    Setting the cursor without scrolling leaves the pane showing somewhere else
    entirely, and the next verb then edits a line the operator cannot see — the
    status describes one thing, the screen shows another. Every programmatic
    cursor move goes through here for that reason.
    """
    if line is not None:
        w.cursor = max(0, min(getattr(w, "total", 1) - 1, int(line)))
    if col is not None:
        w.cursor_x = max(0, int(col))
    if hasattr(w, "_after_cursor_move"):
        w._after_cursor_move()
    if hasattr(w, "_scroll_cursor_into_view"):
        w._scroll_cursor_into_view()
    if hasattr(w, "_hscroll"):
        w._hscroll()
    w.refresh()


def cursor_on(app, word: str, line: int | None = None, occurrence: int = 1) -> bool:
    """Place the cursor on the ``occurrence``-th token equal to ``word`` in the
    active code pane (optionally restricted to ``line``). Verified with the app's
    own tokenizer so 'main' won't match inside 'domain'. Disasm scan is limited to
    already-cached lines (what's on/near screen); decomp searches the whole body.
    Returns whether it found and moved.

    Search starts at the VIEWPORT, not at row 0. A continuous listing is the
    whole segment, so counting from the top finds an occurrence in some unrelated
    function thousands of rows away -- and the cursor then lands there, off
    screen, where the next verb edits something the operator cannot see. Wrapping
    to the rows above keeps every match reachable; landing scrolls, so wherever
    it goes is visible.
    """
    w = _active_widget(app)
    if isinstance(w, HexView):
        raise ValueError("cursor_on: not supported in the hex view")
    if isinstance(w, GraphView):
        raise ValueError("cursor_on: not supported in the graph view — use "
                         "graph {action:'block'} or goto")
    if isinstance(w, DecompView):
        texts = list(w._texts)
    else:
        texts = [(w._line_plain(i) or "") for i in range(getattr(w, "total", 0))]
    orig = (w.cursor, w.cursor_x)
    if line is not None:
        rows = [line]
    else:
        # From the top of the viewport, then wrap round to what's above it.
        top = round(w.scroll_offset.y)
        rows = list(range(top, len(texts))) + list(range(0, top))
    hits = 0
    for i in rows:
        if not (0 <= i < len(texts)):
            continue
        t = texts[i]
        col = t.find(word)
        while col != -1:
            w.cursor, w.cursor_x = i, col
            if w.word_under_cursor() == word:
                hits += 1
                if hits >= max(1, occurrence):
                    place_cursor(w)   # scrolls: an off-screen cursor edits blind
                    return True
            col = t.find(word, col + 1)
    w.cursor, w.cursor_x = orig  # not found: leave the cursor untouched
    return False


def functions(app, flt: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    idx = app._func_index
    if idx is None:
        return []
    flt = (flt or "").lower()
    out = []
    for f in idx.all_loaded():
        if flt and flt not in f.name.lower():
            continue
        out.append({"ea": f.addr, "name": f.name, "size": f.size})
        if len(out) >= limit:
            break
    return out


def _target_ea(app, target) -> int | None:
    """Resolve a target (None=current function, a name, or 0xADDR/int) to an ea."""
    if target is None:
        return app._cur.ea if app._cur else None
    if isinstance(target, int):
        return target
    return app.program.resolve(str(target))


def _func_at(app, ea: int | None):
    return app.program.function_of(ea) if ea is not None else None


def pseudocode(app, target=None) -> dict[str, Any]:
    """Full decompiled body of a function (the whole thing, not the viewport)."""
    ea = _target_ea(app, target)
    fn = _func_at(app, ea)
    dea = fn.addr if fn else ea
    if dea is None:
        return {"ea": None, "error": "no target"}
    d = app.program.decompile(dea)
    return {"ea": dea, "name": (fn.name if fn else None), "failed": d.failed,
            "error": d.error, "truncated": d.truncated, "code": d.code}


def disassembly(app, target=None, max_lines: int = 2000) -> dict[str, Any]:
    """Full (bounded) disassembly of a function as text."""
    ea = _target_ea(app, target)
    fn = _func_at(app, ea)
    dea = fn.addr if fn else ea
    if dea is None:
        return {"ea": None, "error": "no target"}
    m = app.program.disasm(dea, fn.name if fn else None)
    total = m.total()
    lines = m.lines(0, min(total, max(1, max_lines)), prefetch=False)
    return {"ea": dea, "name": (fn.name if fn else None), "total": total,
            "lines": [{"ea": ln.ea, "text": ln.text} for ln in lines]}


def _xref_dicts(xs, limit: int) -> list[dict[str, Any]]:
    return [{"frm": x.frm, "to": x.to, "type": x.type, "kind": x.kind,
             "fn_addr": x.fn_addr, "fn_name": x.fn_name} for x in xs[:limit]]


def xrefs_to(app, target, limit: int = 200) -> list[dict[str, Any]]:
    ea = _target_ea(app, target)
    return _xref_dicts(app.program.xrefs_to(ea), limit) if ea is not None else []


def xrefs_from(app, target, limit: int = 200) -> list[dict[str, Any]]:
    """References *out of* the target. For a function (a bare name / its entry ea)
    this is whole-body — the callees, string and data refs from the decompiler
    (the server's xrefs_from is address-scoped, so it only sees the entry
    instruction). For an explicit mid-function 0xADDR it stays address-scoped."""
    ea = _target_ea(app, target)
    if ea is None:
        return []
    fn = app.program.function_of(ea)
    if fn is not None and fn.addr == ea:  # function target -> decomp outgoing refs
        out = []
        for r in app.program.decompile(ea).refs[:limit]:
            tf = app.program.function_of(r.addr)
            is_func = bool(tf and tf.addr == r.addr)
            out.append({"to": r.addr, "name": r.name or (tf.name if tf else None),
                        "string": r.string, "is_func": is_func,
                        "type": "code" if is_func else "data"})
        return out
    return _xref_dicts(app.program.xrefs_from(ea), limit)


def resolve(app, name) -> dict[str, Any]:
    try:
        return {"ea": app.program.resolve(str(name))}
    except Exception:  # noqa: BLE001
        return {"ea": None}


# --------------------------------------------------------------------------- #
# Keystroke injection
# --------------------------------------------------------------------------- #
def _text_to_keys(text: str, delay_ms: int = 0) -> list[str]:
    """Each printable char becomes a key; interleave wait:<ms> for the typed-out
    aesthetic (App._press_keys understands 'wait:NN')."""
    keys: list[str] = []
    for i, ch in enumerate(text):
        if delay_ms and i:
            keys.append(f"wait:{delay_ms}")
        keys.append(ch)
    return keys


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
class RpcServer:
    def __init__(self, app, path: str):
        self.app = app
        self.path = path
        self._server: asyncio.AbstractServer | None = None
        self._busy = False  # single-driver gate: one client connection at a time

    async def start(self) -> None:
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass
        self._server = await asyncio.start_unix_server(self._on_client, path=self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass

    async def _on_client(self, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        if self._busy:
            # No multi-driver support yet: refuse a second concurrent client
            # rather than let two drivers interleave mutations.
            try:
                writer.write(json.dumps(
                    {"id": None, "error": {"message": "busy: another client is "
                     "connected (single-driver only)"}}).encode() + b"\n")
                await writer.drain()
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            return
        self._busy = True
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break
                resp = await self._handle_line(line)
                writer.write(json.dumps(resp).encode() + b"\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._busy = False
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle_line(self, line: bytes) -> dict[str, Any]:
        rid = None
        try:
            req = json.loads(line.decode())
            rid = req.get("id")
            method = req.get("method")
            params = req.get("params") or {}
            result = await self._dispatch(method, params)
            return {"id": rid, "result": result}
        except Exception as e:  # noqa: BLE001 — report, never kill the connection
            # ``str(KeyError("msg"))`` returns ``repr("msg")`` (adds quotes), which
            # mangles our friendly resolve messages; unwrap the single arg instead.
            if isinstance(e, KeyError) and len(e.args) == 1 and isinstance(e.args[0], str):
                msg = e.args[0]
            else:
                msg = str(e)
            return {"id": rid, "error": {"message": f"{type(e).__name__}: {msg}"}}

    # -- composed helpers (semantic verbs) -------------------------------- #
    async def _press(self, keys, pred=None, timeout=20.0, what=""):
        await self.app._press_keys([str(k) for k in keys])
        ok = await settle(self.app, pred, timeout=timeout)
        if pred is not None and not ok:
            # Never report success for an action that did not happen: the caller
            # would go on to edit whatever the *previous* location was.
            raise TimeoutError(
                f"{what or 'action'} did not complete within {timeout}s "
                f"(still at {_where(self.app)}); retry with a larger timeout=")
        return snapshot(self.app)

    async def _graph(self, params, timeout):
        """Drive / read the control-flow graph.

        Everything goes through the real keys and the real view state, so a
        driver sees exactly what a person would -- and 'show' is a pure read,
        which is what you want between edits.
        """
        app = self.app
        action = str(params.get("action") or "show").lower()
        gv = app.query_one(GraphView)
        want_blocks = params.get("blocks", True) not in (False, "false", "0", 0)

        if action == "show":
            return {**snapshot(app), "graph": graph_info(app, blocks=want_blocks)}
        if action in ("open", "toggle", "close"):
            if action == "open" and app._active == "graph":
                return {**snapshot(app), "graph": graph_info(app, blocks=want_blocks)}
            if action == "close" and app._active != "graph":
                return {**snapshot(app), "graph": graph_info(app, blocks=want_blocks)}
            want = "graph" if action in ("open", "toggle") and \
                app._active != "graph" else None
            res = await self._press(
                ["space"],
                (lambda: app._active == "graph") if want else
                (lambda: app._active != "graph"),
                timeout, f"graph {action}")
            return {**res, "graph": graph_info(app, blocks=want_blocks)}

        if app._active != "graph":
            raise ValueError(f"graph {action}: the graph is not open "
                             f"(graph {{action:'open'}} first)")
        if action == "zoom":
            before = gv._zoom
            await self._press(["z"], lambda: gv._zoom != before, timeout, "graph zoom")
        elif action == "entry":
            await self._press(["0"], None, timeout, "graph entry")
        elif action in ("succ", "pred"):
            before = gv.cursor_node
            await self._press(["J" if action == "succ" else "K"],
                              lambda: gv.cursor_node != before, timeout,
                              f"graph {action}")
        elif action == "block":
            target = params.get("target")
            if target is None:
                raise ValueError("graph block: need target=<block id|0xADDR>")
            nid = None
            s = str(target)
            if s.startswith("0x") or s.startswith("0X"):
                ea = int(s, 16)
                b = gv.fc.block_at(ea) if gv.fc else None
                if b is None:
                    raise ValueError(f"graph block: {s} is not in this graph")
                nid = b.id
            else:
                nid = int(s)
                if gv.lay is None or nid not in gv.lay.by_id:
                    raise ValueError(f"graph block: no block {nid}")
            gv.cursor_node = nid
            gv.cursor_row = 0
            gv.cursor_x = 0
            gv._clamp_cursor()
            gv._center_cursor()
            gv.refresh()
            await settle(app, None, timeout=2)
        else:
            raise ValueError(f"graph: unknown action {action!r}")
        return {**snapshot(app), "graph": graph_info(app, blocks=want_blocks)}

    async def _fill_prompt(self, open_key, input_id, value, delay_ms, clear):
        """Open a prompt (a keystroke), optionally clear its prefill, type the
        value with the typed-out delay, submit. Returns after the prompt closes."""
        from textual.widgets import Input
        app = self.app
        await app._press_keys([open_key])
        await settle(app, lambda: app.query_one(f"#{input_id}", Input).display, timeout=10)
        inp = app.query_one(f"#{input_id}", Input)
        if not inp.display:
            # Say *why*. The old message always blamed the word under the cursor,
            # which sent readers hunting for a cursor problem when the real cause
            # was usually a modal eating the opening keystroke.
            modal = type(app.screen).__name__
            why = (f"modal {modal!r} has focus and ate the {open_key!r} keystroke"
                   if modal in _MODALS or modal != "Screen"
                   else "no renameable token under the cursor")
            raise RuntimeError(f"{input_id!r} prompt did not open: {why}")
        if clear:
            inp.value = ""
        await app._press_keys(_text_to_keys(value, delay_ms))
        await app._press_keys(["enter"])

    async def _rename_many(self, params: dict[str, Any], timeout: float) -> dict:
        """Apply a whole symbol file in one worker call.

        The per-symbol path (goto + typed rename prompt) is the right thing for
        one name a human is watching, and hopeless for the case a firmware image
        always brings: hundreds of names from a loader map, an emulator's
        symbols.json, or another tool's export. Each of those renames costs a
        navigation (which pulls a listing page and a decompile) plus two prompt
        round-trips, so 400 symbols is tens of minutes of driving and the pane
        just flickers. IDA's own rename tool already takes a *list*; this hands
        it the whole list, then refreshes the caches and the function table once.
        """
        app = self.app
        items = params.get("items")
        src = params.get("file")
        if isinstance(items, str):        # `drive raw` hands params through as text
            items = json.loads(items)
        if items is None:
            if not src:
                raise ValueError("rename_many needs items=[{addr,name}] or file=<json>")
            with open(os.path.expanduser(str(src))) as f:
                items = json.load(f)
        if isinstance(items, dict):       # {"0x4370": "name"} is a natural shape too
            items = [{"addr": k, "name": v} for k, v in items.items()]
        if not isinstance(items, list) or not items:
            raise ValueError("rename_many: items must be a non-empty list")

        ops, skipped = [], 0
        for it in items:
            if not isinstance(it, dict):
                skipped += 1
                continue
            # Accept the field names symbol files actually use.
            addr = next((it[k] for k in ("addr", "start", "ea", "address")
                         if it.get(k) is not None), None)
            name = it.get("name") or it.get("label")
            if addr is None or not name:
                skipped += 1
                continue
            ea = int(str(addr), 0) if isinstance(addr, str) else int(addr)
            ops.append({"addr": hex(ea), "name": str(name)})
        if not ops:
            raise ValueError("rename_many: no usable {addr,name} entries")

        overwrite = params.get("allow_overwrite", True)
        if isinstance(overwrite, str):
            overwrite = overwrite.lower() not in ("0", "false", "no", "")
        batch = {"func": ops, "allow_overwrite": bool(overwrite)}
        # The worker is blocking and single-threaded; off the event loop it goes,
        # or the TUI freezes for the length of the batch.
        res = await asyncio.to_thread(app.program.client.call, "rename", batch=batch)
        summary = res.get("summary", {}) if isinstance(res, dict) else {}
        failed = [r for r in (res.get("func") or []) if isinstance(r, dict)
                  and r.get("error")] if isinstance(res, dict) else []

        # Names live in the IDB, but every cache in front of it is now stale --
        # including Hex-Rays', which is per-function and does NOT notice that a
        # *callee* was renamed. That cache is persisted in the .i64, so without
        # this a batch import leaves pseudocode calling sub_98C0 forever while
        # the listing (and every readback) says memset.
        try:
            await asyncio.to_thread(app.program.client.call, "force_recompile")
        except Exception:  # noqa: BLE001 -- older worker without the tool
            pass
        app.program.bump_names()
        app.program.invalidate_functions()
        app._func_index = None
        app._load_functions()             # re-streams the function table
        await settle(app, timeout=timeout)
        app._dirty = True
        app._status(f"renamed {summary.get('ok', 0)} symbols"
                    + (f", {len(failed)} failed" if failed else "")
                    + "   (Ctrl+S to save)")
        snap = snapshot(app)
        snap["rename_many"] = {
            "requested": len(ops), "skipped": skipped,
            "ok": summary.get("ok", 0), "failed": summary.get("failed", 0),
            "errors": [{"addr": r.get("addr"), "error": r.get("error")}
                       for r in failed[:10]],
        }
        return snap

    def _goto_target_pred(self, target):
        """A predicate that holds once a goto to ``target`` has landed."""
        app = self.app
        try:
            ea = app.program.resolve(target)
        except Exception:  # noqa: BLE001 — unknown name; caller falls back to generic
            return None
        if app._active == "hex":
            return lambda: app.query_one(HexView).cursor_va() == ea
        fn = app.program.function_of(ea)
        want = fn.addr if fn else ea
        return lambda: app._cur is not None and app._cur.ea == want

    #: Verbs that drive the *main* app by injecting keystrokes. If a modal is on
    #: top it eats those keys, so they must refuse rather than silently no-op.
    _NEEDS_NO_MODAL = {
        "goto", "open", "rename", "comment", "retype", "follow", "back",
        "toggle_view", "hex", "save", "search", "move", "cursor", "cursor_on",
        "define", "opfmt",
    }
    #: Modals the driver is expected to interact with (they have their own verbs).
    _DRIVABLE_MODALS = {"XrefsScreen", "SymbolPalette", "StructEditor",
                        "ProjectPalette", "QuitScreen"}

    def _modal_kind(self) -> str | None:
        scr = self.app.screen
        name = type(scr).__name__
        return name if name in _MODALS or name in self._DRIVABLE_MODALS else None

    async def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        app = self.app
        params = _coerce_params(params)
        if method in self._NEEDS_NO_MODAL:
            modal = self._modal_kind()
            if modal is not None:
                raise RuntimeError(
                    f"modal {modal!r} is on top and will swallow this verb's "
                    f"keystrokes; dismiss it first (close) or use its own verb "
                    f"(select/symbols/xrefs). Note: a binary with no entry "
                    f"function can land in the symbol palette on startup.")
        if method in (None, "ping"):
            module = None
            try:
                module = app._module() if app.client else None
            except Exception:  # noqa: BLE001
                pass
            return {"ok": True, "proto": PROTO_VERSION, "module": module,
                    **_readiness(app)}
        if method == "methods":
            return METHODS
        if method == "quit":
            # Route through the same teardown a human gets, so a dirty database
            # is written instead of dropped. `app.exit()` alone skips the dirty
            # check entirely, and the caller (pane stop) then kills the pane --
            # which used to destroy a whole session's annotations.
            dirty = list(app._dirty_labels())
            save = params.get("save", True)
            if isinstance(save, str):
                save = save.lower() not in ("0", "false", "no", "")

            def _go():
                if dirty and save:
                    app._on_quit_choice("save")   # saves, then exits
                else:
                    app._on_quit_choice("discard")

            # answer first, then tear down (so this response still gets written)
            asyncio.get_running_loop().call_later(0.2, _go)
            return {"ok": True, "quitting": True, "saving": bool(dirty and save),
                    "dirty": dirty}

        if method in _PROGRAM_METHODS and app.program is None:
            raise ValueError("not ready: still connecting / loading functions")

        if method == "keys":
            keys = params.get("keys") or []
            if not isinstance(keys, list):
                raise ValueError("keys must be a list")
            await app._press_keys([str(k) for k in keys])
            if params.get("settle", True):
                await settle(app, timeout=float(params.get("timeout", 20.0)))
            return snapshot(app)

        if method == "text":
            text = str(params.get("text", ""))
            keys = _text_to_keys(text, int(params.get("delay_ms", 0)))
            await app._press_keys(keys)
            if params.get("settle", True):
                await settle(app, timeout=float(params.get("timeout", 20.0)))
            return snapshot(app)

        if method == "state":
            return snapshot(app)
        if method == "view":
            return view_lines(app, params.get("lines"))
        if method == "screen":
            return screen_text(app, str(params.get("format", "text")))
        if method == "functions":
            return functions(app, params.get("filter"), int(params.get("limit", 50)))

        # -- projects ------------------------------------------------------ #
        if method == "trace":
            if app._trace is None:
                raise ValueError("no trace loaded (launch with --trace FILE)")
            t = app._trace
            if "seek" in params:
                v = params["seek"]
                # "!50" seeks a percentage, like Tenet's timestamp shell.
                if isinstance(v, str) and v.startswith("!"):
                    idx = int(float(v[1:]) * (t.length - 1) / 100.0)
                else:
                    idx = int(str(v).replace(",", ""), 0) if isinstance(v, str) else int(v)
                app._seek(idx)
            elif "goto" in params:      # first execution of an address/name
                tgt = params["goto"]
                ea = (int(str(tgt), 0) if str(tgt).lower().startswith("0x")
                      else app.program.resolve(str(tgt)))
                first = t.first_execution(ea)
                if first is None:
                    raise ValueError(f"{tgt} never executed in this trace")
                app._seek(first)
            elif "step" in params:
                n = int(params.get("step") or 1)
                over = bool(params.get("over"))
                for _ in range(abs(n)):
                    (app._step_over if over else app._step)(1 if n > 0 else -1)
            await settle(app, timeout=float(params.get("timeout", 20.0)))
            snap = snapshot(app)
            snap["trace"] = {"idx": app._t, "length": t.length,
                             "pc": hex(t.ip(app._t)),
                             "changed": sorted(t.changed(app._t))}
            return snap

        if method == "binaries":
            if app._project is None:
                raise ValueError("not a project session (launch with --project)")
            counts = app._index.counts() if app._index is not None else {}
            resident = set(app._pool.resident()) if app._pool is not None else set()
            return {"active": app._binary, "hops": list(app._hops),
                    "binaries": [{"label": r.label, "source": r.source,
                                  "active": r.label == app._binary,
                                  "resident": r.label in resident,
                                  "indexed": int(counts.get(r.label, 0))}
                                 for r in app._project.refs]}

        if method == "switch":
            if app._project is None:
                raise ValueError("not a project session (launch with --project)")
            label = str(params.get("binary") or params.get("label") or "")
            if app._project.by_label(label) is None:
                have = ", ".join(r.label for r in app._project.refs)
                raise ValueError(f"no such binary {label!r} (have: {have})")
            addr = params.get("addr")
            if label == app._binary and addr is None:
                return snapshot(app)
            if addr is None:
                app._switch_binary(label)
            else:
                # Same path a project search hit takes, so it records a hop and
                # Esc comes back here.
                app._switch_then_goto(label, int(str(addr), 0)
                                      if isinstance(addr, str) else int(addr))
            await settle(app, lambda: app._binary == label
                         and app._func_index is not None
                         and app._func_index.complete,
                         timeout=float(params.get("timeout", 300.0)))
            return snapshot(app)

        # -- structured introspection (heavy: run off the UI loop) -------- #
        loop = asyncio.get_running_loop()
        if method == "pseudocode":
            return await loop.run_in_executor(None, pseudocode, app, params.get("target"))
        if method == "disassembly":
            mx = int(params.get("max", 2000))
            return await loop.run_in_executor(
                None, disassembly, app, params.get("target"), mx)
        if method == "xrefs_to":
            lim = int(params.get("limit", 200))
            return await loop.run_in_executor(
                None, xrefs_to, app, params.get("target"), lim)
        if method == "xrefs_from":
            lim = int(params.get("limit", 200))
            return await loop.run_in_executor(
                None, xrefs_from, app, params.get("target"), lim)
        if method == "resolve":
            return await loop.run_in_executor(None, resolve, app, params.get("name"))

        # -- semantic verbs (typed-with-delay high-level ops) ------------- #
        delay = int(params.get("delay_ms", TYPE_DELAY_MS))
        timeout = float(params.get("timeout", 20.0))

        # optional ergonomic: place the cursor on a token before an edit/follow
        if method in ("rename", "retype", "follow") and params.get("word"):
            if not cursor_on(app, str(params["word"]), params.get("line"),
                             int(params.get("occurrence", 1))):
                raise ValueError(f"cursor_on: token {params['word']!r} not found "
                                 "in the current view")
            await drain(app)

        if method == "cursor_on":
            found = cursor_on(app, str(params["word"]), params.get("line"),
                              int(params.get("occurrence", 1)))
            await drain(app)
            snap = snapshot(app)
            snap["found"] = found
            return snap

        if method in ("goto", "open"):
            target = str(params.get("target", ""))
            pred = self._goto_target_pred(target)
            await self._fill_prompt("g", "goto", target, delay, clear=False)
            ok = await settle(app, pred, timeout=timeout)
            if pred is not None and not ok:
                # A goto that silently "succeeds" without moving is worse than an
                # error: on a big database the listing build can outrun the
                # default timeout, and every subsequent rename/comment then lands
                # on the function the caller *used* to be looking at.
                raise TimeoutError(
                    f"goto {target!r} did not land within {timeout}s "
                    f"(still at {_where(app)}); retry with a larger timeout=")
            return snapshot(app)

        if method == "define":
            kind = str(params.get("kind", "code")).lower()
            if kind not in _DEFINE_KEYS:
                raise ValueError(
                    f"unknown define kind {kind!r}; one of "
                    f"{', '.join(sorted(_DEFINE_KEYS))}")
            target = params.get("target")
            if target not in (None, ""):
                # Land on the address first. A raw image is mostly *undefined*,
                # so the target usually has no name and no function — the goto
                # predicate can't be address-based, only "we moved".
                await self._fill_prompt("g", "goto", str(target), delay,
                                        clear=False)
                await settle(app, timeout=timeout)
            if app._active == "hex":
                # backslash leaves hex for the code view (which may be decomp).
                await self._press(["backslash"],
                                  lambda: app._active != "hex", timeout,
                                  "leave the hex view")
            if app._active == "decomp":
                # These bindings live on the listing; in the decompiler the key
                # would be swallowed or do something else entirely.
                await self._press(["tab"], lambda: app._active == "listing",
                                  timeout, "switch to the listing")
            if app._active != "listing":
                raise RuntimeError(
                    f"define needs the listing view, but the active pane is "
                    f"{app._active!r}")
            snap = await self._press([_DEFINE_KEYS[kind]], timeout=timeout,
                                     what=f"define {kind}")
            snap["define"] = {"kind": kind, "status": snap.get("status", "")}
            return snap

        if method == "opfmt":
            mode = str(params.get("mode", "cycle")).lower()
            if mode not in _OPFMT_MODES:
                raise ValueError(f"unknown opfmt mode {mode!r}; one of "
                                 f"{', '.join(_OPFMT_MODES)}")
            target = params.get("target")
            if target not in (None, ""):
                await self._fill_prompt("g", "goto", str(target), delay,
                                        clear=False)
                await settle(app, timeout=timeout)
            if app._active == "hex":
                await self._press(["backslash"], lambda: app._active != "hex",
                                  timeout, "leave the hex view")
            view = _active_widget(app)
            if isinstance(view, HexView):
                raise RuntimeError("opfmt needs a code view, not the hex view")
            if params.get("word"):
                # Land the column on the literal first: WHICH operand gets
                # reformatted is decided by where the cursor is.
                if not cursor_on(app, str(params["word"]), params.get("line"),
                                 int(params.get("occurrence", 1) or 1)):
                    raise RuntimeError(
                        f"{params['word']!r} is not on screen in this view, so "
                        f"there is no literal to reformat")
                await drain(app)
            elif params.get("line") is not None or params.get("col") is not None:
                place_cursor(view, params.get("line"), params.get("col"))
                await drain(app)
            before = _where(app)
            if mode in _OPFMT_KEYS:
                snap = await self._press([_OPFMT_KEYS[mode]], timeout=timeout,
                                         what=f"opfmt {mode}")
            else:
                view.focus()
                view.action_op_format(mode)
                await settle(app, timeout=timeout)
                snap = snapshot(app)
            snap["opfmt"] = {"mode": mode, "at": before,
                             "status": snap.get("status", "")}
            return snap

        if method == "rename_many":
            return await self._rename_many(params, timeout)

        if method == "rename":
            await self._fill_prompt("n", "rename", str(params["name"]), delay, clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)
        if method == "comment":
            # Comments can be long; skip the per-char delay so the agent isn't
            # blocked for seconds watching the typing animation.  Also: the
            # prompt is single-line, so literal newlines (0x0a) get swallowed by
            # the Input widget.  The app's _do_comment converts the two-char
            # sequence '\n' into a real newline for IDA, so we escape here.
            ctext = str(params["text"]).replace("\n", "\\n")
            await self._fill_prompt("semicolon", "comment", ctext, 0,
                                    clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)
        if method == "retype":
            await self._fill_prompt("y", "retype", str(params["proto"]), delay, clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)

        if method == "follow":
            depth = len(app._nav)
            return await self._press(["enter"], lambda: len(app._nav) > depth,
                                     timeout, "follow")
        if method == "back":
            return await self._press(["escape"], timeout=timeout)
        if method == "toggle_view":
            before = app._active

            def _toggled():
                # Normal case: the shown view flipped.
                if app._active != before:
                    return True
                # Fallback case: a tab toward pseudocode on a function Hex-Rays
                # can't decompile snaps `_active` back to disasm (see
                # App._apply_decomp), so `_active` never changes and the naive
                # `_active != before` predicate would block for the full
                # timeout. Treat "requested decomp but it's known-failed" as
                # settled (the decompile is cached, so this is cheap).
                cur = app._cur
                if before == "disasm" and cur is not None:
                    try:
                        return app.program.decompile(cur.ea).failed
                    except Exception:  # noqa: BLE001
                        return False
                return False

            return await self._press(["tab"], _toggled, timeout, "toggle_view")
        if method == "hex":
            return await self._press(["backslash"], lambda: app._active == "hex",
                                     timeout, "hex")
        if method == "graph":
            return await self._graph(params, timeout)
        if method == "xrefs":
            return await self._press(
                ["x"], lambda: type(app.screen).__name__ == "XrefsScreen",
                timeout, "xrefs")
        if method == "symbols":
            await app._press_keys(["ctrl+n"])
            await settle(app, lambda: type(app.screen).__name__ == "SymbolPalette", timeout=10)
            q = params.get("query")
            if q:
                await app._press_keys(_text_to_keys(str(q), delay))
            await settle(app, timeout=timeout)
            return snapshot(app)
        if method == "structs":
            return await self._press(
                ["ctrl+t"], lambda: type(app.screen).__name__ == "StructEditor",
                timeout, "structs")
        if method == "close":
            return await self._press(["escape"], timeout=timeout)
        if method == "save":
            return await self._press(["ctrl+s"], timeout=timeout)

        if method == "search":
            term = str(params.get("term", ""))
            open_key = "slash" if int(params.get("direction", 1)) >= 0 else "question_mark"
            await self._fill_prompt(open_key, "search", term, delay, clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)

        if method == "select":
            from textual.widgets import OptionList
            scr = app.screen
            if type(scr).__name__ not in _MODALS:
                raise ValueError("select: no modal list is open")
            try:
                ol = scr.query_one(OptionList)
            except Exception:
                raise ValueError("select: the open modal has no list to select from")
            idx = params.get("index")
            if idx is not None and ol.option_count:
                ol.highlighted = max(0, min(ol.option_count - 1, int(idx)))
                await drain(app)
            await app._press_keys(["enter"])
            await settle(app, timeout=timeout)
            return snapshot(app)

        if method == "move":
            key = _MOVE_KEYS.get(str(params.get("dir")))
            if key is None:
                raise ValueError(f"unknown move dir: {params.get('dir')!r} "
                                 f"(one of {sorted(_MOVE_KEYS)})")
            n = max(1, int(params.get("n", 1)))
            await app._press_keys([key] * n)
            if params.get("settle", True):
                await drain(app)  # light: pump only, keep movement snappy
            return snapshot(app)

        if method == "cursor":
            w = _active_widget(app)
            if isinstance(w, HexView):
                raise ValueError("cursor: not supported in the hex view (use goto)")
            place_cursor(w, params.get("line"), params.get("col"))
            await drain(app)
            return snapshot(app)

        raise ValueError(f"unknown method: {method!r}")
