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
from .app import DecompView, DisasmView, HexView

PROTO_VERSION = 1
TYPE_DELAY_MS = 35  # default per-char delay for high-level typed ops (aesthetic)

# Verbs that dereference app.program — refused with a clear error before load.
_PROGRAM_METHODS = {
    "goto", "open", "rename", "comment", "retype", "follow", "xrefs", "symbols",
    "structs", "search", "select", "save", "hex", "toggle_view",
    "pseudocode", "disassembly", "xrefs_to", "xrefs_from", "resolve",
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
    "comment": "{text,delay_ms?} comment the current line",
    "retype": "{proto,word?,delay_ms?} set the prototype/type under the cursor",
    "follow": "{word?} follow the reference under (or 'word') the cursor",
    "cursor_on": "{word,line?,occurrence?=1} place the cursor on a token",
    "back": "pop the nav stack",
    "toggle_view": "disasm <-> pseudocode",
    "hex": "hex view",
    "xrefs": "open the xref picker",
    "symbols": "{query?} open the symbol palette",
    "structs": "open the struct editor",
    "search": "{term,direction?=1} incremental search in the code view",
    "select": "{index?} choose the highlighted/nth item in the open modal",
    "save": "persist the .i64 (Ctrl+S)",
    "close": "dismiss a modal (Escape)",
    "move": "{dir,n?=1} fast movement (down/up/.../pagedown)",
    "cursor": "{line?,col?} set the code-pane cursor directly",
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
    if app._active == "disasm":
        return app.query_one(DisasmView)
    return app.query_one(DecompView)


_MODALS = ("XrefsScreen", "SymbolPalette", "StructEditor", "ConfirmScreen")


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
        "pref": app._pref,
        "function": ({"ea": cur.ea, "name": cur.name} if cur else None),
        "cursor": _cursor_info(app, w),
        "status": st,
        "filter": app._filter_term,
        "nav_depth": len(app._nav),
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


def cursor_on(app, word: str, line: int | None = None, occurrence: int = 1) -> bool:
    """Place the cursor on the ``occurrence``-th token equal to ``word`` in the
    active code pane (optionally restricted to ``line``). Verified with the app's
    own tokenizer so 'main' won't match inside 'domain'. Disasm scan is limited to
    already-cached lines (what's on/near screen); decomp searches the whole body.
    Returns whether it found and moved."""
    w = _active_widget(app)
    if isinstance(w, HexView):
        raise ValueError("cursor_on: not supported in the hex view")
    if isinstance(w, DecompView):
        texts = list(w._texts)
    else:
        texts = [(w._line_plain(i) or "") for i in range(getattr(w, "total", 0))]
    orig = (w.cursor, w.cursor_x)
    rows = [line] if line is not None else range(len(texts))
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
                    if hasattr(w, "_after_cursor_move"):
                        w._after_cursor_move()
                    w.refresh()
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
    return [{"frm": x.frm, "to": x.to, "type": x.type,
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
            return {"id": rid, "error": {"message": f"{type(e).__name__}: {e}"}}

    # -- composed helpers (semantic verbs) -------------------------------- #
    async def _press(self, keys, pred=None, timeout=20.0):
        await self.app._press_keys([str(k) for k in keys])
        await settle(self.app, pred, timeout=timeout)
        return snapshot(self.app)

    async def _fill_prompt(self, open_key, input_id, value, delay_ms, clear):
        """Open a prompt (a keystroke), optionally clear its prefill, type the
        value with the typed-out delay, submit. Returns after the prompt closes."""
        from textual.widgets import Input
        app = self.app
        await app._press_keys([open_key])
        await settle(app, lambda: app.query_one(f"#{input_id}", Input).display, timeout=10)
        inp = app.query_one(f"#{input_id}", Input)
        if not inp.display:
            raise RuntimeError(f"{input_id!r} prompt did not open (word under cursor?)")
        if clear:
            inp.value = ""
        await app._press_keys(_text_to_keys(value, delay_ms))
        await app._press_keys(["enter"])

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

    async def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        app = self.app
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
            # answer first, then tear down (so this response still gets written)
            asyncio.get_running_loop().call_later(0.2, app.exit)
            return {"ok": True, "quitting": True}

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
            await settle(app, pred, timeout=timeout)
            return snapshot(app)

        if method == "rename":
            await self._fill_prompt("n", "rename", str(params["name"]), delay, clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)
        if method == "comment":
            await self._fill_prompt("semicolon", "comment", str(params["text"]), delay,
                                    clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)
        if method == "retype":
            await self._fill_prompt("y", "retype", str(params["proto"]), delay, clear=True)
            await settle(app, timeout=timeout)
            return snapshot(app)

        if method == "follow":
            depth = len(app._nav)
            return await self._press(["enter"], lambda: len(app._nav) > depth, timeout)
        if method == "back":
            return await self._press(["escape"], timeout=timeout)
        if method == "toggle_view":
            before = app._active
            return await self._press(["tab"], lambda: app._active != before, timeout)
        if method == "hex":
            return await self._press(["backslash"], lambda: app._active == "hex", timeout)
        if method == "xrefs":
            return await self._press(
                ["x"], lambda: type(app.screen).__name__ == "XrefsScreen", timeout)
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
                ["ctrl+t"], lambda: type(app.screen).__name__ == "StructEditor", timeout)
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
            if "line" in params and params["line"] is not None:
                w.cursor = max(0, min(getattr(w, "total", 1) - 1, int(params["line"])))
            if "col" in params and params["col"] is not None:
                w.cursor_x = max(0, int(params["col"]))
            if hasattr(w, "_after_cursor_move"):
                w._after_cursor_move()
            w.refresh()
            await drain(app)
            return snapshot(app)

        raise ValueError(f"unknown method: {method!r}")
