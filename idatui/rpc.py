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

from ._sync import settle
from .app import DecompView, DisasmView, HexView

PROTO_VERSION = 1


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
        "loaded": app.program is not None and app._func_index is not None,
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


def screen_text(app) -> dict[str, Any]:
    """Plain-text render of the whole screen — exactly what the viewer sees."""
    width, height = app.size
    console = Console(width=width, height=height or 40, file=io.StringIO(),
                      force_terminal=True, color_system="truecolor", record=True,
                      legacy_windows=False, safe_box=False)
    render = app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens, simplify=False)
    console.print(render)
    return {"width": width, "height": height, "text": console.export_text(styles=False)}


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

    async def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        app = self.app
        if method in (None, "ping"):
            return {"ok": True, "proto": PROTO_VERSION, "loaded": app.program is not None}

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
            return screen_text(app)
        if method == "functions":
            return functions(app, params.get("filter"), int(params.get("limit", 50)))

        raise ValueError(f"unknown method: {method!r}")
