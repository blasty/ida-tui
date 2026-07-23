#!/usr/bin/env python
"""Throwaway spike: in-process idalib vs the ida-mcp HTTP transport.

This is NOT wired into the app. It exists to make the "should idatui keep the
MCP transport or interface with IDA directly?" question a decision you can feel
and measure, behind a tiny Backend seam that mirrors idatui's hot paths.

    # A/B latency table (opens a COPY in-process; also hits a running server
    # on :8745 if there is one, so you can compare apples to apples):
    ~/ida-venv/bin/python experiments/inproc_spike.py --bench [--n 400]

    # tiny Textual app on the IN-PROCESS backend. F5/Enter decompiles the
    # selected function INLINE on the event loop, so you feel the main-thread
    # hitch; 'd' decompiles every function in a row (a big, obvious freeze):
    ~/ida-venv/bin/python experiments/inproc_spike.py --tui

Key facts this spike encodes (all verified):
  * idalib must be imported/opened on the MAIN python thread (it installs a
    SIGINT handler) and every call must be on that same thread ("Function can be
    called from the main thread only"); execute_sync from a worker thread hangs.
    => DirectBackend opens the DB in main() and is only ever called from the
       Textual event loop (also the main thread). No worker threads touch IDA.
  * That is exactly why the mcp path stays responsive: the blocking happens in
    another process, so the TUI's event loop never blocks. In-process, a slow
    call (decompile ~150ms, analysis seconds) blocks the UI for its duration.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from typing import Protocol

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)


# --------------------------------------------------------------------------- #
# The seam: the handful of hot operations idatui actually leans on.
# --------------------------------------------------------------------------- #
class Backend(Protocol):
    def functions(self) -> list[tuple[int, str]]: ...
    def resolve(self, name: str) -> int | None: ...
    def read_bytes(self, ea: int, n: int) -> bytes: ...
    def disasm_line(self, ea: int) -> str: ...
    def decompile(self, ea: int) -> str: ...
    def xrefs_to(self, ea: int) -> list[int]: ...
    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
# In-process idalib. MUST be constructed on the main thread.
# --------------------------------------------------------------------------- #
class DirectBackend:
    name = "direct (in-process idalib)"

    def __init__(self, path: str) -> None:
        import idapro
        idapro.enable_console_messages(False)
        t = time.time()
        rc = idapro.open_database(path, run_auto_analysis=True)
        self.open_secs = time.time() - t
        if rc:
            raise RuntimeError(f"open_database({path!r}) failed rc={rc}")
        import ida_bytes, ida_funcs, ida_hexrays, ida_name, idaapi, idautils, idc
        self._idapro = idapro
        self.idaapi, self.idautils, self.idc = idaapi, idautils, idc
        self.ida_bytes, self.ida_hexrays = ida_bytes, ida_hexrays
        self.ida_funcs, self.ida_name = ida_funcs, ida_name

    def functions(self):
        return [(ea, self.idc.get_func_name(ea)) for ea in self.idautils.Functions()]

    def resolve(self, name):
        ea = self.idc.get_name_ea_simple(name)
        return None if ea == self.idaapi.BADADDR else ea

    def read_bytes(self, ea, n):
        return self.ida_bytes.get_bytes(ea, n) or b""

    def disasm_line(self, ea):
        return self.idaapi.tag_remove(self.idaapi.generate_disasm_line(ea, 0) or "")

    def decompile(self, ea):
        return str(self.ida_hexrays.decompile(ea))

    def xrefs_to(self, ea):
        return [x.frm for x in self.idautils.XrefsTo(ea)]

    def close(self):
        try:
            self._idapro.close_database(save=False)
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# The current path: everything is an HTTP/JSON tool call to the mcp worker.
# --------------------------------------------------------------------------- #
class McpBackend:
    name = "mcp (HTTP/JSON transport)"

    def __init__(self, url: str = "http://127.0.0.1:8745/mcp", db: str | None = None):
        if REPO not in sys.path:  # idalib's init can reset sys.path out from under us
            sys.path.insert(0, REPO)
        from idatui.client import IDAClient
        self.IDAClient = IDAClient
        self.c = IDAClient(url, db=db)
        self.c.connect()
        if db is None:
            self.c.set_db(self.c.resolve_db())

    def functions(self):
        out: list[tuple[int, str]] = []
        off = 0
        while True:
            r = self.c.call("list_funcs", queries=[{"offset": off, "count": 1000}])
            res = r.get("result", r) if isinstance(r, dict) else r
            rows = res[0].get("funcs", []) if res and isinstance(res[0], dict) else []
            if not rows:
                break
            for fn in rows:
                out.append((int(fn["addr"], 16), fn.get("name", "")))
            off += len(rows)
            if len(rows) < 1000:
                break
        return out

    def resolve(self, name):
        r = self.c.call("resolve_names", queries=[name])
        res = r.get("result", []) if isinstance(r, dict) else []
        ea = res[0].get("ea") if res and isinstance(res[0], dict) else None
        return int(ea, 16) if ea else None

    def read_bytes(self, ea, n):
        r = self.c.call("read_raw", addr=hex(ea), size=int(n))
        return bytes.fromhex(r["hex"]) if isinstance(r, dict) and r.get("hex") else b""

    def disasm_line(self, ea):
        r = self.c.call("heads", addr=hex(ea), count=1)
        rows = r.get("heads", []) if isinstance(r, dict) else []
        return rows[0].get("text", "") if rows else ""

    def decompile(self, ea):
        r = self.c.call("decompile", addr=hex(ea))
        return r.get("code", "") if isinstance(r, dict) else str(r)

    def xrefs_to(self, ea):
        r = self.c.call("xref_query", queries=[{"addr": hex(ea), "direction": "to",
                                                "include_fn": True, "count": 2000}])
        res = r.get("result", []) if isinstance(r, dict) else []
        refs = res[0].get("refs", []) if res and isinstance(res[0], dict) else []
        return [int(x["frm"], 16) for x in refs if x.get("frm")]

    def close(self):
        try:
            self.c.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# bench
# --------------------------------------------------------------------------- #
def _time(fn, n):
    # warm once (caches, jit-ish), then time n calls
    fn()
    t = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t) / n * 1e6  # us/call


def bench(target: str, n: int) -> None:
    tmp = "/tmp/inproc_spike_target"
    shutil.copy(target, tmp)
    for e in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        try:
            os.remove(tmp + e)
        except OSError:
            pass
    print(f"opening {os.path.basename(target)} in-process (main thread)…", flush=True)
    direct = DirectBackend(tmp)
    print(f"  open+analysis: {direct.open_secs:.2f}s\n", flush=True)

    funcs = direct.functions()
    sample = [ea for ea, _ in funcs[: min(40, len(funcs))]]
    main = direct.resolve("main") or sample[0]

    mcp = None
    try:
        import socket
        socket.create_connection(("127.0.0.1", 8745), 0.3).close()
        mcp = McpBackend()
        print("also benching the running mcp server on :8745\n", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"(no mcp server on :8745 — direct-only numbers)  [{e}]\n", flush=True)

    ops = {
        "resolve(main)":        (lambda b: b.resolve("main"), n),
        "read_bytes(main,16)":  (lambda b: b.read_bytes(main, 16), n),
        "read_bytes(main,4096)": (lambda b: b.read_bytes(main, 4096), n),
        "disasm_line(main)":    (lambda b: b.disasm_line(main), n),
        "xrefs_to(sample)":     (lambda b, i=[0]: b.xrefs_to(sample[i.__setitem__(0,(i[0]+1)%len(sample)) or i[0]]), min(n, 200)),
        "decompile(cached)":    (lambda b: b.decompile(main), min(n, 40)),
    }
    print(f"{'op':22} {'direct us':>12} {'mcp us':>12} {'speedup':>9}")
    print("-" * 58)
    for label, (fn, cnt) in ops.items():
        d = _time(lambda: fn(direct), cnt)
        if mcp is not None:
            try:
                m = _time(lambda: fn(mcp), cnt)
                print(f"{label:22} {d:12.1f} {m:12.1f} {m/d:8.0f}x")
            except Exception as e:  # noqa: BLE001
                print(f"{label:22} {d:12.1f} {'ERR':>12}   ({e})")
        else:
            print(f"{label:22} {d:12.1f} {'-':>12} {'-':>9}")
    direct.close()
    if mcp:
        mcp.close()


# --------------------------------------------------------------------------- #
# tui — feel the inline hitch
# --------------------------------------------------------------------------- #
def _build_spike_app(backend: "DirectBackend"):
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal
    from textual.widgets import Footer, OptionList, Static
    from textual.widgets.option_list import Option

    class Spike(App):
        CSS = """
        #cols { height: 1fr; }
        OptionList { width: 42; border-right: solid $accent; }
        #code { width: 1fr; padding: 0 1; }
        #status { height: 1; background: $panel-darken-2; color: $text-muted; padding: 0 1; }
        """
        BINDINGS = [
            Binding("f5,enter", "decompile", "Decompile (inline)"),
            Binding("d", "decompile_all", "Decompile ALL (big freeze)"),
            Binding("b", "bytes", "Read bytes"),
            Binding("q", "quit", "Quit"),
        ]

        def compose(self) -> ComposeResult:
            with Horizontal(id="cols"):
                ol = OptionList(id="list")
                for ea, nm in backend.functions():
                    ol.add_option(Option(f"{ea:08x}  {nm}", id=str(ea)))
                yield ol
                yield Static("select a function, press F5 to decompile inline",
                             id="code")
            yield Static("in-process idalib — every call runs on the UI thread",
                         id="status")
            yield Footer()

        def on_mount(self):
            self.query_one("#list", OptionList).focus()

        def _sel_ea(self) -> int | None:
            ol = self.query_one("#list", OptionList)
            if ol.highlighted is None:
                return None
            return int(ol.get_option_at_index(ol.highlighted).id)

        def action_decompile(self):
            ea = self._sel_ea()
            if ea is None:
                return
            t = time.perf_counter()
            code = backend.decompile(ea)          # <-- BLOCKS the event loop
            dt = (time.perf_counter() - t) * 1e3
            self.query_one("#code", Static).update(
                "\n".join(code.splitlines()[:40]))
            self.query_one("#status", Static).update(
                f"decompiled {backend.idc.get_func_name(ea)} in {dt:.0f} ms "
                f"(UI was frozen for those {dt:.0f} ms)")

        def action_decompile_all(self):
            funcs = backend.functions()
            t = time.perf_counter()
            n = 0
            for ea, _ in funcs:
                try:
                    backend.decompile(ea)         # <-- long, uninterruptible freeze
                    n += 1
                except Exception:  # noqa: BLE001
                    pass
            dt = (time.perf_counter() - t) * 1e3
            self.query_one("#status", Static).update(
                f"decompiled {n} funcs in {dt:.0f} ms — the whole UI was frozen "
                f"the entire time (no spinner, no input)")

        def action_bytes(self):
            ea = self._sel_ea()
            if ea is None:
                return
            t = time.perf_counter()
            b = backend.read_bytes(ea, 64)
            dt = (time.perf_counter() - t) * 1e6
            self.query_one("#status", Static).update(
                f"read 64 bytes in {dt:.1f} us: {b[:16].hex()}…")

    return Spike()


def _open_copy(target: str) -> "DirectBackend":
    tmp = "/tmp/inproc_spike_target"
    shutil.copy(target, tmp)
    for e in (".i64", ".id0", ".id1", ".id2", ".nam", ".til"):
        try:
            os.remove(tmp + e)
        except OSError:
            pass
    print("opening in-process (blocks the terminal until analysis is done)…", flush=True)
    return DirectBackend(tmp)  # MAIN THREAD open, before the event loop starts


def tui(target: str) -> None:
    backend = _open_copy(target)
    try:
        _build_spike_app(backend).run()
    finally:
        backend.close()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--bench", action="store_true", help="A/B latency table")
    p.add_argument("--tui", action="store_true", help="feel the inline hitch")
    p.add_argument("--n", type=int, default=400, help="bench iterations")
    p.add_argument("--target", default=os.path.join(REPO, "targets", "echo"))
    args = p.parse_args(argv)
    if args.tui:
        tui(args.target)
    else:
        bench(args.target, args.n)


if __name__ == "__main__":
    main()
