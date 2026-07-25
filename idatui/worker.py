"""idatui's own idalib worker — the replacement for the ida-pro-mcp supervisor.

Opens ONE database in-process (on the main thread, as idalib requires) and
serves ida-pro-mcp's *tool functions* over a unix socket with length-prefixed
pickle. Same tool implementations as the MCP path (we call
``MCP_SERVER.tools.methods[name](**args)`` directly), so return shapes are
byte-identical — but with ~50us/call instead of the HTTP path's ~5ms, and no
supervisor / HTTP / JSON / 50KB-truncation machinery.

    python -m idatui.worker <sock_path> <binary_path>

The socket only appears once the database is open + analyzed, so a client can
poll ``connect()`` to know when the worker is ready. Requests are served
serially on the main thread (idalib is single-threaded; every tool runs inline
through its own execute_sync, which is a no-op on the main thread).

Protocol (both directions length-prefixed: 4-byte big-endian len + pickle):
    request  = (tool_name: str, kwargs: dict)
    response = (ok: bool, result_or_error)
    tool_name == "__shutdown__" ends the worker.
"""
from __future__ import annotations

import os
import pickle
import socket
import struct
import sys
import uuid


# --------------------------------------------------------------------------- #
# framing
# --------------------------------------------------------------------------- #
def _recvn(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def send(sock: socket.socket, obj) -> None:
    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv(sock: socket.socket):
    hdr = _recvn(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    body = _recvn(sock, n)
    return None if body is None else pickle.loads(body)


# --------------------------------------------------------------------------- #
# worker
# --------------------------------------------------------------------------- #
def _ensure_tools_injected() -> None:
    """Inject idatui's custom tools (heads/read_raw/resolve_names/func_types/...)
    into the installed ida_pro_mcp, idempotently, so the worker is self-sufficient
    (nothing else has to inject these tools first). Must run BEFORE
    ida_pro_mcp.ida_mcp is imported (the injected code lives in api_types.py)."""
    import importlib.util
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    patch = os.path.join(repo, "server", "patch_server.py")
    if not os.path.exists(patch):
        return
    try:
        spec = importlib.util.spec_from_file_location("_idatui_patch", patch)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # IDA-free; just defines + patches api_types
        mod.main()
    except Exception as e:  # noqa: BLE001 -- tools may already be present
        sys.stderr.write(f"idatui: tool injection skipped: {e}\n")


def _has_database(binpath: str) -> bool:
    """Whether IDA already has a database for ``binpath``.

    IDA names it ``<file>.i64`` (keeping the extension), but a database made
    from ``foo.bin`` can also appear as ``foo.i64`` depending on how it was
    created — check both, because guessing wrong here means re-passing load
    switches to an existing database, which fails the open.
    """
    return (os.path.exists(binpath + ".i64")
            or os.path.exists(os.path.splitext(binpath)[0] + ".i64"))


def _open_and_register(binpath: str, load_args: str = ""):
    """Open the DB (main thread) then import ida-pro-mcp so every @tool registers
    against this live database. Returns (tools_dict, module_name, save_fn).

    ``load_args`` is passed to IDA as command-line switches, which is the only
    way to tell it how to read a headerless blob: a raw firmware image has no
    format to detect, so without ``-p<processor>`` it loads as metapc at 0 and
    finds nothing. Ignored once a database exists — the .i64 already records how
    it was loaded, and re-passing conflicting switches is how you corrupt one.
    """
    _ensure_tools_injected()  # before any ida_pro_mcp import
    import idapro
    idapro.enable_console_messages(False)
    args = load_args or None
    if args and _has_database(binpath):
        # The .i64 already records how this image was loaded. Passing the
        # switches again on reopen makes IDA fail outright (rc != 0) — the load
        # options belong to the FIRST open only.
        args = None
    if idapro.open_database(binpath, run_auto_analysis=True,
                            args=args):  # nonzero == failure
        raise RuntimeError(
            f"failed to open {binpath}: the .i64 is likely held by a running "
            f"ida-mcp worker (try: pkill -f idalib) or wedged from a crash "
            f"(delete its .id0/.id1/.id2/.nam/.til next to the binary)")
    import ida_auto
    ida_auto.auto_wait()  # block until auto-analysis settles (match ida-mcp)

    # importing the package registers all api_*/patched tools against MCP_SERVER
    from ida_pro_mcp.ida_mcp import MCP_SERVER  # noqa: WPS433

    import ida_nalt
    module = os.path.basename(ida_nalt.get_root_filename() or binpath)

    def save():
        import idc
        try:
            idc.save_database(idc.get_idb_path(), 0)
        except Exception:  # noqa: BLE001
            import ida_loader, ida_pro  # noqa: WPS433
            ida_loader.save_database(idc.get_idb_path(), 0)

    return MCP_SERVER.tools.methods, module, save


def serve(sockpath: str, binpath: str, load_args: str = "") -> None:
    tools, module, save = _open_and_register(binpath, load_args)
    sid = uuid.uuid4().hex[:8]

    def dispatch(name: str, args: dict):
        args = dict(args)
        args.pop("database", None)  # single-DB worker: no session routing
        # session-management shims (were the supervisor's job):
        if name in ("idb_open",):
            return {"success": True,
                    "session": {"session_id": sid, "module": module,
                                "input_path": binpath}}
        if name in ("idb_save", "save"):
            save()
            return {"success": True}
        if name in ("server_health", "ping", "health", "state"):
            return {"module": module, "ok": True, "session_id": sid}
        if name in ("idb_list",):
            return {"sessions": [{"session_id": sid, "module": module,
                                  "input_path": binpath}]}
        fn = tools.get(name)
        if fn is None:
            raise KeyError(f"unknown tool: {name!r}")
        result = fn(**args)
        # Match the MCP server's structuredContent: a dict passes through, any
        # other return (list/scalar) is wrapped as {"result": ...}. domain.py
        # parses that exact shape (e.g. lookup_funcs -> payload["result"]).
        return result if isinstance(result, dict) else {"result": result}

    try:
        os.unlink(sockpath)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sockpath)
    srv.listen(8)
    try:
        while True:
            conn, _ = srv.accept()
            try:
                while True:
                    req = recv(conn)
                    if req is None:
                        break
                    name, args = req
                    if name == "__shutdown__":
                        return
                    try:
                        send(conn, (True, dispatch(name, args)))
                    except Exception as e:  # noqa: BLE001 -- report, keep serving
                        send(conn, (False, f"{type(e).__name__}: {e}"))
            except (ConnectionError, OSError):
                pass
            finally:
                conn.close()
    finally:
        try:
            import idapro
            idapro.close_database(save=False)
        except Exception:  # noqa: BLE001
            pass
        try:
            os.unlink(sockpath)
        except OSError:
            pass


def main(argv=None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2:
        sys.stderr.write(
            "usage: python -m idatui.worker <sock> <binary> [ida-load-args]\n")
        raise SystemExit(2)
    try:
        serve(argv[0], argv[1], argv[2] if len(argv) > 2 else "")
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 -- surface a clean cause + code 1
        import traceback
        sys.stderr.write(f"\nWORKER-FATAL: {type(e).__name__}: {e}\n")
        traceback.print_exc()
        sys.stderr.flush()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
