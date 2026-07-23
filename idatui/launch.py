"""One-shot launcher: ``ida-tui foo.elf`` and you're in the TUI.

Does the whole plumbing so you don't have to:

  * ensures the ida-pro-mcp supervisor is up (starts ``spawn.sh`` detached and
    waits for the port if it isn't) — works inside OR outside tmux;
  * recovers a binary wedged by a crashed worker (sweeps the stale unpacked
    ``.id0/.id1/.id2/.nam/.til`` files left when a worker was hard-killed, then
    retries) — the packed ``.i64`` is never touched;
  * reuses an already-open session for the same binary, or opens it fresh;
  * launches the TUI attached to that session with keepalive on.

Usage:

    ida-tui /path/to/binary          # open (or adopt) a binary and drive it
    ida-tui                          # attach to the sole open session
    ida-tui --db 80d83396            # attach to a specific session

Everything ``idatui.tui`` accepts (--url, --rpc, --no-keepalive) is accepted
here too. The heavy lifting for probing/reaping the supervisor lives in
``pane.py``; this module adds the tmux-free auto-start and lock recovery.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from .client import DEFAULT_URL, IDAClient, IDAError
from .pane import REPO, _server_addr, _server_up

# The unpacked working-copy files IDA writes next to a `.i64` while a database is
# open. A hard-killed worker leaves them behind and then the `.i64` refuses to
# reopen ("Failed to open database"). Safe to delete when nothing holds the DB.
_LOCK_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


def _log(msg: str) -> None:
    print(f"ida-tui: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# supervisor auto-start (tmux-free)
# --------------------------------------------------------------------------- #
def _server_log_path() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return os.path.join(base, "idatui-supervisor.log")


def _start_supervisor(target: str | None) -> subprocess.Popen | None:
    """Start ``spawn.sh`` detached (its own session, so it outlives us) with the
    given initial target. Returns the Popen (for a failure hint) or None."""
    cmd = os.environ.get("IDATUI_SERVER_CMD", "./spawn.sh")
    env = dict(os.environ)
    if target:
        env["IDA_MCP_TARGET"] = target
    logf = open(_server_log_path(), "ab", buffering=0)
    try:
        return subprocess.Popen(
            cmd, cwd=REPO, shell=True, env=env,
            stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,
            start_new_session=True,  # detach: survives this process exiting
        )
    except OSError as e:
        _log(f"could not start supervisor ({cmd!r}): {e}")
        return None


def _ensure_server(url: str, target: str | None, timeout: float = 90.0) -> bool:
    """Make sure the supervisor is listening; start it if not. Returns True when
    the port is up. Only auto-starts a local server."""
    host, port = _server_addr(url)
    if _server_up(host, port):
        return True
    if host not in ("127.0.0.1", "localhost", "::1"):
        _log(f"server at {host}:{port} is down and not local — cannot auto-start")
        return False
    _log(f"supervisor not running — starting it (log: {_server_log_path()})")
    proc = _start_supervisor(target)
    deadline = time.time() + timeout
    spun = False
    while time.time() < deadline:
        if _server_up(host, port):
            if spun:
                _log("supervisor is up")
            return True
        if proc is not None and proc.poll() is not None:
            _log("supervisor exited during startup — check the log above")
            return False
        spun = True
        time.sleep(0.5)
    _log(f"supervisor did not come up within {timeout:.0f}s")
    return False


# --------------------------------------------------------------------------- #
# session resolution + lock recovery
# --------------------------------------------------------------------------- #
def _sweep_locks(binary: str) -> int:
    """Remove stale unpacked DB files next to ``binary``. Returns how many."""
    stem = os.path.splitext(binary)[0]
    n = 0
    for base in (binary, stem):  # IDA may key on the full name or the stem
        for suf in _LOCK_SUFFIXES:
            p = base + suf
            try:
                os.remove(p)
                n += 1
            except OSError:
                pass
    return n


def _existing_session(client: IDAClient, binary: str) -> str | None:
    """A live session already open on ``binary`` (by real path), if any."""
    target = os.path.realpath(binary)
    for s in client.list_sessions():
        if s.session_id and s.input_path and os.path.realpath(s.input_path) == target:
            return s.session_id
    return None


def _open_binary(client: IDAClient, binary: str, ttl: int) -> str:
    """Open (or adopt) ``binary`` and return its session id. Recovers from a
    crashed-worker lock by sweeping stale files and retrying once."""
    existing = _existing_session(client, binary)
    if existing:
        _log(f"adopting the open session for {os.path.basename(binary)} ({existing})")
        # re-open on the same path is idempotent and (re)applies the TTL
        try:
            client.call("idb_open", input_path=binary, idle_ttl_sec=ttl)
        except IDAError:
            pass
        return existing

    def _do_open() -> str:
        r = client.call("idb_open", input_path=binary, idle_ttl_sec=ttl)
        sess = r.get("session") if isinstance(r, dict) else None
        sid = (sess or {}).get("session_id") if isinstance(sess, dict) else None
        if not sid:  # fall back to whatever list_sessions now shows for this path
            sid = _existing_session(client, binary)
        if not sid:
            raise IDAError(f"idb_open returned no session id for {binary}")
        return sid

    try:
        return _do_open()
    except IDAError as e:
        # A wedged database from a hard-killed worker: sweep THIS binary's
        # unpacked working-copy files (never the .i64) and retry once. We only
        # get here when no live session already holds this binary (adopted
        # above), so the sweep can't race a healthy session.
        swept = _sweep_locks(binary)
        if not swept:
            raise e
        _log(f"recovered a wedged database (removed {swept} stale lock "
             f"file(s)); retrying")
        return _do_open()


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ida-tui",
        description="Open a binary in the IDA TUI, doing all the server plumbing.")
    p.add_argument("binary", nargs="?",
                   help="binary to open/adopt (omit to attach to the sole session)")
    p.add_argument("--url", default=os.environ.get("IDA_MCP_URL", DEFAULT_URL),
                   help=f"MCP server URL (default {DEFAULT_URL})")
    p.add_argument("--db", default=os.environ.get("IDA_MCP_DB"),
                   help="attach to an existing session id (skips open)")
    p.add_argument("--ttl", type=int, default=1800,
                   help="worker idle-TTL seconds for the opened session (default 1800)")
    p.add_argument("--no-keepalive", action="store_true",
                   help="do not run the keepalive heartbeat")
    p.add_argument("--rpc", metavar="PATH",
                   help="listen for RPC on this unix socket (puppeteer the TUI)")
    p.add_argument("--no-server", action="store_true",
                   help="do not auto-start the supervisor if it's down")
    args = p.parse_args(argv)

    binary = None
    if args.binary and not args.db:
        binary = os.path.abspath(os.path.expanduser(args.binary))
        if not os.path.isfile(binary):
            _log(f"no such file: {binary}")
            return 2
        if not os.access(os.path.dirname(binary), os.W_OK):
            _log(f"directory not writable (IDA writes a .i64 there): "
                 f"{os.path.dirname(binary)}")
            return 2

    # 1) supervisor up (seed it with our target so its initial worker is useful)
    if not args.no_server:
        if not _ensure_server(args.url, binary):
            return 1
    elif not _server_up(*_server_addr(args.url)):
        _log("supervisor is down and --no-server was given")
        return 1

    # 2) resolve the session. If a session is already open on this binary, adopt
    #    it (instant). Otherwise DON'T open here — defer the (possibly long)
    #    analysis to the TUI so its chrome + "loading…" overlay are on screen
    #    during the wait, instead of a blank terminal before the TUI even starts.
    db = args.db
    open_path = None
    if binary is not None and db is None:
        try:
            client = IDAClient(args.url)
            client.connect()
            db = _existing_session(client, binary)
        except Exception:  # noqa: BLE001 -- probe only; the TUI will open it
            db = None
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        if db:
            _log(f"adopting the open session for {os.path.basename(binary)} ({db})")
        else:
            open_path = binary  # TUI opens it with the loading overlay up

    # 3) hand off to the TUI (imported late so --help works without textual)
    try:
        from .app import IdaTui
    except ImportError as e:
        _log(f"the TUI needs textual; run with ~/ida-venv/bin/python  ({e})")
        return 1
    rpc_path = os.path.abspath(os.path.expanduser(args.rpc)) if args.rpc else None
    IdaTui(url=args.url, db=db, open_path=open_path, ttl=args.ttl,
           keepalive=not args.no_keepalive, rpc_path=rpc_path).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
