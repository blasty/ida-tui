"""Spawn/stop/list idatui TUI panes in tmux, for an agent to drive over RPC.

The agent (running inside a tmux pane) can open a fresh pane with the TUI
running against a binary, wait until it's ready, drive it over the RPC socket,
then close it — all without a human touching the keyboard.

    # open a binary in a new pane, block until analysed + drivable, print JSON
    python -m idatui.pane spawn --open /abs/path/to/bin
    # -> {"sock": "/run/user/1000/idatui-3f2a.sock", "pane": "%7", "ready": true, ...}

    # or attach to an existing session id
    python -m idatui.pane spawn --db 80d83396

    # drive it (see docs/RPC.md / the idatui-rpc skill)
    python -m idatui.rpcclient --sock <sock> pseudocode target=main

    # inventory + teardown
    python -m idatui.pane list
    python -m idatui.pane stop --sock <sock>        # graceful quit + kill pane

Requires: running inside tmux, and the ida-pro-mcp supervisor already up
(./spawn.sh). Uses ~/ida-venv/bin/python for the TUI (needs textual) unless
--python / IDATUI_PYTHON says otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Any

from .rpcclient import RpcClient, RpcError

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PY = os.environ.get(
    "IDATUI_PYTHON", os.path.expanduser("~/ida-venv/bin/python"))


def _sockdir() -> str:
    return os.environ.get("XDG_RUNTIME_DIR") or "/tmp"


def _registry_path() -> str:
    return os.path.join(_sockdir(), "idatui-panes.json")


def _load_registry() -> list[dict[str, Any]]:
    try:
        with open(_registry_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _save_registry(rows: list[dict[str, Any]]) -> None:
    tmp = _registry_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rows, f)
    os.replace(tmp, _registry_path())


def _pane_alive(pane: str) -> bool:
    out = subprocess.run(["tmux", "list-panes", "-a", "-F", "#{pane_id}"],
                         capture_output=True, text=True)
    return pane in out.stdout.split()


def _tmux(*args: str) -> str:
    return subprocess.run(["tmux", *args], capture_output=True, text=True,
                          check=True).stdout.strip()


# --------------------------------------------------------------------------- #
# spawn
# --------------------------------------------------------------------------- #
def spawn(args) -> int:
    if not os.environ.get("TMUX"):
        print("error: not inside tmux (spawn creates a tmux pane)", file=sys.stderr)
        return 2
    if not args.open and not args.db:
        print("error: pass --open <binary> or --db <session>", file=sys.stderr)
        return 2

    sock = args.sock or os.path.join(_sockdir(), f"idatui-{secrets.token_hex(3)}.sock")
    target = os.path.abspath(os.path.expanduser(args.open)) if args.open else args.db
    if args.open and not os.path.exists(target):
        print(f"error: no such binary: {target}", file=sys.stderr)
        return 2

    # the command the pane runs: become the TUI so kill-pane kills it cleanly
    inner = [args.python, "-m", "idatui.tui", "--rpc", sock]
    if args.open:
        inner += ["--open", target]
    else:
        inner += ["--db", target]
    if args.url:
        inner += ["--url", args.url]
    cmd = f"cd {REPO!r} && exec " + " ".join(_q(a) for a in inner)

    split = ["split-window", "-v" if args.vertical else "-h",
             "-P", "-F", "#{pane_id}"]
    if args.size:
        split += ["-l", str(args.size)]
    if args.detached:
        split += ["-d"]
    anchor = os.environ.get("TMUX_PANE")
    if anchor:
        split += ["-t", anchor]
    split.append(cmd)
    pane = _tmux(*split)

    row = {"sock": sock, "pane": pane, "target": target,
           "kind": "open" if args.open else "db", "started": time.time()}
    reg = [r for r in _load_registry() if r.get("sock") != sock]
    reg.append(row)
    _save_registry(reg)

    ready = _wait_ready(sock, args.timeout, pane)
    row.update(ready)
    print(json.dumps(row))
    return 0 if ready.get("ready") else 1


def _q(s: str) -> str:
    import shlex
    return shlex.quote(s)


def _wait_ready(sock: str, timeout: float, pane: str) -> dict[str, Any]:
    """Poll the socket + ping until the TUI reports ready (or timeout)."""
    deadline = time.time() + timeout
    last: dict[str, Any] = {"ready": False}
    while time.time() < deadline:
        if not _pane_alive(pane):
            return {"ready": False, "error": "pane exited during startup"}
        if os.path.exists(sock):
            try:
                with RpcClient(sock) as c:
                    last = c.call("ping")
                if last.get("ready"):
                    return last
            except (OSError, RpcError, ConnectionError):
                pass
        time.sleep(0.4)
    last = dict(last)
    last["ready"] = False
    last.setdefault("error", "timed out waiting for the TUI to become ready")
    return last


# --------------------------------------------------------------------------- #
# stop / list
# --------------------------------------------------------------------------- #
def stop(args) -> int:
    reg = _load_registry()
    rows = [r for r in reg
            if (args.sock and r.get("sock") == args.sock)
            or (args.pane and r.get("pane") == args.pane)]
    if not rows and args.sock:  # allow stopping an untracked socket
        rows = [{"sock": args.sock, "pane": args.pane}]
    if not rows:
        print("error: no matching pane (need --sock or --pane)", file=sys.stderr)
        return 2
    for r in rows:
        sock, pane = r.get("sock"), r.get("pane")
        if sock and os.path.exists(sock):
            try:  # ask it to quit gracefully first
                with RpcClient(sock) as c:
                    c.call("quit")
                time.sleep(0.4)
            except (OSError, RpcError, ConnectionError):
                pass
        if pane and _pane_alive(pane):
            subprocess.run(["tmux", "kill-pane", "-t", pane],
                           capture_output=True)
        if sock:
            try:
                os.unlink(sock)
            except OSError:
                pass
    _save_registry([r for r in reg if r not in rows])
    print(json.dumps({"stopped": [r.get("sock") or r.get("pane") for r in rows]}))
    return 0


def list_panes(args) -> int:
    reg = _load_registry()
    alive = []
    for r in reg:
        r = dict(r)
        r["pane_alive"] = _pane_alive(r.get("pane", ""))
        r["sock_up"] = bool(r.get("sock") and os.path.exists(r["sock"]))
        if args.prune and not r["pane_alive"]:
            if r.get("sock") and os.path.exists(r["sock"]):
                try:
                    os.unlink(r["sock"])
                except OSError:
                    pass
            continue
        alive.append(r)
    if args.prune:
        _save_registry(alive)
    print(json.dumps(alive, indent=2))
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="idatui.pane",
                                description="spawn/manage idatui TUI panes in tmux")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("spawn", help="open a TUI pane and wait until ready")
    sp.add_argument("--open", metavar="PATH", help="binary to open (dir must be writable)")
    sp.add_argument("--db", metavar="SESSION", help="attach to an existing session id")
    sp.add_argument("--sock", help="RPC socket path (default: auto in $XDG_RUNTIME_DIR)")
    sp.add_argument("--python", default=DEFAULT_PY, help=f"python for the TUI ({DEFAULT_PY})")
    sp.add_argument("--url", help="MCP server URL (default: idatui's default)")
    sp.add_argument("--vertical", action="store_true", help="split vertically (stacked)")
    sp.add_argument("--size", help="new pane size (tmux -l value, e.g. 60%% or 120)")
    sp.add_argument("--detached", action="store_true", help="don't focus the new pane")
    sp.add_argument("--timeout", type=float, default=300.0,
                    help="seconds to wait for readiness (fresh --open analysis is slow)")
    sp.set_defaults(fn=spawn)

    st = sub.add_parser("stop", help="graceful quit + kill the pane")
    st.add_argument("--sock")
    st.add_argument("--pane")
    st.set_defaults(fn=stop)

    ls = sub.add_parser("list", help="list tracked panes")
    ls.add_argument("--prune", action="store_true", help="drop dead panes (and their sockets)")
    ls.set_defaults(fn=list_panes)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
