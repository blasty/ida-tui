"""Spawn/stop/list idatui TUI panes in slosh or tmux, for an agent to drive over RPC.

The agent (running inside a slosh or tmux pane) can open a fresh pane with the
TUI running against a binary, wait until it's ready, drive it over the RPC
socket, then close it — all without a human touching the keyboard.

The multiplexer is auto-detected ($SLOSH -> slosh, $ZELLIJ -> zellij, $TMUX ->
tmux) and recorded per pane in the registry, so stop/list/capture/keys keep
working across all of them (and across a mixed set of panes). $IDATUI_MUX forces
a backend. (zellij is the legacy backend, kept working but no longer the house
multiplexer.)

    # open a binary in a new pane, block until analysed + drivable, print JSON
    python -m idatui.pane spawn --open /abs/path/to/bin
    # -> {"sock": "/run/user/1000/idatui-3f2a.sock", "pane": "%7", "ready": true, ...}

    # drive it (see docs/RPC.md / the idatui-rpc skill)
    python -m idatui.rpcclient --sock <sock> pseudocode target=main

    # inventory + teardown
    python -m idatui.pane list
    python -m idatui.pane stop --sock <sock>        # graceful quit + kill pane

    # mux-agnostic screen scrape / key injection (for debugging the input layer)
    python -m idatui.pane capture --pane <pane>
    python -m idatui.pane keys --pane <pane> Escape

Requires: running inside slosh or tmux. Each pane leases a registered GUI or
shared managed idalib database through IDA Nexus. Uses ~/ida-venv/bin/python for
the TUI (needs textual) unless --python / IDATUI_PYTHON says otherwise.
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
    "IDATUI_PYTHON", os.path.expanduser("~/ida-venv/bin/python")
)


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


# --------------------------------------------------------------------------- #
# terminal multiplexer backends
#
# Everything that touches panes goes through here, so the rest of the module (and
# every caller) is mux-agnostic. tmux pane ids look like ``%7``; zellij ids look
# like ``terminal_3``, which is what ``zellij action new-pane`` prints; slosh ids
# are bare integers ('7'), so a pane id alone is enough to route a later
# stop/capture even if the registry predates the ``mux`` field.
# --------------------------------------------------------------------------- #
MUXES = ("tmux", "zellij", "slosh")


def _detect_mux() -> str:
    """Which multiplexer we're running under: 'slosh', 'tmux', 'zellij', or ''."""
    forced = os.environ.get("IDATUI_MUX", "").strip().lower()
    if forced:
        return forced if forced in MUXES else "?" + forced
    # slosh first: it is the house multiplexer, and a slosh session started from
    # inside tmux inherits $TMUX while the pane we can actually create is the
    # slosh one. (slosh's own pty clears $ZELLIJ for the same reason.)
    if os.environ.get("SLOSH"):
        return "slosh"
    if os.environ.get("ZELLIJ"):
        return "zellij"
    if os.environ.get("TMUX"):
        return "tmux"
    return ""


def _mux_of_pane(pane: str) -> str:
    """Infer the backend from a pane id ('%7' tmux, 'terminal_3' zellij, '7' slosh)."""
    if pane.startswith(("terminal_", "plugin_")):
        return "zellij"
    if pane.startswith("%"):
        return "tmux"
    if pane.isdigit():
        return "slosh"
    return _detect_mux() or "tmux"


def _zellij_argv() -> list[str]:
    """Base zellij argv, pinned to our session when we know it (so it still works
    from a process that isn't itself attached)."""
    session = os.environ.get("IDATUI_ZELLIJ_SESSION") or os.environ.get(
        "ZELLIJ_SESSION_NAME"
    )
    return ["zellij", "-s", session] if session else ["zellij"]


def _tmux(*args: str) -> str:
    return subprocess.run(
        ["tmux", *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _zellij(*args: str) -> str:
    return subprocess.run(
        [*_zellij_argv(), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _slosh_argv() -> list[str]:
    """Base slosh argv for the control socket, pinned to our session.

    $SLOSH_BIN rather than ``slosh``: a session may have been started from a
    build tree, where ``slosh`` is not on $PATH.
    """
    exe = os.environ.get("SLOSH_BIN") or "slosh"
    session = os.environ.get("IDATUI_SLOSH_SESSION") or os.environ.get("SLOSH_SESSION")
    return [exe, "-s", session, "cmd"] if session else [exe, "cmd"]


def _slosh(cmd: str, **params: Any) -> dict[str, Any]:
    """One JSON control-socket call. Raises RuntimeError on a refusal.

    Always the JSON form, never the bare-verb alias: the bare form answers
    unwrapped (`panes` is the array itself), so a parser written for one shape
    silently finds nothing in the other.
    """
    out = subprocess.run(
        [*_slosh_argv(), json.dumps({"cmd": cmd, **params})],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        # e.g. 'slosh: no session named X' -- a failed call, not an {"ok":false}
        raise RuntimeError((out.stderr or out.stdout).strip() or f"slosh {cmd} failed")
    try:
        reply = json.loads(out.stdout or "{}")
    except ValueError:
        raise RuntimeError(f"slosh {cmd}: unparseable reply {out.stdout[:120]!r}")
    if not reply.get("ok"):
        raise RuntimeError(f"slosh {cmd}: {reply.get('error', 'refused')}")
    return reply


def _slosh_panes() -> list[dict[str, Any]]:
    try:
        rows = _slosh("panes").get("panes")
    except (OSError, RuntimeError):
        return []
    return rows if isinstance(rows, list) else []


def _slosh_row(pane: str) -> dict[str, Any] | None:
    return next((r for r in _slosh_panes() if str(r.get("id")) == str(pane)), None)


def _kdl_str(s: str) -> str:
    """Quote a value for a KDL layout (slosh's parser knows \\" and \\\\)."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _zellij_panes() -> list[dict[str, Any]]:
    try:
        out = subprocess.run(
            [*_zellij_argv(), "action", "list-panes", "--state", "--json"],
            capture_output=True,
            text=True,
        )
        rows = json.loads(out.stdout or "[]")
    except (OSError, ValueError):
        return []
    return rows if isinstance(rows, list) else []


def _pane_alive(pane: str, mux: str | None = None) -> bool:
    """True if the pane exists *and* its command is still running.

    slosh and zellij both keep an exited pane on screen (holding its output)
    rather than removing it like tmux does; that husk must count as dead or
    ``stop`` would wait out its whole timeout and ``_wait_ready`` would never
    notice a launcher that died on startup.
    """
    if not pane:
        return False
    mux = mux or _mux_of_pane(pane)
    if mux == "slosh":
        row = _slosh_row(pane)
        return bool(row and row.get("alive"))
    if mux == "zellij":
        want = pane.split("_", 1)[-1]
        for row in _zellij_panes():
            if str(row.get("id")) == want and bool(row.get("is_plugin")) is False:
                return not row.get("exited", False)
        return False
    out = subprocess.run(
        ["tmux", "list-panes", "-a", "-F", "#{pane_id}"], capture_output=True, text=True
    )
    return pane in out.stdout.split()


def _pane_exists(pane: str, mux: str | None = None) -> bool:
    """True if the pane is still on screen at all (including a dead-pane husk)."""
    if not pane:
        return False
    mux = mux or _mux_of_pane(pane)
    if mux == "slosh":
        return _slosh_row(pane) is not None
    if mux == "zellij":
        want = pane.split("_", 1)[-1]
        return any(
            str(r.get("id")) == want and not r.get("is_plugin") for r in _zellij_panes()
        )
    return _pane_alive(pane, "tmux")


def _pane_kill(pane: str, mux: str | None = None) -> None:
    """Remove the pane. Idempotent, and also clears a dead-pane husk."""
    if not pane:
        return
    mux = mux or _mux_of_pane(pane)
    if mux == "slosh":
        try:
            _slosh("close", id=int(pane))
        except (OSError, RuntimeError, ValueError):
            pass  # already gone: closing is idempotent from our side
        return
    if mux == "zellij":
        subprocess.run(
            [*_zellij_argv(), "action", "close-pane", "--pane-id", pane],
            capture_output=True,
        )
    else:
        subprocess.run(["tmux", "kill-pane", "-t", pane], capture_output=True)


def _pane_split(
    inner: list[str], *, mux: str, vertical: bool, size: str | None, detached: bool
) -> str:
    """Open a pane running ``inner`` (argv) in REPO, and return its pane id."""
    if mux == "slosh":
        # slosh's `split` verb only ever makes a shell pane, and typing a command
        # into a shell is the thing not to do: a pane that was *given* a command
        # is the one with alive/exit_code to poll and `rerun` to repeat. So the
        # pane comes from a one-tab layout and is then moved in beside us.
        origin = next((r for r in _slosh_panes() if r.get("focused")), None)
        tag = "idatui:" + secrets.token_hex(3)
        command = f"cd {_q(REPO)} && exec " + " ".join(_q(a) for a in inner)
        kdl = (
            'layout { tab name="idatui" { pane '
            f"purpose={_kdl_str(tag)} cwd={_kdl_str(REPO)} command={_kdl_str(command)}"
            " } }"
        )
        _slosh("apply-layout", kdl=kdl)
        # Find it by the purpose we declared, never by "the newest id": a
        # declared purpose is locked, so the program in the pane cannot rename
        # itself out from under us the way a title changes.
        row = next((r for r in _slosh_panes() if r.get("purpose") == tag), None)
        if row is None:
            raise RuntimeError("slosh applied the layout but reported no pane for it")
        pane = str(row.get("id"))
        if origin:
            # Into the tab we were called from, so the TUI sits beside the agent
            # and is on screen for `capture`. The pane keeps its pty/scrollback,
            # and the layout's now-empty tab goes away by itself.
            try:
                _slosh(
                    "move-pane",
                    id=int(pane),
                    tab=int(origin.get("tab_id", 0)),
                    dir="rows" if vertical else "cols",
                )
            except (OSError, RuntimeError):
                pass  # no room to split: leave it in the tab of its own
            if detached:  # slosh focuses what it creates/moves; hop back
                _slosh("focus", id=int(origin.get("id", 0)))
        return pane

    if mux == "zellij":
        # zellij runs the argv directly (no shell) and takes the cwd as a flag,
        # so there's nothing to quote. --name labels the pane in the UI.
        argv = [
            *_zellij_argv(),
            "action",
            "new-pane",
            "--direction",
            "down" if vertical else "right",
            "--cwd",
            REPO,
            "--name",
            "idatui",
        ]
        argv += ["--", *inner]
        pane = subprocess.run(
            argv, capture_output=True, text=True, check=True
        ).stdout.strip()
        # zellij prints the new pane id ('terminal_3'); without it we could not
        # target this pane later, so treat a missing id as a hard failure.
        if not pane.startswith(("terminal_", "plugin_")):
            raise RuntimeError(f"zellij new-pane did not return a pane id: {pane!r}")
        if detached:
            # zellij always focuses the pane it creates and has no -d; hop back
            # to the pane we were called from.
            origin = os.environ.get("ZELLIJ_PANE_ID")
            if origin:
                subprocess.run(
                    [*_zellij_argv(), "action", "focus-pane-id", f"terminal_{origin}"],
                    capture_output=True,
                )
        return pane

    cmd = f"cd {REPO!r} && exec " + " ".join(_q(a) for a in inner)
    split = ["split-window", "-v" if vertical else "-h", "-P", "-F", "#{pane_id}"]
    if size:
        split += ["-l", str(size)]
    if detached:
        split += ["-d"]
    anchor = os.environ.get("TMUX_PANE")
    if anchor:
        split += ["-t", anchor]
    split.append(cmd)
    return _tmux(*split)


def _slosh_capture(pane: str) -> str:
    """One slosh pane's visible screen, cut out of the session snapshot.

    ``snapshot`` is the whole composited session (every visible pane, borders and
    all), and only the active tab is composited at all — so a pane parked in
    another tab is brought up and put back.
    """
    row = _slosh_row(pane)
    if row is None:
        raise RuntimeError(f"no such slosh pane: {pane}")
    tabs = _slosh("tabs").get("tabs") or []
    active = next((t for t in tabs if t.get("active")), None)
    restore = None
    if active and row.get("tab_id") != active.get("id"):
        _slosh("select-tab", id=int(row.get("tab_id", 0)))
        restore = int(active.get("id", 0))
        row = _slosh_row(pane) or row  # rects are a function of the frame
    try:
        text = _slosh("snapshot", format="text").get("text", "")
    finally:
        if restore is not None:
            _slosh("select-tab", id=restore)
    x, y = int(row.get("content_x", 0)), int(row.get("content_y", 0))
    w, h = int(row.get("content_w", 0)), int(row.get("content_h", 0))
    lines = text.splitlines()[y : y + h]
    return "\n".join(ln[x : x + w].rstrip() for ln in lines).rstrip()


def _pane_capture(pane: str, mux: str | None = None) -> str:
    """The pane's visible screen as text."""
    mux = mux or _mux_of_pane(pane)
    if mux == "slosh":
        return _slosh_capture(pane)
    if mux == "zellij":
        return _zellij("action", "dump-screen", "--pane-id", pane)
    return _tmux("capture-pane", "-p", "-t", pane)


# tmux key names -> zellij key names (zellij rejects e.g. "Escape", wants "Esc").
_ZELLIJ_KEYS = {
    "escape": "Esc",
    "bspace": "Backspace",
    "space": "Space",
    "pageup": "PageUp",
    "pagedown": "PageDown",
    "ppage": "PageUp",
    "npage": "PageDown",
    "ic": "Insert",
    "dc": "Delete",
}


def _to_zellij_key(key: str) -> str:
    """Accept tmux-flavoured key names so callers can stay mux-agnostic."""
    low = key.lower()
    if low in _ZELLIJ_KEYS:
        return _ZELLIJ_KEYS[low]
    if len(key) > 2 and key[1] == "-" and key[0] in "CM":  # C-a / M-x
        return ("Ctrl " if key[0] == "C" else "Alt ") + key[2:]
    return key


# tmux key names -> the bytes a terminal actually sends (slosh writes bytes).
_SLOSH_KEYS = {
    "escape": "\x1b",
    "enter": "\r",
    "cr": "\r",
    "tab": "\t",
    "btab": "\x1b[Z",
    "space": " ",
    "bspace": "\x7f",
    "up": "\x1b[A",
    "down": "\x1b[B",
    "right": "\x1b[C",
    "left": "\x1b[D",
    "home": "\x1b[H",
    "end": "\x1b[F",
    "pageup": "\x1b[5~",
    "ppage": "\x1b[5~",
    "pagedown": "\x1b[6~",
    "npage": "\x1b[6~",
    "ic": "\x1b[2~",
    "insert": "\x1b[2~",
    "dc": "\x1b[3~",
    "delete": "\x1b[3~",
    "f1": "\x1bOP",
    "f2": "\x1bOQ",
    "f3": "\x1bOR",
    "f4": "\x1bOS",
}


def _to_slosh_bytes(key: str) -> str:
    """Accept tmux-flavoured key names so callers can stay mux-agnostic."""
    low = key.lower()
    if low in _SLOSH_KEYS:
        return _SLOSH_KEYS[low]
    if len(key) > 2 and key[1] == "-" and key[0] in "CM":  # C-a / M-x
        rest = key[2:]
        if key[0] == "M":
            return "\x1b" + _to_slosh_bytes(rest)
        return chr(ord(rest[0]) & 0x1F) if len(rest) == 1 else rest
    return key


def _pane_keys(pane: str, keys: list[str], mux: str | None = None) -> None:
    """Inject real terminal keystrokes into the pane (the input-layer cross-check)."""
    mux = mux or _mux_of_pane(pane)
    if mux == "slosh":
        data = "".join(_to_slosh_bytes(k) for k in keys)
        prev = next((r for r in _slosh_panes() if r.get("focused")), None)
        # Both `raw` and `send` land in the *focused* pane, so focus first and
        # put focus back after. `raw` rather than `send`: `send` is decoded as
        # session input, where C-a is slosh's leader and would be swallowed
        # instead of reaching the TUI.
        _slosh("focus", id=int(pane))
        try:
            _slosh("raw", data=data)
        finally:
            if prev and str(prev.get("id")) != str(pane):
                _slosh("focus", id=int(prev.get("id", 0)))
        return
    if mux == "zellij":
        subprocess.run(
            [
                *_zellij_argv(),
                "action",
                "send-keys",
                "--pane-id",
                pane,
                *[_to_zellij_key(k) for k in keys],
            ],
            check=True,
        )
    else:
        subprocess.run(["tmux", "send-keys", "-t", pane, *keys], check=True)


# IDA Nexus owns database process lifetime: a closed pane drops its lease at the
# socket/kernel boundary and IDA Nexus decides whether a managed worker still
# has clients. There is nothing for the pane layer to reap.


def _count_live_panes() -> int:
    return sum(
        1 for r in _load_registry() if _pane_alive(r.get("pane", ""), r.get("mux"))
    )


def _reap_orphan_workers(force: bool = False) -> int:
    """Compatibility no-op: IDA Nexus workers are shared and lease-managed."""
    del force
    return 0


# --------------------------------------------------------------------------- #
# spawn
# --------------------------------------------------------------------------- #
def spawn(args) -> int:
    mux = args.mux or _detect_mux()
    if mux.startswith("?"):
        print(
            f"error: unknown multiplexer {mux[1:]!r} (want {'/'.join(MUXES)})",
            file=sys.stderr,
        )
        return 2
    if not mux:
        print(
            "error: not inside slosh or tmux (spawn creates a pane there). "
            "Set $IDATUI_MUX=slosh|tmux to force a backend.",
            file=sys.stderr,
        )
        return 2
    if not args.open and not getattr(args, "project", None):
        print("error: pass --open <binary> or --project <file>", file=sys.stderr)
        return 2

    sock = args.sock or os.path.join(_sockdir(), f"idatui-{secrets.token_hex(3)}.sock")
    project = (
        os.path.abspath(os.path.expanduser(args.project))
        if getattr(args, "project", None)
        else None
    )
    target = os.path.abspath(os.path.expanduser(args.open)) if args.open else None
    if target is not None and not os.path.exists(target):
        print(f"error: no such binary: {target}", file=sys.stderr)
        return 2
    if project is not None and target is None and not os.path.exists(project):
        print(f"error: no such project: {project}", file=sys.stderr)
        return 2

    # The pane owns only the TUI. IDA Nexus's lease cleanup handles crashes;
    # kill-pane must never reap a shared GUI/idalib database.
    if project is not None:
        # launch takes: --project FILE [binaries...]; extra binaries are added to
        # the project (and a missing project file is created from them).
        inner = [args.python, "-m", "idatui.launch", "--project", project]
        if target is not None:
            inner.append(target)
        inner += ["--rpc", sock]
    else:
        inner = [args.python, "-m", "idatui.launch", target, "--rpc", sock]
    # Loading a headerless blob: without these IDA reads a raw firmware image as
    # x86 at 0 and analyses to nothing, and the pane comes up ready-but-empty.
    # They are launch's options; spawn just forwards them (a project records
    # them per binary, so they're only needed on the first open).
    for opt in ("processor", "base", "ida_args"):
        val = getattr(args, opt, None)
        if val:
            inner += ["--" + opt.replace("_", "-"), str(val)]
    if getattr(args, "trace", None):
        inner += ["--trace", os.path.abspath(os.path.expanduser(args.trace))]
    # Where the database goes, for a binary whose own directory cannot hold one
    # (/bin/ls). Without it the TUI picks a writable location itself and says so
    # in the status line -- an RPC-driven pane is never asked, because nothing
    # would answer and spawn would wait out its whole timeout in front of the
    # dialog. Pass it when the location matters.
    if getattr(args, "idb", None):
        inner += ["--idb", os.path.abspath(os.path.expanduser(args.idb))]

    if args.size and mux != "tmux":
        print(
            f"note: --size is tmux-only; {mux} tiles the new pane evenly",
            file=sys.stderr,
        )
    try:
        pane = _pane_split(
            inner,
            mux=mux,
            vertical=args.vertical,
            size=args.size,
            detached=args.detached,
        )
    except (OSError, subprocess.CalledProcessError, RuntimeError) as e:
        print(f"error: could not create a {mux} pane: {e}", file=sys.stderr)
        return 2

    row = {
        "sock": sock,
        "pane": pane,
        "mux": mux,
        "target": project or target,
        "kind": "project" if project else "open",
        "started": time.time(),
    }
    reg = [r for r in _load_registry() if r.get("sock") != sock]
    reg.append(row)
    _save_registry(reg)

    ready = _wait_ready(sock, args.timeout, pane, mux=mux)
    row.update(ready)
    print(json.dumps(row))
    return 0 if ready.get("ready") else 1


def _q(s: str) -> str:
    import shlex

    return shlex.quote(s)


def _wait_ready(
    sock: str,
    timeout: float,
    pane: str,
    stuck_after: float = 45.0,
    mux: str | None = None,
) -> dict[str, Any]:
    """Poll the socket + ping until the TUI reports ready (or timeout).

    Emits a one-time hint if IDA Nexus discovery/opening is still not ready after
    ``stuck_after`` seconds.
    """
    start = time.time()
    deadline = start + timeout
    warned = False
    last: dict[str, Any] = {"ready": False}
    while time.time() < deadline:
        if not _pane_alive(pane, mux):
            return {"ready": False, "error": "pane exited during startup"}
        if os.path.exists(sock):
            try:
                with RpcClient(sock) as c:
                    last = c.call("ping")
                if last.get("ready"):
                    return last
            except (OSError, RpcError, ConnectionError):
                pass
        if not warned and (time.time() - start) > stuck_after:
            warned = True
            why = (
                "RPC socket not created yet"
                if not os.path.exists(sock)
                else "TUI up but analysis not ready"
            )
            print(
                f"still waiting ({int(time.time() - start)}s): {why}. "
                f"Check IDA Nexus registrations and worker logs.",
                file=sys.stderr,
            )
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
    rows = [
        r
        for r in reg
        if (args.sock and r.get("sock") == args.sock)
        or (args.pane and r.get("pane") == args.pane)
    ]
    if not rows and args.sock:  # allow stopping an untracked socket
        rows = [{"sock": args.sock, "pane": args.pane}]
    if not rows:
        print("error: no matching pane (need --sock or --pane)", file=sys.stderr)
        return 2
    killed: list[str] = []
    for r in rows:
        sock, pane, mux = r.get("sock"), r.get("pane"), r.get("mux")
        quit_ok = False
        if sock and os.path.exists(sock):
            try:  # ask it to quit gracefully first
                with RpcClient(sock) as c:
                    c.call("quit")
                quit_ok = True
            except (OSError, RpcError, ConnectionError):
                pass
        # Wait for the pane to actually go away. Quitting runs App.on_unmount,
        # which writes every dirty database; a 90 MB .i64 takes tens of seconds.
        # Killing the pane on a fixed short sleep truncated that save and
        # silently destroyed the session's work, so block on the real signal.
        if pane and quit_ok:
            deadline = time.monotonic() + float(args.timeout)
            while time.monotonic() < deadline and _pane_alive(pane, mux):
                time.sleep(0.25)
        if pane:
            # Still running past the timeout = force kill (and warn). Otherwise
            # it exited cleanly, but under zellij the pane lingers as an exit
            # husk, so close it either way to leave the layout as we found it.
            if _pane_alive(pane, mux):
                killed.append(pane)
            _pane_kill(pane, mux)
        if sock:
            try:
                os.unlink(sock)
            except OSError:
                pass
    _save_registry([r for r in reg if r not in rows])
    # Reap the workers those panes leaked (safe: only fires once no pane is live).
    reaped = _reap_orphan_workers()
    out = {"stopped": [r.get("sock") or r.get("pane") for r in rows]}
    if reaped:
        out["reaped_workers"] = reaped
    if killed:
        # Only ever reached on timeout: say so, because it means a save may have
        # been cut short rather than "clean teardown".
        out["force_killed"] = killed
        out["warning"] = (
            f"pane(s) did not exit within {args.timeout}s and were "
            "killed; unsaved database changes may be lost"
        )
    print(json.dumps(out))
    return 0


def list_panes(args) -> int:
    reg = _load_registry()
    alive = []
    for r in reg:
        r = dict(r)
        r.setdefault("mux", _mux_of_pane(r.get("pane", "")))
        r["pane_alive"] = _pane_alive(r.get("pane", ""), r.get("mux"))
        r["sock_up"] = bool(r.get("sock") and os.path.exists(r["sock"]))
        if args.prune and not r["pane_alive"]:
            if r.get("sock") and os.path.exists(r["sock"]):
                try:
                    os.unlink(r["sock"])
                except OSError:
                    pass
            # a slosh/zellij pane whose command exited is still on screen; drop it
            if r.get("pane") and _pane_exists(r["pane"], r.get("mux")):
                _pane_kill(r["pane"], r.get("mux"))
            continue
        alive.append(r)
    if args.prune:
        _save_registry(alive)
        reaped = _reap_orphan_workers()
        if reaped:
            print(f"reaped {reaped} orphaned idalib worker(s)", file=sys.stderr)
    print(json.dumps(alive, indent=2))
    return 0


def reap(args) -> int:
    """Deprecated no-op; shared IDA Nexus workers are managed by leases."""
    print(
        json.dumps(
            {
                "reaped_workers": 0,
                "live_panes": _count_live_panes(),
                "forced": args.force,
                "deprecated": True,
            }
        )
    )
    return 0


def capture(args) -> int:
    """Print a pane's visible screen (slosh snapshot / tmux capture-pane)."""
    pane = args.pane or _resolve_pane(args.sock)
    if not pane:
        return 2
    try:
        print(_pane_capture(pane, args.mux or None))
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"error: could not capture {pane}: {e}", file=sys.stderr)
        return 1
    return 0


def send_keys(args) -> int:
    """Inject real terminal keystrokes (slosh raw / tmux send-keys).

    Key names are tmux-flavoured and translated per backend, so `keys --pane P
    Escape` does the right thing under either mux.
    """
    pane = args.pane or _resolve_pane(args.sock)
    if not pane:
        return 2
    try:
        _pane_keys(pane, args.keys, args.mux or None)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"error: could not send keys to {pane}: {e}", file=sys.stderr)
        return 1
    return 0


def _resolve_pane(sock: str | None) -> str | None:
    """Pane id for a socket, or the single live pane if there's exactly one."""
    reg = _load_registry()
    if sock:
        for r in reg:
            if r.get("sock") == sock:
                return r.get("pane")
        print(f"error: no tracked pane for {sock}", file=sys.stderr)
        return None
    live = [r for r in reg if _pane_alive(r.get("pane", ""), r.get("mux"))]
    if len(live) == 1:
        return live[0].get("pane")
    if not live:
        print("error: no live panes (pass --pane)", file=sys.stderr)
    else:
        print("error: several live panes, pass --pane or --sock:", file=sys.stderr)
        for r in live:
            print(
                f"  {r.get('pane')}  {r.get('sock')}  {r.get('target')}",
                file=sys.stderr,
            )
    return None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="idatui.pane",
        description="spawn/manage idatui TUI panes in slosh or tmux",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("spawn", help="open a TUI pane and wait until ready")
    sp.add_argument(
        "--open", metavar="PATH", help="binary to open (its dir must be writable)"
    )
    sp.add_argument(
        "--trace",
        metavar="FILE",
        help="Tenet execution trace to load alongside the binary",
    )
    sp.add_argument(
        "--project",
        metavar="FILE",
        help="project file to open instead of a single binary; "
        "any --open paths are added to it (created if absent)",
    )
    sp.add_argument(
        "--processor",
        metavar="NAME",
        help="IDA processor for a headerless blob: arm, armb, "
        "mipsb, metapc, … (passed to idatui.launch)",
    )
    sp.add_argument(
        "--base",
        metavar="ADDR",
        help="load address for a headerless blob, e.g. 0x8000000 (16-byte aligned)",
    )
    sp.add_argument(
        "--ida-args",
        metavar="STR",
        dest="ida_args",
        help="extra IDA command-line switches, passed through",
    )
    sp.add_argument(
        "--idb",
        metavar="FILE",
        help="keep the database at this .i64 path instead of beside the binary "
        "(passed to idatui.launch)",
    )
    sp.add_argument(
        "--sock", help="RPC socket path (default: auto in $XDG_RUNTIME_DIR)"
    )
    sp.add_argument(
        "--python", default=DEFAULT_PY, help=f"python for the TUI ({DEFAULT_PY})"
    )
    sp.add_argument(
        "--vertical", action="store_true", help="split vertically (stacked)"
    )
    sp.add_argument(
        "--size",
        help="new pane size (tmux -l value, e.g. 60%% or 120; "
        "ignored under slosh/zellij)",
    )
    sp.add_argument("--detached", action="store_true", help="don't focus the new pane")
    sp.add_argument(
        "--mux",
        choices=MUXES,
        default="",
        help="multiplexer to spawn in (default: autodetect from "
        "$SLOSH/$ZELLIJ/$TMUX; $IDATUI_MUX overrides)",
    )
    sp.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="seconds to wait for readiness (fresh --open analysis is slow)",
    )
    sp.set_defaults(fn=spawn)

    st = sub.add_parser("stop", help="graceful quit + kill the pane")
    st.add_argument("--sock")
    st.add_argument("--pane")
    st.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="seconds to wait for the pane to exit (it saves dirty "
        "databases on the way out) before force-killing it",
    )
    st.set_defaults(fn=stop)

    ls = sub.add_parser("list", help="list tracked panes")
    ls.add_argument(
        "--prune", action="store_true", help="drop dead panes (and their sockets)"
    )
    ls.set_defaults(fn=list_panes)

    rp = sub.add_parser("reap", help="deprecated no-op (IDA Nexus uses shared leases)")
    rp.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    rp.set_defaults(fn=reap)

    cp = sub.add_parser("capture", help="print a pane's visible screen")
    cp.add_argument("--pane")
    cp.add_argument("--sock", help="resolve the pane from this socket")
    cp.add_argument("--mux", choices=MUXES, default="")
    cp.set_defaults(fn=capture)

    kp = sub.add_parser(
        "keys",
        help="inject real keystrokes into a pane "
        "(tmux-style names, translated per mux)",
    )
    kp.add_argument("keys", nargs="+", help="e.g. Escape, Enter, C-a, g m a i n")
    kp.add_argument("--pane")
    kp.add_argument("--sock", help="resolve the pane from this socket")
    kp.add_argument("--mux", choices=MUXES, default="")
    kp.set_defaults(fn=send_keys)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
