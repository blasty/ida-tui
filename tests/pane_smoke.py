#!/usr/bin/env python3
"""Smoke test for idatui.pane's supervisor auto-start machinery (no IDA needed).

    python3 tests/pane_smoke.py

Uses IDATUI_SERVER_CMD to launch a dummy port-binder in a tmux pane instead of
the real ./spawn.sh, so we can exercise _ensure_server end-to-end (start, detect,
idempotency, remote guard) without a real ida-pro-mcp server. Must run in tmux.
"""
import os
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui import pane  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> int:
    if not os.environ.get("TMUX"):
        print("error: must run inside tmux", file=sys.stderr)
        return 2

    # a dummy "supervisor": bind the port and idle, so _server_up sees it.
    fake = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    fake.write(
        "import socket,sys,time\n"
        "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        "s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen(); time.sleep(300)\n")
    fake.close()
    port = _free_port()
    os.environ["IDATUI_SERVER_CMD"] = f"{sys.executable} {fake.name} {port}"

    server_pane = None
    try:
        check("port starts down", not pane._server_up("127.0.0.1", port))

        srv = pane._ensure_server("127.0.0.1", port, timeout=15.0)
        server_pane = srv.get("server_pane")
        check("ensure_server starts the supervisor and it comes up",
              srv.get("server_started") and srv.get("server_up") and server_pane,
              str(srv))
        check("port is now up", pane._server_up("127.0.0.1", port))

        srv2 = pane._ensure_server("127.0.0.1", port, timeout=5.0)
        check("ensure_server is idempotent when already up",
              srv2.get("server_started") is False and srv2.get("server_up") is True,
              str(srv2))

        srv3 = pane._ensure_server("10.255.255.1", 9, timeout=2.0)
        check("remote+down server is not auto-started",
              srv3.get("server_started") is False and "local" in (srv3.get("error") or ""),
              str(srv3))
    finally:
        if server_pane:
            subprocess.run(["tmux", "kill-pane", "-t", server_pane],
                           capture_output=True)
        os.unlink(fake.name)
        os.environ.pop("IDATUI_SERVER_CMD", None)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
