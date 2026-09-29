#!/usr/bin/env python3
"""Does a REAL terminal mouse click move the pseudocode cursor?

The pilot's `pilot.click()` posts MouseDown/MouseUp/Click straight at a widget,
which bypasses Textual's own click synthesis -- so it can pass while a real
terminal does nothing. This runs the app in a pty, injects SGR mouse bytes on
stdin like a terminal emulator would, and reads the cursor back over the RPC.

    PYTHONPATH=. ~/ida-venv/bin/python experiments/click_pty.py targets/echo
"""

import fcntl
import json
import os
import pty
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLS, ROWS = 160, 48


def call(sock_path, method, **params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(sock_path)
    s.sendall(
        (json.dumps({"id": 1, "method": method, "params": params}) + "\n").encode()
    )
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode())


def mouse(master, col, row, button=0):
    """SGR (1006) press + release at 1-based (col,row)."""
    press = f"\x1b[<{button};{col};{row}M".encode()
    release = f"\x1b[<{button};{col};{row}m".encode()
    os.write(master, press)
    time.sleep(0.05)
    os.write(master, release)
    time.sleep(0.35)


def main(binary):
    tmp = tempfile.mkdtemp(prefix="idatui-clickpty-")
    target = os.path.join(tmp, os.path.basename(binary))
    shutil.copy2(binary, target)
    for ext in (".i64", ".pristine.i64"):
        src = binary + ext
        if os.path.exists(src):
            shutil.copy2(src, target + ".i64")
            break
    sock_path = os.path.join(tmp, "rpc.sock")

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    env = dict(
        os.environ, TERM="xterm-256color", COLORTERM="truecolor", IDATUI_KITTY="0"
    )
    proc = subprocess.Popen(
        [os.path.join(ROOT, "ida-tui"), target, "--rpc", sock_path],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        cwd=ROOT,
        close_fds=True,
    )
    os.close(slave)
    sink = []

    def drain():
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                return
            if not data:
                return
            sink.append(data)

    threading.Thread(target=drain, daemon=True).start()

    try:
        deadline = time.time() + 300
        while time.time() < deadline:
            if os.path.exists(sock_path):
                try:
                    r = call(sock_path, "ping")
                    if r.get("result", {}).get("ready"):
                        break
                except Exception:
                    pass
            time.sleep(0.5)
        else:
            raise SystemExit("app never became ready")

        fns = call(sock_path, "functions", limit=400)["result"]
        fn = max(fns, key=lambda f: f["size"])
        print("function:", fn["name"], hex(fn["ea"]))
        call(sock_path, "goto", target=fn["name"])
        st = call(sock_path, "state")["result"]
        if st.get("active") != "decomp":
            call(sock_path, "toggle_view")
        st = call(sock_path, "state")["result"]
        print("state:", json.dumps(st)[:400])

        view = call(sock_path, "screen")["result"]["text"].split("\n")
        for i, ln in enumerate(view[:14]):
            print(f"{i:3d}|{ln[:110]}")

        print("--- row sweep (decomp) ---")
        bad = []
        for row in range(1, ROWS + 1):
            mouse(master, 30, row)
            cur = call(sock_path, "state")["result"]["cursor"]
            want = row - 1  # viewport row -> line, scroll_y 0, no top chrome?
            print(f"  row {row:3d} -> line {cur.get('line')} col {cur.get('col')}")
            if cur.get("line") is None:
                bad.append(row)
        print("rows with no cursor:", bad)

        print("--- column sweep (decomp, row 14) ---")
        for col in (5, 20, 60, 90, 95, 96, 100, 130, 150, 160):
            mouse(master, col, 14)
            cur = call(sock_path, "state")["result"]["cursor"]
            print(f"  col {col:3d} -> line {cur.get('line')} col {cur.get('col')}")

        print("--- split view (s) ---")
        call(sock_path, "keys", keys=["s"])
        st = call(sock_path, "state")["result"]
        print("active:", st.get("active"), "status:", st.get("status"))
        txt = call(sock_path, "screen")["result"]["text"].split("\n")
        for i, ln in enumerate(txt[8:12], start=8):
            print(f"{i:3d}|{ln[:150]}")
        for col, row in ((30, 10), (110, 10), (110, 20)):
            before = call(sock_path, "state")["result"]["cursor"]
            mouse(master, col, row)
            after = call(sock_path, "state")["result"]["cursor"]
            print(f"  split click col={col} row={row}: {before} -> {after}")
        call(sock_path, "keys", keys=["s"])

        print("--- listing pane, same test ---")
        st = call(sock_path, "state")["result"]
        if st.get("active") != "listing":
            call(sock_path, "toggle_view")
        st = call(sock_path, "state")["result"]
        print("active:", st.get("active"))
        before = call(sock_path, "state")["result"]["cursor"]
        mouse(master, 30, 12)
        after = call(sock_path, "state")["result"]["cursor"]
        print(f"click at col=30 row=12: {before} -> {after}")
    finally:
        try:
            call(sock_path, "quit")
        except Exception:
            pass
        try:
            proc.wait(timeout=45)
        except Exception:
            proc.terminate()
        os.close(master)
        shutil.rmtree(tmp, ignore_errors=True)


main(os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "targets/echo"))
