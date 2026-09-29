#!/usr/bin/env python3
"""How long does a typed RPC op actually take, per character?

Runs the real TUI in a pty (NOT the pilot -- tests/_fixtures.fast_keys patches
Textual's per-key idle wait away, which is exactly the cost we want to see) and
times the semantic verbs at several delay_ms values.

    PYTHONPATH=. ~/ida-venv/bin/python experiments/type_bench.py targets/echo
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
    s.settimeout(120)
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


def main(binary):
    tmp = tempfile.mkdtemp(prefix="idatui-typebench-")
    target = os.path.join(tmp, os.path.basename(binary))
    shutil.copy2(binary, target)
    for ext in (".pristine.i64", ".i64"):
        if os.path.exists(binary + ext):
            shutil.copy2(binary + ext, target + ".i64")
            break
    sock_path = os.path.join(tmp, "rpc.sock")

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    env = dict(os.environ, TERM="xterm-256color", IDATUI_KITTY="0")
    proc = subprocess.Popen(
        [os.path.join(ROOT, "ida-tui"), target, "--rpc", sock_path],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        cwd=ROOT,
    )
    os.close(slave)

    def drain():
        while True:
            try:
                if not os.read(master, 65536):
                    return
            except OSError:
                return

    threading.Thread(target=drain, daemon=True).start()

    try:
        deadline = time.time() + 300
        while time.time() < deadline:
            if os.path.exists(sock_path):
                try:
                    if call(sock_path, "ping")["result"].get("ready"):
                        break
                except Exception:
                    pass
            time.sleep(0.3)
        else:
            raise SystemExit("never ready")

        fns = call(sock_path, "functions", limit=400)["result"]
        names = [f["name"] for f in fns if f["name"].startswith("sub_")][:4]
        big = max(fns, key=lambda f: f["size"])["name"]
        print("targets:", big, names[:2])

        for delay in (35, 12, 0):
            # goto types <name> into the g prompt: len(name) characters.
            t0 = time.time()
            call(sock_path, "goto", target=big, delay_ms=delay)
            dt = time.time() - t0
            n = len(big)
            print(
                f"goto  delay_ms={delay:>2}  {dt:6.2f}s for {n} chars"
                f"  -> {dt / n * 1000:6.1f} ms/char"
            )

        # raw text injection into a prompt, isolating keystroke cost from the
        # work a verb does after Enter.
        for delay in (35, 12, 0):
            word = "abcdefghijklmnopqrstuvwxyz"
            call(sock_path, "keys", keys=["g"])
            t0 = time.time()
            call(sock_path, "text", text=word, delay_ms=delay)
            dt = time.time() - t0
            call(sock_path, "keys", keys=["escape"])
            print(
                f"text  delay_ms={delay:>2}  {dt:6.2f}s for {len(word)} chars"
                f"  -> {dt / len(word) * 1000:6.1f} ms/char"
            )
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
