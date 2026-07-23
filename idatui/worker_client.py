"""WorkerClient — a drop-in replacement for ``IDAClient`` backed by our own
idalib worker (``idatui.worker``) over a unix socket instead of ida-pro-mcp's
HTTP/JSON transport.

It exposes exactly the surface the app/domain use on the client
(``call``/``call_envelope``/``connect``/``set_db``/``resolve_db``/
``list_sessions``/``health``/``keepalive``/``close``) and returns byte-identical
payloads (the worker calls the same tool functions), so ``domain.py`` and the
app are unchanged — you just construct a WorkerClient instead of an IDAClient.

Concurrency: the app fires calls from several worker threads over one client;
the worker is single-threaded, so calls are serialized under a lock (the worker
processes one tool at a time anyway — and at ~50us/call that's free).
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from typing import Any

from .client import IDAToolError, IDAConnectionError, Session
from .worker import recv as _recv
from .worker import send as _send


class _NoopKeepAlive:
    """The worker is ours and never idles out, so keepalive is a no-op."""

    def __init__(self) -> None:
        self.beats = self.failures = 0

    def start(self):
        return self

    def stop(self) -> None:
        pass


class WorkerClient:
    def __init__(self, binary_path: str, *, ttl: int = 0,
                 python: str | None = None) -> None:
        self._bin = os.path.abspath(os.path.expanduser(binary_path))
        self._python = python or sys.executable
        tag = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._sock_path = f"/tmp/idatui-worker-{tag}.sock"
        self._log_path = f"/tmp/idatui-worker-{tag}.log"
        self._proc: subprocess.Popen | None = None
        self._sock: socket.socket | None = None
        self._sid = uuid.uuid4().hex[:8]
        self._lock = threading.Lock()       # serialize socket use
        self._spawn_lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------- #
    def connect(self, timeout: float = 1800.0, progress=None) -> "WorkerClient":
        """Spawn the worker (opens + analyzes the DB) and connect once ready."""
        with self._spawn_lock:
            if self._sock is not None:
                return self
            if self._proc is None or self._proc.poll() is not None:
                self._proc = subprocess.Popen(
                    [self._python, "-m", "idatui.worker",
                     self._sock_path, self._bin],
                    cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    stdout=open(self._log_path, "wb"),
                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                )
            deadline = time.time() + timeout
            t0 = time.time()
            while time.time() < deadline:
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.connect(self._sock_path)
                    self._sock = s
                    return self
                except OSError:
                    if self._proc.poll() is not None:
                        raise IDAConnectionError(
                            f"worker exited (code {self._proc.returncode}): "
                            f"{self._log_tail()}  [full log: {self._log_path}]")
                    if progress:
                        progress(f"auto-analyzing {os.path.basename(self._bin)}… "
                                 f"({int(time.time() - t0)}s)")
                    time.sleep(0.2)
            raise IDAConnectionError("worker did not become ready in time")

    def close(self) -> None:
        with self._lock:
            s = self._sock
            self._sock = None
            if s is not None:
                try:
                    _send(s, ("__shutdown__", {}))
                except Exception:  # noqa: BLE001
                    pass
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    self._proc.kill()
                except Exception:  # noqa: BLE001
                    pass

    # -- the call surface -------------------------------------------------- #
    def call(self, tool: str, *, timeout: float | None = None, **args) -> Any:
        if self._sock is None:
            self.connect()
        with self._lock:
            s = self._sock
            if s is None:
                raise IDAConnectionError("worker connection is closed")
            try:
                _send(s, (tool, args))
                reply = _recv(s)
            except (OSError, ConnectionError) as e:
                self._sock = None
                raise IDAConnectionError(f"worker transport failed: {e}") from e
        if reply is None:
            self._sock = None
            raise IDAConnectionError("worker closed the connection")
        ok, payload = reply
        if not ok:
            raise IDAToolError(tool, str(payload))
        return payload

    def call_envelope(self, tool: str, *, timeout: float | None = None,
                      **args) -> dict:
        # domain.decompile() reads result.structuredContent — mirror that shape.
        return {"result": {"structuredContent": self.call(tool, timeout=timeout,
                                                           **args)}}

    # -- session shims (single-DB worker) --------------------------------- #
    def set_db(self, db: str | None) -> None:
        if db:
            self._sid = db

    def resolve_db(self) -> str:
        return self._sid

    def list_sessions(self) -> list[Session]:
        return [Session(session_id=self._sid,
                        filename=os.path.basename(self._bin),
                        input_path=self._bin, is_active=True)]

    def health(self) -> dict:
        try:
            return self.call("server_health")
        except IDAToolError:
            return {"module": os.path.basename(self._bin), "ok": True}

    def keepalive(self, interval: float = 120.0) -> _NoopKeepAlive:
        return _NoopKeepAlive()

    def _log_tail(self, n: int = 400) -> str:
        """Last meaningful line(s) of the worker log (skip IDA's licence banner),
        so a startup crash surfaces the real cause instead of just 'code 1'."""
        try:
            with open(self._log_path, encoding="utf-8", errors="replace") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return "(no worker log)"
        # the worker prints a clean 'WORKER-FATAL: ...' line on a startup crash
        for ln in reversed(lines):
            if ln.startswith("WORKER-FATAL:"):
                return ln[len("WORKER-FATAL:"):].strip()[-n:]
        skip = ("thank you", "licensed to", "[mcp]", "ida ", "hex-rays")
        meaningful = [ln for ln in lines
                      if not any(s in ln.lower() for s in skip)]
        return " | ".join((meaningful or lines)[-3:])[-n:]

    # context manager parity with IDAClient
    def __enter__(self) -> "WorkerClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()
