"""Stdlib-only client for the idatui RPC socket. Drive the TUI from another pane.

    # point at the socket the TUI was launched with (--rpc), or set IDATUI_RPC_SOCK
    python -m idatui.rpcclient --sock /tmp/ida.sock state
    python -m idatui.rpcclient goto target=main
    python -m idatui.rpcclient keys g m a i n enter        # 'keys' takes positionals
    python -m idatui.rpcclient text "hello world" delay_ms=40
    python -m idatui.rpcclient move dir=down n=5
    python -m idatui.rpcclient screen                      # prints the raw screen text

Also usable as a library:
    from idatui.rpcclient import RpcClient
    with RpcClient(sock) as c:
        c.call("goto", target="main")

No auth: whoever can r/w the socket drives the app.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any


class RpcClient:
    #: Default read timeout (s). Bounds any single call so a slow/hung server
    #: (e.g. Hex-Rays grinding on an undecompilable function) can't block the
    #: CLI forever. Override via ctor or the IDATUI_RPC_TIMEOUT env var.
    #:
    #: 90s was too tight on real firmware: a comment on a 42k-line flat listing
    #: (one segment, no function boundaries to limit the rebuild) took 26-106s,
    #: so the client reported "no response ... server busy or the op is hung"
    #: for edits that had in fact been applied. A driver that believes a
    #: successful edit failed is worse than a slow one -- it redoes the work, or
    #: "fixes" something that was never broken. Real hangs still get caught,
    #: just later.
    DEFAULT_TIMEOUT = 300.0

    def __init__(self, sock_path: str, timeout: float | None = None):
        self.path = sock_path
        self._sock: socket.socket | None = None
        self._buf = b""
        self._id = 0
        if timeout is None:
            env = os.environ.get("IDATUI_RPC_TIMEOUT")
            timeout = float(env) if env else self.DEFAULT_TIMEOUT
        self.timeout = timeout

    def __enter__(self) -> "RpcClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        if self.timeout and self.timeout > 0:
            s.settimeout(self.timeout)
        self._sock = s

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def call(self, method: str, **params: Any) -> Any:
        assert self._sock is not None, "not connected"
        self._id += 1
        req = {"id": self._id, "method": method, "params": params}
        self._sock.sendall(json.dumps(req).encode() + b"\n")
        while b"\n" not in self._buf:
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout as e:
                raise RpcError(
                    f"no response for {method!r} within {self.timeout}s "
                    f"(server busy or the op is hung, e.g. a failed decompile)"
                ) from e
            if not chunk:
                raise ConnectionError("server closed the connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        resp = json.loads(line.decode())
        if "error" in resp and resp["error"]:
            raise RpcError(resp["error"].get("message", "rpc error"))
        return resp.get("result")


class RpcError(Exception):
    pass


def _coerce(v: str) -> Any:
    """Params are strings on the CLI; only booleans need coercing (the server
    int()s numeric params itself, and addresses/names must stay strings)."""
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    return v


def main(argv: list[str]) -> int:
    sock = os.environ.get("IDATUI_RPC_SOCK")
    args = list(argv)
    if args and args[0] == "--sock":
        sock = args[1]
        args = args[2:]
    if not sock:
        print("error: no socket (pass --sock PATH or set IDATUI_RPC_SOCK)",
              file=sys.stderr)
        return 2
    if not args:
        print("error: no method given", file=sys.stderr)
        return 2

    method, rest = args[0], args[1:]
    params: dict[str, Any] = {}
    if method == "keys":
        params["keys"] = rest                     # every positional is a key name
    elif method == "text" and rest and "=" not in rest[0]:
        # first positional is the literal text; the rest may be key=value
        params["text"] = rest[0]
        for tok in rest[1:]:
            k, _, val = tok.partition("=")
            params[k] = _coerce(val)
    else:
        for tok in rest:
            k, _, val = tok.partition("=")
            if not _:
                print(f"error: expected key=value, got {tok!r}", file=sys.stderr)
                return 2
            params[k] = _coerce(val)

    try:
        with RpcClient(sock) as c:
            result = c.call(method, **params)
    except (OSError, RpcError, ConnectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # 'screen' is meant to be read as text; everything else as JSON.
    if method == "screen" and isinstance(result, dict) and "text" in result:
        sys.stdout.write(result["text"])
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
