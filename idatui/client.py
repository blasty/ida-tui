"""Persistent, thread-safe client for the ida-pro-mcp (idalib) MCP server.

This is the foundation the whole TUI stands on. Unlike the throwaway CLI in the
ida-mcp skill (which re-does the MCP handshake and spins a fresh socket on every
call), this client:

  * Performs the MCP handshake exactly once and keeps the session warm
    (measured: ~7ms/call warm vs ~60ms cold).
  * Reuses TCP connections via a small keep-alive pool (no socket churn over a
    long TUI session) while still allowing concurrent calls from worker threads.
  * Has a precise, *grounded* error taxonomy (see below) so callers can tell
    apart transport failures, protocol errors, hard tool errors, and soft
    per-item "not found" results.
  * Recovers automatically from an expired server session (404 -> re-handshake
    -> retry once) and from transient transport hiccups (bounded retries).
  * Auto-injects the mandatory ``database=<session_id>`` argument, resolving a
    single open session automatically and refusing to guess when several are
    open.

Error taxonomy (verified against the live server, 2026-07):

  IDAConnectionError  transport could not be established / was lost
  IDATimeoutError     a request exceeded its deadline
  IDAProtocolError    malformed / unexpected HTTP or JSON-RPC framing
  IDARPCError         JSON-RPC ``error`` object in the envelope
  IDAToolError        tool returned ``result.isError == true`` (hard failure:
                      bad params, unknown tool, missing database, ...)
  IDASessionError     no session / multiple sessions and none pinned

Note the deliberate *non*-error: a tool that returns ``isError == false`` with an
``error`` field inside its payload (e.g. ``decompile`` on an unknown address, or
per-item failures in a batch tool) is treated as *data*, not an exception. The
caller inspects the payload. Raising on those would break every batch tool.

The client is stdlib-only (``http.client`` / ``urllib.parse``).
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

DEFAULT_URL = "http://127.0.0.1:8745/mcp"
PROTOCOL_VERSION = "2025-06-18"

# Tools that must NOT receive an injected ``database`` argument.
SESSION_AGNOSTIC_TOOLS = frozenset({"idb_list", "idb_open", "int_convert"})

# Substrings (lowercased) that identify a stale/invalid IDB session in a tool
# error message. Verified against the live server: after a server restart the
# old session id is gone and every call fails with "Session not found: <id>".
_STALE_SESSION_MARKERS = ("session not found", "database is required")


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class IDAError(Exception):
    """Base class for all client errors."""


class IDAConnectionError(IDAError):
    """The transport could not be established or was lost."""


class IDATimeoutError(IDAError):
    """A request exceeded its deadline."""


class IDAProtocolError(IDAError):
    """Malformed or unexpected HTTP / JSON-RPC framing."""


class IDARPCError(IDAError):
    """The JSON-RPC envelope carried an ``error`` object."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class IDAToolError(IDAError):
    """A tool call returned ``result.isError == true`` (a hard failure)."""

    def __init__(self, tool: str, message: str):
        super().__init__(f"tool {tool!r} failed: {message}")
        self.tool = tool
        self.message = message


class IDASessionError(IDAError):
    """No IDB session is open, or several are and none was pinned."""


# --------------------------------------------------------------------------- #
# Session model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Session:
    session_id: str
    filename: str
    input_path: str
    is_active: bool = False
    is_analyzing: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        return cls(
            session_id=d.get("session_id", ""),
            filename=d.get("filename", ""),
            input_path=d.get("input_path", ""),
            is_active=bool(d.get("is_active", False)),
            is_analyzing=bool(d.get("is_analyzing", False)),
        )


# --------------------------------------------------------------------------- #
# Transport: a tiny keep-alive connection pool over http.client
# --------------------------------------------------------------------------- #
class _Transport:
    """Keep-alive HTTP/1.1 pool. Thread-safe. One request == one pooled conn.

    Connections are checked out, used for exactly one request/response, then
    returned to the pool if still healthy. On a dropped/broken connection the
    request is retried on a fresh connection (bounded by ``max_retries``).
    """

    def __init__(self, url: str, *, max_retries: int = 2, pool_size: int = 8):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise IDAConnectionError(f"unsupported scheme: {parts.scheme!r}")
        self._https = parts.scheme == "https"
        self._host = parts.hostname or "127.0.0.1"
        self._port = parts.port or (443 if self._https else 80)
        self._path = parts.path or "/"
        self._max_retries = max_retries
        self._pool_size = pool_size
        self._idle: deque[http.client.HTTPConnection] = deque()
        self._lock = threading.Lock()

    def _new_conn(self, timeout: float) -> http.client.HTTPConnection:
        cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        return cls(self._host, self._port, timeout=timeout)

    def _checkout(self, timeout: float) -> http.client.HTTPConnection:
        with self._lock:
            while self._idle:
                conn = self._idle.popleft()
                # Reuse only if the socket still looks alive.
                if conn.sock is not None:
                    conn.timeout = timeout
                    try:
                        conn.sock.settimeout(timeout)
                    except OSError:
                        try:
                            conn.close()
                        except OSError:
                            pass
                        continue
                    return conn
        return self._new_conn(timeout)

    def _checkin(self, conn: http.client.HTTPConnection) -> None:
        with self._lock:
            if len(self._idle) < self._pool_size:
                self._idle.append(conn)
                return
        try:
            conn.close()
        except OSError:
            pass

    def request(
        self, body: bytes, headers: dict[str, str], timeout: float
    ) -> tuple[int, dict[str, str], bytes]:
        """POST ``body``; return (status, response_headers, response_body)."""
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            conn = self._checkout(timeout)
            try:
                conn.request("POST", self._path, body=body, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                data = resp.read()  # must fully drain before reuse
            except socket.timeout as e:
                self._discard(conn)
                raise IDATimeoutError(f"request timed out after {timeout}s") from e
            except (
                http.client.RemoteDisconnected,
                http.client.BadStatusLine,
                ConnectionError,
                OSError,
            ) as e:
                # A stale pooled connection, or the server closed on us. Drop it
                # and retry on a fresh connection.
                self._discard(conn)
                last_exc = e
                continue
            else:
                if resp.will_close:
                    self._discard(conn)
                else:
                    self._checkin(conn)
                return status, resp_headers, data
        raise IDAConnectionError(
            f"transport failed after {self._max_retries + 1} attempts: {last_exc}"
        ) from last_exc

    def _discard(self, conn: http.client.HTTPConnection) -> None:
        try:
            conn.close()
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            while self._idle:
                self._discard(self._idle.popleft())


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #
class IDAClient:
    """A warm, thread-safe handle to one MCP server (and one pinned IDB).

    Typical use::

        with IDAClient(db="4f2223f9") as ida:
            ida.health()
            funcs = ida.call("list_funcs", queries=[{"count": 50}])
            code = ida.call("decompile", addr="main")

    Concurrency: safe to call from multiple threads (Textual workers). Requests
    run on independent pooled connections; only the id counter and handshake
    state are lock-guarded, so calls do not serialize on each other.
    """

    def __init__(
        self,
        url: str = DEFAULT_URL,
        db: str | None = None,
        *,
        timeout: float = 30.0,
        max_retries: int = 2,
        pool_size: int = 8,
        client_name: str = "idatui",
        client_version: str = "0.0.1",
        auto_recover_session: bool = True,
    ):
        self.url = url
        self._db = db
        self.timeout = timeout
        self.auto_recover_session = auto_recover_session
        self._transport = _Transport(url, max_retries=max_retries, pool_size=pool_size)
        self._client_info = {"name": client_name, "version": client_version}

        self._rid = 0
        self._sid: str | None = None
        self._ready = False
        self._state_lock = threading.Lock()  # guards _rid, _sid, _ready
        self._handshake_lock = threading.Lock()  # serializes (re)handshake

    # -- lifecycle --------------------------------------------------------- #
    def __enter__(self) -> "IDAClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> "IDAClient":
        """Ensure the MCP handshake has completed (idempotent, thread-safe)."""
        if self._ready:
            return self
        self._handshake()
        return self

    def close(self) -> None:
        self._transport.close()

    # -- low-level plumbing ------------------------------------------------ #
    def _next_id(self) -> int:
        with self._state_lock:
            self._rid += 1
            return self._rid

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        sid = self._sid
        if sid:
            h["Mcp-Session-Id"] = sid
        return h

    def _handshake(self) -> None:
        with self._handshake_lock:
            if self._ready:
                return
            with self._state_lock:
                self._sid = None
            rid = self._next_id()
            status, headers, body = self._transport.request(
                self._encode(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": self._client_info,
                        },
                    }
                ),
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                self.timeout,
            )
            if status // 100 != 2:
                raise IDAProtocolError(
                    f"initialize failed: HTTP {status}: {body[:200]!r}"
                )
            sid = headers.get("mcp-session-id")
            envelope = self._parse_body(body, rid)
            self._raise_on_rpc_error(envelope)
            with self._state_lock:
                self._sid = sid
            # notifications/initialized is a fire-and-forget notification.
            self._transport.request(
                self._encode({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                self._headers(),
                self.timeout,
            )
            with self._state_lock:
                self._ready = True

    @staticmethod
    def _encode(obj: dict) -> bytes:
        return json.dumps(obj).encode()

    @staticmethod
    def _parse_body(body: bytes, want_id: int) -> dict:
        """Extract the JSON-RPC envelope for ``want_id`` from a (possibly SSE) body."""
        text = body.decode("utf-8", "replace")
        found: dict | None = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                line = line[5:].strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("id") == want_id:
                found = obj
        if found is None:
            raise IDAProtocolError(
                f"no JSON-RPC response with id={want_id} in body: {text[:200]!r}"
            )
        return found

    @staticmethod
    def _raise_on_rpc_error(envelope: dict) -> None:
        err = envelope.get("error")
        if err:
            raise IDARPCError(
                code=err.get("code", -1),
                message=err.get("message", "unknown"),
                data=err.get("data"),
            )

    def _rpc(self, method: str, params: dict, *, timeout: float | None = None) -> dict:
        """Send a JSON-RPC request, recovering once from an expired session."""
        if not self._ready:
            self._handshake()
        to = self.timeout if timeout is None else timeout
        rid = self._next_id()
        payload = self._encode(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        )
        status, headers, body = self._transport.request(payload, self._headers(), to)

        if status == 404 and self._sid is not None:
            # Server session expired: re-handshake and retry exactly once.
            with self._state_lock:
                self._ready = False
            self._handshake()
            rid = self._next_id()
            payload = self._encode(
                {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
            )
            status, headers, body = self._transport.request(
                payload, self._headers(), to
            )

        if status // 100 != 2:
            raise IDAProtocolError(f"HTTP {status}: {body[:200]!r}")

        envelope = self._parse_body(body, rid)
        self._raise_on_rpc_error(envelope)
        return envelope

    # -- tool calls -------------------------------------------------------- #
    @staticmethod
    def _extract_payload(tool: str, result: dict) -> Any:
        """Turn an MCP ``result`` object into a Python payload, or raise.

        Precedence:
          1. ``isError == true``            -> IDAToolError (hard failure)
          2. ``structuredContent`` present  -> return it (already parsed)
          3. ``content[0].text`` is JSON    -> return parsed JSON
          4. otherwise                      -> return the raw text string
        """
        if result.get("isError"):
            text = _first_text(result) or "(no message)"
            raise IDAToolError(tool, text)
        if "structuredContent" in result:
            return result["structuredContent"]
        text = _first_text(result)
        if text is None:
            return result
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    def _prepare_args(self, tool: str, args: dict) -> tuple[dict, bool]:
        """Return (arguments, db_was_injected). Never mutates the caller's dict."""
        prepared = dict(args)
        if tool in SESSION_AGNOSTIC_TOOLS or "database" in prepared:
            return prepared, False
        prepared["database"] = self.resolve_db()
        return prepared, True

    def call_envelope(self, tool: str, *, timeout: float | None = None, **args) -> dict:
        """Call ``tool`` and return the full JSON-RPC envelope (for debugging)."""
        prepared, _ = self._prepare_args(tool, args)
        return self._rpc(
            "tools/call", {"name": tool, "arguments": prepared}, timeout=timeout
        )

    def call(self, tool: str, *, timeout: float | None = None, **args) -> Any:
        """Call ``tool`` and return its payload (parsed JSON when possible).

        Raises IDAToolError on a hard tool failure. Soft/per-item errors (an
        ``error`` field with ``isError == false``) are returned as data.

        If ``auto_recover_session`` is set and the db was auto-injected, a stale
        "Session not found" error (e.g. after a server restart) triggers exactly
        one transparent recovery: drop the stale pin, re-resolve the session,
        and retry. A db the caller pinned explicitly is never silently switched.
        """
        prepared, injected = self._prepare_args(tool, args)
        envelope = self._rpc(
            "tools/call", {"name": tool, "arguments": prepared}, timeout=timeout
        )
        try:
            return self._extract_payload(tool, envelope.get("result", {}))
        except IDAToolError as e:
            if not (injected and self.auto_recover_session and _is_stale_session(e)):
                raise
            # The pinned IDB session vanished (server restart). Re-resolve the
            # sole session and retry once. resolve_db() raises IDASessionError
            # if zero/many sessions exist, so we never guess.
            self.set_db(None)
            prepared2, _ = self._prepare_args(tool, args)
            envelope2 = self._rpc(
                "tools/call", {"name": tool, "arguments": prepared2}, timeout=timeout
            )
            return self._extract_payload(tool, envelope2.get("result", {}))

    # -- session management ------------------------------------------------ #
    def list_sessions(self) -> list[Session]:
        result = self._rpc("tools/call", {"name": "idb_list", "arguments": {}})
        payload = self._extract_payload("idb_list", result.get("result", {}))
        sessions = payload.get("sessions", []) if isinstance(payload, dict) else []
        return [Session.from_dict(s) for s in sessions]

    def resolve_db(self) -> str:
        """Return the pinned session id, auto-resolving a lone open session.

        Raises IDASessionError if none is open, or if several are open and none
        has been pinned via ``db=`` / :meth:`set_db`.
        """
        if self._db:
            return self._db
        sessions = self.list_sessions()
        usable = [s for s in sessions if s.session_id]
        if len(usable) == 1:
            self._db = usable[0].session_id
            return self._db
        if not usable:
            raise IDASessionError(
                "no open IDB session with a usable id; open one with idb_open"
            )
        opts = ", ".join(f"{s.session_id} ({s.filename})" for s in usable)
        raise IDASessionError(
            f"multiple sessions open; pin one with db=... . Options: {opts}"
        )

    def set_db(self, db: str | None) -> None:
        self._db = db

    @property
    def db(self) -> str | None:
        return self._db

    # -- convenience ------------------------------------------------------- #
    def health(self) -> dict:
        return self.call("server_health")

    def list_tools(self) -> list[tuple[str, str]]:
        envelope = self._rpc("tools/list", {})
        out = []
        for t in envelope.get("result", {}).get("tools", []):
            desc = (t.get("description") or "").splitlines()
            out.append((t["name"], desc[0] if desc else ""))
        return out

    def schema(self, tool: str) -> dict:
        envelope = self._rpc("tools/list", {})
        for t in envelope.get("result", {}).get("tools", []):
            if t["name"] == tool:
                return t.get("inputSchema", {})
        raise IDAError(f"tool not found: {tool}")


def _is_stale_session(e: IDAToolError) -> bool:
    msg = e.message.lower()
    return any(marker in msg for marker in _STALE_SESSION_MARKERS)


def _first_text(result: dict) -> str | None:
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                return item.get("text")
    return None


# --------------------------------------------------------------------------- #
# Tiny self-check CLI:  python -m idatui.client [--db ID] [--url URL] [health]
# --------------------------------------------------------------------------- #
def _main(argv: list[str]) -> int:
    import os

    url = DEFAULT_URL
    db = os.environ.get("IDA_MCP_DB")
    rest: list[str] = []
    it = iter(argv)
    for a in it:
        if a == "--url":
            url = next(it)
        elif a == "--db":
            db = next(it)
        else:
            rest.append(a)

    ida = IDAClient(url, db=db)
    try:
        ida.connect()
        t0 = time.time()
        sessions = ida.list_sessions()
        print(f"sessions ({(time.time() - t0) * 1e3:.1f}ms):")
        for s in sessions:
            mark = "*" if s.is_active else " "
            print(f"  {mark} {s.session_id or '<none>':10} {s.filename}")
        try:
            h = ida.health()
            print("health:", json.dumps(h, indent=1)[:400])
        except IDASessionError as e:
            print(f"health: skipped ({e})")
    finally:
        ida.close()
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))
