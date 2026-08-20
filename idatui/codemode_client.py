"""Client adapter from ida-tui's domain operations to IDA Code Mode.

``DatabaseHandle`` is the lifecycle boundary: it discovers an already-registered
GUI database, reuses a shared managed idalib worker, or starts one when needed.
The TUI never owns or terminates an IDA process.  Closing this client releases
only its lease.

Remote operations are ordinary typed Python functions declared in
``idatui.remote_ops``. Code Mode installs their content-addressed modules once
per handle; subsequent calls send only encoded arguments. The optimized
IDAPython listing/decompiler implementation remains real source in
``idatui.remote_tools`` and is installed through the same module interface.
"""

from __future__ import annotations

import os
import shlex
import threading
import time
from collections.abc import Callable
from typing import Any

from .errors import IDAConnectionError, IDATimeoutError, IDAToolError, Session

# ida_codemode is imported EAGERLY-IF-PRESENT but never at hard import cost.
#
# The paging/graph/trace layers and their offline test suites must keep importing
# `idatui` on a machine with no IDA and no Code Mode installed -- that is the
# house rule the stdlib-only worker client used to satisfy for free, and
# `tests/run.py --fast` (380 checks, any python3) depends on it. A hard top-level
# import here makes the whole package unimportable, so the failure is deferred to
# the first operation that genuinely needs the library.
_CODEMODE_ERROR: Exception | None = None
try:
    from ida_codemode import (
        CodeModeConnectionError,
        DatabaseBusyError,
        DatabaseDisconnectedError,
        DatabaseHandle,
        DatabaseInstance,
        DatabaseOpenOptions,
        RemoteError,
        find_database_owner,
        wait_database_released,
    )
except ImportError as _exc:  # library absent: usable only for offline layers
    _CODEMODE_ERROR = _exc
    # Bound to None rather than left undefined so the names stay patchable: the
    # offline contract tests inject a fake DatabaseHandle here.
    CodeModeConnectionError = DatabaseDisconnectedError = RemoteError = None  # type: ignore[assignment,misc]
    DatabaseBusyError = DatabaseHandle = DatabaseInstance = None  # type: ignore[assignment,misc]
    DatabaseOpenOptions = find_database_owner = wait_database_released = None  # type: ignore[assignment]


def _require_codemode() -> None:
    """Raise an actionable error when the Code Mode library is missing.

    Gated on the binding, not on the original import result, so a test that
    injects a fake ``DatabaseHandle`` exercises the real adapter logic.
    """
    if DatabaseHandle is None:
        raise IDAConnectionError(
            "ida-codemode is not installed in this environment "
            f"({_CODEMODE_ERROR}). Install it (e.g. `uv sync`, or "
            "`pip install ida-codemode`) so ida-tui can lease a "
            "database."
        ) from _CODEMODE_ERROR


def database_owner(idb_path: str, staged_path: str | None = None):
    """The Code Mode instance that owns ``idb_path``/``staged_path``, else None.

    Returns None when the Code Mode library is absent: with no library there is
    no client in this environment that could be holding the database, and the
    IDA-free layers (project staging) must keep working. Discovery errors with
    the library installed still propagate because unknown ownership is unsafe.
    """
    if DatabaseHandle is None:
        return None
    if staged_path:
        owner = find_database_owner(
            staged_path,
            output_database=idb_path,
            timeout=0.5,
        )
        return owner or find_database_owner(staged_path, timeout=0.5)
    return find_database_owner(idb_path, timeout=0.5)


def registered_database(path: str, output_database: str | None = None) -> bool:
    """Whether a live/lock-held Code Mode instance owns this target."""
    _require_codemode()
    return (
        find_database_owner(
            path,
            output_database=output_database,
            timeout=0.5,
        )
        is not None
    )


class _NoopKeepAlive:
    """Compatibility shim: the DatabaseHandle's SSE lease is the heartbeat."""

    def __init__(self) -> None:
        self.beats = self.failures = 0

    def start(self) -> "_NoopKeepAlive":
        return self

    def stop(self) -> None:
        pass


def _parse_load_args(value: str) -> tuple[str | None, int | None, str | None]:
    """Translate ida-tui's legacy first-open switches to Code Mode options.

    Code Mode has typed options for processor, natural loading address and file
    type.  It deliberately has no arbitrary command-line escape hatch; reject
    switches we cannot represent instead of silently loading a blob wrongly.
    """
    processor: str | None = None
    loading_address: int | None = None
    file_type: str | None = None
    unsupported: list[str] = []
    try:
        words = shlex.split(value or "", posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"invalid IDA load options: {exc}") from exc
    for word in words:
        if word.startswith("-p") and len(word) > 2:
            processor = word[2:]
        elif word.startswith("-b") and len(word) > 2:
            try:
                # IDA's -b is in 16-byte paragraphs. DatabaseHandle expects the
                # natural address, which is the safer public API.
                loading_address = int(word[2:], 16) << 4
            except ValueError as exc:
                raise ValueError(f"invalid IDA loading address: {word!r}") from exc
        elif word.startswith("-T") and len(word) > 2:
            file_type = word[2:]
        else:
            unsupported.append(word)
    if unsupported:
        joined = " ".join(unsupported)
        raise ValueError(
            "ida-codemode cannot represent arbitrary IDA load options: "
            f"{joined!r}; use processor/base/file type options instead"
        )
    return processor, loading_address, file_type


class IDBEventListener:
    """Debounced, closeable delivery of another client's IDB changes.

    Code Mode's subscription is a blocking iterator, so one daemon thread reads
    it and a second waits for a quiet period before handing a batch to the UI.
    Keeping the debounce here avoids a permanent Textual worker (which would
    make the app's worker-idle contract impossible) and bounds refresh work to
    one pass per edit burst.
    """

    def __init__(
        self,
        client: "CodeModeClient",
        callback: Callable[[tuple[dict[str, Any], ...]], None],
        *,
        on_error: Callable[[BaseException], None] | None = None,
        debounce: float = 0.2,
    ) -> None:
        self._client = client
        self._callback = callback
        self._on_error = on_error
        self._debounce = max(float(debounce), 0.0)
        self._condition = threading.Condition()
        self._closed = False
        self._subscription = None
        self._pending: list[dict[str, Any]] = []
        self._deadline = 0.0
        self._reader = threading.Thread(
            target=self._read, name="idatui-idb-events", daemon=True
        )
        self._deliverer = threading.Thread(
            target=self._deliver, name="idatui-idb-refresh", daemon=True
        )
        self._deliverer.start()
        self._reader.start()

    def _report(self, error: BaseException) -> None:
        disconnected = DatabaseDisconnectedError
        if isinstance(disconnected, type) and isinstance(error, disconnected):
            error = self._client._connection_error(error)
        with self._condition:
            closed = self._closed
        if not closed and self._on_error is not None:
            self._on_error(error)

    def _read(self) -> None:
        try:
            subscription = self._client.subscribe_idb_events()
        except Exception as exc:  # noqa: BLE001 -- surfaced through on_error
            self._report(exc)
            with self._condition:
                self._closed = True
                self._pending.clear()
                self._condition.notify_all()
            return
        with self._condition:
            if self._closed:
                subscription.close()
                return
            self._subscription = subscription
        try:
            for event in subscription:
                with self._condition:
                    if self._closed:
                        break
                if self._client.owns_event(event):
                    continue
                with self._condition:
                    if self._closed:
                        break
                    self._pending.append(event)
                    self._deadline = time.monotonic() + self._debounce
                    self._condition.notify_all()
        except Exception as exc:  # noqa: BLE001 -- stream failures are recoverable
            self._report(exc)
        finally:
            subscription.close()
            with self._condition:
                if self._subscription is subscription:
                    self._subscription = None
                self._closed = True
                self._pending.clear()
                self._condition.notify_all()

    def _deliver(self) -> None:
        while True:
            with self._condition:
                while not self._closed and not self._pending:
                    self._condition.wait()
                if self._closed:
                    return
                remaining = self._deadline - time.monotonic()
                if remaining > 0:
                    self._condition.wait(remaining)
                    continue
                batch = tuple(self._pending)
                self._pending.clear()
            try:
                self._callback(batch)
            except Exception as exc:  # noqa: BLE001 -- keep the stream alive
                self._report(exc)

    def close(self) -> None:
        """Stop delivery and unblock the subscription reader."""
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._pending.clear()
            subscription = self._subscription
            self._condition.notify_all()
        if subscription is not None:
            subscription.close()


class CodeModeClient:
    """A leased GUI/idalib database accessed through ``ida_codemode``."""

    def __init__(
        self,
        binary_path: str,
        *,
        ttl: int = 0,
        load_args: str = "",
        processor: str | None = None,
        loading_address: int | None = None,
        file_type: str | None = None,
        output_database: str | None = None,
        spawn: bool = True,
        new_database: bool = False,
    ) -> None:
        del ttl  # managed-worker lifetime is lease-based, not idle-TTL based
        self._path = os.path.abspath(os.path.expanduser(binary_path))
        parsed_processor, parsed_address, parsed_file_type = _parse_load_args(load_args)
        self._processor = processor or parsed_processor
        self._loading_address = (
            loading_address if loading_address is not None else parsed_address
        )
        self._file_type = file_type or parsed_file_type
        self._output_database = output_database
        self._spawn = spawn
        self._new_database = new_database
        self._handle: DatabaseHandle | None = None
        self._last_instance: DatabaseInstance | None = None
        self._connect_lock = threading.Lock()

    def connect(self, timeout: float = 1800.0, progress=None) -> "CodeModeClient":
        _require_codemode()
        with self._connect_lock:
            handle = self._handle
            if handle is not None:
                if handle.connected:
                    return self
                raise IDAConnectionError(
                    "Code Mode database disconnected; explicit rediscovery required"
                )
            if progress:
                progress(
                    f"discovering Code Mode database for {os.path.basename(self._path)}…"
                )
            try:
                # A Ctrl+L reload releases its current managed-worker lease, but
                # that worker remains registered during Code Mode's final-lease
                # grace period. Retry only that known handoff window. A GUI or
                # another long-lived client remains busy and yields a clear
                # failure rather than being modified underneath its owner.
                deadline = time.monotonic() + min(timeout, 60.0)
                while True:
                    try:
                        handle = DatabaseHandle.open(
                            self._path,
                            options=DatabaseOpenOptions(
                                spawn=self._spawn,
                                startup_timeout=max(0.1, timeout),
                                output_database=self._output_database,
                                processor=self._processor,
                                # The natural byte address is converted to IDA's
                                # paragraph-based -b value by Code Mode.
                                image_base=self._loading_address,
                                file_type=self._file_type,
                                new_database=self._new_database,
                            ),
                        )
                        break
                    except DatabaseBusyError:
                        if not self._new_database or time.monotonic() >= deadline:
                            raise
                        if progress:
                            progress(
                                "waiting for the previous Code Mode lease to close…"
                            )
                        owner = find_database_owner(
                            self._path,
                            output_database=self._output_database,
                            timeout=0.5,
                        )
                        if owner is not None:
                            wait_database_released(
                                owner,
                                max(0.0, deadline - time.monotonic()),
                            )
                        else:
                            time.sleep(0.2)
                if progress:
                    backend = handle.instance.backend
                    progress(
                        f"attached to {backend} database; waiting for auto-analysis…"
                    )
                handle.wait_autoanalysis(timeout=timeout)
            except Exception as exc:  # normalize the dependency's transport errors
                raise self._connection_error(exc) from exc
            self._handle = handle
            self._last_instance = handle.instance
            return self

    @staticmethod
    def _connection_error(exc: BaseException) -> IDAConnectionError:
        return IDAConnectionError(str(exc) or type(exc).__name__)

    @property
    def connected(self) -> bool:
        return self._handle is not None and self._handle.connected

    @property
    def pid(self) -> int | None:
        return self._handle.instance.pid if self._handle is not None else None

    @property
    def backend(self) -> str | None:
        return self._handle.instance.backend if self._handle is not None else None

    def owns_event(self, event: dict[str, Any]) -> bool:
        """Whether ``event`` was produced through this client's handle."""
        handle = self._handle
        return handle is not None and handle.owns_event(event)

    def subscribe_idb_events(self):
        """Open Code Mode's closeable IDB-change iterator."""
        if not self.connected:
            self.connect()
        handle = self._handle
        if handle is None:
            raise IDAConnectionError("Code Mode database is not connected")
        try:
            return handle.subscribe_idb_events()
        except (DatabaseDisconnectedError, CodeModeConnectionError) as exc:
            raise self._connection_error(exc) from exc

    def watch_idb_events(
        self,
        callback: Callable[[tuple[dict[str, Any], ...]], None],
        *,
        on_error: Callable[[BaseException], None] | None = None,
        debounce: float = 0.2,
    ) -> IDBEventListener:
        """Deliver external IDB changes in debounced batches."""
        return IDBEventListener(self, callback, on_error=on_error, debounce=debounce)

    def call(self, operation: Callable[..., Any], /, **args) -> Any:
        """Execute one source-backed remote declaration through this client."""
        name = getattr(operation, "__name__", "remote operation")
        try:
            from .remote_ops import bind

            remote = bind(operation)
        except KeyError as exc:
            raise IDAToolError(
                name, f"remote operation {name!r} is not registered"
            ) from exc
        if not self.connected:
            self.connect()
        handle = self._handle
        if handle is None:
            raise IDAConnectionError("Code Mode database is not connected")
        try:
            return remote(handle, **args)
        except RemoteError as exc:
            message = str(exc)
            if exc.details.get("traceback"):
                message += f"\n{exc.details['traceback']}"
            if exc.code == "operation_timeout":
                raise IDATimeoutError(message) from exc
            raise IDAToolError(name, message) from exc
        except (DatabaseDisconnectedError, CodeModeConnectionError) as exc:
            raise self._connection_error(exc) from exc

    def save_database(self) -> dict[str, Any]:
        if not self.connected:
            self.connect()
        handle = self._handle
        if handle is None:
            raise IDAConnectionError("Code Mode database is not connected")
        try:
            return handle.save_database()
        except RemoteError as exc:
            raise IDAToolError("save_database", str(exc)) from exc
        except (DatabaseDisconnectedError, CodeModeConnectionError) as exc:
            raise self._connection_error(exc) from exc

    def discard_database(self, timeout: float = 5.0) -> bool:
        """Discard a final managed-worker lease; otherwise transfer finalization.

        ``False`` is an expected ownership result: a GUI owns its session, or
        another lease still shares the managed worker. A busy final worker is
        retried briefly so background reads finishing during quit do not turn a
        real discard into an implicit save.
        """
        handle = self._handle
        if handle is None or not handle.connected:
            return False
        entry = handle.instance
        if entry.backend != "idalib" or not getattr(entry, "managed", False):
            return False
        deadline = time.monotonic() + max(float(timeout), 0.0)
        while True:
            try:
                handle.shutdown_database(save=False)
                return True
            except RemoteError as exc:
                if exc.code in ("instance_shared", "shutdown_not_supported"):
                    return False
                if exc.code == "instance_busy" and time.monotonic() < deadline:
                    time.sleep(0.05)
                    continue
                raise IDAToolError("shutdown_database", str(exc)) from exc
            except (DatabaseDisconnectedError, CodeModeConnectionError) as exc:
                raise self._connection_error(exc) from exc

    def health(self) -> dict[str, Any]:
        if not self.connected:
            self.connect()
        assert self._handle is not None
        entry = self._handle.instance
        module = os.path.basename(entry.exe_path or entry.idb_path or self._path)
        return {
            "ok": self._handle.connected,
            "module": module,
            "backend": entry.backend,
            "record_id": entry.record_id,
            "input_path": entry.exe_path,
            "idb_path": entry.idb_path,
        }

    def keepalive(self, interval: float = 120.0) -> _NoopKeepAlive:
        del interval
        return _NoopKeepAlive()

    def resolve_db(self) -> str:
        if not self.connected:
            self.connect()
        assert self._handle is not None
        return self._handle.instance.record_id

    def set_db(self, db: str | None) -> None:
        del db  # one handle is permanently bound to one registered database

    def list_sessions(self) -> list[Session]:
        if not self.connected:
            self.connect()
        assert self._handle is not None
        entry = self._handle.instance
        path = entry.exe_path or entry.idb_path or self._path
        return [
            Session(
                session_id=entry.record_id,
                filename=os.path.basename(path),
                input_path=path,
                is_active=True,
            )
        ]

    def close(self, grace: float = 0.0) -> None:
        del grace
        with self._connect_lock:
            handle, self._handle = self._handle, None
        if handle is not None:
            self._last_instance = handle.instance
            handle.close()  # release our lease; never close a GUI/other client's DB

    def wait_released(self, timeout: float = 45.0) -> bool:
        """Wait until a managed instance releases its lifetime lock.

        Normal application shutdown must not wait: another client may retain the
        worker. This is an explicit test/maintenance helper for deleting a
        temporary IDB safely after this client closes. GUI instances return
        ``False`` immediately because clients never own their lifetime.
        """
        instance = self._last_instance
        if instance is None or instance.backend != "idalib":
            return False
        return wait_database_released(instance, timeout)

    def __enter__(self) -> "CodeModeClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()
