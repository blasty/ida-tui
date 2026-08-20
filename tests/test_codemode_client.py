"""IDA-free contract tests for the Code Mode client adapter."""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tempfile
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.errors import IDAConnectionError, IDAToolError  # noqa: E402
from idatui import remote_ops  # noqa: E402
import idatui.codemode_client as module  # noqa: E402
from idatui.codemode_client import CodeModeClient, _parse_load_args  # noqa: E402

#: Pure: fakes the DatabaseHandle, never touches IDA or the Code Mode library.
NEEDS_IDA = False

PASS = FAIL = 0


def check(name: str, condition: bool, detail="") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


@dataclass(frozen=True)
class FakeEntry:
    pid: int = 123
    backend: str = "gui"
    record_id: str = "123-abcdef"
    exe_path: str = ""
    idb_path: str = ""
    managed: bool = False


_CLOSED = object()


class FakeSubscription:
    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue()
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        item = self._queue.get()
        if isinstance(item, BaseException):
            raise item
        if item is _CLOSED:
            raise StopIteration
        return item

    def emit(self, event: dict) -> None:
        self._queue.put(event)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._queue.put(_CLOSED)


class FakeHandle:
    def __init__(self, path: str) -> None:
        self.connected = True
        self.instance = FakeEntry(exe_path=path, idb_path=path + ".i64")
        self.waited = None
        self.saved = 0
        self.closed = False
        self.code = ""
        self.codes = []
        self.code_timeout = None
        self.operation_label = None
        self.event_origin_id = "fake-handle-origin"
        self.owns_checks = 0
        self.subscription = FakeSubscription()
        self.shutdown_calls = []
        self.shutdown_error = None

    def wait_autoanalysis(self, timeout=None):
        self.waited = timeout
        return {"complete": True, "status": "complete"}

    def execute_python(
        self,
        code,
        timeout=None,
        *,
        operation_id=None,
        operation_label=None,
        persist_globals=False,
        filename=None,
    ):
        self.code = code
        self.codes.append(code)
        self.code_timeout = timeout
        self.operation_label = operation_label
        result = (
            {
                "__remote_ida_status__": "ok",
                "__remote_ida_value__": {"sentinel": 7},
            }
            if ".modules.get(" in code
            else True
        )
        return {"result": result, "stdout": "", "stderr": ""}

    def subscribe_idb_events(self):
        return self.subscription

    def owns_event(self, event):
        self.owns_checks += 1
        return event.get("origin_id") == self.event_origin_id

    def save_database(self):
        self.saved += 1
        return {"saved": True, "idb_path": self.instance.idb_path}

    def shutdown_database(self, *, save=True):
        self.shutdown_calls.append(save)
        if self.shutdown_error is not None:
            raise module.RemoteError(self.shutdown_error, self.shutdown_error, 409)
        return {"shutting_down": True, "save": save}

    def close(self):
        self.subscription.close()
        self.connected = False
        self.closed = True


class FakeDatabaseHandle:
    opened = None
    opens = 0
    kwargs = None

    @classmethod
    def open(cls, path, **kwargs):
        cls.opens += 1
        cls.opened = path
        cls.kwargs = kwargs
        return FakeHandle(path)


@dataclass(frozen=True)
class FakeOpenOptions:
    """Stand-in for DatabaseOpenOptions when the library is not installed.

    Deliberately STRICT (no **kwargs): an option the adapter invents would
    raise here, and `_option_fields_are_real` checks the surviving names
    against the real dataclass wherever it is importable.
    """

    spawn: bool = True
    startup_timeout: float = 120.0
    output_database: str | None = None
    processor: str | None = None
    image_base: int | None = None
    file_type: str | None = None
    new_database: bool = False


class FakeBusy(Exception):
    """Stand-in for DatabaseBusyError: `except None` is a TypeError."""


class FakeDisconnected(Exception):
    """Stand-in for DatabaseDisconnectedError in stdlib-only runs."""


def _open_kwargs_are_real(sent: dict):
    """(ok, detail) for the kwargs the adapter passes to DatabaseHandle.open.

    Skips (passes) when ida_codemode is not installed, so the file stays pure.
    """
    try:
        import inspect
        from ida_codemode import DatabaseHandle as Real
    except ImportError:
        return True, "ida_codemode not installed - signature not checked"
    accepted = set(inspect.signature(Real.open).parameters)
    unknown = sorted(set(sent) - accepted)
    return not unknown, f"open() rejects {unknown}"


def _option_fields_are_real(options):
    """(ok, detail) for the option names the adapter fills in.

    The open() signature no longer names the loader options -- they moved
    inside DatabaseOpenOptions -- so the `loading_address` class of bug now
    hides there instead. Check it in the same way.
    """
    try:
        import dataclasses
        from ida_codemode import DatabaseOpenOptions as Real
    except ImportError:
        return True, "ida_codemode not installed - fields not checked"
    accepted = {field.name for field in dataclasses.fields(Real)}
    unknown = sorted({f.name for f in dataclasses.fields(options)} - accepted)
    return not unknown, f"DatabaseOpenOptions rejects {unknown}"


def main() -> int:
    proc, base, file_type = _parse_load_args("-parm:ARMv7-M -b800000 -TRaw")
    check(
        "legacy switches map to typed Code Mode options",
        (proc, base, file_type) == ("arm:ARMv7-M", 0x8000000, "Raw"),
        (proc, base, file_type),
    )
    try:
        _parse_load_args("-parm -zcustom")
    except ValueError as exc:
        check("arbitrary IDA switches fail loudly", "cannot represent" in str(exc), exc)
    else:
        check("arbitrary IDA switches fail loudly", False)

    original = module.DatabaseHandle
    module.DatabaseHandle = FakeDatabaseHandle
    # The library's own names when it is installed; strict fakes when it is not
    # (this file must keep running under a stdlib-only python3).
    original_options = module.DatabaseOpenOptions
    original_busy = module.DatabaseBusyError
    original_disconnected = module.DatabaseDisconnectedError
    module.DatabaseOpenOptions = original_options or FakeOpenOptions
    module.DatabaseBusyError = original_busy or FakeBusy
    module.DatabaseDisconnectedError = original_disconnected or FakeDisconnected
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.bin")
            with open(path, "wb") as file:
                file.write(b"sample")
            client = CodeModeClient(path, load_args="-parm:ARMv7-A -b100")
            notes = []
            client.connect(timeout=42, progress=notes.append)
            handle = client._handle
            check(
                "connect delegates database discovery to DatabaseHandle.open",
                FakeDatabaseHandle.opened == path and handle is not None,
            )
            options = FakeDatabaseHandle.kwargs["options"]
            check(
                "typed loader options cross the dependency boundary",
                options.processor == "arm:ARMv7-A" and options.image_base == 0x1000,
                options,
            )
            check(
                "every open option exists in the real library",
                *_option_fields_are_real(options),
            )
            # A fake that swallows **kwargs cannot catch a keyword the real
            # library does not have -- which is exactly how this port shipped
            # `loading_address` (the real name is `image_base`) and would have
            # raised TypeError on the very first connect. Check the names we
            # send against the real signature whenever it is importable.
            check(
                "every open() keyword exists in the real library",
                *_open_kwargs_are_real(FakeDatabaseHandle.kwargs),
            )
            check(
                "connect waits for Code Mode autoanalysis",
                handle.waited == 42,
                getattr(handle, "waited", None),
            )
            check(
                "progress distinguishes discovery and backend attachment",
                len(notes) == 2 and "gui" in notes[-1],
                notes,
            )
            result = client.call(
                remote_ops.list_funcs, queries=[{"offset": 0, "count": 2}]
            )
            check(
                "remote operation returns its JSON result",
                result == {"sentinel": 7},
                result,
            )
            check(
                "operation source is real Python installed through ida-domain",
                any("db.functions.get_all()" in code for code in handle.codes),
                handle.codes[0][:200],
            )
            check(
                "remote operations attribute IDB events to IDA TUI",
                handle.operation_label == "IDA TUI",
                handle.operation_label,
            )
            batches = []
            delivered = threading.Event()

            def changed(batch):
                batches.append(batch)
                delivered.set()

            watcher = client.watch_idb_events(changed, debounce=0.05)
            handle.subscription.emit({"event_name": "renamed", "origin_id": "peer-1"})
            handle.subscription.emit(
                {"event_name": "cmt_changed", "origin_id": "peer-2"}
            )
            check(
                "event bursts produce one debounced refresh",
                delivered.wait(1) and len(batches) == 1 and len(batches[0]) == 2,
                batches,
            )
            delivered.clear()
            handle.subscription.emit(
                {"event_name": "renamed", "origin_id": handle.event_origin_id}
            )
            time.sleep(0.1)
            check(
                "the listener uses handle ownership to ignore its own events",
                not delivered.is_set()
                and len(batches) == 1
                and handle.owns_checks >= 3,
                (batches, handle.owns_checks),
            )
            handle.subscription.emit(
                {"event_name": "byte_patched", "origin_id": "peer-3"}
            )
            watcher.close()
            time.sleep(0.1)
            check(
                "closing drops a pending debounced refresh",
                not delivered.is_set() and len(batches) == 1,
                batches,
            )
            check(
                "health exposes registry identity",
                client.health()["record_id"] == "123-abcdef",
            )
            client.save_database()
            check("save uses the public Code Mode save route", handle.saved == 1)
            check(
                "GUI leases transfer rather than claiming discard",
                client.discard_database() is False and handle.shutdown_calls == [],
                handle.shutdown_calls,
            )
            handle.instance = FakeEntry(
                backend="idalib", managed=True, exe_path=path, idb_path=path + ".i64"
            )
            check(
                "a final managed lease discards without saving",
                client.discard_database() is True and handle.shutdown_calls == [False],
                handle.shutdown_calls,
            )
            handle.shutdown_error = "instance_shared"
            check(
                "a shared managed lease transfers finalization",
                client.discard_database() is False,
                handle.shutdown_calls,
            )
            handle.shutdown_error = "instance_busy"
            try:
                client.discard_database(timeout=0)
            except IDAToolError as exc:
                check(
                    "a busy final lease never silently saves",
                    exc.tool == "shutdown_database",
                    exc,
                )
            else:
                check("a busy final lease never silently saves", False)
            handle.shutdown_error = None
            handle.instance = FakeEntry(exe_path=path, idb_path=path + ".i64")
            opens = FakeDatabaseHandle.opens
            handle.connected = False
            try:
                client.health()
            except IDAConnectionError as exc:
                check(
                    "a disconnected handle requires explicit rediscovery",
                    "explicit rediscovery" in str(exc)
                    and FakeDatabaseHandle.opens == opens,
                    (exc, FakeDatabaseHandle.opens, opens),
                )
            else:
                check("a disconnected handle requires explicit rediscovery", False)
            client.close()
            check("close releases only the handle lease", handle.closed)
            check(
                "GUI lifetime is never claimed by the client",
                client.wait_released(0) is False,
            )
            disconnected = CodeModeClient(path).connect()
            stream_errors = []
            stream_failed = threading.Event()

            def failed(error):
                stream_errors.append(error)
                stream_failed.set()

            stream_watch = disconnected.watch_idb_events(
                lambda _batch: None, on_error=failed, debounce=0
            )
            disconnected._handle.subscription.emit(
                module.DatabaseDisconnectedError("GUI database closed")
            )
            check(
                "stream disconnects become application connection errors",
                stream_failed.wait(1)
                and isinstance(stream_errors[0], IDAConnectionError),
                stream_errors,
            )
            stream_watch.close()
            disconnected.close()
    finally:
        module.DatabaseHandle = original
        module.DatabaseOpenOptions = original_options
        module.DatabaseBusyError = original_busy
        module.DatabaseDisconnectedError = original_disconnected

    client = CodeModeClient(__file__)

    def unknown_operation():
        pass

    try:
        client.call(unknown_operation)
    except IDAToolError as exc:
        check(
            "unknown adapter operations are explicit",
            exc.tool == "unknown_operation",
        )
    else:
        check("unknown adapter operations are explicit", False)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
