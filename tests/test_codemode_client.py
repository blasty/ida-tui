"""IDA-free contract tests for the Code Mode client adapter."""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import idatui.codemode_client as module  # noqa: E402
from idatui.codemode_client import CodeModeClient, _parse_load_args  # noqa: E402
from idatui.errors import IDAToolError  # noqa: E402

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


class FakeHandle:
    def __init__(self, path: str) -> None:
        self.connected = True
        self.instance = FakeEntry(exe_path=path, idb_path=path + ".i64")
        self.waited = None
        self.saved = 0
        self.closed = False
        self.code = ""
        self.code_timeout = None

    def wait_autoanalysis(self, timeout=None):
        self.waited = timeout
        return {"complete": True, "status": "complete"}

    def execute_python(self, code, timeout=None):
        self.code = code
        self.code_timeout = timeout
        return {"result": {"sentinel": 7}, "stdout": "", "stderr": ""}

    def save_database(self):
        self.saved += 1
        return {"saved": True, "idb_path": self.instance.idb_path}

    def close(self):
        self.connected = False
        self.closed = True


class FakeDatabaseHandle:
    opened = None
    kwargs = None

    @classmethod
    def open(cls, path, **kwargs):
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
    check("legacy switches map to typed Code Mode options",
          (proc, base, file_type) == ("arm:ARMv7-M", 0x8000000, "Raw"),
          (proc, base, file_type))
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
    module.DatabaseOpenOptions = original_options or FakeOpenOptions
    module.DatabaseBusyError = original_busy or FakeBusy
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.bin")
            with open(path, "wb") as file:
                file.write(b"sample")
            client = CodeModeClient(path, load_args="-parm:ARMv7-A -b100")
            notes = []
            client.connect(timeout=42, progress=notes.append)
            handle = client._handle
            check("connect delegates database discovery to DatabaseHandle.open",
                  FakeDatabaseHandle.opened == path and handle is not None)
            options = FakeDatabaseHandle.kwargs["options"]
            check("typed loader options cross the dependency boundary",
                  options.processor == "arm:ARMv7-A"
                  and options.image_base == 0x1000,
                  options)
            check("every open option exists in the real library",
                  *_option_fields_are_real(options))
            # A fake that swallows **kwargs cannot catch a keyword the real
            # library does not have -- which is exactly how this port shipped
            # `loading_address` (the real name is `image_base`) and would have
            # raised TypeError on the very first connect. Check the names we
            # send against the real signature whenever it is importable.
            check("every open() keyword exists in the real library",
                  *_open_kwargs_are_real(FakeDatabaseHandle.kwargs))
            check("connect waits for Code Mode autoanalysis",
                  handle.waited == 42, getattr(handle, "waited", None))
            check("progress distinguishes discovery and backend attachment",
                  len(notes) == 2 and "gui" in notes[-1], notes)
            result = client.invoke("list_funcs", queries=[{"offset": 0, "count": 2}])
            check("invoke returns execute_python's result", result == {"sentinel": 7}, result)
            check("operation scripts use the preloaded ida-domain database",
                  "db.functions.get_all()" in handle.code, handle.code[:200])
            check("health exposes registry identity",
                  client.health()["record_id"] == "123-abcdef")
            client.save_database()
            check("save uses the public Code Mode save route", handle.saved == 1)
            client.close()
            check("close releases only the handle lease", handle.closed)
            check("GUI lifetime is never claimed by the client",
                  client.wait_released(0) is False)
    finally:
        module.DatabaseHandle = original
        module.DatabaseOpenOptions = original_options
        module.DatabaseBusyError = original_busy

    client = CodeModeClient(__file__)
    try:
        client.invoke("not-an-operation")
    except IDAToolError as exc:
        check("unknown adapter operations are explicit", exc.tool == "not-an-operation")
    else:
        check("unknown adapter operations are explicit", False)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
