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
        self.entry = FakeEntry(exe_path=path, idb_path=path + ".i64")
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
        return {"saved": True, "idb_path": self.entry.idb_path}

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


def _open_kwargs_are_real(sent: dict):
    """(ok, detail) for the kwargs the adapter passes to DatabaseHandle.open.

    Skips (passes) when ida_codemode is not installed, so the file stays pure.
    """
    try:
        import inspect
        from ida_codemode.client import DatabaseHandle as Real
    except ImportError:
        return True, "ida_codemode not installed - signature not checked"
    accepted = set(inspect.signature(Real.open).parameters)
    unknown = sorted(set(sent) - accepted)
    return not unknown, f"open() rejects {unknown}"


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
            check("typed loader options cross the dependency boundary",
                  FakeDatabaseHandle.kwargs["processor"] == "arm:ARMv7-A"
                  and FakeDatabaseHandle.kwargs["image_base"] == 0x1000,
                  FakeDatabaseHandle.kwargs)
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
