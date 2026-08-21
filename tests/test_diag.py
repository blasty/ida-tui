#!/usr/bin/env python3
"""idatui.diag — the channel swallowed errors go down.

Pure: no IDA, no worker, no Textual.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: pure: a ring buffer and a log file.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False

from idatui import diag  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def t_swallow_keeps_going():
    diag.clear()
    ran = []
    with diag.swallow("a thing"):
        raise ValueError("nope")
    ran.append("after")
    check("swallow() does not propagate", ran == ["after"])
    r = diag.recent()
    check("the error is recorded", len(r) == 1, str(r))
    check("with what was being attempted", r[0]["what"] == "a thing", str(r[0]))
    check(
        "and the exception type and message",
        r[0]["error"] == "ValueError: nope",
        r[0]["error"],
    )
    check(
        "and where it was actually raised",
        r[0]["where"].startswith("test_diag.py:"),
        r[0]["where"],
    )


def t_reraise():
    """The app turns IDAConnectionError into a reconnect; swallow() must not eat
    the exceptions its caller genuinely handles."""
    diag.clear()

    class Wanted(Exception):
        pass

    try:
        with diag.swallow("keeps its own", reraise=(Wanted,)):
            raise Wanted("mine")
        check("reraise lets the listed type through", False, "not raised")
    except Wanted:
        check("reraise lets the listed type through", True)
    check(
        "and a reraised error is not recorded twice",
        diag.recent() == [],
        str(diag.recent()),
    )
    with diag.swallow("still swallows others", reraise=(Wanted,)):
        raise ValueError("other")
    check("other types are still swallowed", len(diag.recent()) == 1)


def t_ring_is_bounded():
    diag.clear()
    for i in range(diag._MAX + 25):
        diag.note(f"item {i}", RuntimeError(str(i)))
    r = diag.recent(1000)
    check("the ring is bounded", len(r) == diag._MAX, f"{len(r)}")
    check(
        "it keeps the NEWEST entries",
        r[-1]["what"] == f"item {diag._MAX + 24}",
        r[-1]["what"],
    )
    check(
        "recent(n) returns the last n, newest last",
        [e["what"] for e in diag.recent(3)]
        == [
            f"item {diag._MAX + 22}",
            f"item {diag._MAX + 23}",
            f"item {diag._MAX + 24}",
        ],
        str(diag.recent(3)),
    )


def t_log_file():
    diag.clear()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.log")
        os.environ["IDATUI_LOG"] = path
        try:
            with diag.swallow("logged thing"):
                raise KeyError("missing")
        finally:
            os.environ.pop("IDATUI_LOG", None)
        body = open(path, encoding="utf-8").read()
        check("the log records what was attempted", "logged thing" in body, body[:200])
        check("and the error", "KeyError" in body, body[:200])
        check(
            "and a traceback, which the ring doesn't carry",
            "Traceback" in body and "t_log_file" in body,
            body[:300],
        )


def t_log_is_off_by_default():
    diag.clear()
    os.environ.pop("IDATUI_LOG", None)
    with diag.swallow("unlogged"):
        raise ValueError("x")
    check(
        "without $IDATUI_LOG nothing is written, but the ring still has it",
        len(diag.recent()) == 1,
    )


def t_broken_log_path_is_harmless():
    """A bad log path must never be the thing that breaks the app."""
    diag.clear()
    os.environ["IDATUI_LOG"] = "/nonexistent-dir-xyz/deep/x.log"
    try:
        with diag.swallow("still fine"):
            raise ValueError("boom")
        check("an unwritable log path doesn't raise", True)
        check("and the error is still recorded in the ring", len(diag.recent()) == 1)
    finally:
        os.environ.pop("IDATUI_LOG", None)


def t_env_read_per_call():
    """The pilot and the RPC tests set $IDATUI_LOG after importing the app, so a
    value cached at import would silently disable the thing under test."""
    diag.clear()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "late.log")
        os.environ["IDATUI_LOG"] = path  # set AFTER import
        try:
            diag.log("hello")
        finally:
            os.environ.pop("IDATUI_LOG", None)
        check(
            "a log path set after import is honoured",
            os.path.exists(path) and "hello" in open(path).read(),
        )


def t_thread_safe():
    diag.clear()

    def go(n):
        for i in range(40):
            diag.note(f"t{n}-{i}", RuntimeError("x"))

    ts = [threading.Thread(target=go, args=(n,)) for n in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    r = diag.recent(1000)
    check(
        "concurrent notes don't corrupt the ring",
        len(r) == diag._MAX and all("what" in e for e in r),
        f"{len(r)}",
    )
    check("the recording thread is captured", all(e["thread"] for e in r))


def main() -> int:
    for fn in (
        t_swallow_keeps_going,
        t_reraise,
        t_ring_is_bounded,
        t_log_file,
        t_log_is_off_by_default,
        t_broken_log_path_is_harmless,
        t_env_read_per_call,
        t_thread_safe,
    ):
        print(f"\n{fn.__name__}")
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            import traceback

            check(f"{fn.__name__} did not crash", False, f"{type(e).__name__}: {e}")
            traceback.print_exc()
    diag.clear()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
