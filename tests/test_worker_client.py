#!/usr/bin/env python3
"""WorkerClient: spawn, transport, failure reporting, shutdown.

This is the layer between the app and idalib, and it had no tests -- which is
awkward, because it is where the failures are silent and expensive. A worker
that dies during startup, a socket that drops mid-call, two UI threads sharing
one socket: none of those look like a bug from the outside, they look like the
TUI hanging or showing stale data.

None of it needs IDA. The client spawns whatever ``_WORKER_PY`` points at, so
these tests point it at a fake that speaks the same length-prefixed pickle
protocol and can be told to misbehave on demand.
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: pure: a fake worker over a unix socket, no idalib anywhere.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False

from idatui import worker_client as wc          # noqa: E402
from idatui.errors import IDAConnectionError, IDAToolError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


# --------------------------------------------------------------------------- #
# A worker that isn't IDA
# --------------------------------------------------------------------------- #
#: Speaks the real protocol (idatui.worker.send/recv) and implements a handful
#: of tools whose only job is to be predictable, plus the misbehaviours we need:
#: dying at startup, dropping the socket mid-conversation, taking its time.
FAKE_WORKER = r'''
import os, socket, sys, time
sys.path.insert(0, %(repo)r)
from idatui.worker import send, recv

sock_path, binary = sys.argv[1], sys.argv[2]
mode = os.environ.get("FAKE_MODE", "ok")

if mode == "die":
    # A startup crash, the way the real worker reports one.
    print("IDA Pro: thank you for using it")      # banner noise, must be skipped
    print("WORKER-FATAL: could not open database: it is wedged")
    sys.stdout.flush()
    sys.exit(3)
if mode == "hang":
    time.sleep(60)      # never binds: connect() must time out
    sys.exit(0)

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
if os.path.exists(sock_path):
    os.unlink(sock_path)
srv.bind(sock_path)
srv.listen(1)
conn, _ = srv.accept()
served = 0
while True:
    msg = recv(conn)
    if msg is None:
        break
    tool, args = msg
    if tool == "__shutdown__":
        # The real worker closes its database here; a clean exit is the signal
        # the client waits for rather than killing us.
        open(sock_path + ".clean", "w").write("shutdown")
        break
    served += 1
    if tool == "drop":
        conn.close()            # vanish mid-conversation
        break
    if tool == "boom":
        send(conn, (False, "the tool exploded"))
        continue
    if tool == "slow":
        time.sleep(float(args.get("secs", 0.2)))
        send(conn, (True, {"tool": tool, "args": args, "n": served}))
        continue
    send(conn, (True, {"tool": tool, "args": args, "n": served,
                       "binary": os.path.basename(binary)}))
sys.exit(0)
'''


def _install_fake(tmpdir: str) -> str:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(tmpdir, "fake_worker.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(FAKE_WORKER % {"repo": repo})
    wc._WORKER_PY = path
    return path


def client(tmpdir, **kw):
    """A client wired to the fake worker, running under THIS interpreter.

    ``python=`` matters: the real constructor probes three interpreters for
    ``import ida_pro_mcp`` and that is both slow and beside the point here.
    """
    binary = os.path.join(tmpdir, "target.bin")
    if not os.path.exists(binary):
        with open(binary, "wb") as fh:
            fh.write(b"\x7fELF" + b"\0" * 60)
    return wc.WorkerClient(binary, python=sys.executable, **kw)


# --------------------------------------------------------------------------- #
def t_roundtrip(tmp):
    c = client(tmp)
    try:
        c.connect(timeout=30)
        r = c.call("survey_binary", depth=2)
        check("a call round-trips through the socket",
              r["tool"] == "survey_binary" and r["args"] == {"depth": 2}, str(r))
        check("the worker got the binary path we asked for",
              r["binary"] == "target.bin", str(r))
        check("pid is exposed for memory accounting", isinstance(c.pid, int))
        r2 = c.call("second")
        check("the connection is reused, not respawned per call",
              r2["n"] == 2, f"n={r2['n']}")
    finally:
        c.close(grace=5)


def t_envelope(tmp):
    """domain.decompile reads result.structuredContent -- keep that shape."""
    c = client(tmp)
    try:
        c.connect(timeout=30)
        env = c.call_envelope("decompile", addr="0x1000")
        inner = env["result"]["structuredContent"]
        check("call_envelope wraps the payload the way domain.py unwraps it",
              inner["tool"] == "decompile" and inner["args"] == {"addr": "0x1000"},
              str(env))
    finally:
        c.close(grace=5)


def t_tool_error(tmp):
    c = client(tmp)
    try:
        c.connect(timeout=30)
        try:
            c.call("boom")
            check("a failing tool raises IDAToolError", False, "no exception")
        except IDAToolError as e:
            check("a failing tool raises IDAToolError", True)
            check("the error names the tool", e.tool == "boom", f"tool={e.tool!r}")
            check("and carries the worker's message",
                  "exploded" in e.message, e.message)
        # A tool error is not a transport error: the connection must survive it,
        # or one bad decompile would tear down the session.
        r = c.call("after")
        check("the connection survives a tool error", r["tool"] == "after", str(r))
    finally:
        c.close(grace=5)


def t_dropped_socket(tmp):
    """The reconnect trigger. The app catches IDAConnectionError and reconnects;
    if a drop raised something else, or left _sock set, it would instead surface
    as a crash or as every later call failing."""
    c = client(tmp)
    try:
        c.connect(timeout=30)
        try:
            c.call("drop")
            check("a dropped socket raises IDAConnectionError", False,
                  "no exception")
        except IDAConnectionError:
            check("a dropped socket raises IDAConnectionError", True)
        except Exception as e:  # noqa: BLE001
            check("a dropped socket raises IDAConnectionError", False,
                  f"got {type(e).__name__}: {e}")
        check("the dead socket is cleared, so a retry can reconnect",
              c._sock is None)
    finally:
        c.close(grace=5)


def t_startup_crash(tmp):
    """A worker that dies before binding must say WHY.

    'worker exited (code 3)' on its own is indistinguishable from a bug in the
    app; the real cause is the last meaningful line of its log, and the licence
    banner must not be mistaken for it.
    """
    os.environ["FAKE_MODE"] = "die"
    try:
        c = client(tmp)
        try:
            c.connect(timeout=30)
            check("a worker that exits during startup raises", False,
                  "connect() returned")
        except IDAConnectionError as e:
            msg = str(e)
            check("a worker that exits during startup raises", True)
            check("the exit code is reported", "code 3" in msg, msg)
            check("the WORKER-FATAL line is surfaced",
                  "wedged" in msg, msg)
            check("the licence banner is not mistaken for the error",
                  "thank you" not in msg.lower(), msg)
            check("the full log path is offered", ".log" in msg, msg)
    finally:
        os.environ.pop("FAKE_MODE", None)


def t_connect_timeout(tmp):
    """A worker that never binds must give up, not block the UI forever."""
    os.environ["FAKE_MODE"] = "hang"
    try:
        c = client(tmp)
        t0 = time.time()
        try:
            c.connect(timeout=0.4)
            check("connect() gives up on a worker that never binds", False,
                  "returned")
        except IDAConnectionError as e:
            took = time.time() - t0
            check("connect() gives up on a worker that never binds", True)
            check("it honours the timeout it was given", took < 10, f"{took:.1f}s")
            check("and says so", "in time" in str(e), str(e))
        finally:
            # grace=0: it is sleeping by design, don't wait it out.
            c.close(grace=0)
    finally:
        os.environ.pop("FAKE_MODE", None)


def t_progress(tmp):
    """connect() reports progress while analysis runs -- that callback is the
    only thing on screen during a long open."""
    os.environ["FAKE_MODE"] = "hang"
    seen = []
    try:
        c = client(tmp)
        try:
            c.connect(timeout=0.6, progress=seen.append)
        except IDAConnectionError:
            pass
        finally:
            c.close(grace=0)
    finally:
        os.environ.pop("FAKE_MODE", None)
    check("connect() reports progress while waiting", bool(seen),
          f"{len(seen)} callbacks")
    check("progress names the binary being analysed",
          any("target.bin" in s for s in seen), str(seen[:1]))


def t_serialized(tmp):
    """One socket, many UI threads.

    The app fires calls from several worker threads over one client. The frames
    are length-prefixed pickle with no request ids, so if two calls interleaved
    on the wire each would read the other's reply -- silently, as wrong data
    rather than an error. The lock is the only thing preventing that, so this
    checks every thread gets its own answer back.
    """
    c = client(tmp)
    try:
        c.connect(timeout=30)
        out, errs = {}, []

        def go(i):
            try:
                out[i] = c.call("slow", secs=0.05, tag=i)
            except Exception as e:  # noqa: BLE001
                errs.append(e)

        threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
        t0 = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        took = time.time() - t0
        check("concurrent calls all completed", len(out) == 8 and not errs,
              f"{len(out)} results, errors={errs[:1]}")
        check("each thread got ITS OWN reply, not another's",
              all(out[i]["args"]["tag"] == i for i in out),
              str({i: out[i]["args"].get("tag") for i in sorted(out)}))
        check("calls were serialized, not interleaved",
              took >= 8 * 0.05, f"{took:.2f}s for 8 x 0.05s")
        check("the worker saw every call exactly once",
              sorted(r["n"] for r in out.values()) == list(range(1, 9)),
              str(sorted(r["n"] for r in out.values())))
    finally:
        c.close(grace=5)


def t_clean_shutdown(tmp):
    """close() must let the worker close its database.

    A hard kill leaves the .i64 unpacked into .id0/.id1/... and the database
    then fails to reopen. So close() sends __shutdown__ and WAITS; only a truly
    stuck worker gets signalled.
    """
    c = client(tmp)
    c.connect(timeout=30)
    sock_path = c._sock_path
    proc = c._proc
    c.close(grace=15)
    check("close() sends __shutdown__ rather than killing",
          os.path.exists(sock_path + ".clean"))
    check("and waits for the worker to exit on its own",
          proc.poll() == 0, f"returncode={proc.poll()}")


def t_call_after_close(tmp):
    """A closed client must stay closed.

    call() reconnects when _sock is None, which is what makes a dropped socket
    recoverable -- but it made an explicitly CLOSED client resurrect too, and
    spawn a whole new idalib worker to serve one stray call. Teardown and
    binary-switch both close while @work threads are in flight, so quitting
    during a decompile left a fresh process re-opening the .i64 we had just
    released. (Verified before the fix: pid 1066961 -> 1066962.)
    """
    c = client(tmp)
    c.connect(timeout=30)
    pid = c.pid
    c.close(grace=5)
    try:
        c.call("zombie")
        check("a call after close() does not resurrect the worker", False,
              f"call succeeded; pid {pid} -> {c.pid}")
    except IDAConnectionError as e:
        check("a call after close() does not resurrect the worker", True)
        check("and says the client was closed", "closed" in str(e), str(e))
    check("no second worker was spawned", c.pid == pid, f"{pid} -> {c.pid}")
    # ... but an explicit reconnect still revives it: that is how the app
    # recovers from a worker that segfaulted.
    c.connect(timeout=30)
    r = c.call("revived")
    check("connect() revives a closed client", r["tool"] == "revived", str(r))
    c.close(grace=5)


def t_worker_python_override(tmp):
    """$IDATUI_WORKER_PYTHON wins, and the answer is cached.

    Without the override the constructor probes interpreters with a subprocess
    each, which is why the override exists at all.
    """
    wc._worker_python_cache = None
    os.environ["IDATUI_WORKER_PYTHON"] = sys.executable
    try:
        got = wc._find_worker_python()
        check("$IDATUI_WORKER_PYTHON is honoured", got == sys.executable, got)
    finally:
        os.environ.pop("IDATUI_WORKER_PYTHON", None)
        wc._worker_python_cache = None
    missing = "/nonexistent/python-that-is-not-there"
    os.environ["IDATUI_WORKER_PYTHON"] = missing
    try:
        got = wc._find_worker_python()
        check("an override that doesn't exist falls back instead of crashing",
              got != missing and os.path.exists(got), got)
    finally:
        os.environ.pop("IDATUI_WORKER_PYTHON", None)
        wc._worker_python_cache = None


def t_session_shims(tmp):
    """The single-DB worker still has to answer the session questions the app
    inherited from the old multi-session HTTP client."""
    c = client(tmp)
    try:
        c.connect(timeout=30)
        sess = c.list_sessions()
        check("list_sessions describes the one open database",
              len(sess) == 1 and sess[0].filename == "target.bin"
              and sess[0].is_active, str(sess))
        c.set_db("chosen")
        check("set_db/resolve_db round-trip", c.resolve_db() == "chosen")
        ka = c.keepalive()
        ka.start()
        ka.stop()
        check("keepalive is a no-op the app can still drive",
              ka.beats == 0 and ka.failures == 0)
        h = c.health()
        check("health answers even though the fake has no server_health tool",
              isinstance(h, dict) and h, str(h))
    finally:
        c.close(grace=5)


def t_log_tail(tmp):
    """_log_tail picks the real error out of IDA's noise."""
    c = client(tmp)
    with open(c._log_path, "w", encoding="utf-8") as fh:
        fh.write("Thank you for using IDA\n"
                 "Licensed to: somebody\n"
                 "[MCP] registering tools\n"
                 "WORKER-FATAL: Failed to open database\n")
    check("_log_tail surfaces WORKER-FATAL over the banner",
          c._log_tail() == "Failed to open database", repr(c._log_tail()))
    with open(c._log_path, "w", encoding="utf-8") as fh:
        fh.write("Thank you for using IDA\nsomething odd happened\n")
    tail = c._log_tail()
    check("without a FATAL line it skips the banner and keeps the rest",
          "odd happened" in tail and "Thank you" not in tail, repr(tail))
    os.unlink(c._log_path)
    check("a missing log is reported, not raised",
          "no worker log" in c._log_tail(), repr(c._log_tail()))


def main() -> int:
    import tempfile
    tests = [t_roundtrip, t_envelope, t_tool_error, t_dropped_socket,
             t_startup_crash, t_connect_timeout, t_progress, t_serialized,
             t_clean_shutdown, t_call_after_close, t_worker_python_override,
             t_session_shims, t_log_tail]
    with tempfile.TemporaryDirectory(prefix="idatui-wc-") as tmp:
        _install_fake(tmp)
        for fn in tests:
            print(f"\n{fn.__name__}")
            try:
                fn(tmp)
            except Exception as e:  # noqa: BLE001 -- isolate one test's crash
                import traceback
                check(f"{fn.__name__} did not crash", False,
                      f"{type(e).__name__}: {e}")
                traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
