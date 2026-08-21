#!/usr/bin/env python3
"""Trace integration over the RPC socket — the path an agent actually takes.

The UI tests (test_trace_ui.py) drive the trace via in-process keystrokes and
the Textual pilot. This one spawns a real mux pane with ``--trace`` and drives
every trace verb through the RPC socket, validating the JSON responses an agent
would see. It exercises the serialization, the settle/timeout machinery, and
the response shape that a driver depends on.

Requires: tmux or zellij, IDA (idalib), and a trace. Records a fresh trace with the QEMU
tracer if built; falls back to /tmp/echotrace.0.log if present; skips with a
message otherwise.

    ~/ida-venv/bin/python tests/test_trace_rpc.py
"""

#: spawns a real mux pane with --trace.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = True
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.rpcclient import RpcClient, RpcError  # noqa: E402
from idatui.trace import Trace  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACER = os.path.expanduser("~/.pi/agent/skills/tenet-trace/scripts/tenet-trace")
FALLBACK_TRACE = "/tmp/echotrace.0.log"
BINARY = os.path.join(REPO, "targets", "echo")

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   [{name}]")
    else:
        FAIL += 1
        print(f"  FAIL [{name}]   {detail}")


def make_trace(tmp, binary):
    """Record a short trace of the echo binary."""
    out = os.path.join(tmp, "t")
    try:
        subprocess.run(
            [TRACER, "-o", out, binary, "hello"],
            capture_output=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    log = out + ".0.log"
    return log if os.path.exists(log) else None


def spawn_pane(target, trace_log, timeout=300):
    """Spawn an idatui pane with --trace and wait for readiness."""
    cmd = [
        sys.executable,
        "-m",
        "idatui.pane",
        "spawn",
        "--open",
        target,
        "--trace",
        trace_log,
        "--detached",
        "--size",
        "60%",
        "--timeout",
        str(timeout),
    ]
    r = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout + 30, cwd=REPO
    )
    if r.returncode != 0:
        print(f"  spawn failed: {r.stderr.strip()}", file=sys.stderr)
        return None
    return json.loads(r.stdout)


def stop_pane(sock, timeout=60):
    cmd = [
        sys.executable,
        "-m",
        "idatui.pane",
        "stop",
        "--sock",
        sock,
        "--timeout",
        str(timeout),
    ]
    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10, cwd=REPO)


def main() -> int:
    global PASS, FAIL
    if not os.environ.get("TMUX") and not os.environ.get("ZELLIJ"):
        print("  skip: not inside tmux or zellij (test spawns a pane)")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        # Scratch copy so the suite never writes into the tracked tree.
        target = os.path.join(tmp, "echo")
        shutil.copy2(BINARY, target)

        # Get a trace.
        trace_log = make_trace(tmp, target)
        if trace_log is None and os.path.exists(FALLBACK_TRACE):
            trace_log = FALLBACK_TRACE
        if trace_log is None:
            print(
                f"  skip: no trace available (tracer at {TRACER}, "
                f"fallback {FALLBACK_TRACE})"
            )
            return 0

        # Load our own model for ground-truth comparisons.
        model = Trace.load(trace_log)
        check(
            "model loaded for ground truth", model.length > 10, f"length={model.length}"
        )

        # Spawn the pane.
        info = spawn_pane(target, trace_log)
        if info is None or not info.get("ready"):
            print(f"  FAIL: pane did not become ready: {info}")
            return 1
        sock = info["sock"]
        check("pane spawned and ready", True)

        try:
            with RpcClient(sock) as c:
                run_trace_tests(c, model)
        finally:
            stop_pane(sock)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


def run_trace_tests(c: RpcClient, model: Trace):
    """All RPC-level trace tests, given a connected client and the model."""

    # ------------------------------------------------------------------ #
    # Basic: ping should show the trace is loaded
    # ------------------------------------------------------------------ #
    p = c.call("ping")
    check("ping reports ready", p.get("ready") is True)

    # ------------------------------------------------------------------ #
    # trace verb: seek to timestamp 0
    # ------------------------------------------------------------------ #
    r = c.call("trace", seek=0)
    check("trace seek=0 returns a snapshot", "active" in r and "trace" in r)
    tr = r["trace"]
    check(
        "response includes trace metadata",
        "idx" in tr and "length" in tr and "pc" in tr and "changed" in tr,
        f"keys={list(tr.keys())}",
    )
    check("idx is 0 after seeking to 0", tr["idx"] == 0)
    check(
        "length matches the model",
        tr["length"] == model.length,
        f"{tr['length']} vs {model.length}",
    )
    check(
        "pc at 0 is a hex string",
        isinstance(tr["pc"], str) and tr["pc"].startswith("0x"),
        tr["pc"],
    )

    # ------------------------------------------------------------------ #
    # seek to a mid-trace timestamp
    # ------------------------------------------------------------------ #
    mid = model.length // 2
    r = c.call("trace", seek=mid)
    tr = r["trace"]
    check(
        "seek to midpoint lands correctly",
        tr["idx"] == mid,
        f"got {tr['idx']}, want {mid}",
    )
    # The model's IP at this point, rebased — the RPC should agree.
    # We can't compare directly because the model isn't rebased yet, but
    # the pc should be a small address (database-space, not ASLR'd).
    pc = int(tr["pc"], 16)
    check("pc is in database space (not ASLR'd)", pc < 0x100000, f"pc={tr['pc']}")

    # ------------------------------------------------------------------ #
    # seek by percentage (Tenet shell syntax)
    # ------------------------------------------------------------------ #
    r = c.call("trace", seek="!0")
    check("seek !0 (0%) goes to the start", r["trace"]["idx"] == 0)
    r = c.call("trace", seek="!100")
    check(
        "seek !100 (100%) goes to the end",
        r["trace"]["idx"] == model.length - 1,
        f"got {r['trace']['idx']}, want {model.length - 1}",
    )
    r = c.call("trace", seek="!50")
    check(
        "seek !50 (50%) goes to the midpoint",
        abs(r["trace"]["idx"] - mid) <= 1,
        f"got {r['trace']['idx']}, want ~{mid}",
    )

    # ------------------------------------------------------------------ #
    # step forward/backward
    # ------------------------------------------------------------------ #
    c.call("trace", seek=0)
    r = c.call("trace", step=1)
    check(
        "step=1 advances one timestamp",
        r["trace"]["idx"] == 1,
        f"got {r['trace']['idx']}",
    )
    r = c.call("trace", step=1)
    check(
        "another step=1 reaches 2", r["trace"]["idx"] == 2, f"got {r['trace']['idx']}"
    )
    r = c.call("trace", step=-1)
    check("step=-1 goes backward", r["trace"]["idx"] == 1, f"got {r['trace']['idx']}")

    # Step backward at the start should clamp to 0.
    c.call("trace", seek=0)
    r = c.call("trace", step=-1)
    check(
        "step=-1 at t=0 stays at 0", r["trace"]["idx"] == 0, f"got {r['trace']['idx']}"
    )

    # Multi-step.
    c.call("trace", seek=0)
    r = c.call("trace", step=5)
    check(
        "step=5 advances five timestamps",
        r["trace"]["idx"] == 5,
        f"got {r['trace']['idx']}",
    )

    # ------------------------------------------------------------------ #
    # step over (follows SP)
    # ------------------------------------------------------------------ #
    # Find a call in the model: SP drops and later recovers.
    sp_name = "rsp" if "rsp" in model.reg_at else "esp"
    call_at = None
    for i in range(1, min(model.length - 1, 400)):
        a = model.register(sp_name, i)
        b = model.register(sp_name, i + 1)
        if a and b and b < a:
            ret = next(
                (
                    j
                    for j in range(i + 1, model.length)
                    if (model.register(sp_name, j) or 0) >= a
                ),
                None,
            )
            if ret and ret > i + 3:
                call_at = (i, ret)
                break
    if call_at is not None:
        i, ret = call_at
        c.call("trace", seek=i)
        r = c.call("trace", step=1, over=True)
        check(
            "step over skips the callee",
            r["trace"]["idx"] == ret,
            f"from {i}, got {r['trace']['idx']}, expected {ret}",
        )
        check("step over goes further than a plain step", r["trace"]["idx"] > i + 1)
    else:
        check("found a call to step over", False, "none in this short trace")

    # ------------------------------------------------------------------ #
    # goto: first execution of a function by name
    # ------------------------------------------------------------------ #
    r = c.call("trace", goto="main")
    tr = r["trace"]
    check("goto main lands on a timestamp", tr["idx"] >= 0)
    check(
        "and the function context says main",
        r.get("function", {}).get("name") == "main",
        f"function={r.get('function')}",
    )

    # goto by hex address.
    main_ea = r["function"]["ea"]
    c.call("trace", seek=0)  # reset position
    r = c.call("trace", goto=hex(main_ea))
    check(
        "goto by hex address works",
        r["trace"]["idx"] >= 0 and r["function"]["ea"] == main_ea,
        f"idx={r['trace']['idx']}, ea={r.get('function', {}).get('ea')}",
    )

    # goto a function that was never executed.
    try:
        c.call("trace", goto="0xDEADBEEF")
        check("goto an unexecuted address raises", False, "no error raised")
    except RpcError as e:
        check("goto an unexecuted address raises", "never executed" in str(e), str(e))

    # ------------------------------------------------------------------ #
    # changed registers in the response
    # ------------------------------------------------------------------ #
    c.call("trace", seek=0)
    r = c.call("trace", step=1)
    changed = r["trace"]["changed"]
    check(
        "changed is a list of register names",
        isinstance(changed, list) and all(isinstance(s, str) for s in changed),
        f"{changed}",
    )
    # The PC always changes on a step (it's a different instruction).
    check("rip is always in changed", "rip" in changed, f"{changed}")

    # ------------------------------------------------------------------ #
    # the cursor tracks the trace: seek moves the code view
    # ------------------------------------------------------------------ #
    # Seek to two different timestamps and verify the cursor ea changes.
    r1 = c.call("trace", seek=10)
    r2 = c.call("trace", seek=min(50, model.length - 1))
    ea1 = r1.get("cursor", {}).get("ea")
    ea2 = r2.get("cursor", {}).get("ea")
    check(
        "the cursor ea follows the trace pc",
        ea1 is not None
        and ea2 is not None
        and (ea1 != ea2 or r1["trace"]["pc"] == r2["trace"]["pc"]),
        f"ea1={ea1}, ea2={ea2}",
    )

    # ------------------------------------------------------------------ #
    # trace verb without a trace raises cleanly
    # ------------------------------------------------------------------ #
    # (Can't test this on THIS pane since it has a trace. But we can test
    # the error path by verifying the error message shape for bad params.)
    try:
        c.call("trace")  # no seek/goto/step — should still return a snapshot
        # Actually, if none of seek/goto/step is given, it just settles and
        # returns the current state — that's fine, it's a status query.
        r = c.call("trace")
        check(
            "trace with no action is a status query",
            "trace" in r and r["trace"]["idx"] >= 0,
        )
    except RpcError:
        check("trace with no action is a status query", False, "raised an error")

    # ------------------------------------------------------------------ #
    # snapshot shape: the trace key is present on every trace response
    # ------------------------------------------------------------------ #
    r = c.call("trace", seek=3)
    for key in ("idx", "length", "pc", "changed"):
        check(
            f"trace response has '{key}'",
            key in r.get("trace", {}),
            f"trace={r.get('trace')}",
        )

    # Standard snapshot fields are ALSO present (the trace response is a
    # superset of a normal snapshot).
    for key in ("active", "function", "cursor", "status", "ready"):
        check(
            f"trace response also has snapshot key '{key}'",
            key in r,
            f"keys={list(r.keys())}",
        )

    # ------------------------------------------------------------------ #
    # edge cases: seek beyond bounds
    # ------------------------------------------------------------------ #
    r = c.call("trace", seek=-1)
    check("seek -1 clamps to 0", r["trace"]["idx"] == 0)
    r = c.call("trace", seek=model.length + 1000)
    check(
        "seek beyond length clamps to the end",
        r["trace"]["idx"] == model.length - 1,
        f"got {r['trace']['idx']}",
    )

    # ------------------------------------------------------------------ #
    # seek with comma-separated numbers (ergonomic)
    # ------------------------------------------------------------------ #
    r = c.call("trace", seek="100")
    check(
        "seek accepts a string number", r["trace"]["idx"] == min(100, model.length - 1)
    )

    # ------------------------------------------------------------------ #
    # pseudocode still works with a trace loaded
    # ------------------------------------------------------------------ #
    c.call("trace", goto="main")
    r = c.call("pseudocode", target="main", lines=5)
    check(
        "pseudocode works alongside the trace",
        "code" in r and "main" in r.get("code", ""),
        f"keys={list(r.keys())}",
    )

    # ------------------------------------------------------------------ #
    # state includes trace position
    # ------------------------------------------------------------------ #
    c.call("trace", seek=7)
    r = c.call("state")
    # The state verb doesn't include trace info (that's trace-specific),
    # but the standard snapshot fields should be consistent.
    check("state works with a trace loaded", r.get("ready") is True and "cursor" in r)

    # ------------------------------------------------------------------ #
    # view_lines works with trail painted
    # ------------------------------------------------------------------ #
    c.call("trace", seek=min(40, model.length - 1))
    r = c.call("view", lines=10)
    check(
        "view returns lines with a trace active",
        "lines" in r and len(r["lines"]) > 0,
        f"keys={list(r.keys())}",
    )

    # ------------------------------------------------------------------ #
    # navigation works alongside trace: goto a function, trace follows
    # ------------------------------------------------------------------ #
    c.call("trace", goto="main")
    start_idx = c.call("trace")["trace"]["idx"]
    r = c.call("goto", target="error_at_line")
    check(
        "goto still works with trace loaded",
        r.get("function", {}).get("name") == "error_at_line",
    )
    # The trace timestamp should NOT change from a regular goto — the trace
    # position is independent of navigation.
    r2 = c.call("trace")
    check(
        "regular goto does not change the trace position",
        r2["trace"]["idx"] == start_idx,
        f"was {start_idx}, now {r2['trace']['idx']}",
    )


if __name__ == "__main__":
    raise SystemExit(main())
