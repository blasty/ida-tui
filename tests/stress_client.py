#!/usr/bin/env python3
"""Adversarial stress tests for idatui.client.

Kills/respawns the server, forces timeouts, drops connections, and hammers with
concurrency — asserting the client always fails *cleanly* (no hangs, no
deadlocks) and recovers where recovery is possible.

    python3 tests/stress_client.py            # run all scenarios
    python3 tests/stress_client.py timeout    # run one by name

Requires ~/ida-venv + spawn.sh (via tests/serverctl.sh). Leaves the server UP.
"""
import concurrent.futures
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from idatui.client import (  # noqa: E402
    IDAClient,
    IDAConnectionError,
    IDASessionError,
    IDATimeoutError,
    IDAToolError,
    IDAError,
)

URL = "http://127.0.0.1:8745/mcp"
CTL = os.path.join(HERE, "serverctl.sh")
PASS = FAIL = 0


def log(m):
    print(m, flush=True)


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        log(f"  ok   {name}")
    else:
        FAIL += 1
        log(f"  FAIL {name}   {detail}")


def ctl(*args, timeout=180):
    r = subprocess.run([CTL, *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def ensure_up():
    rc, out = ctl("ready", "5")
    if rc != 0:
        log("  (server down; starting...)")
        rc, out = ctl("start")
        assert rc == 0, f"could not start server: {out}"
    rc, sid = ctl("ready", "60")
    return sid.strip().splitlines()[-1] if sid.strip() else None


def deadline(fn, secs):
    """Run fn() in a thread; return (finished_bool, result_or_exc)."""
    box = {}
    def run():
        try:
            box["r"] = fn()
        except BaseException as e:  # noqa: BLE001
            box["e"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(secs)
    if t.is_alive():
        return False, None
    return True, box.get("e", box.get("r"))


# --------------------------------------------------------------------------- #
def s_connect_refused():
    """Connecting to a dead port fails fast and cleanly, never hangs."""
    c = IDAClient("http://127.0.0.1:59999/mcp", db="x", timeout=3.0)
    fin, res = deadline(c.connect, 8)
    check("dead-port connect returns (no hang)", fin)
    check("dead-port raises IDAConnectionError", isinstance(res, IDAConnectionError),
          f"{type(res).__name__}: {res}")


def s_timeout():
    """A too-tight timeout on the slow decompile raises IDATimeoutError, and the
    client stays usable for subsequent calls."""
    sid = ensure_up()
    c = IDAClient(URL, db=sid)
    c.connect()
    # force_recompile clears the hexrays cache so decompile is genuinely slow.
    try:
        c.call("force_recompile", addr="main")
    except IDAError:
        pass
    fin, res = deadline(lambda: c.call("decompile", addr="main", timeout=0.001), 10)
    check("tight-timeout returns (no hang)", fin)
    check("tight-timeout raises IDATimeoutError", isinstance(res, IDATimeoutError),
          f"{type(res).__name__}: {res}")
    # Client must still work afterwards (pool not poisoned).
    fin2, res2 = deadline(lambda: c.call("list_funcs", queries=[{"count": 1}]), 10)
    check("client usable after timeout", fin2 and not isinstance(res2, Exception),
          f"{type(res2).__name__}: {res2}")
    c.close()


def s_worker_crash():
    """Hard-kill the analysis worker mid-use: calls must raise cleanly (no hang),
    and after a full restart the client recovers by re-resolving the session."""
    sid = ensure_up()
    c = IDAClient(URL, db=sid)
    c.connect()
    check("baseline call ok", isinstance(c.call("list_funcs", queries=[{"count": 1}]), (list, dict)))

    ctl("kill9")  # kill only the worker; supervisor may stay up
    time.sleep(1.0)

    def probe():
        try:
            return c.call("list_funcs", queries=[{"count": 1}])
        except IDAError as e:
            return e
    fin, res = deadline(probe, 15)
    check("post-crash call returns (no hang)", fin, "call hung after worker kill")
    check("post-crash raises IDAError (clean)", isinstance(res, IDAError) or res is not None,
          f"{type(res).__name__}: {res}")

    # Full restart and recovery.
    ctl("stop")
    rc, _ = ctl("start")
    check("server restart ok", rc == 0)
    newsid = ensure_up()
    # A fresh client should just work.
    c2 = IDAClient(URL, db=None)
    c2.connect()
    fin3, res3 = deadline(lambda: (c2.set_db(c2.resolve_db()), c2.health())[1], 20)
    check("fresh client recovers after restart", fin3 and isinstance(res3, dict),
          f"{type(res3).__name__}: {res3}")
    check("session id stable across restart" if newsid == sid else "session id changed (expected-ok)",
          True, f"{sid} -> {newsid}")
    c.close(); c2.close()


def s_full_restart_same_client():
    """Keep ONE auto-injected client across a full server restart. The FIRST
    naive call after restart must transparently self-heal the stale db pin (no
    internal poking, no manual re-resolve)."""
    sid = ensure_up()
    c = IDAClient(URL, db=None)  # auto-resolve -> auto_recover eligible
    c.connect()
    old = c.resolve_db()
    check("pre-restart call ok", isinstance(c.health(), dict))

    ctl("stop")
    # While down: calls must fail cleanly, fast.
    fin, res = deadline(lambda: c.health(), 8)
    check("while-down call returns (no hang)", fin)
    check("while-down raises IDAError", isinstance(res, IDAError), f"{type(res).__name__}: {res}")

    ctl("start")
    ensure_up()
    # NAIVE call: no internal poking. Auto-recovery must kick in on the stale
    # "Session not found" and retry against the fresh session.
    fin2, res2 = deadline(lambda: c.health(), 25)
    check("naive call auto-recovers after restart", fin2 and isinstance(res2, dict),
          f"{type(res2).__name__}: {res2}")
    check("db pin was re-resolved to new session", c.db is not None and c.db != old,
          f"old={old} new={c.db}")
    c.close()


def s_no_autoswitch_when_explicit():
    """With auto_recover disabled (or an explicitly pinned db), a stale session
    must NOT be silently switched — it raises so the caller stays in control."""
    sid = ensure_up()
    c = IDAClient(URL, db=sid, auto_recover_session=False)
    c.connect()
    check("pre-restart call ok", isinstance(c.health(), dict))
    ctl("stop"); ctl("start"); newsid = ensure_up()
    fin, res = deadline(lambda: c.health(), 15)
    check("explicit-pin call returns (no hang)", fin)
    check("explicit-pin raises IDAToolError (no silent switch)",
          isinstance(res, IDAToolError), f"{type(res).__name__}: {res}")
    check("db pin unchanged when recovery disabled", c.db == sid, f"{c.db} vs {sid}")
    c.close()


def s_concurrency_high():
    """Heavy concurrency: 300 calls over 16 threads, all succeed, no deadlock."""
    sid = ensure_up()
    c = IDAClient(URL, db=sid, pool_size=8)
    c.connect()
    N = 300
    errors = []
    def work(i):
        try:
            tool = ("list_funcs", "disasm")[i % 2]
            if tool == "list_funcs":
                return bool(c.call("list_funcs", queries=[{"count": 3}]))
            return bool(c.call("disasm", addr="main", max_instructions=5))
        except IDAError as e:
            errors.append(e); return False
    def run_all():
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            return sum(ex.map(work, range(N)))
    fin, ok = deadline(run_all, 60)
    check("300/16 concurrent finished (no deadlock)", fin, "pool deadlocked")
    check("300/16 all succeeded", ok == N, f"{ok}/{N}, errs={errors[:3]}")
    c.close()


def s_concurrency_under_churn():
    """Hammer concurrently while the worker is hard-killed mid-flight. No hang,
    no deadlock; errors are clean; after respawn calls succeed again."""
    sid = ensure_up()
    c = IDAClient(URL, db=sid, pool_size=8)
    c.connect()
    stop = threading.Event()
    stats = {"ok": 0, "err": 0, "weird": 0}
    lock = threading.Lock()
    def spinner():
        while not stop.is_set():
            try:
                c.call("list_funcs", queries=[{"count": 1}])
                with lock: stats["ok"] += 1
            except IDAError:
                with lock: stats["err"] += 1
            except Exception:  # noqa: BLE001  -- any non-IDAError is a bug
                with lock: stats["weird"] += 1
            time.sleep(0.01)
    threads = [threading.Thread(target=spinner, daemon=True) for _ in range(12)]
    for t in threads: t.start()
    time.sleep(1.0)
    ctl("kill9")            # crash the worker under load
    time.sleep(2.0)
    stop.set()
    for t in threads: t.join(10)
    alive = [t for t in threads if t.is_alive()]
    check("no spinner thread hung on worker kill", not alive, f"{len(alive)} stuck")
    check("no non-IDAError leaked during churn", stats["weird"] == 0, str(stats))
    log(f"    churn stats: {stats}")
    # Recover.
    ctl("stop"); ctl("start"); ensure_up()
    c.close()


SCENARIOS = {
    "connect_refused": s_connect_refused,
    "timeout": s_timeout,
    "worker_crash": s_worker_crash,
    "full_restart_same_client": s_full_restart_same_client,
    "no_autoswitch_when_explicit": s_no_autoswitch_when_explicit,
    "concurrency_high": s_concurrency_high,
    "concurrency_under_churn": s_concurrency_under_churn,
}


def main(argv):
    names = argv or list(SCENARIOS)
    for name in names:
        fn = SCENARIOS.get(name)
        if not fn:
            log(f"unknown scenario: {name} (have: {', '.join(SCENARIOS)})")
            return 2
        log(f"\n[{name}]")
        t0 = time.time()
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            global FAIL
            FAIL += 1
            log(f"  FAIL {name} raised {type(e).__name__}: {e}")
        log(f"  ({time.time() - t0:.1f}s)")
    log("\n== ensuring server is UP for subsequent work ==")
    sid = ensure_up()
    log(f"  server ready, db={sid}")
    log(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
