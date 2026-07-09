#!/usr/bin/env python3
"""Prove that an interactive session can 'just chill' without the worker idling
out. Uses a deliberately short worker TTL to keep the test fast.

    python3 tests/test_keepalive.py

Needs ~/ida-venv + a running server (tests/serverctl.sh) and a writable target.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
from idatui.client import IDAClient, IDAToolError  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def alive(c, sid):
    try:
        c.set_db(sid)
        c.health()
        return True
    except IDAToolError:
        return False


def main():
    target = os.path.join(REPO, "targets", "ls_ttl")
    if not os.path.exists(target):
        src = os.path.join(REPO, "bin", "ls")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        import shutil
        shutil.copy(src, target)

    c = IDAClient(timeout=300)
    c.connect()
    SHORT = 12  # worker self-exits after ~12s idle unless kept alive

    print("[heartbeat keeps a short-TTL worker alive]")
    sid = c.call("idb_open", input_path=target, idle_ttl_sec=SHORT)["session"]["session_id"]
    c.set_db(sid)
    ka = c.keepalive(interval=4.0).start()
    time.sleep(SHORT * 2 + 2)  # idle well past the TTL, but heartbeat is beating
    ok = alive(c, sid)
    check("alive past 2x TTL with heartbeat", ok, f"beats={ka.beats}")
    check("heartbeat actually beat", ka.beats >= 4, f"beats={ka.beats}")
    check("heartbeat had no failures", ka.failures == 0, f"failures={ka.failures}")
    ka.stop()

    print("\n[bump_idle_ttl makes it effectively immortal]")
    sid = c.call("idb_open", input_path=target, idle_ttl_sec=SHORT)["session"]["session_id"]
    c.set_db(sid)
    c.bump_idle_ttl()  # ~1e9 seconds
    time.sleep(SHORT * 2 + 6)  # zero requests during this window
    check("alive past 2x TTL after bump, zero requests", alive(c, sid))

    c.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
