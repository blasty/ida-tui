#!/usr/bin/env python3
"""The launcher's option handling, and the file handling it must NOT do.

The old `_sweep_locks` deleted `.id0/.id1/.id2/.nam/.til` next to the user's
binary when a database failed to open. That was only defensible while the TUI
exclusively owned a private worker; under IDA Nexus a GUI or another client may
own the database, so the sweep is gone. Its tests are replaced by one that keeps
it gone -- deleting a shared database's working files is unrecoverable, and this
is the cheapest guard against someone reintroducing the "helpful" cleanup.

Pure: no IDA, no IDA Nexus library, no Textual.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: pure: file handling only, nothing is opened.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False

import idatui.launch as launch  # noqa: E402
from idatui.launch import _load_args  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def touch(*paths):
    for p in paths:
        with open(p, "wb") as fh:
            fh.write(b"x")


def t_no_lock_sweeping():
    """The launcher must not delete database working files any more.

    IDA Nexus's registry locks, health probes and IDA itself arbitrate database
    ownership now. A sweep here would delete files out from under a live GUI.
    """
    check("_sweep_locks is gone", not hasattr(launch, "_sweep_locks"))
    check("the scratch-suffix list is gone", not hasattr(launch, "_LOCK_SUFFIXES"))
    src = open(launch.__file__, encoding="utf-8").read()
    check(
        "the launcher does not remove files at all",
        "os.remove" not in src and "shutil.rmtree" not in src,
        "launch.py deletes something again",
    )


def t_load_args():
    """The single-binary path turns the load options into IDA switches."""
    check("no options means no switches", _load_args({}) == "", repr(_load_args({})))
    a = _load_args({"processor": "arm", "base": 0x8000})
    check("a processor reaches the switches", "-parm" in a, a)
    # -b is in PARAGRAPHS, not bytes: 0x8000 >> 4 == 0x800.
    check("a base is converted to paragraphs", "-b800" in a, a)
    b = _load_args({"base": "0x1000"})
    check(
        "a base given as a hex STRING is accepted (project files write those)",
        "-b100" in b,
        b,
    )
    check(
        "no base means no -b switch",
        "-b" not in _load_args({"processor": "arm"}),
        _load_args({"processor": "arm"}),
    )
    c = _load_args({"ida_args": "-p1"})
    check("extra ida_args are passed through", "-p1" in c, c)


def t_idb_option():
    """``--idb`` names where the database goes, for a binary in /bin.

    The launcher only has to accept it and hand it over; choosing a location and
    asking about one live in idbpath/app (tests/test_idbpath.py).
    """
    src = open(launch.__file__, encoding="utf-8").read()
    check("the launcher offers --idb", '"--idb"' in src)
    check("...and passes it to the app", "idb_path=idb_path" in src)
    with tempfile.TemporaryDirectory() as tmp:
        # A project keeps its databases in its sidecar, so the two options mean
        # contradictory things; refusing beats silently ignoring one.
        proj = os.path.join(tmp, "p.idatui-project")
        binary = os.path.join(tmp, "bin")
        touch(binary)
        rc = launch.main(
            ["--project", proj, binary, "--idb", os.path.join(tmp, "x.i64")]
        )
        check("--idb with --project is refused", rc == 2, f"rc={rc}")


def main() -> int:
    for fn in (t_no_lock_sweeping, t_load_args, t_idb_option):
        print(f"\n{fn.__name__}")
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            import traceback

            check(f"{fn.__name__} did not crash", False, f"{type(e).__name__}: {e}")
            traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
