#!/usr/bin/env python3
"""Deciding where a binary's database can be written.

The case: ``ida-tui /bin/ls`` asks IDA for ``/bin/ls.i64``, a normal user cannot
write ``/bin``, and the backend reports "idalib worker launcher NNN exited with
status 1" after a full analysis wait. These checks pin the pre-flight answer that
replaces that, and the two properties the proposed location must have — stable
per binary (so a session's names come back) and collision-free.

Pure: no IDA, no IDA Nexus, no Textual.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: pure: path arithmetic plus os.access against real temp dirs.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False

from idatui import idbpath  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def touch(path, mode=0o644):
    with open(path, "wb") as fh:
        fh.write(b"\x7fELF")
    os.chmod(path, mode)
    return path


def t_expected_idb():
    """Must agree with ida_nexus's own derivation, or we check the wrong file."""
    check(
        "a binary gets .i64 appended",
        idbpath.expected_idb("/bin/ls") == "/bin/ls.i64",
        idbpath.expected_idb("/bin/ls"),
    )
    check(
        "a path that IS a database is left alone",
        idbpath.expected_idb("/tmp/x/foo.i64") == "/tmp/x/foo.i64",
        idbpath.expected_idb("/tmp/x/foo.i64"),
    )
    check(
        "the suffix check is case-insensitive, like the resolver's",
        idbpath.expected_idb("/tmp/x/FOO.I64") == "/tmp/x/FOO.I64",
        idbpath.expected_idb("/tmp/x/FOO.I64"),
    )
    check(
        "a relative path is absolute afterwards",
        os.path.isabs(idbpath.expected_idb("ls")),
    )


def t_blocked_reason(tmp):
    """The pre-flight answer: None for a writable directory, a reason otherwise."""
    good = touch(os.path.join(tmp, "app"))
    check("a writable directory is not blocked", idbpath.blocked_reason(good) is None)

    ro = os.path.join(tmp, "ro")
    os.mkdir(ro, 0o700)
    binary = touch(os.path.join(ro, "ls"))  # the binary first: /bin/ls exists
    os.chmod(ro, 0o500)
    reason = idbpath.blocked_reason(binary)
    check("an unwritable directory is blocked", reason is not None, repr(reason))
    check("the reason names the directory", ro in (reason or ""), repr(reason))

    # A read-only database in a writable directory is also a dead end: IDA
    # rewrites the .i64 on save, so it cannot be treated as a read-only view.
    b2 = touch(os.path.join(tmp, "app2"))
    touch(b2 + ".i64", mode=0o444)
    reason2 = idbpath.blocked_reason(b2)
    check(
        "an unwritable existing database is blocked", reason2 is not None, repr(reason2)
    )
    check(
        "...and the reason names the database, not the directory",
        (reason2 or "").startswith(b2 + ".i64"),
        repr(reason2),
    )
    os.chmod(b2 + ".i64", 0o644)
    check(
        "a writable existing database is not blocked",
        idbpath.blocked_reason(b2) is None,
        repr(idbpath.blocked_reason(b2)),
    )

    # Not our question to answer: launch.py already rejects a path that is
    # neither a file nor a registered database.
    check(
        "a file that does not exist is not reported as blocked",
        idbpath.blocked_reason(os.path.join(tmp, "nope")) is None,
    )
    os.chmod(ro, 0o700)


def t_no_side_effects(tmp):
    """The pre-flight check must not touch the user's directory."""
    binary = touch(os.path.join(tmp, "probe-target"))
    before = sorted(os.listdir(tmp))
    for _ in range(3):
        idbpath.blocked_reason(binary)
    check("blocked_reason creates nothing", sorted(os.listdir(tmp)) == before)


def t_relocated(tmp):
    """Stable per binary, unique between binaries, and named like the binary."""
    os.environ[idbpath.DB_DIR_ENV] = os.path.join(tmp, "dbs")
    try:
        a = os.path.join(tmp, "a")
        os.makedirs(a, exist_ok=True)
        b = os.path.join(tmp, "b")
        os.makedirs(b, exist_ok=True)
        one, two = touch(os.path.join(a, "busybox")), touch(os.path.join(b, "busybox"))
        p1, p2 = idbpath.relocated_idb(one), idbpath.relocated_idb(two)
        check(
            "the proposal is stable across calls (yesterday's work comes back)",
            p1 == idbpath.relocated_idb(one),
        )
        check("two binaries with the same name do not collide", p1 != p2, f"{p1} {p2}")
        check("it is recognisable", os.path.basename(p1).startswith("busybox-"), p1)
        check("it is an .i64", p1.endswith(".i64"), p1)
        check(
            "it lands under the configured root",
            p1.startswith(os.path.join(tmp, "dbs")),
            p1,
        )
        check(
            "the scratch stem is unique too (IDA unpacks beside the .i64)",
            os.path.splitext(os.path.basename(p1))[0]
            != os.path.splitext(os.path.basename(p2))[0],
        )
        # The relocated path is the one thing that must never need the original
        # directory to be writable.
        check("nothing is created just by proposing", not os.path.isdir(p1))
        idbpath.ensure_parent(p1)
        check("ensure_parent creates the directory", os.path.isdir(os.path.dirname(p1)))
        check(
            "...privately (a database exposes the binary and the session)",
            stat.S_IMODE(os.stat(os.path.dirname(p1)).st_mode) == 0o700,
            oct(stat.S_IMODE(os.stat(os.path.dirname(p1)).st_mode)),
        )
        check(
            "a database path relocates by its own name, without a doubled suffix",
            os.path.basename(idbpath.relocated_idb(os.path.join(a, "fw.i64"))).count(
                ".i64"
            )
            == 1,
            idbpath.relocated_idb(os.path.join(a, "fw.i64")),
        )
    finally:
        os.environ.pop(idbpath.DB_DIR_ENV, None)


def t_db_root(tmp):
    """Databases are user DATA, not cache: cleaners may empty a cache directory."""
    saved = {k: os.environ.get(k) for k in (idbpath.DB_DIR_ENV, "XDG_DATA_HOME")}
    try:
        os.environ.pop(idbpath.DB_DIR_ENV, None)
        os.environ["XDG_DATA_HOME"] = os.path.join(tmp, "share")
        root = idbpath.db_root()
        check(
            "XDG_DATA_HOME is honoured",
            root == os.path.join(tmp, "share", "idatui", "db"),
            root,
        )
        os.environ[idbpath.DB_DIR_ENV] = os.path.join(tmp, "explicit")
        check(
            f"{idbpath.DB_DIR_ENV} overrides it",
            idbpath.db_root() == os.path.join(tmp, "explicit"),
            idbpath.db_root(),
        )
        os.environ.pop("XDG_DATA_HOME")
        os.environ.pop(idbpath.DB_DIR_ENV)
        check("the default is not a cache directory", ".cache" not in idbpath.db_root())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def t_can_create(tmp):
    """The truthful probe, used only after an open has already failed."""
    check(
        "a writable directory can hold a database",
        idbpath.can_create(os.path.join(tmp, "new.i64")),
    )
    check(
        "...and the probe cleans up after itself",
        not os.path.exists(os.path.join(tmp, "new.i64")),
    )
    ro = os.path.join(tmp, "ro2")
    os.mkdir(ro, 0o500)
    check(
        "an unwritable directory cannot",
        not idbpath.can_create(os.path.join(ro, "x.i64")),
    )
    os.chmod(ro, 0o700)
    existing = touch(os.path.join(tmp, "keep.i64"))
    check("an existing database counts as creatable", idbpath.can_create(existing))
    with open(existing, "rb") as fh:
        check(
            "...and is NOT truncated by the probe",
            fh.read() == b"\x7fELF",
            "the probe destroyed a database",
        )


def t_describe(tmp):
    """The dialog's one line has to distinguish resume from start-fresh."""
    target = os.path.join(tmp, "d", "ls-1234abcd.i64")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fresh = idbpath.describe("/bin/ls", target)
    check(
        "a new database says the original is untouched", "/bin/ls.i64" in fresh, fresh
    )
    touch(target)
    resumed = idbpath.describe("/bin/ls", target)
    check(
        "an existing one says the work comes back", "resum" in resumed.lower(), resumed
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        for fn in (
            t_expected_idb,
            t_blocked_reason,
            t_no_side_effects,
            t_relocated,
            t_db_root,
            t_can_create,
            t_describe,
        ):
            print(f"\n{fn.__name__}")
            sub = os.path.join(tmp, fn.__name__)
            os.makedirs(sub, exist_ok=True)
            try:
                fn(sub) if fn is not t_expected_idb else fn()
            except Exception as e:  # noqa: BLE001
                import traceback

                check(f"{fn.__name__} did not crash", False, f"{type(e).__name__}: {e}")
                traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
