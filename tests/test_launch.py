#!/usr/bin/env python3
"""The launcher's file handling -- the part that deletes things.

`_sweep_locks` runs automatically when a database fails to open, and it removes
files next to the user's binary. That is exactly the kind of code that must not
be tested by trying it, so it is tested here: which files it takes, which it
must never take, and what it reports.

Pure: no IDA, no worker, no Textual.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: pure: file handling only, nothing is opened.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False

from idatui.launch import _LOCK_SUFFIXES, _load_args, _sweep_locks  # noqa: E402

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


def t_sweeps_the_scratch_files():
    """IDA unpacks a .i64 into .id0/.id1/.id2/.nam/.til while it is open; a
    hard-killed worker leaves them and the .i64 then refuses to reopen."""
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "echo")
        touch(binary, *[binary + s for s in _LOCK_SUFFIXES])
        n = _sweep_locks(binary)
        check("every unpacked scratch file is swept", n == len(_LOCK_SUFFIXES),
              f"swept {n} of {len(_LOCK_SUFFIXES)}")
        check("none of them survive",
              not any(os.path.exists(binary + s) for s in _LOCK_SUFFIXES))
        check("the binary itself is untouched", os.path.exists(binary))


def t_sweeps_by_stem_too():
    """IDA keys the scratch on the full name or the stem depending on how the
    database was created, so both are swept."""
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "prog.elf")
        stem = os.path.join(d, "prog")
        touch(binary, stem + ".id0", stem + ".nam", binary + ".id1")
        n = _sweep_locks(binary)
        check("scratch named after the stem is swept too", n == 3, f"n={n}")
        check("stem-keyed files are gone",
              not os.path.exists(stem + ".id0")
              and not os.path.exists(stem + ".nam"))
        check("full-name-keyed files are gone", not os.path.exists(binary + ".id1"))
        check("the binary itself is untouched", os.path.exists(binary))


def t_never_the_database():
    """The .i64 IS the database. Nothing is saved unless idb_save was called, so
    deleting it throws away every rename and comment in the session."""
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "echo")
        db = binary + ".i64"
        stem_db = os.path.join(d, "echo.i64")
        touch(binary, db, binary + ".id0")
        _sweep_locks(binary)
        check("the .i64 is never swept", os.path.exists(db))
        check("nor the stem-keyed .i64", os.path.exists(stem_db))
        check(".i64 is not in the suffix list", ".i64" not in _LOCK_SUFFIXES,
              str(_LOCK_SUFFIXES))


def t_never_the_input_itself():
    """`.til` is both an unpacked-DB suffix and the extension of an IDA type
    library, so `ida-tui mylib.til` used to sweep its own argument out of
    existence -- irreversibly, on a path that runs automatically when an open
    fails. Same for anything named *.id0/*.id1/*.id2/*.nam.
    """
    for suf in _LOCK_SUFFIXES:
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "mylib" + suf)
            touch(binary)
            _sweep_locks(binary)
            check(f"a binary named *{suf} is not deleted by its own sweep",
                  os.path.exists(binary), f"{binary} was removed")


def t_relative_path_is_still_the_input():
    """The guard compares absolute paths -- a relative argument names the same
    file and must be protected the same way."""
    with tempfile.TemporaryDirectory() as d:
        cwd = os.getcwd()
        try:
            os.chdir(d)
            touch("mylib.til")
            _sweep_locks("mylib.til")
            check("a relative path to the input is protected too",
                  os.path.exists("mylib.til"))
        finally:
            os.chdir(cwd)


def t_missing_files_are_fine():
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "nothing-here")
        touch(binary)
        n = _sweep_locks(binary)
        check("sweeping with nothing to sweep reports 0", n == 0, f"n={n}")
        check("and does not raise", True)


def t_leaves_the_neighbours_alone():
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "echo")
        other = os.path.join(d, "other.id0")       # another binary's scratch
        src = os.path.join(d, "echo.c")
        touch(binary, other, src, binary + ".id0")
        _sweep_locks(binary)
        check("another binary's scratch is left alone", os.path.exists(other))
        check("unrelated neighbours are left alone", os.path.exists(src))
        check("our own scratch is still swept", not os.path.exists(binary + ".id0"))


def t_load_args():
    """The single-binary path turns the load options into IDA switches."""
    check("no options means no switches", _load_args({}) == "", repr(_load_args({})))
    a = _load_args({"processor": "arm", "base": 0x8000})
    check("a processor reaches the switches", "-parm" in a, a)
    # -b is in PARAGRAPHS, not bytes: 0x8000 >> 4 == 0x800.
    check("a base is converted to paragraphs", "-b800" in a, a)
    b = _load_args({"base": "0x1000"})
    check("a base given as a hex STRING is accepted (project files write those)",
          "-b100" in b, b)
    check("no base means no -b switch", "-b" not in _load_args({"processor": "arm"}),
          _load_args({"processor": "arm"}))
    c = _load_args({"ida_args": "-p1"})
    check("extra ida_args are passed through", "-p1" in c, c)


def main() -> int:
    for fn in (t_sweeps_the_scratch_files, t_sweeps_by_stem_too,
               t_never_the_database, t_never_the_input_itself,
               t_relative_path_is_still_the_input, t_missing_files_are_fine,
               t_leaves_the_neighbours_alone, t_load_args):
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
