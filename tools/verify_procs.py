#!/usr/bin/env python3
"""Check every name in ``formats.PROCESSORS`` against a real IDA.

Run this before adding a processor to the list.

A wrong ``-p`` name is not a soft failure: IDA refuses to open the database
(rc=4) with nothing useful said, which is the same silent-failure class the load
dialog exists to prevent. Offering a name that doesn't work would hand the user
a dead end from inside the very UI meant to rescue them.

Two of the first twenty entries were wrong — ``h8`` and ``sparc`` are module
FILENAMES (procs/h8.so, procs/sparc.so), not processor names; the real ones are
``h8300`` and ``sparcb``/``sparcl``. The aliases people reach for first
(``arm64``, ``aarch64``, ``mips``, ``m68k``) are all invalid too, which is why
they appear in the human labels instead, where the filter can still find them.

    /usr/bin/python tools/verify_procs.py        # needs idalib, not textual
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.formats import PROCESSORS  # noqa: E402


def main() -> int:
    import idapro
    idapro.enable_console_messages(False)
    import ida_auto
    import ida_ida

    blob = bytes(range(256)) * 8
    bad: list[tuple[str, int, str]] = []
    for name, desc in PROCESSORS:
        # A fresh directory each time: once a database exists IDA ignores the
        # load switches, and every name after the first would "pass".
        d = tempfile.mkdtemp()
        path = os.path.join(d, "probe.bin")
        with open(path, "wb") as f:
            f.write(blob)
        rc = idapro.open_database(path, run_auto_analysis=False, args=f"-p{name}")
        got = ""
        if rc == 0:
            ida_auto.auto_wait()
            got = ida_ida.inf_get_procname()
            idapro.close_database(save=False)
        ok = rc == 0 and got.lower() == name.lower()
        print(f"  {'ok  ' if ok else 'BAD '} {name:<12} rc={rc} -> {got!r}   {desc}")
        if not ok:
            bad.append((name, rc, got))

    print(f"\n{len(PROCESSORS) - len(bad)}/{len(PROCESSORS)} verified")
    for name, rc, got in bad:
        print(f"  {name}: rc={rc} procname={got!r}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
