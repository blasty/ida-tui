#!/usr/bin/env python3
"""Cross-platform checks for the optional kitty-graphics startup splash.

Pure: stdlib only, no terminal, Textual, Code Mode, or IDA.
"""
from __future__ import annotations

import builtins
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NEEDS_IDA = False

from idatui import kittygfx  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def t_no_termios_falls_back():
    """Native Windows has no termios; the splash must simply use ANSI art."""
    original_import = builtins.__import__

    def without_termios(name, *args, **kwargs):
        if name == "termios":
            raise ModuleNotFoundError("No module named 'termios'")
        return original_import(name, *args, **kwargs)

    builtins.__import__ = without_termios
    try:
        check("missing termios disables graphics", kittygfx._query_tty(0) is False)
    except Exception as exc:  # the original Windows startup crash
        check("missing termios does not escape", False,
              f"{type(exc).__name__}: {exc}")
    finally:
        builtins.__import__ = original_import


def t_probe_failure_is_never_fatal():
    """Even an unexpected platform/probe error cannot prevent TUI startup."""
    original_query = kittygfx._query_tty
    original_stdout = sys.__stdout__
    original_supported = kittygfx._supported
    old_env = os.environ.pop("IDATUI_KITTY", None)

    class Tty:
        def isatty(self):
            return True

    def broken_query():
        raise RuntimeError("terminal API failed")

    try:
        sys.__stdout__ = Tty()
        kittygfx._query_tty = broken_query
        kittygfx._supported = None
        check("probe exception disables graphics", kittygfx.supported() is False)
        check("failed result is cached", kittygfx.supported() is False)
    except Exception as exc:
        check("probe exception does not escape", False,
              f"{type(exc).__name__}: {exc}")
    finally:
        kittygfx._query_tty = original_query
        kittygfx._supported = original_supported
        sys.__stdout__ = original_stdout
        if old_env is not None:
            os.environ["IDATUI_KITTY"] = old_env


def main() -> int:
    for fn in (t_no_termios_falls_back, t_probe_failure_is_never_fatal):
        print(f"\n{fn.__name__}")
        fn()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
