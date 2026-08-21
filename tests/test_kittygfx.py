#!/usr/bin/env python3
"""Kitty graphics escapes: what we actually send to the terminal (no IDA).

The splash re-anchors itself on every progress note, so the escape it sends has
to be a REPLACEMENT, not another copy. That is one key (``p``) and it is
invisible in every screenshot, which is exactly why it needs a test.

Also the cross-platform contract: graphics are optional everywhere, so a
missing ``termios`` (native Windows) or a failing terminal probe must disable
the splash, never prevent TUI startup.
"""

#: pure stdlib escape-construction checks; no IDA, no Textual.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import builtins
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


class Tty:
    """Capture what kittygfx writes, in place of the real stdout."""

    def __init__(self):
        self.sent = []
        self._real = kittygfx._write

    def __enter__(self):
        kittygfx._write = lambda data: (self.sent.append(data), True)[1]
        return self

    def __exit__(self, *exc):
        kittygfx._write = self._real

    @property
    def blob(self):
        return "".join(self.sent)

    def cmds(self, action):
        """Every graphics command with the given ``a=`` action."""
        return [c for c in re.findall(r"\x1b_G([^;\x1b]*)", self.blob)
                if f"a={action}" in c.split(",")]


def keys(cmd):
    return dict(kv.split("=", 1) for kv in cmd.split(",") if "=" in kv)


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

    class FakeTty:
        def isatty(self):
            return True

    def broken_query():
        raise RuntimeError("terminal API failed")

    try:
        sys.__stdout__ = FakeTty()
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
    # -- graphics stay optional on every platform ---------------------------- #
    t_no_termios_falls_back()
    t_probe_failure_is_never_fatal()

    kittygfx._uploaded[kittygfx.LOGO_ID] = (768, 801)   # pretend it's uploaded

    # -- the bug: anonymous placements STACK ------------------------------- #
    # A placement is identified by (image id, placement id). With no p key
    # every place() adds another copy at the same cell: a long load left the
    # terminal compositing hundreds of copies of an RGBA image over itself.
    with Tty() as tty:
        for _ in range(50):
            kittygfx.place(4, 10, 60, 26)
        placements = tty.cmds("p")
        check("place() emits one command per call", len(placements) == 50,
              f"{len(placements)}")
        check("every placement carries a placement id (replaces, not stacks)",
              all("p" in keys(c) for c in placements),
              f"{placements[0] if placements else '(none)'}")
        check("the placement id is the same every time (one image on screen)",
              len({keys(c)["p"] for c in placements}) == 1,
              f"{sorted({keys(c).get('p') for c in placements})}")
        check("...and it is non-zero (p=0 means anonymous)",
              keys(placements[0])["p"] not in ("0", ""), f"{placements[0]}")

    # -- the rest of the escape still says what it used to ------------------ #
    with Tty() as tty:
        ok = kittygfx.place(4, 10, 60, 26)
        k = keys(tty.cmds("p")[0])
        check("place() reports success", ok)
        check("image id, source pixels and cell box are unchanged",
              (k["i"], k["s"], k["v"], k["c"], k["r"])
              == (str(kittygfx.LOGO_ID), "768", "801", "60", "26"), f"{k}")
        check("the terminal is told not to move the cursor (C=1)",
              k.get("C") == "1", f"{k}")
        check("the cursor is saved and restored around the placement",
              tty.blob.startswith("\x1b[s") and tty.blob.endswith("\x1b[u"),
              repr(tty.blob[:8] + "..." + tty.blob[-8:]))
        check("the placement is positioned 1-based (row 4 -> line 5)",
              "\x1b[5;11H" in tty.blob, repr(tty.blob[:24]))

    # -- deleting still removes EVERY placement of the image ---------------- #
    # d=i is by image id, so it takes the placement with us regardless of p.
    with Tty() as tty:
        kittygfx.clear()
        k = keys(tty.cmds("d")[0])
        check("clear() deletes by image id (d=i), keeping the upload",
              k.get("d") == "i" and k.get("i") == str(kittygfx.LOGO_ID), f"{k}")
        check("clear() does not free the image data (lowercase d)",
              kittygfx.is_uploaded(), "upload was dropped")

    with Tty() as tty:
        kittygfx.delete()
        k = keys(tty.cmds("d")[0])
        check("delete() frees the image data too (d=I)", k.get("d") == "I", f"{k}")
        check("...and forgets the upload, so the next place() refuses",
              not kittygfx.is_uploaded() and kittygfx.place(0, 0, 10, 10) is False)

    # -- refusals ----------------------------------------------------------- #
    kittygfx._uploaded[kittygfx.LOGO_ID] = (768, 801)
    with Tty() as tty:
        check("a zero-sized box is refused, not sent",
              kittygfx.place(0, 0, 0, 10) is False
              and kittygfx.place(0, 0, 10, 0) is False and not tty.sent,
              f"{tty.sent}")
    kittygfx._uploaded.pop(kittygfx.LOGO_ID, None)

    # -- fit(): aspect ratio against non-square cells ----------------------- #
    check("fit() keeps the aspect ratio for 9x22 cells",
          kittygfx.fit((768, 801), 60, 99, cell=(9, 22)) == (60, 26),
          f"{kittygfx.fit((768, 801), 60, 99, cell=(9, 22))}")
    check("fit() shrinks to the row budget instead of overflowing",
          kittygfx.fit((768, 801), 60, 10, cell=(9, 22))[1] == 10,
          f"{kittygfx.fit((768, 801), 60, 10, cell=(9, 22))}")
    check("fit() never returns a zero dimension",
          all(v >= 1 for v in kittygfx.fit((768, 801), 1, 1, cell=(9, 22))))
    check("fit() survives a degenerate image size",
          kittygfx.fit((0, 0), 60, 26) == (60, 26))

    # -- png_size() reads the header, not the pixels ------------------------ #
    logo = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "logo.png")
    if os.path.exists(logo):
        check("png_size() reads logo.png's IHDR",
              kittygfx.png_size(logo) == (768, 801), f"{kittygfx.png_size(logo)}")
    check("png_size() returns None for a non-PNG", kittygfx.png_size(__file__) is None)
    check("png_size() returns None for a missing file",
          kittygfx.png_size("/nonexistent/nope.png") is None)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
