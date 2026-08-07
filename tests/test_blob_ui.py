#!/usr/bin/env python3
"""A blob that analyses to NOTHING must still be usable.

Zero functions is the normal outcome for a raw image described wrongly — and it
used to leave two empty panes and a status that said "functions still loading…",
which was a lie: loading had finished, there was simply nothing to land on.

Needs IDA (spawns a real worker). ~40s.
"""

#: spawns a real worker on a raw blob and drives the pilot.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = True
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from textual.widgets import Input, Static  # noqa: E402

from idatui.app import ConfirmScreen, IdaTui, ListingView  # noqa: E402
from _fixtures import fast_keys, staged, synthetic  # noqa: E402

fast_keys()   # ~85ms -> ~2ms per keypress; see _fixtures.fast_keys
from idatui._sync import settle  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


async def wait(pred, pilot, t=240.0):
    for _ in range(int(t / 0.05)):
        await pilot.pause(0.05)
        try:
            if pred():
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


#: File offset of the planted instruction run -> ea 0x4000 + PLANTED.
PLANTED = 0x40


def _blob_bytes() -> bytes:
    """A DETERMINISTIC pseudo-random blob with real AArch64 instructions planted.

    Seeded, not os.urandom: the bytes must be identical every run or the
    pristine-database cache can never apply (this suite used to pay ~40s of
    auto-analysis per run because the content, and the path, changed each time).
    Determinism also removes a genuine flake -- whether 64KB of chance bytes
    contains something IDA reads as a function is luck, and "and really has no
    functions" is asserted below.
    """
    import random
    data = bytearray(random.Random(0xB10BCAFE).randbytes(64 * 1024))
        # -parm puts IDA in AArch64 mode, so these are A64 encodings; the ARM32
        # spelling of a nop (0xE1A00000) is NOT decodable there and made this
        # test fail for a reason that had nothing to do with what it checks.
    for k, insn in enumerate((0xD503201F,   # nop
                              0xD503201F,   # nop
                              0xD65F03C0)):  # ret  <- the run must stop here
        data[PLANTED + k * 4:PLANTED + k * 4 + 4] = insn.to_bytes(4, "little")
    return bytes(data)


#: -parm puts IDA in AArch64 mode (the ARM32 spelling of a nop is not decodable
#: there); -b400 sets the image base. The cached database must be built with the
#: SAME switches, so both go through one factory.
BLOB_ARGS = "-parm -b400"


def _blob_app(path):
    return IdaTui(open_path=path, keepalive=False, load_args=BLOB_ARGS)


def head_at(lst, ea):
    """The listing row for ``ea`` off the LIVE model, or None.

    Always re-reads ``lst.model``: an edit may rebuild the model, and holding
    the old object shows pre-edit rows -- which looks exactly like the edit
    silently failing.
    """
    m = lst.model
    if m is None:
        return None
    i = m.index_of_ea(ea)
    return m.get(i) if i is not None and i >= 0 else None


async def run() -> int:
    blob_src = synthetic("rnd.bin", _blob_bytes)
    # staged() analyses once ever and copies the result in on later runs.
    async with staged(blob_src, _blob_app) as blob:
        # Skip the dialog by answering up front; this test is about what
        # happens AFTER a described blob turns out to contain nothing.
        app = _blob_app(blob)
        async with app.run_test(size=(140, 44)) as pilot:
            ok = await wait(lambda: app._func_index is not None
                            and app._func_index.complete, pilot)
            check("a random blob still finishes loading", ok)
            check("and really has no functions", len(app._func_index) == 0,
                  f"n={len(app._func_index)}")

            landed = await wait(lambda: app._cur is not None, pilot, 60)
            check("it lands somewhere instead of leaving empty panes", landed,
                  f"cur={app._cur}")
            lst = app.query_one(ListingView)
            check("the listing actually has rows to show",
                  lst.total > 0, f"total={lst.total}")
            check("landed at the image base", app._cur is not None
                  and app._cur.ea == 0x4000, f"{app._cur.ea if app._cur else None:#x}")

            status = str(app.query_one("#status", Static).render())
            check("the status says there are no functions (not 'still loading')",
                  "no functions" in status and "still loading" not in status,
                  status[:90])
            check("and points at the likely cause",
                  "processor" in status and "Ctrl+L" in status, status[:90])

            # The hint is a property of the database, so it must survive moving
            # around — an earlier version wrote it once and the next status
            # write erased it.
            lst.focus()
            await pilot.press("down")
            await pilot.press("down")
            await settle(app)
            status2 = str(app.query_one("#status", Static).render())
            check("the hint survives navigating", "no functions" in status2,
                  status2[:90])

            # -- byte-granular carving ---------------------------------- #
            # An undefined run arrives as ONE head ("db N dup(?)"). It has to
            # PRESENT as one row per byte or there is no cursor position to
            # press `c` at, which is how IDA works and the only way to find an
            # instruction stream that doesn't start at the run's first byte.
            m = lst.model
            check("an undefined run presents one row per byte",
                  m.loaded() >= 4096 and len(m._heads) < 64,
                  f"rows={m.loaded()} physical heads={len(m._heads)}")
            rows = m.window(0, 4)
            check("each row is a single addressable byte",
                  [h.ea for h in rows] == [0x4000, 0x4001, 0x4002, 0x4003]
                  and all(h.size == 1 for h in rows),
                  f"{[(hex(h.ea), h.size) for h in rows]}")
            check("and shows its value, not a placeholder",
                  all(h.text.startswith("db ") and "dup" not in h.text
                      for h in rows), f"{[h.text for h in rows]}")

            # The point of all this: land on an arbitrary byte and convert it.
            i = m.index_of_ea(0x4021)
            check("an address inside the run resolves to its own row",
                  i >= 0 and m.get(i).ea == 0x4021,
                  f"row={i} ea={m.get(i).ea if i >= 0 else None}")

            target = 0x4000 + PLANTED        # a NOP we put there ourselves
            lst.cursor = m.index_of_ea(target)
            lst._scroll_cursor_into_view()
            await settle(app, lambda: lst._cursor_ea() == target)
            check("the cursor sits on the byte we aimed at",
                  lst._cursor_ea() == target,
                  f"{lst._cursor_ea():#x} want {target:#x}")
            await pilot.press("c")
            # settle(), not a fixed sleep AND not a bare predicate: an edit can
            # look done for a moment and then be replaced when a queued listing
            # rebuild lands, so the gate has to be "the row is code AND the app
            # has stopped working". settle() is the same helper the app's own
            # RPC layer uses, so tests and driver agree on what "done" means.
            await settle(app, lambda: (lambda h: h is not None and h.kind == "code")(
                head_at(lst, target)), timeout=30)
            # Re-read the model: defining an item rebuilds it, and holding the
            # old object shows pre-edit rows -- which looks exactly like the
            # edit silently failing.
            m = lst.model
            h = head_at(lst, target)
            check("`c` on a chosen byte carves an instruction there",
                  h is not None and h.kind == "code",
                  f"kind={h.kind if h else None} text={h.text if h else None!r}")
            if h is not None and h.kind == "code":
                print(f"       carved {target:#x}: {h.text}")
                # `c` runs until something stops it, like IDA — one instruction
                # at a time means pressing it once per opcode for the length of
                # a routine. We planted nop/nop/nop/ret, so it must take all
                # four and stop AT the ret, not run on into the random bytes
                # after it.
                run = [m.get(m.index_of_ea(target + k * 4)) for k in range(3)]
                check("`c` keeps going until control flow ends",
                      all(x is not None and x.kind == "code" for x in run),
                      f"{[(hex(x.ea), x.kind) for x in run if x]}")
                check("and stops at the ret instead of running into junk",
                      m.get(m.index_of_ea(target + 12)).kind == "unknown",
                      f"{m.get(m.index_of_ea(target + 12)).text!r}")
                status = str(app.query_one("#status", Static).render())
                check("the status reports what the run did",
                      "3 instructions" in status and "control flow" in status,
                      status[:80])
                check("the carved row spans the instruction, not one byte",
                      h.size == 4, f"size={h.size}")
                check("bytes before it stay individually addressable",
                      m.get(m.index_of_ea(target - 1)).size == 1
                      and m.get(m.index_of_ea(target - 1)).ea == target - 1)

            # -- an edit must not move the view -------------------------- #
            # Every mutation rebuilds the model, and row indices don't survive
            # that: carving collapses four byte rows into one instruction row.
            # All the edit paths go through ViewAnchor, which remembers
            # ADDRESSES. This runs in its own app, so unlike the shared scenario
            # suite it can mutate the database freely.
            lst.cursor = m.index_of_ea(0x4200)
            lst._scroll_cursor_into_view()
            await settle(app, lambda: lst._cursor_ea() == 0x4200)
            ctop = lst.model.get(round(lst.scroll_offset.y)).ea
            ccur = lst._cursor_ea()
            old = lst.model
            await pilot.press("semicolon")
            await wait(lambda: app.query_one("#comment", Input).display, pilot, 20)
            for ch in "note":
                await pilot.press(ch)
            await pilot.press("enter")
            # Wait for the COMMENT ITSELF to show up, not for the model object to
            # be replaced: a comment now re-renders the listing in place (the
            # walk is kept), so `model is not old` never becomes true and this
            # burned its full 30s timeout on every run -- after which the check
            # below passed vacuously, because nothing had happened at all.
            # The prompt closing plus quiescence is the real end of the edit.
            # (The listing re-renders its text lazily, so the comment is not
            # necessarily visible in model rows the moment the worker returns --
            # which is why this waits for the app, not for the text.)
            await settle(app, lambda: not app.query_one("#comment", Input).display,
                         timeout=30)
            check("commenting leaves the view where it was",
                  lst.model.get(round(lst.scroll_offset.y)).ea == ctop
                  and lst._cursor_ea() == ccur,
                  f"top {ctop:#x} -> "
                  f"{lst.model.get(round(lst.scroll_offset.y)).ea:#x}, "
                  f"cursor {ccur:#x} -> {lst._cursor_ea():#x}")

            # -- carving must not move the view -------------------------- #
            # Defining code collapses rows (four byte rows become one
            # instruction), so anything that remembers a row INDEX puts you
            # somewhere else afterwards. Scroll down far enough that there is a
            # viewport to lose, then check the top ADDRESS is unchanged.
            far = 0x4000 + 0x600
            lst.cursor = lst.model.index_of_ea(far)
            lst._scroll_cursor_into_view()
            await settle(app, lambda: lst._cursor_ea() == far)
            top_before = lst.model.get(round(lst.scroll_offset.y)).ea
            cur_before = lst._cursor_ea()
            check("scrolled somewhere with rows above us",
                  round(lst.scroll_offset.y) > 0, f"top={lst.scroll_offset.y}")
            await pilot.press("c")
            # No predicate here on purpose: this spot is random data, so the
            # carve may legitimately produce nothing and "the row became code"
            # would never hold (it timed out for 30s and then passed anyway).
            # What is being checked is that the VIEW did not move, so the gate
            # is simply "the app has finished reacting".
            await settle(app, timeout=30)
            m2 = lst.model
            top_after = m2.get(round(lst.scroll_offset.y)).ea
            check("carving leaves the scroll position where it was",
                  top_after == top_before,
                  f"{top_before:#x} -> {top_after:#x}")
            check("and leaves the cursor on the same address",
                  lst._cursor_ea() == cur_before,
                  f"{cur_before:#x} -> {lst._cursor_ea():#x}")

            # -- `p` after carving: the rest of the app must notice ------ #
            # The "no functions" hint was latched at load and only cleared on a
            # reload, so it kept telling you the processor/base were wrong long
            # after you'd defined a function. The function index was never
            # rebuilt either, which meant Ctrl+N couldn't find what `p` made.
            check("no functions yet, and the hint says so",
                  len(app._func_index) == 0
                  and "no functions" in str(app.query_one("#status", Static).render()),
                  f"n={len(app._func_index)}")
            lst.cursor = lst.model.index_of_ea(target)
            lst._scroll_cursor_into_view()
            await settle(app, lambda: lst._cursor_ea() == target)
            mp = lst.model
            await pilot.press("p")
            await wait(lambda: lst.model is not mp and lst.model is not None,
                       pilot, 40)
            await wait(lambda: app._func_index is not None
                       and len(app._func_index) > 0, pilot, 60)
            check("`p` creates a function the index can see",
                  len(app._func_index) == 1, f"n={len(app._func_index)}")
            status = str(app.query_one("#status", Static).render())
            check("and the stale 'no functions' hint is gone",
                  "no functions" not in status, status[:90])
            check("the status names the function it made",
                  "created function" in status, status[:90])

            await pilot.press("ctrl+l")
            opened = await wait(lambda: isinstance(app.screen, ConfirmScreen), pilot, 20)
            check("Ctrl+L offers to reload with different options", opened,
                  f"screen={type(app.screen).__name__}")
            if opened:
                note = str(app.screen.query_one("#confirm-note", Static).render())
                # We just made a function, so it must NOT claim nothing is lost —
                # reloading throws the database away and that is now a real cost.
                check("the confirmation counts what would be lost",
                      "1 function," in note and "nothing is lost" not in note,
                      note[:80])
                await pilot.press("escape")
                await settle(app, lambda: not isinstance(app.screen, ConfirmScreen))
                check("declining leaves the binary open",
                      not isinstance(app.screen, ConfirmScreen) and app._cur is not None)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
