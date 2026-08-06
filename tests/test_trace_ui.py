#!/usr/bin/env python3
"""The trace dock: registers, timeline, and stepping through time.

Needs IDA and a trace. Generates its own trace with the QEMU tracer if the
tracer is built; skips with a message otherwise, since neither the emulator nor
the trace is part of this repo.
"""

#: needs IDA and a trace; skips if the tracer isn't built.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = True
import asyncio
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from textual.widgets import Input, OptionList, Static  # noqa: E402

from _fixtures import staged  # noqa: E402
from idatui.app import (DecompView, IdaTui, ListingView,  # noqa: E402
                        RegWriteScreen, TraceDock)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACER = os.path.expanduser(
    "~/.pi/agent/skills/tenet-trace/scripts/tenet-trace")
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


def make_trace(tmp, binary):
    out = os.path.join(tmp, "t")
    try:
        subprocess.run([TRACER, "-o", out, binary, "hi"],
                       capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    log = out + ".0.log"
    return log if os.path.exists(log) else None


async def run() -> int:
    binary = os.path.join(REPO, "targets", "echo")
    # Scratch copy seeded from the golden database (tests/_fixtures.py):
    # opening a binary writes a .i64 beside it and the suite must not touch
    # anything tracked. On echo the seeding saves only ~0.2s (it analyses fast);
    # it is here so a suite pointed at a bigger target doesn't pay for analysis
    # on every run.
    async with staged(binary, lambda p: IdaTui(open_path=p, keepalive=False),
                      prefix="idatui-traceui-") as target:
        tmp = os.path.dirname(target)
        log = make_trace(tmp, target)
        if not log:
            print(f"  skip: could not record a trace (tracer at {TRACER})")
            return 0

        app = IdaTui(open_path=target, keepalive=False, trace_path=log)
        async with app.run_test(size=(160, 44)) as pilot:
            ok = await wait(lambda: app._trace is not None, pilot, 300)
            check("the trace loads alongside the binary", ok)
            if not ok:
                return 1
            t = app._trace
            check("it has instructions", t.length > 10, f"{t.length}")

            # Rebasing: the tracer runs the binary relocated, so without a slide
            # nothing in the trace matches anything on screen.
            check("trace addresses were rebased onto the database",
                  t.slide != 0 and t.ip(0) < 0x1000000,
                  f"slide={t.slide:#x} ip0={t.ip(0):#x}")
            idx = app._func_index
            touched = [f.name for f in idx.all_loaded() if t.executions(f.addr)]
            check("and now line up with real functions",
                  len(touched) > 1 and "main" in touched, f"{touched[:6]}")

            dock = app.query_one(TraceDock)
            check("the dock is docked and visible", dock.display)
            head = str(dock.query_one("#trace-head", Static).render())
            check("it shows where we are in time", "0" in head and "%" in head,
                  head[:60])
            regs = str(dock.query_one("#trace-regs", Static).render())
            check("and the register state at that time", "rip" in regs.lower(),
                  regs[:60])

            # -- stepping --------------------------------------------------- #
            lst = app.query_one(ListingView)
            lst.focus()
            await pilot.pause(0.4)
            await pilot.press("]")
            await wait(lambda: app._t == 1, pilot, 20)
            check("] steps forward one instruction", app._t == 1, f"t={app._t}")
            check("the code view follows the trace",
                  lst._cursor_ea() == t.ip(1),
                  f"{lst._cursor_ea()} vs {t.ip(1)}")
            await pilot.press("[")
            await wait(lambda: app._t == 0, pilot, 20)
            check("[ steps backward", app._t == 0, f"t={app._t}")
            await pilot.press("[")
            await pilot.pause(0.4)
            check("and stops at the start of the trace", app._t == 0)

            # -- step over -------------------------------------------------- #
            # A call pushes, so the callee runs with SP below where we started;
            # stepping until SP comes back up lands after the return. Find a
            # real call in this trace rather than assuming one is at a fixed
            # place.
            sp = "rsp" if "rsp" in t.reg_at else "esp"
            call_at = None
            for i in range(1, min(t.length - 1, 400)):
                a, b = t.register(sp, i), t.register(sp, i + 1)
                if a and b and b < a:
                    ret = next((j for j in range(i + 1, t.length)
                                if (t.register(sp, j) or 0) >= a), None)
                    if ret and ret > i + 3:
                        call_at = (i, ret)
                        break
            if call_at is None:
                check("found a call to step over", False, "none in this trace")
            else:
                i, ret = call_at
                app._seek(i)
                await wait(lambda: app._t == i, pilot, 20)
                await pilot.press("}")
                await wait(lambda: app._t != i, pilot, 30)
                check("} steps OVER a call instead of into it",
                      app._t == ret, f"{i} -> {app._t}, expected {ret}")
                check("which is further than a plain step", app._t > i + 1)

            # -- memory at time T -------------------------------------------- #
            # This is where a trace's memory actually lives: measured on two
            # real traces, NONE of the accesses fell inside the image — every
            # one was stack or heap. A memory view that could only address the
            # image would have nothing to show.
            dock = app.query_one(TraceDock)
            app._seek(min(60, t.length - 1))
            await wait(lambda: "stack (" in
                       str(dock.query_one("#trace-stack", Static).render()),
                       pilot, 5)
            stack = str(dock.query_one("#trace-stack", Static).render())
            check("the dock shows the stack at this timestamp",
                  "stack (" in stack and len(stack.splitlines()) > 4, stack[:60])
            sp_name = next(r for r in ("rsp", "esp", "sp") if r in t.reg_at)
            sp = t.register(sp_name, app._t)
            check("anchored at the stack pointer",
                  f"{sp:012x}" in stack, f"sp={sp:#x} / {stack[:80]}")

            # A trace knows what it observed and nothing else. Unseen bytes are
            # printed as '?', never as zeros — rendering them as zero would
            # invent facts about memory nobody looked at.
            data, known = t.memory_raw(sp, 8, app._t)
            if not all(known):
                check("memory the trace never saw is marked unknown",
                      "?" in stack, stack[:80])
            else:
                check("known stack words are shown as values",
                      any(c in "0123456789abcdef" for c in stack), stack[:60])

            # Stepping must move the memory view with time.
            before = stack
            app._seek(min(80, t.length - 1))
            await wait(lambda: str(dock.query_one("#trace-stack",
                                                  Static).render()) != before,
                       pilot, 5)
            check("and it follows as you move through time",
                  str(dock.query_one("#trace-stack", Static).render()) != before)

            # -- trails ------------------------------------------------------ #
            # Not "every address the trace ever touched": on a loop-heavy
            # program that's almost everything and says nothing. The last/next
            # few dozen steps say how you got here and where you're going.
            app._seek(min(40, t.length - 1))
            await wait(lambda: bool(lst.trail), pilot, 5)
            trail = lst.trail
            kinds = {k for k in trail.values()}
            check("the listing is painted with an execution trail",
                  {"now", "past", "future"} <= kinds, f"{sorted(kinds)}")
            check("'now' is the instruction we're standing on",
                  trail.get(t.ip(app._t)) == "now", f"{trail.get(t.ip(app._t))}")
            check("the step behind is past, the step ahead is future",
                  trail.get(t.ip(app._t - 1)) == "past"
                  and trail.get(t.ip(app._t + 1)) == "future",
                  f"{trail.get(t.ip(app._t - 1))}, {trail.get(t.ip(app._t + 1))}")
            painted = [y for y in range(min(lst.size.height, 30))
                       if any(seg.style and seg.style.bgcolor
                              for seg in lst.render_line(y))]
            check("and it actually reaches the screen", painted, "no tinted rows")

            # -- the same trail on PSEUDOCODE -------------------------------- #
            # The point of doing this in our app rather than using Tenet: a
            # trace's addresses are instructions, but decomp_map (built for the
            # split view) says which instructions each pseudocode line covers,
            # so the trail lands on C.
            main_ea = app.program.resolve("main")
            first = t.first_execution(main_ea)
            if first is None:
                check("main was executed in the trace", False)
            else:
                app._seek(first + 12)
                await wait(lambda: app._t == first + 12, pilot, 20)
                lst.focus()
                await pilot.press("tab")
                got = await wait(lambda: app.query_one(DecompView).display
                                 and app.query_one(DecompView)._texts, pilot, 120)
                dec = app.query_one(DecompView)
                check("pseudocode is available for the traced function", got)
                app._seek(first + 12)
                await wait(lambda: len(dec.trail) > 2, pilot, 5)
                check("pseudocode lines are painted with the trail",
                      len(dec.trail) > 2, f"{len(dec.trail)} lines")
                now = [i for i, k in dec.trail.items() if k == "now"]
                check("exactly one pseudocode line is 'now'",
                      len(now) == 1, f"{now}")
                # The 'now' line must be the one covering the current
                # instruction, not merely some executed line.
                covered = app._trail_map[now[0]] if now and app._trail_map else []
                check("and it's the line covering the current instruction",
                      t.ip(app._t) in covered,
                      f"pc={t.ip(app._t):#x} line covers {[hex(a) for a in covered][:4]}")

                # Stepping must not throw you out of the view you're reading.
                # A step navigates to an address, and navigating to an address
                # opens the LISTING unless the decompiler is preferred — so
                # stepping through C used to drop you into disassembly on the
                # first keypress. Found by watching a demo, not by a test.
                await pilot.press("]")
                await pilot.pause(1.2)
                check("stepping in pseudocode stays in pseudocode",
                      app._active == "decomp", f"active={app._active}")
                await pilot.press("[")
                await pilot.pause(1.2)
                check("and so does stepping backward",
                      app._active == "decomp", f"active={app._active}")

            # -- split view: a step is a GLOBAL move ------------------------ #
            # Normal navigation moves one pane and gives the companion a band,
            # never a cursor, so the two can't chase each other. Time isn't
            # navigation though: both panes show the same instant, so the
            # listing cursor must sit on the current instruction.
            app.action_toggle_split()
            await wait(lambda: app._split and lst.display
                       and app.query_one(DecompView).display, pilot, 10)
            if not app._split:
                check("split view toggled on", False)
            else:
                base = t.first_execution(main_ea) or 0
                tracked = 0
                for k in range(2, 8):
                    app._seek(base + k)
                    # Wait for the cursor to arrive rather than sleeping a flat
                    # 0.5s and hoping. Same question -- does the listing follow
                    # the pc? -- but it costs what it costs instead of 3s.
                    if await wait(lambda: lst._cursor_ea() == t.ip(app._t),
                                  pilot, 5):
                        tracked += 1
                check("stepping in split moves the listing cursor to the pc",
                      tracked == 6, f"{tracked}/6 steps tracked")
                check("and the trail follows in both panes",
                      lst.trail.get(t.ip(app._t)) == "now",
                      f"{lst.trail.get(t.ip(app._t))}")

                # The pseudocode cursor follows too — but only for instructions
                # the decompiler actually attributes to a line. About half
                # aren't, and the tempting fallback (nearest mapped address at
                # or before the pc) is unsound because C lines are not monotonic
                # in address: an early instruction resolved to a line near the
                # END of the function. Better to wait than to jump somewhere
                # unrelated.
                dec = app.query_one(DecompView)
                mapped = missed = 0
                for k in range(2, 30):
                    app._seek(base + k)
                    pc = t.ip(app._t)
                    # Settle on something that does NOT presuppose the answer:
                    # the listing cursor reaching the pc (checked just above)
                    # and the trail map belonging to the loaded function. Waiting
                    # on `pc in _trail_line_of` instead would burn the timeout on
                    # every unmapped instruction -- about half of them -- and be
                    # slower than the flat sleep it replaces.
                    await wait(lambda: lst._cursor_ea() == pc
                               and app._trail_map_ea == dec.loaded_ea, pilot, 5)
                    if app._trail_map_ea == dec.loaded_ea and pc in app._trail_line_of:
                        mapped += 1
                        # Mapped: the pseudocode cursor is expected, so it's fair
                        # to wait for it -- and this is the assertion, so the
                        # miss is still counted if it never arrives.
                        line = app._trail_line_of[pc]
                        await wait(lambda: dec.cursor == line, pilot, 3)
                        if dec.cursor != line:
                            missed += 1
                check("the pseudocode cursor follows every mapped instruction",
                      mapped > 3 and missed == 0,
                      f"{mapped} mapped, {missed} not followed")

            # -- a late navigation must not drag the view back --------------- #
            # Navigations run in workers and finish out of order. The trace's
            # OPENING seek goes to the entry point (t=0 is _start), takes a
            # while, and used to arrive after later seeks — leaving the cursor
            # on _start while the trace was elsewhere, and it never settled.
            # Anything cursor-based done right after a seek then acted on the
            # wrong address.
            two = [a for a in t.by_ip if len(t.by_ip[a]) > 1]
            if two:
                a = max(two, key=lambda x: len(t.by_ip[x]))
                s0, s1 = list(t.by_ip[a])[:2]
                dbaddr = a + t.slide
                app._seek(s0)
                await wait(lambda: lst._cursor_ea() == dbaddr, pilot, 60)
                app._seek(s1)
                await pilot.pause(3.0)     # long enough for a stale one to land
                check("a stale navigation doesn't drag the cursor away",
                      lst._cursor_ea() == dbaddr and app._cur.ea == dbaddr,
                      f"cursor={lst._cursor_ea():#x} cur={app._cur.ea:#x} "
                      f"want {dbaddr:#x}")

            # -- seeking, as opposed to stepping ---------------------------- #
            # "When else did this instruction run?" — the question that makes a
            # trace more than a very long single-step log.
            hot = max(t.by_ip, key=lambda a: len(t.by_ip[a]))
            stamps = list(t.by_ip[hot])
            db = hot + t.slide
            if len(stamps) < 2 or lst.model is None:
                check("found an address executed more than once", False,
                      f"{len(stamps)} executions")
            else:
                if app._split:
                    app.action_toggle_split()
                    await pilot.pause(1.0)
                if app._active != "listing":
                    # focus() does NOT make a view active outside split mode;
                    # Tab is what switches which one is showing.
                    await pilot.press("tab")
                    await wait(lambda: app._active == "listing", pilot, 60)
                app._seek(stamps[0])
                await pilot.pause(1.2)
                lst.focus()
                row = lst.model.index_of_ea(db)
                lst.cursor = row
                lst._scroll_cursor_into_view()
                await pilot.pause(0.4)
                check("cursor is on the repeated instruction",
                      lst._cursor_ea() == db, f"{lst._cursor_ea():#x} vs {db:#x}")
                await pilot.press(">")
                await pilot.pause(1.0)
                check("> seeks to the next execution of it",
                      app._t == stamps[1], f"t={app._t}, expected {stamps[1]}")
                status = str(app.query_one("#status", Static).render())
                check("and says which execution this is",
                      f"2 of {len(stamps)}" in status, status[:80])
                lst.cursor = row
                await pilot.pause(0.2)
                await pilot.press("<")
                await pilot.pause(1.0)
                check("< seeks back to the previous one",
                      app._t == stamps[0], f"t={app._t}, expected {stamps[0]}")
                # An edge must SAY it's an edge rather than silently doing
                # nothing, which is indistinguishable from a broken key.
                lst.cursor = row
                await pilot.pause(0.2)
                await pilot.press("<")
                await pilot.pause(1.0)
                status = str(app.query_one("#status", Static).render())
                check("and the first execution says so instead of moving",
                      app._t == stamps[0] and "first" in status, status[:80])

            # -- "which instruction set this register?" ---------------------- #
            app._seek(min(200, t.length - 1))
            await pilot.pause(1.0)
            lst.focus()
            await pilot.press("W")
            opened = await wait(lambda: isinstance(app.screen, RegWriteScreen),
                                pilot, 20)
            check("W lists the registers and where each was set", opened,
                  f"screen={type(app.screen).__name__}")
            if opened:
                sc = app.screen
                pick = next((k for k, (n, v, l, x) in enumerate(sc._rows)
                             if l is not None and l != app._t), None)
                if pick is None:
                    check("a register was set by an earlier instruction", False)
                    await pilot.press("escape")
                else:
                    name, _v, last, _n = sc._rows[pick]
                    sc.query_one(OptionList).highlighted = pick
                    await pilot.pause(0.3)
                    await pilot.press("enter")
                    await wait(lambda: app._t == last, pilot, 30)
                    check("choosing one seeks to the write that set it",
                          app._t == last, f"t={app._t}, expected {last}")
                    # The real check: that instruction must actually have
                    # written the register we asked about.
                    check("and that instruction really wrote it",
                          name in t.changed(app._t),
                          f"{name} not in {sorted(t.changed(app._t))}")

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
