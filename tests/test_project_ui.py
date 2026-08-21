#!/usr/bin/env python3
"""End-to-end pilot for project mode: two binaries, switching between them.

Needs idalib (it spawns real workers, one per binary) and textual:

    ~/ida-venv/bin/python tests/test_project_ui.py [bin1 bin2]

Defaults to targets/echo + targets/cat. The binaries are copied into a temp
source dir first, so the "source tree stays pristine" promise is checkable.
"""

#: spawns one real worker per binary and drives the pilot.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = True
import asyncio
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fixtures import fast_keys  # noqa: E402

from idatui._sync import settle as quiesce  # noqa: E402
from idatui._sync import wait_for

fast_keys()  # ~85ms -> ~2ms per keypress; see _fixtures.fast_keys
from textual.widgets import Input, OptionList, Static  # noqa: E402

from idatui.app import IdaTui, ProjectPalette  # noqa: E402
from idatui.project import Project  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


async def run(bins):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        srcs = []
        for b in bins:
            dst = os.path.join(src, os.path.basename(b))
            shutil.copy2(b, dst)
            srcs.append(dst)
        proj = Project.create(os.path.join(tmp, "proj.json"), srcs, name="proj")
        proj.stage_all()
        first, second = (r.label for r in proj.refs)

        app = IdaTui(keepalive=False, project=proj)
        async with app.run_test(size=(140, 44)) as pilot:

            async def settle(pred, t=180.0):
                return await wait_for(pred, pilot.pause, t, 0.05)

            async def usable(t=180.0):
                """Loaded AND drivable.

                An index that has finished streaming does not mean the app is
                taking keys yet: the loading overlay is a ModalScreen and it is
                dismissed a moment later, by auto-land. Between those two the
                app looks ready and swallows every keypress -- so a test that
                waits only for the index presses Ctrl+O into the overlay and
                sees no switcher. Which side of that gap the poll lands on is
                decided by how fast the backend happens to be, so it has to be
                waited for explicitly, not hoped for.
                """
                return await settle(
                    lambda: (
                        app.program is not None
                        and app._func_index is not None
                        and app._func_index.complete
                        and app._loading_screen is None
                        and len(app.screen_stack) == 1
                    ),
                    t,
                )

            # -- boots on the project's first binary ----------------------- #
            ok = await usable()
            check("project mode boots on the first binary", ok, f"binary={app._binary}")
            check(
                "the active binary is the first one",
                app._binary == first,
                f"{app._binary}",
            )
            n_first = len(app._func_index)
            check("its functions loaded", n_first > 10, f"n={n_first}")
            status = str(app.query_one("#status", Static).render())
            check(
                "the status line names the active binary",
                f"[{first}]" in status,
                status[:60],
            )

            # -- the switcher lists the project ---------------------------- #
            await pilot.press("ctrl+o")
            opened = await settle(lambda: isinstance(app.screen, ProjectPalette), 20)
            check(
                "Ctrl+O opens the binary switcher",
                opened,
                f"screen={type(app.screen).__name__}",
            )
            if not opened:
                return
            pal = app.screen
            check(
                "the switcher lists every project binary",
                len(pal._results) == 2,
                f"{[e['label'] for e in pal._results]}",
            )
            check(
                "it marks which one is active",
                any(e["active"] and e["label"] == first for e in pal._results),
            )
            check(
                "it marks the other as not yet opened",
                any(not e["resident"] and e["label"] == second for e in pal._results),
            )
            ol = pal.query_one(OptionList)
            check(
                "the switcher opens on the binary you're already in",
                ol.highlighted is not None
                and pal._results[ol.highlighted]["label"] == first,
                f"highlighted={ol.highlighted} "
                f"={pal._results[ol.highlighted]['label'] if ol.highlighted is not None else None} "
                f"want={first}",
            )

            # -- switch to the second binary -------------------------------- #
            pal.query_one(Input).value = second
            await settle(lambda: bool(pal._results), 20)
            await pilot.press("enter")
            switched = await settle(
                lambda: (
                    app._binary == second
                    and app.program is not None
                    and app._func_index is not None
                    and app._func_index.complete
                    and len(app.screen_stack) == 1
                )
            )
            check("switching opens the other binary", switched, f"binary={app._binary}")
            check(
                "the second binary has its own function index",
                app._func_index is not None and len(app._func_index) > 5,
                f"n={len(app._func_index) if app._func_index else 0}",
            )
            check(
                "both binaries now have live workers",
                sorted(app._pool.resident()) == sorted([first, second]),
                f"{app._pool.resident()}",
            )
            landed = await settle(lambda: app._cur is not None, 60)
            check("it lands somewhere in the new binary", landed, f"cur={app._cur}")
            where = app._cur.ea if app._cur else None

            # -- switch back: resident, so state is restored ---------------- #
            await pilot.press("ctrl+o")
            reopened = await settle(lambda: isinstance(app.screen, ProjectPalette), 20)
            check(
                "the switcher reopens after a switch",
                reopened,
                f"screen={type(app.screen).__name__}",
            )
            if not reopened:
                return
            app.screen.query_one(Input).value = first
            await settle(lambda: bool(app.screen._results), 20)
            await pilot.press("enter")
            back = await settle(
                lambda: (
                    app._binary == first
                    and app._func_index is not None
                    and app._func_index.complete
                    and len(app.screen_stack) == 1
                ),
                120,
            )
            check(
                "switching back returns to the first binary",
                back,
                f"binary={app._binary}",
            )
            check(
                "its function index came back intact",
                app._func_index is not None and len(app._func_index) == n_first,
                f"n={len(app._func_index) if app._func_index else 0} want={n_first}",
            )

            # and forward again: the second binary's position was remembered
            await pilot.press("ctrl+o")
            if not await settle(lambda: isinstance(app.screen, ProjectPalette), 20):
                check(
                    "returning to a binary restores where you were",
                    False,
                    "switcher did not reopen",
                )
                return
            app.screen.query_one(Input).value = second
            await settle(lambda: bool(app.screen._results), 20)
            await pilot.press("enter")
            again = await settle(
                lambda: app._binary == second and app._cur is not None, 120
            )
            check(
                "returning to a binary restores where you were",
                again and app._cur.ea == where,
                f"cur={app._cur.ea if app._cur else None} want={where}",
            )

            # -- project-wide symbol search ------------------------------- #
            # 'main' exists in BOTH binaries: identical name, so the rank tuple
            # ties and a bare sort() would fall through to comparing Hit objects
            # ('<' not supported between instances of 'Hit').
            from idatui.app import SymbolPalette

            await settle(
                lambda: app._index is not None and len(app._index.counts()) == 2, 60
            )
            check(
                "both binaries got indexed",
                len(app._index.counts()) == 2,
                f"{app._index.counts()}",
            )
            await pilot.press("ctrl+n")
            if await settle(lambda: isinstance(app.screen, SymbolPalette), 20):
                pal = app.screen
                pal.query_one(Input).value = "main"
                await settle(lambda: bool(pal._results), 20)
                # The palette re-applies inside the key handler, so the gate is
                # quiescence -- NOT "a foreign binary appeared", which is the
                # thing under test and would sit out its whole timeout on the
                # day it breaks.
                await pilot.press("f2")  # widen to the whole project
                await quiesce(app)
                names = [(b, n) for b, _, n in pal._results]
                check(
                    "project scope finds a name shared by both binaries",
                    len({b for b, n in names if n == "main"}) == 2,
                    f"{names[:6]}",
                )
                await pilot.press("escape")
                await settle(lambda: not isinstance(app.screen, SymbolPalette), 20)

            # -- a cross-binary jump is not a one-way door ----------------- #
            # Nav history is per-binary, so arriving in another binary lands you
            # in an empty history. Esc must fall through to the binary you came
            # from, or a project search hit (and, since phase 3, following an
            # import) strands you.
            here, there = app._binary, (first if app._binary == second else second)
            hops0 = len(app._hops)
            target = app._index.search("main", limit=200)
            tgt = next((h for h in target if h.binary == there), None)
            if tgt is None:
                check(
                    "cross-binary jump records a hop",
                    False,
                    "no hit in the other binary",
                )
            else:
                app._switch_then_goto(tgt.binary, tgt.addr)
                jumped = await settle(
                    lambda: (
                        app._binary == there
                        and app._func_index is not None
                        and app._func_index.complete
                    ),
                    180,
                )
                check(
                    "a project hit switches to the other binary",
                    jumped,
                    f"binary={app._binary} want={there}",
                )
                check(
                    "the jump records where it came from",
                    len(app._hops) == hops0 + 1 and app._hops[-1] == here,
                    f"hops={app._hops}",
                )
                # spend the local history first, then Esc must cross back
                for _ in range(6):
                    if not app._hops or app._binary != there:
                        break
                    await pilot.press("escape")
                    await quiesce(app)
                returned = await settle(lambda: app._binary == here, 180)
                check(
                    "Esc crosses back to the binary the jump came from",
                    returned,
                    f"binary={app._binary} want={here} hops={app._hops}",
                )
                check(
                    "the hop is consumed, not repeated",
                    not app._hops,
                    f"hops={app._hops}",
                )

            # -- xrefs: callers in OTHER project binaries ------------------ #
            # xrefs_to only sees this database, so an exported function looks
            # unused from the inside even when the rest of the project calls it.
            # The selection rule is "only for a symbol we actually export"; two
            # executables share no linkage, so here it must stay quiet.
            from idatui.app import XrefsScreen

            fake = app._foreign_importers(app._cur.ea, "strrchr", None)
            check(
                "no cross-binary callers for a symbol this binary doesn't export",
                fake == [],
                f"{fake}",
            )

            # The routing a real cross-binary caller takes: the dialog carries a
            # (binary, addr) payload instead of a bare address, and choosing it
            # goes through the same switch path as a search hit — hop included,
            # so Esc comes back.
            where_from = app._binary
            other = first if where_from == second else second
            hit = next(
                (h for h in app._index.search("main", limit=200) if h.binary == other),
                None,
            )
            if hit is None:
                check(
                    "a cross-binary xref jumps to the other binary",
                    False,
                    "no symbol found in the other binary",
                )
            else:
                hops0 = len(app._hops)
                app.push_screen(
                    XrefsScreen(
                        "xrefs to fake",
                        [
                            (
                                (hit.binary, hit.addr),
                                f"{hit.addr:08X}  import  [{hit.binary}]",
                            )
                        ],
                    ),
                    app._on_xref_chosen,
                )
                await settle(lambda: isinstance(app.screen, XrefsScreen), 20)
                await pilot.press("enter")
                jumped = await settle(
                    lambda: (
                        app._binary == other
                        and app._func_index is not None
                        and app._func_index.complete
                    ),
                    180,
                )
                check(
                    "a cross-binary xref jumps to the other binary",
                    jumped,
                    f"binary={app._binary} want={other}",
                )
                check(
                    "and records a hop so Esc returns",
                    len(app._hops) == hops0 + 1 and app._hops[-1] == where_from,
                    f"hops={app._hops}",
                )
                app._hops.clear()

            # -- and the same toggle for strings --------------------------- #
            from idatui.app import StringsPalette

            await pilot.press("quotation_mark")
            if await settle(lambda: isinstance(app.screen, StringsPalette), 30):
                pal = app.screen
                pal.query_one(Input).value = "usage"
                await settle(lambda: bool(pal._results), 20)
                local = {b for b, _, _ in pal._results}
                await pilot.press("f2")
                await quiesce(app)
                wide = {b for b, _, _ in pal._results}
                check(
                    "strings: local scope is this binary only",
                    local == {None},
                    f"{local}",
                )
                check(
                    "strings: F2 widens across the project",
                    len(wide) >= 2 and None not in wide,
                    f"{wide}",
                )
                await pilot.press("escape")
                await settle(lambda: not isinstance(app.screen, StringsPalette), 20)

        # -- the promise: nothing was written next to the sources ---------- #
        left = sorted(os.listdir(src))
        check(
            "the source tree stays pristine (no .i64/scratch beside it)",
            left == sorted(os.path.basename(s) for s in srcs),
            f"{left}",
        )
        staged = sorted(os.listdir(proj.bin_dir))
        check(
            "IDA's artifacts all live in the project sidecar",
            any(f.endswith(".i64") for f in staged),
            f"{staged}",
        )

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


def main(argv):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bins = argv or [
        os.path.join(repo, "targets", "echo"),
        os.path.join(repo, "targets", "cat"),
    ]
    for b in bins:
        if not os.path.isfile(b):
            print(f"no such binary: {b}")
            return 2
    return asyncio.run(run(bins))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
