#!/usr/bin/env python3
"""``ida-tui /bin/ls`` must ask where to put the database, not fail obscurely.

IDA writes its database beside the binary, so a binary in a system directory
made IDA Nexus fail the open with

    idalib worker launcher 2425195 exited with status 1
    [ida-nexus] Failed to open database /usr/bin/ls

after a full analysis wait -- naming neither the file it could not create nor
the reason. This drives the replacement: a pre-flight check, a dialog with a
writable default, and ``output_database`` carried into the client.

NEEDS_IDA is True because this needs **textual** (run.py picks the IDA venv for
those); it never opens a database -- ``_connect`` is stubbed, so it costs ~1s.
"""

#: needs textual (run.py's interpreter choice), but spawns NO worker.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = True
import asyncio
import os
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _fixtures import fast_keys  # noqa: E402

fast_keys()

from idatui import idbpath  # noqa: E402
from idatui._sync import settle  # noqa: E402
from idatui.app import IdaTui, IdbLocationScreen  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def _app(path, **kw):
    """The app with the open stubbed out: this suite is about the DECISION.

    ``_connect`` is a Textual worker; replacing the bound attribute is enough
    because every caller goes through ``self._connect()``. ``connects`` records
    that we would have opened the database, which is the other half of the
    contract (answering the dialog must actually proceed).
    """
    app = IdaTui(open_path=path, keepalive=False, **kw)
    app.connects = 0

    def stub():
        app.connects += 1

    app._connect = stub
    return app


def _readonly_dir(tmp, name="sysdir"):
    """A directory holding a binary that the directory will not let us write."""
    d = os.path.join(tmp, name)
    os.makedirs(d, exist_ok=True)
    binary = os.path.join(d, "ls")
    shutil.copy("/bin/ls" if os.path.exists("/bin/ls") else sys.executable, binary)
    os.chmod(d, 0o500)
    return d, binary


async def t_asks_and_relocates(tmp):
    d, binary = _readonly_dir(tmp)
    try:
        app = _app(binary)
        async with app.run_test(size=(120, 40)) as pilot:
            await settle(app)
            screen = app.screen
            check(
                "an unwritable location asks instead of opening",
                isinstance(screen, IdbLocationScreen),
                type(screen).__name__,
            )
            check("nothing was opened while the dialog is up", app.connects == 0)
            text = str(app.screen.query_one("#idb-msg").render())
            check(
                "the dialog names the file IDA could not create",
                binary + ".i64" in text,
                text[:120],
            )
            check("...and why", "not writable" in text, text[:120])
            proposed = app.screen.query_one("#idb-path").value
            check(
                "it proposes the stable per-binary location",
                proposed == idbpath.relocated_idb(binary),
                proposed,
            )

            await pilot.press("enter")
            await settle(app)
            check(
                "accepting records it as the database location",
                app._idb_path == idbpath.relocated_idb(binary),
                str(app._idb_path),
            )
            check(
                "...creates the directory for it",
                os.path.isdir(os.path.dirname(app._idb_path)),
            )
            check("...and proceeds to open", app.connects == 1)
            check(
                "the original directory was left untouched",
                os.listdir(d) == ["ls"],
                str(os.listdir(d)),
            )
    finally:
        os.chmod(d, 0o700)


async def t_esc_quits(tmp):
    """With nowhere to put the database there is no session to show."""
    d, binary = _readonly_dir(tmp, "sysdir2")
    try:
        app = _app(binary)
        async with app.run_test(size=(120, 40)) as pilot:
            await settle(app)
            check("the dialog is up", isinstance(app.screen, IdbLocationScreen))
            await pilot.press("escape")
            await settle(app)
            check("Esc does not open anything", app.connects == 0)
            check("Esc does not leave an empty app", app._idb_path is None)
            check(
                "...and does not arm the save-on-exit path",
                app._save_on_exit is False,
                str(app._save_on_exit),
            )
    finally:
        os.chmod(d, 0o700)


async def t_edited_path(tmp):
    """The proposal is a default, not a decision."""
    d, binary = _readonly_dir(tmp, "sysdir3")
    chosen = os.path.join(tmp, "elsewhere", "mine")
    try:
        app = _app(binary)
        async with app.run_test(size=(120, 40)) as pilot:
            await settle(app)
            inp = app.screen.query_one("#idb-path")
            inp.value = chosen
            await pilot.press("enter")
            await settle(app)
            check(
                "a typed path is used, with .i64 supplied",
                app._idb_path == chosen + ".i64",
                str(app._idb_path),
            )
            check(
                "its directory is created privately",
                os.path.isdir(os.path.dirname(chosen))
                and stat.S_IMODE(os.stat(os.path.dirname(chosen)).st_mode) == 0o700,
            )
    finally:
        os.chmod(d, 0o700)


async def t_writable_is_untouched(tmp):
    """The common case must not gain a dialog."""
    binary = os.path.join(tmp, "own")
    shutil.copy("/bin/ls" if os.path.exists("/bin/ls") else sys.executable, binary)
    app = _app(binary)
    async with app.run_test(size=(120, 40)):
        await settle(app)
        check(
            "a writable directory opens straight away",
            not isinstance(app.screen, IdbLocationScreen) and app.connects == 1,
            f"{type(app.screen).__name__} connects={app.connects}",
        )
        check("and no database location is forced", app._idb_path is None)


async def t_explicit_idb_wins(tmp):
    """``--idb`` is an answer already given; do not ask again."""
    d, binary = _readonly_dir(tmp, "sysdir4")
    target = os.path.join(tmp, "explicit.i64")
    try:
        app = _app(binary, idb_path=target)
        async with app.run_test(size=(120, 40)):
            await settle(app)
            check(
                "--idb skips the dialog",
                not isinstance(app.screen, IdbLocationScreen) and app.connects == 1,
                f"{type(app.screen).__name__} connects={app.connects}",
            )
            check("and is what gets used", app._idb_path == target, str(app._idb_path))
    finally:
        os.chmod(d, 0o700)


async def t_rpc_driven_does_not_ask(tmp):
    """A puppeteered TUI has nobody to ask, and `pane spawn` is waiting on it.

    Left as a dialog, an RPC-driven pane never reports ready and spawn burns its
    whole timeout in front of a modal. Taking the proposal destroys nothing.
    """
    d, binary = _readonly_dir(tmp, "sysdir_rpc")
    try:
        app = _app(binary, rpc_path=os.path.join(tmp, "nope.sock"))
        app._start_rpc = lambda: None  # the socket is not the point here
        async with app.run_test(size=(120, 40)):
            await settle(app)
            check(
                "an RPC-driven TUI relocates without asking",
                not isinstance(app.screen, IdbLocationScreen)
                and app._idb_path == idbpath.relocated_idb(binary),
                f"{type(app.screen).__name__} {app._idb_path}",
            )
            check("...and still opens", app.connects == 1, str(app.connects))
            status = str(app.query_one("#status").render())
            check(
                "...and says where the database went",
                app._idb_path in status and "not writable" in status,
                status[:120],
            )
    finally:
        os.chmod(d, 0o700)


async def t_client_gets_output_database(tmp):
    """The decision has to reach the backend, or it changes nothing.

    ``NexusClient`` is stubbed: what matters here is the argument, and
    constructing the real one needs the IDA Nexus library.
    """
    import idatui.app as appmod

    d, binary = _readonly_dir(tmp, "sysdir5")
    seen = {}

    class FakeClient:
        def __init__(self, path, **kw):
            seen.update(kw, path=path)

        def connect(self, **kw):
            return self

    real = appmod.NexusClient
    appmod.NexusClient = FakeClient
    try:
        app = IdaTui(
            open_path=binary, keepalive=False, idb_path=os.path.join(tmp, "x.i64")
        )
        async with app.run_test(size=(120, 40)):
            await settle(app)
            # Off the app thread: the opener reports progress with
            # call_from_thread, which refuses to run on the loop it posts to.
            await asyncio.to_thread(app._open_database_client)
        check(
            "output_database carries the chosen location",
            seen.get("output_database") == os.path.join(tmp, "x.i64"),
            str(seen),
        )
        check(
            "and the binary is still what gets opened",
            seen.get("path") == binary,
            str(seen),
        )
    finally:
        appmod.NexusClient = real
        os.chmod(d, 0o700)


async def run() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ[idbpath.DB_DIR_ENV] = os.path.join(tmp, "dbs")
        try:
            for fn in (
                t_asks_and_relocates,
                t_esc_quits,
                t_edited_path,
                t_writable_is_untouched,
                t_explicit_idb_wins,
                t_rpc_driven_does_not_ask,
                t_client_gets_output_database,
            ):
                print(f"\n{fn.__name__}")
                sub = os.path.join(tmp, fn.__name__)
                os.makedirs(sub, exist_ok=True)
                try:
                    await fn(sub)
                except Exception as e:  # noqa: BLE001
                    import traceback

                    check(
                        f"{fn.__name__} did not crash",
                        False,
                        f"{type(e).__name__}: {e}",
                    )
                    traceback.print_exc()
        finally:
            os.environ.pop(idbpath.DB_DIR_ENV, None)
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
