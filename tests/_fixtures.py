"""Shared setup for the suites that need a real analysed binary.

Two things every IDA suite has to get right, and only test_scenarios did:

**Work on a scratch copy.** Opening a binary writes a `.i64` beside it, and the
suites EDIT it -- they define code, undefine items, rename and comment, and IDA
saves that. Run against the tracked target and each run inherits the last one's
damage: a scenario started failing with no code change because an earlier one
had undefined an instruction. A suite whose result depends on its own history
can't be trusted to accuse the code.

**Seed from a golden database.** Auto-analysis is the bulk of a suite's runtime
(`targets/echo` is ~30s of it) and it produces the same answer every time. Doing
it once and keeping the result as `<binary>.pristine.i64` -- which nothing ever
writes back to -- turns that into a file copy.

    with staged("targets/echo") as target:
        app = IdaTui(open_path=target, ...)

The cache is rebuilt whenever it is older than the binary, so editing a target
doesn't silently test the previous one. `.pristine.i64` is gitignored.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile


def fast_keys() -> None:
    """Make a simulated keypress cost ~2ms instead of ~85ms. Call before the app.

    **The problem.** Textual sends a key and then calls ``wait_for_idle``
    *twice*, and that helper sleeps in 20ms granules until *process* time stops
    advancing -- a CPU-load heuristic standing in for "the state is predictable
    now", which takes even more granules on a loaded box. Measured here: 84ms
    per keypress, which was 23s of the pilot suite's 43s.

    **The fix, and why it is not just deletion.** Removing the heuristic alone
    broke nine checks that read state straight after a keypress -- so it *was*
    doing a job, badly. This replaces it with the real gate the rest of the
    suite already uses: send the keys, then ``settle`` (message pump drained,
    threaded workers finished). That is strictly stronger than "the CPU looks
    idle", and it is ~2ms.

    **What it still cannot see:** anything driven by a TIMER rather than a
    worker -- the function-list filter's 80ms debounce, and Textual's own frame
    timer (so a widget's ``region``/``size`` is not laid out just because the
    app settled). Those need a wait on the effect: ``wait(lambda: rows < full)``,
    ``wait(lambda: inp.region.height >= 1)``. Every such site in this repo is
    commented; if a check that reads geometry or a debounced view starts
    flaking, that is the reason.

    Verified equivalent, not just faster: pressing j 40 times moves 40 rows with
    and without the patch, and the full suite passes with identical counts.
    """
    import textual.app
    from textual.pilot import Pilot

    from idatui._sync import settle

    if not hasattr(textual.app, "wait_for_idle"):  # pragma: no cover
        raise RuntimeError(
            "textual.app.wait_for_idle is gone -- tests/_fixtures.fast_keys "
            "needs updating for this Textual version")

    async def _yield_instead_of_sleeping(min_sleep: float = 0.0,
                                         max_sleep: float = 1.0) -> None:
        await asyncio.sleep(0)

    async def _press(self, *keys: str) -> None:
        if keys:
            await self._app._press_keys(keys)
            await settle(self._app, timeout=5.0)

    textual.app.wait_for_idle = _yield_instead_of_sleeping
    Pilot.press = _press


def cache_path(binary: str) -> str:
    return binary + ".pristine.i64"


def cache_is_fresh(binary: str) -> bool:
    c = cache_path(binary)
    return os.path.exists(c) and os.path.getmtime(c) >= os.path.getmtime(binary)


#: Generated targets live here so their pristine caches survive between runs.
#: Gitignored; safe to delete (the next run rebuilds both).
SYNTHETIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".synthetic")


def synthetic(name: str, build) -> str:
    """A generated binary at a STABLE path, rebuilt only when its bytes change.

    Generated targets used to be written into a fresh TemporaryDirectory on
    every run, which quietly defeated the whole pristine-cache scheme: a new
    path with new bytes every time means auto-analysis is paid in full, every
    run, forever. `test_blob_ui`'s 64KB blob cost ~40s a run that way.

    ``build()`` must be DETERMINISTIC and return bytes. That is also what makes
    the suites reproducible: a blob built from os.urandom can, by luck, contain
    something IDA reads as a function, and then a test asserting "no functions"
    fails for reasons no one can reproduce.
    """
    os.makedirs(SYNTHETIC_DIR, exist_ok=True)
    path = os.path.join(SYNTHETIC_DIR, name)
    data = build()
    if not os.path.exists(path) or open(path, "rb").read() != data:
        with open(path, "wb") as fh:          # content changed -> cache is stale
            fh.write(data)
        for stale in (cache_path(path), path + ".i64"):
            if os.path.exists(stale):
                os.remove(stale)
    return path


async def build_pristine(binary: str, cache: str, app_factory) -> None:
    """Analyse ``binary`` once and keep the database as a golden copy.

    ``app_factory(path)`` builds the IdaTui -- passed in so this module needs no
    import of the app (and so a suite can hand over its own load options).
    """
    print(f"  (building pristine database for {os.path.basename(binary)}\u2026)")
    app = app_factory(binary)
    async with app.run_test(size=(140, 44)) as pilot:
        for _ in range(6000):
            await pilot.pause(0.05)
            if app._func_index is not None and app._func_index.complete:
                break
        app.program.client.save_database()
    # Textual's headless run_test context does not reliably emit App.Unmount on
    # every platform/version; release the IDA Nexus lease explicitly.
    if app.program is not None:
        app.program.close()
    if app.client is not None:
        app.client.close()
    db = binary + ".i64"
    if os.path.exists(db):
        shutil.copy2(db, cache)


@contextlib.contextmanager
def scratch_copy(binary: str, prefix: str = "idatui-test-"):
    """A temp-dir copy of ``binary``, seeded from the pristine cache if there is
    a fresh one. Yields the copy's path; the directory goes away after.

    Does NOT build the cache (that needs an app and an event loop) -- a suite
    that wants one calls :func:`build_pristine` first. Without a cache this is
    still correct, just slow: the worker analyses from scratch.
    """
    with tempfile.TemporaryDirectory(prefix=prefix) as d:
        target = os.path.join(d, os.path.basename(binary))
        shutil.copy2(binary, target)
        if cache_is_fresh(binary):
            shutil.copy2(cache_path(binary), target + ".i64")
        yield target


@contextlib.asynccontextmanager
async def staged(binary: str, app_factory=None, prefix: str = "idatui-test-"):
    """:func:`scratch_copy`, building the pristine cache first if it's missing.

    This is what a suite wants: one call, and the analysis is paid once ever
    rather than once per run.
    """
    if app_factory is not None and not cache_is_fresh(binary):
        with tempfile.TemporaryDirectory(prefix=prefix) as seed_dir:
            seed = os.path.join(seed_dir, os.path.basename(binary))
            shutil.copy2(binary, seed)
            await build_pristine(seed, cache_path(binary), app_factory)
    with scratch_copy(binary, prefix) as target:
        yield target
