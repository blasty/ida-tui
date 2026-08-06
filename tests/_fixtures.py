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

import contextlib
import os
import shutil
import tempfile


def cache_path(binary: str) -> str:
    return binary + ".pristine.i64"


def cache_is_fresh(binary: str) -> bool:
    c = cache_path(binary)
    return os.path.exists(c) and os.path.getmtime(c) >= os.path.getmtime(binary)


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
        app.program.client.call("idb_save", timeout=600.0)
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
