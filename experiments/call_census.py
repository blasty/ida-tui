"""Count backend round-trips per user action.

Answers "are we batching, or paying a round-trip per item?" with numbers rather
than intent. Wraps ``CodeModeClient.invoke`` on the live app, drives a headless
Pilot through realistic actions, and reports calls + wall time + which
operations were used for each.

    PYTHONPATH=. ~/ida-venv/bin/python experiments/call_census.py [BINARY]

Read it as: an action costing 1-8 calls is amortised (the snippet looped inside
the database); an action whose call count scales with the number of rows or
symbols on screen is a round-trip-per-item bug worth fixing.
"""
from __future__ import annotations

import asyncio
import collections
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
from _fixtures import fast_keys, staged  # noqa: E402

fast_keys()

from idatui.app import IdaTui, ListingView  # noqa: E402
from idatui.codemode_client import CodeModeClient  # noqa: E402


class Census:
    """Patch invoke() once; measure named spans against it."""

    def __init__(self) -> None:
        self.ops: collections.Counter = collections.Counter()
        self.n = 0
        original = CodeModeClient.invoke

        def counting(client, operation, *a, **kw):
            self.n += 1
            self.ops[operation] += 1
            return original(client, operation, *a, **kw)

        CodeModeClient.invoke = counting
        self._original = original

    def restore(self) -> None:
        CodeModeClient.invoke = self._original

    def span(self, label: str):
        return _Span(self, label)


class _Span:
    def __init__(self, census: Census, label: str) -> None:
        self.c, self.label = census, label

    def __enter__(self):
        self.n0 = self.c.n
        self.ops0 = self.c.ops.copy()
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        ms = (time.perf_counter() - self.t0) * 1000
        used = self.c.ops - self.ops0
        detail = " ".join(f"{k}x{v}" if v > 1 else k
                          for k, v in sorted(used.items(), key=lambda kv: -kv[1]))
        print(f"  {self.label:<34} {self.c.n - self.n0:>3} calls  {ms:7.1f}ms   {detail}")
        return False


async def main() -> int:
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "targets/bash")
    async with staged(binary, lambda p: IdaTui(open_path=p, keepalive=False),
                      prefix="idatui-census-") as target:
        app = IdaTui(open_path=target, keepalive=False)
        census = Census()
        try:
            async with app.run_test(size=(140, 44)) as pilot:
                for _ in range(200):
                    if getattr(app, "_cur", None) is not None:
                        break
                    await pilot.pause(0.05)
                print(f"\n# {os.path.basename(binary)} — backend calls per action\n")

                # THE BACKGROUND GROWER MUST FINISH FIRST.
                #
                # ListingView._grow streams the WHOLE segment in 500-head pages
                # on a worker thread, so it lands calls continuously no matter
                # what the user is doing. Measuring an action while it runs
                # attributes its traffic to that action -- every span comes out
                # at a near-identical "~1 call per 10ms of pause", which says
                # nothing about the action. Drain it, report it as its own line,
                # then measure against a quiet backend.
                def listing_done() -> bool:
                    try:
                        m = app.query_one(ListingView).model
                    except Exception:
                        return False
                    return m is not None and m.complete

                with census.span("boot: stream the whole segment"):
                    for _ in range(2000):
                        if listing_done():
                            break
                        await pilot.pause(0.05)
                    await pilot.pause(0.4)
                drained = listing_done()
                print(f"  {'(grower finished: ' + str(drained) + ')':<34}\n"
                      f"  -- everything below is on a QUIET backend --\n")

                with census.span("scroll one page (pagedown)"):
                    await pilot.press("pagedown")
                    await pilot.pause(0.2)

                with census.span("scroll 20 pages"):
                    for _ in range(20):
                        await pilot.press("pagedown")
                    await pilot.pause(0.5)

                with census.span("switch to pseudocode (tab)"):
                    await pilot.press("tab")
                    await pilot.pause(0.6)

                with census.span("cursor down x30 in pseudocode"):
                    for _ in range(30):
                        await pilot.press("down")
                    await pilot.pause(0.3)

                with census.span("open graph (space)"):
                    await pilot.press("space")
                    await pilot.pause(0.8)

                with census.span("open symbol palette (ctrl+n)"):
                    await pilot.press("ctrl+n")
                    await pilot.pause(0.4)

                with census.span("type 5 chars into the palette"):
                    for ch in "write":
                        await pilot.press(ch)
                    await pilot.pause(0.4)
                await pilot.press("escape")
                await pilot.pause(0.2)

                with census.span("hex view (backslash)"):
                    await pilot.press("backslash")
                    await pilot.pause(0.5)

                with census.span("scroll hex 10 pages"):
                    for _ in range(10):
                        await pilot.press("pagedown")
                    await pilot.pause(0.4)

                print(f"\n  {'TOTAL':<34} {census.n:>3} calls")
                top = ", ".join(f"{k}x{v}" for k, v in census.ops.most_common(6))
                print(f"  most-used ops: {top}\n")
        finally:
            census.restore()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
