"""Settle/wait helpers shared by the pilot tests and the live RPC driver.

The single source of truth for "the UI has finished reacting to what I just did".
Both the headless test harness and the in-process RPC server need the exact same
guarantee before they read state back, so it lives here once.

Two yield strategies feed the same poll loop: under a Pilot (tests) we yield with
``pilot.pause`` (which also drains the screen); live (RPC) we yield with
``asyncio.sleep`` and drain explicitly via a throwaway ``Pilot(app)``.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

from textual.pilot import Pilot


async def wait_for(
    pred: Callable[[], bool],
    tick: Callable[[float], Awaitable[None]],
    timeout: float = 20.0,
    step: float = 0.02,
) -> bool:
    """Poll ``pred`` until true or ``timeout`` elapses.

    ``tick(step)`` yields control between polls: ``pilot.pause`` in tests,
    ``asyncio.sleep`` in the live app. Returns whether ``pred`` became true.
    """
    waited = 0.0
    while waited < timeout:
        if pred():
            return True
        await tick(step)
        waited += step
    return False


async def drain(app, timeout: float = 15.0) -> None:
    """Wait for the message pump and every widget to process queued events.

    Reuses Textual's own ``Pilot._wait_for_screen`` (it only needs ``app``), so
    it works against a live app with no real Pilot attached.
    """
    try:
        await Pilot(app)._wait_for_screen(timeout=timeout)
    except Exception:  # noqa: BLE001 — best-effort; never let settle explode
        pass


async def workers_idle(app, timeout: float = 20.0) -> None:
    """Wait (bounded) for all threaded ``@work`` workers to finish.

    Safe because the app has no perpetual Textual workers — the keepalive is a
    client-side thread, not a worker. A timeout guards against a wedged worker.
    """
    try:
        await asyncio.wait_for(app.workers.wait_for_complete(), timeout)
    except Exception:  # noqa: BLE001 — timeout or manager churn; fall through
        pass


async def settle(
    app,
    pred: Optional[Callable[[], bool]] = None,
    *,
    timeout: float = 20.0,
    step: float = 0.02,
    rounds: int = 3,
) -> bool:
    """Block until the app is quiescent, then optionally until ``pred`` holds.

    A round = drain the pump, wait for workers, repeat — because a completing
    worker can post a message that spawns the next worker (nav -> decompile).
    With a ``pred`` (the reliable signal, e.g. ``dec.loaded_ea == ea``) we return
    as soon as it holds; without one we return once no workers remain.
    """
    for _ in range(max(1, rounds)):
        await drain(app, min(timeout, 15.0))
        await workers_idle(app, timeout)
        if pred is not None:
            if pred():
                await drain(app, min(timeout, 15.0))
                return True
        elif len(app.workers) == 0:
            await drain(app, min(timeout, 15.0))
            return True
    await drain(app, min(timeout, 15.0))
    if pred is not None:
        return await wait_for(pred, asyncio.sleep, timeout, step)
    return True
