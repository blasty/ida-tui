#!/usr/bin/env python
"""Count what the splash actually SENDS to the terminal.

Pushes a real LoadingScreen onto a bare Textual app with kitty graphics forced
on and kittygfx._write captured, then drives it the way the app does (a status
write per progress tick) and tallies the escapes.

    PYTHONPATH=. ~/ida-venv/bin/python experiments/splash_place_count.py
"""
from __future__ import annotations

import asyncio
import os
import re
import sys

os.environ["IDATUI_KITTY"] = "1"

from textual.app import App, ComposeResult          # noqa: E402
from textual.widgets import Static                  # noqa: E402

from idatui import kittygfx                         # noqa: E402

SENT: list[str] = []


def _fake_write(data: str) -> bool:
    SENT.append(data)
    return True


kittygfx._write = _fake_write            # type: ignore[assignment]
kittygfx._cell = (9, 22)

from idatui.app import LoadingScreen     # noqa: E402


def tally() -> dict[str, int]:
    blob = "".join(SENT)
    return {
        "uploads (a=t)": len(re.findall(r"\x1b_G[^;]*a=t", blob)),
        "placements (a=p)": len(re.findall(r"\x1b_G[^;]*a=p", blob)),
        "deletes (a=d)": len(re.findall(r"\x1b_G[^;]*a=d", blob)),
        "bytes": len(blob),
    }


class Host(App):
    CSS = "#loading-box { width: 70; height: auto; }"

    def compose(self) -> ComposeResult:
        yield Static("host")


async def main() -> None:
    ticks = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    app = Host()
    async with app.run_test(size=(100, 45)) as pilot:
        screen = LoadingScreen("target")
        app.push_screen(screen)
        await pilot.pause()
        await pilot.pause()
        print(f"image mode: {screen._image}")
        after_mount = tally()
        print("after mount:", after_mount)

        # what the app does: _status() -> loading_screen.update_note(), once
        # per progress write. Spread over ~4s of wall clock like a real load.
        for i in range(ticks):
            screen.update_note(f"analyzing… {i}")
            await asyncio.sleep(0.1)
            await pilot.pause()
        print(f"after {ticks} progress notes:", tally())

        screen.dismiss()
        await pilot.pause()
        print("after dismiss:", tally())

    d = tally()
    blob = "".join(SENT)
    cmds = re.findall(r"\x1b_G([^;\x1b]*)", blob)
    ids = {dict(kv.split("=", 1) for kv in c.split(",") if "=" in kv).get("p")
           for c in cmds if "a=p" in c.split(",")}
    onscreen = "unbounded (anonymous)" if None in ids else len(ids)
    print()
    print(f"=> {d['placements (a=p)']} place escapes sent, "
          f"{d['deletes (a=d)']} deletes")
    print(f"   images actually on screen: {onscreen}")
    print("   A placement is identified by (image id, placement id). An a=p with")
    print("   no p= key is ANONYMOUS and stacks a fresh copy every time; with a")
    print("   p= key the terminal replaces the previous one. logo.png is RGBA, so")
    print("   stacking also composites its soft edges towards solid.")
    m = re.search(r"\x1b_G(a=p[^;\x1b]*)", blob)
    print("   placement escape:", m.group(1) if m else "(none)")


asyncio.run(main())
