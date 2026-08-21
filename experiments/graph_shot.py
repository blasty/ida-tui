"""Render the graph view headless at a chosen size and print it.

    ~/ida-venv/bin/python experiments/graph_shot.py [func] [cols] [rows] [zoom] [engine]

The pane a person runs this in is usually too small to judge the layout, and the
pilot lays out synchronously at whatever size you ask for -- so this is the way
to actually look at the thing.
"""

import asyncio
import os
import shutil
import sys

REPO = os.path.expanduser("~/dev/ida-tui-maybe")
sys.path.insert(0, REPO)
os.chdir(REPO)

func = sys.argv[1] if len(sys.argv) > 1 else "sub_2297"
cols = int(sys.argv[2]) if len(sys.argv) > 2 else 170
rows = int(sys.argv[3]) if len(sys.argv) > 3 else 55
zoom = int(sys.argv[4]) if len(sys.argv) > 4 else 0
engine = sys.argv[5] if len(sys.argv) > 5 else None

src, tmp = f"{REPO}/targets/echo", "/tmp/echo_shot"
shutil.copy(src, tmp)
for e in ".i64 .id0 .id1 .id2 .nam .til".split():
    try:
        os.remove(tmp + e)
    except OSError:
        pass

from idatui._sync import wait_for  # noqa: E402
from idatui.app import GraphView, IdaTui  # noqa: E402
from idatui.rpc import screen_text  # noqa: E402


async def main() -> None:
    app = IdaTui(tmp, keepalive=False)
    async with app.run_test(size=(cols, rows)) as pilot:
        await wait_for(
            lambda: app.program is not None and app._cur is not None, pilot.pause, 120
        )
        ea = app.program.resolve(func)
        fn = app.program.function_of(ea)
        app._open_function(fn.addr, fn.name)
        await wait_for(
            lambda: app._cur is not None and app._cur.ea == fn.addr, pilot.pause, 60
        )
        await pilot.pause(0.2)
        await pilot.press("space")
        gv = app.query_one(GraphView)
        if engine:
            gv._engine = engine
            gv._relayout()
            app._graph_status()
        ok = await wait_for(
            lambda: app._active == "graph" and gv.lay is not None, pilot.pause, 90
        )
        if not ok:
            print("graph never opened:", app.query_one("#status").render())
            return
        for _ in range(zoom):
            await pilot.press("z")
            await pilot.pause(0.2)
        await pilot.pause(0.4)
        print(screen_text(app)["text"])
        print()
        print("status:", app.query_one("#status").render())
        print(
            "stats :",
            gv.lay.stats,
            "canvas",
            f"{gv.lay.width}x{gv.lay.height}",
            "zoom",
            gv.ZOOMS[gv._zoom],
        )
        app._save_on_exit = False


asyncio.run(main())
