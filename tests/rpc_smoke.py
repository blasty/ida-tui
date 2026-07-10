#!/usr/bin/env python3
"""End-to-end smoke test for the RPC server, in-process over a real unix socket.

    ~/ida-venv/bin/python tests/rpc_smoke.py --db <session_id>

Boots the TUI headless with --rpc on a temp socket, connects a JSONL client over
that socket (same loop), and exercises the raw + introspection primitives.
"""
import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.app import IdaTui  # noqa: E402
from idatui.client import DEFAULT_URL  # noqa: E402
from idatui._sync import wait_for  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


class Conn:
    """Tiny JSONL client over a unix socket."""
    def __init__(self, r, w):
        self.r, self.w = r, w
        self._id = 0

    async def call(self, method, **params):
        self._id += 1
        self.w.write(json.dumps({"id": self._id, "method": method,
                                 "params": params}).encode() + b"\n")
        await self.w.drain()
        line = await self.r.readline()
        return json.loads(line.decode())


async def run(db):
    sock = os.path.join(tempfile.gettempdir(), f"idatui-rpc-{os.getpid()}.sock")
    url = os.environ.get("IDA_MCP_URL", DEFAULT_URL)
    app = IdaTui(url=url, db=db, keepalive=False, rpc_path=sock)
    async with app.run_test(size=(140, 44)) as pilot:
        # boot: functions loaded + socket up
        await wait_for(lambda: app.query_one("#func-table", DataTable).row_count > 0,
                       pilot.pause, 60)
        await wait_for(lambda: os.path.exists(sock), pilot.pause, 20)
        if app._func_index is not None and not app._func_index.complete:
            app._func_index.load_all()

        r, w = await asyncio.open_unix_connection(sock)
        c = Conn(r, w)

        resp = await c.call("ping")
        check("ping returns proto", resp.get("result", {}).get("proto") == 1, str(resp))

        resp = await c.call("functions", limit=5)
        funcs = resp.get("result", [])
        check("functions lists entries", isinstance(funcs, list) and len(funcs) > 0,
              str(resp)[:120])

        resp = await c.call("state")
        st = resp.get("result", {})
        check("state has an active view", st.get("active") in ("decomp", "disasm", "hex"),
              str(st)[:120])

        # drive it like a user: goto a function by name via raw keys
        target = next((f for f in funcs if f["name"] == "main"), funcs[0])
        keys = ["g"] + list(target["name"]) + ["enter"]
        resp = await c.call("keys", keys=keys)
        st = resp.get("result", {})
        check("keys(goto) navigates to the function",
              st.get("function", {}).get("name") == target["name"],
              f"got {st.get('function')}")

        resp = await c.call("view", lines=6)
        v = resp.get("result", {})
        check("view returns visible lines with a cursor",
              isinstance(v.get("lines"), list) and any(l.get("cur") for l in v["lines"]),
              str(v)[:120])

        resp = await c.call("screen")
        scr = resp.get("result", {})
        check("screen returns a text grid",
              isinstance(scr.get("text"), str) and target["name"] in scr["text"],
              f"len={len(scr.get('text','')) if scr else 0}")

        # raw text primitive into the goto input, then escape out
        from textual.widgets import Input
        await c.call("keys", keys=["g"])
        await c.call("text", text="sub_", settle=False)
        val = app.query_one("#goto", Input).value
        check("text primitive types into the focused input", val == "sub_", f"val={val!r}")
        await c.call("keys", keys=["escape"])

        w.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


def main(argv):
    db = None
    it = iter(argv)
    for a in it:
        if a == "--db":
            db = next(it)
    return asyncio.run(run(db))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
