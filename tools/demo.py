#!/usr/bin/env python3
"""Drive ida-tui through a feature tour, for a screen recording.

Everything here goes through the same RPC layer an agent uses, so the semantic
verbs type into the real prompts character by character -- which is the whole
point for a recording: it looks like someone using it, because it is the app
being used.

    # simplest: it spawns its own pane on a scratch copy and cleans up after
    python tools/demo.py --spawn

    # or record a session you set up yourself (your pane, your size, your zoom)
    ./ida-tui /path/to/bash --rpc /tmp/ida.sock
    python tools/demo.py --sock /tmp/ida.sock

    python tools/demo.py --list                 # the beats, without running
    python tools/demo.py --sock S --speed 0.5   # half the pauses (rehearsal)
    python tools/demo.py --sock S --only graph,split

Edits (rename/comment) are reverted at the end, so the tour is repeatable and
a scratch database is not left renamed. --spawn works on a COPY of the target
so the tracked .i64 is never touched at all.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.rpcclient import RpcClient  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.path.join(REPO, "targets", "bash")

#: Typing speed for the prompts, ms per character. The app's own default is 35;
#: a little slower reads better on video without dragging.
TYPE_MS = 45


class Demo:
    """A sequence of beats against one live TUI."""

    def __init__(self, client: RpcClient, speed: float = 1.0, quiet: bool = False):
        self.c = client
        self.speed = speed
        self.quiet = quiet
        self.undo: list[tuple[str, dict]] = []

    # -- pacing ------------------------------------------------------------ #
    def beat(self, seconds: float = 1.0) -> None:
        """Let the viewer read. Scaled by --speed."""
        time.sleep(max(0.0, seconds * self.speed))

    def say(self, text: str) -> None:
        if not self.quiet:
            print(f"  \033[36m{text}\033[0m", flush=True)

    def do(self, method: str, **params):
        """One RPC call. Failures are reported and skipped, never fatal: a demo
        that dies halfway through a take is worse than one that misses a beat."""
        try:
            return self.c.call(method, **params)
        except Exception as exc:  # noqa: BLE001
            print(f"  \033[31m! {method}: {exc}\033[0m", file=sys.stderr, flush=True)
            return None

    # -- scenes ------------------------------------------------------------ #
    def scene_open(self):
        """Land on a real function and show the listing."""
        self.say("goto main")
        self.do("goto", target="main", delay_ms=TYPE_MS)
        self.beat(1.5)
        self.say("scroll the listing")
        self.do("move", dir="down", n=12)
        self.beat(0.8)
        self.do("move", dir="pagedown")
        self.beat(1.0)
        self.do("move", dir="top")
        self.beat(0.8)

    def scene_pseudocode(self):
        """Hex-Rays, and back."""
        self.say("F5 -> pseudocode")
        self.do("toggle_view")
        self.beat(2.0)
        self.do("move", dir="down", n=8)
        self.beat(1.2)
        self.say("back to the listing")
        self.do("toggle_view")
        self.beat(1.0)

    def scene_opfmt(self):
        """The literal-format ring, IDA's `o`."""
        self.say("cycle a literal's format (o)")
        shown = self.do("opfmt", mode="show")
        if shown is None:
            return
        for fmt in ("dec", "hex", "bin", "default"):
            self.do("opfmt", mode=fmt)
            self.beat(0.9)

    def scene_follow(self):
        """Follow a call and come back."""
        self.say("follow a call, then Escape back")
        self.do("follow")
        self.beat(1.8)
        self.do("back")
        self.beat(1.0)

    def scene_graph(self):
        """The CFG: zoom, minimap, walking edges."""
        self.say("space -> control-flow graph")
        self.do("graph", action="open")
        self.beat(2.2)
        self.say("zoom levels")
        for _ in range(2):
            self.do("keys", keys=["z"])
            self.beat(1.1)
        self.say("minimap")
        self.do("keys", keys=["m"])
        self.beat(1.2)
        self.say("walk the edges")
        for _ in range(3):
            self.do("keys", keys=["J"])
            self.beat(0.7)
        self.do("keys", keys=["m"])
        self.do("graph", action="close")
        self.beat(1.0)

    def scene_split(self):
        """Listing and pseudocode, cursor-synced."""
        self.say("s -> split view, cursor-synced")
        self.do("keys", keys=["s"])
        self.beat(2.2)
        for _ in range(6):
            self.do("move", dir="down", n=2)
            self.beat(0.5)
        self.do("keys", keys=["s"])
        self.beat(1.0)

    def scene_xrefs(self):
        """Who calls this."""
        self.say("x -> xrefs")
        self.do("xrefs")
        self.beat(2.0)
        self.do("close")
        self.beat(0.8)

    def scene_edit(self):
        """Rename and comment -- typed into the real prompts, then reverted."""
        fn = self.do("functions", filter="sub_", limit=1) or []
        target = fn[0] if isinstance(fn, list) and fn else None
        if not target:
            self.say("(no sub_ function to rename; skipping)")
            return
        name, ea = target.get("name"), target.get("ea")
        self.say(f"rename {name} -> demo_dispatch")
        self.do("goto", target=name, delay_ms=TYPE_MS)
        self.beat(0.8)
        self.do("rename", name="demo_dispatch", delay_ms=TYPE_MS)
        self.undo.append(("rename", {"addr": ea, "name": name}))
        self.beat(1.8)
        self.say("comment the line")
        self.do("comment", text="reached from the command dispatcher")
        self.undo.append(("comment", {}))
        self.beat(2.0)

    def scene_browsers(self):
        """Strings, symbols, structs, hex."""
        self.say('" -> strings')
        self.do("keys", keys=["quotation_mark"])
        self.beat(2.0)
        self.do("close")
        self.beat(0.6)

        self.say("ctrl+n -> symbol palette")
        self.do("symbols", query="exec")
        self.beat(2.0)
        self.do("close")
        self.beat(0.6)

        self.say("ctrl+t -> structs")
        self.do("structs")
        self.beat(2.0)
        self.do("close")
        self.beat(0.6)

        self.say("\\ -> hex view")
        self.do("hex")
        self.beat(2.0)
        self.do("hex")
        self.beat(0.8)

    def scene_search(self):
        """Incremental search in the code view."""
        self.say("/ -> search")
        self.do("search", term="call")
        self.beat(1.8)
        self.do("close")
        self.beat(0.8)

    # -- cleanup ----------------------------------------------------------- #
    def revert(self):
        """Undo the demo's edits so the take is repeatable."""
        for kind, args in reversed(self.undo):
            if kind == "rename" and args.get("addr") is not None:
                self.do("rename_many",
                        items=[{"addr": hex(args["addr"]), "name": args["name"]}])
            elif kind == "comment":
                self.do("comment", text="")
        # Re-navigate so the view shows the reverted name: the nav entry caches
        # the name it was opened with, so without this a recording ends on a
        # screen still showing the demo's rename.
        if self.undo:
            self.do("goto", target="main")
        self.undo.clear()


SCENES = [
    ("open", Demo.scene_open),
    ("pseudocode", Demo.scene_pseudocode),
    ("opfmt", Demo.scene_opfmt),
    ("follow", Demo.scene_follow),
    ("graph", Demo.scene_graph),
    ("split", Demo.scene_split),
    ("xrefs", Demo.scene_xrefs),
    ("edit", Demo.scene_edit),
    ("browsers", Demo.scene_browsers),
    ("search", Demo.scene_search),
]


def spawn_pane(target: str) -> tuple[str, str, str]:
    """Spawn a TUI pane on a COPY of ``target``. Returns (sock, pane, tmpdir)."""
    import json
    tmp = tempfile.mkdtemp(prefix="idatui-demo-")
    copy = os.path.join(tmp, os.path.basename(target))
    shutil.copy2(target, copy)
    for suffix in (".i64",):                       # reuse the analysis if present
        if os.path.exists(target + suffix):
            shutil.copy2(target + suffix, copy + suffix)
    out = subprocess.run(
        [sys.executable, "-m", "idatui.pane", "spawn", "--open", copy],
        cwd=REPO, capture_output=True, text=True, check=True).stdout
    row = json.loads(out)
    return row["sock"], row.get("pane", ""), tmp


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sock", help="RPC socket of a running TUI (see --rpc)")
    ap.add_argument("--spawn", action="store_true",
                    help="spawn a pane on a scratch copy, then tear it down")
    ap.add_argument("--target", default=DEFAULT_TARGET, help="binary for --spawn")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="pause multiplier; 0.5 = twice as fast (default 1.0)")
    ap.add_argument("--only", help="comma-separated scene names")
    ap.add_argument("--list", action="store_true", help="list scenes and exit")
    ap.add_argument("--no-revert", action="store_true",
                    help="keep the demo's rename/comment")
    ap.add_argument("--quiet", action="store_true", help="no operator narration")
    args = ap.parse_args(argv)

    if args.list:
        for name, fn in SCENES:
            print(f"  {name:12s} {(fn.__doc__ or '').splitlines()[0]}")
        return 0

    sock, pane, tmp = args.sock, "", ""
    if args.spawn:
        if not os.path.isfile(args.target):
            print(f"no such binary: {args.target}", file=sys.stderr)
            return 2
        print(f"spawning a pane on a copy of {os.path.basename(args.target)}…")
        sock, pane, tmp = spawn_pane(args.target)
        print(f"  sock={sock} pane={pane}")
    if not sock:
        ap.error("pass --sock <path> or --spawn")

    wanted = set(args.only.split(",")) if args.only else None
    scenes = [(n, f) for n, f in SCENES if wanted is None or n in wanted]

    rc = 0
    try:
        with RpcClient(sock) as client:
            ready = client.call("ping")
            if not ready.get("complete"):
                print("  waiting for the function index…", flush=True)
                for _ in range(600):
                    if client.call("ping").get("complete"):
                        break
                    time.sleep(0.5)
            demo = Demo(client, speed=args.speed, quiet=args.quiet)
            print(f"\n\033[1m-- ida-tui demo, {len(scenes)} scenes --\033[0m\n")
            for name, fn in scenes:
                print(f"\033[1m[{name}]\033[0m", flush=True)
                fn(demo)
            if not args.no_revert:
                print("\033[1m[revert]\033[0m", flush=True)
                demo.revert()
            print("\ndone.")
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        rc = 130
    except Exception as exc:  # noqa: BLE001
        print(f"demo failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        rc = 1
    finally:
        if args.spawn and sock:
            subprocess.run([sys.executable, "-m", "idatui.pane", "stop",
                            "--sock", sock], cwd=REPO, capture_output=True)
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
