"""Profile the CLIENT half of streaming a segment.

`profile_remote.py` profiles inside the database process. This one profiles the
other side: unpickling a page, building Heads and maintaining the model's
indexes. Once the backend got cheap that half became the majority of boot, and
nothing else here can see it.

    PYTHONPATH=. ~/ida-venv/bin/python experiments/profile_client.py [BINARY] [--pages N]

Time spent in `invoke` is the backend + transport; everything below it in the
`tottime` list is ours and is what this file is for.
"""

from __future__ import annotations

import argparse
import cProfile
import io
import os
import pstats
import time

from idatui import remote_ops
from idatui.nexus_client import NexusClient
from idatui.domain import Program


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?", default="targets/bash")
    ap.add_argument("--pages", type=int, default=60)
    ap.add_argument("--lines", type=int, default=16)
    ap.add_argument(
        "--text", action="store_true", help="load full pages instead of skeletons"
    )
    args = ap.parse_args()

    client = NexusClient(os.path.abspath(args.binary))
    client.connect()
    program = Program(client)
    regions = client.call(remote_ops.file_regions)
    rows = regions.get("regions") or regions.get("result") or []
    text_seg = next((r for r in rows if ".text" in str(r.get("name", ""))), rows[0])
    model = program.listing(int(str(text_seg["start"]), 16))
    assert model is not None
    model.load_next_page()  # prime one page, and install the remote lib

    want_text = bool(args.text)
    pr = cProfile.Profile()
    started = time.perf_counter()
    pr.enable()
    loaded = 0
    for _ in range(args.pages):
        if model.complete:
            break
        n = model.load_next_page(text=want_text)
        if n == 0:
            break
        loaded += 1
    pr.disable()
    wall = (time.perf_counter() - started) * 1000

    print(
        f"# {os.path.basename(args.binary)}  pages={loaded}  "
        f"text={want_text}  {wall:.0f}ms  ({wall / max(loaded, 1):.2f}ms/page)"
    )
    buf = io.StringIO()
    pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(args.lines)
    print(buf.getvalue())
    program.close()
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
