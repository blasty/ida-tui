"""Time a realistic idatui operation mix against whatever ida-nexus is installed.

The companion to `bench_pack_trace.py`: that one isolates a single workaround,
this one answers "how much faster is the whole client, on real operations".

**It deliberately does not import anything version-specific**, so the SAME file
can measure an OLD idatui checkout (with its `sys.settrace` strip and packing
workarounds) and the current one. To compare across versions, copy it somewhere
outside the repo first -- `git checkout` of an older commit would otherwise
replace or delete it::

    cp experiments/bench_ops.py /tmp/
    # C: current client, current library
    PYTHONPATH=. ~/ida-venv/bin/python /tmp/bench_ops.py

    # B: current client against the OLD library (shows what the workarounds were for)
    git -C ~/dev/ida-nexus checkout 4195f21
    PYTHONPATH=. ~/ida-venv/bin/python /tmp/bench_ops.py

    # A: the client as it SHIPPED on the old library, workarounds and all
    git checkout 8550474          # the commit before the workaround removal
    PYTHONPATH=. ~/ida-venv/bin/python /tmp/bench_ops.py

    git checkout main && git -C ~/dev/ida-nexus checkout main   # ALWAYS restore

ida-nexus is installed **editable** into both venvs, so checking that repo out
swaps the backend under the TUI with no reinstall -- which is what makes this A/B
cheap.
"""

from __future__ import annotations

import argparse
import os
import statistics
import time

from idatui import remote_ops
from idatui.nexus_client import NexusClient


def bench(fn, reps: int) -> tuple[float, float]:
    """Best-of and median wall time in ms; best-of resists co-tenant noise."""
    samples = []
    for _ in range(reps):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000.0)
    return min(samples), statistics.median(samples)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default="targets/bash")
    ap.add_argument("--reps", type=int, default=20)
    args = ap.parse_args()

    client = NexusClient(os.path.abspath(args.target))
    client.connect()
    handle = client._handle

    # Work on the biggest function we can find, so the payload-heavy operations
    # are actually payload-heavy.
    index = client.call(remote_ops.list_funcs, queries=[{"offset": 0, "count": 60}])
    funcs = (index.get("result") or [{}])[0].get("data") or []
    if not funcs:
        print("VERDICT: FAIL - no functions")
        return 1
    big = max(funcs, key=lambda f: f.get("size") or 0)
    ea = big["addr"] if isinstance(big["addr"], str) else hex(big["addr"])

    ops = [
        # Synthetic: isolates the per-operation floor (execute_sync marshalling).
        ("empty round trip", lambda: handle.execute_python("result = 1")),
        # Payload-dominated: what _PACK_EPILOGUE was written for.
        (
            "list_funcs 500",
            lambda: client.call(
                remote_ops.list_funcs, queries=[{"offset": 0, "count": 500}]
            ),
        ),
        (
            "heads 200 (listing page)",
            lambda: client.call(remote_ops.heads, addr=ea, count=200, annotate=True),
        ),
        # IDA-work-dominated: Hex-Rays, nothing upstream can move.
        ("decompile (warm)", lambda: client.call(remote_ops.decompile, addr=ea)),
        ("flowchart (graph)", lambda: client.call(remote_ops.flowchart, addr=ea)),
        # Round-trip-dominated: small payload, so only the floor matters.
        (
            "xrefs_to",
            lambda: client.call(remote_ops.xref_query, direction="to", addr=ea),
        ),
    ]

    print(
        f"# target={os.path.basename(args.target)} func={ea} reps={args.reps} "
        f"backend={client.backend}"
    )
    results = {}
    for name, fn in ops:
        try:
            for _ in range(3):  # warm caches; the first sample is always an outlier
                fn()
            best, med = bench(fn, args.reps)
            results[name] = med
            print(f"{name:28} best {best:8.3f}ms   median {med:8.3f}ms")
        except Exception as exc:  # one broken op must not lose the other five
            print(f"{name:28} FAILED: {type(exc).__name__}: {str(exc)[:60]}")
    client.close()
    print("RESULT " + ";".join(f"{k}={v:.3f}" for k, v in results.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
