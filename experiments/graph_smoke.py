"""End-to-end smoke for the graph path: the `flowchart` tool -> domain ->
idatui.graph layout, through a real idalib worker.

    ~/ida-venv/bin/python experiments/graph_smoke.py [funcname]

Wants: VERDICT: OK
"""
import os
import shutil
import sys
import time

REPO = os.path.expanduser("~/dev/ida-tui-maybe")
sys.path.insert(0, REPO)
os.chdir(REPO)

src, tmp = f"{REPO}/targets/echo", "/tmp/echo_graph"
shutil.copy(src, tmp)
for e in ".i64 .id0 .id1 .id2 .nam .til".split():
    try:
        os.remove(tmp + e)
    except OSError:
        pass

from idatui.worker_client import WorkerClient   # noqa: E402
from idatui.domain import Program               # noqa: E402
from idatui import graph as G                   # noqa: E402

want = sys.argv[1] if len(sys.argv) > 1 else "main"
print("spawning worker + opening echo\u2026", flush=True)
t = time.time()
cl = WorkerClient(tmp)
cl.connect(progress=lambda m: None)
print(f"  worker ready in {time.time()-t:.2f}s", flush=True)
prog = Program(cl)

ok = True
ea = prog.resolve(want)
print(f"resolve({want!r}) = {ea:#x}", flush=True)

t = time.time()
fc = prog.flowchart(ea)
print(f"flowchart() -> {time.time()-t:.2f}s", flush=True)
if fc is None:
    print("VERDICT: FAIL (no flowchart)")
    raise SystemExit(1)

print(f"  {fc.name} @ {fc.func_ea:#x}: {len(fc.blocks)} blocks, entry={fc.entry}")
nrows = sum(len(b.rows) for b in fc.blocks)
print(f"  {nrows} listing rows attached")
ok &= nrows > 0
if not nrows:
    print("  !! no rows attached to any block")

empty = [b for b in fc.blocks if not b.rows]
if empty:
    ok = False
    print(f"  !! {len(empty)} blocks have NO rows, e.g. "
          f"{[hex(b.start) for b in empty[:4]]}")

b0 = fc.blocks[fc.entry]
print(f"  entry block {b0.start:#x}-{b0.end:#x}:")
for h in b0.rows[:5]:
    tags = ",".join(k for k, _ in (h.spans or ()))[:40]
    print(f"    {h.ea:#010x} {h.kind:<7} {h.text[:42]!r}  spans[{tags}]")
ok &= any(h.spans for b in fc.blocks for h in b.rows)
if not any(h.spans for b in fc.blocks for h in b.rows):
    print("  !! no colour spans came through \u2014 highlighting would be dead")

# rows must tile the block exactly, or boxes will have holes
for b in fc.blocks:
    eas = [h.ea for h in b.rows]
    if eas and (min(eas) < b.start or max(eas) >= b.end):
        ok = False
        print(f"  !! block {b.start:#x} has rows outside its range")

blocks = [G.Block(id=b.id, start=b.start, end=b.end, succs=list(b.succs))
          for b in fc.blocks]


def sizer(b):
    src_b = fc.blocks[b.id]
    w = max([len(f"loc_{b.start:X}")]
            + [len(h.text) + 12 for h in src_b.rows]) + 4
    return (w, len(src_b.rows) + 3)


t = time.time()
lay = G.layout(blocks, sizer, entry=fc.entry)
print(f"layout() -> {(time.time()-t)*1000:.0f} ms  {lay.stats}", flush=True)
print(f"  canvas {lay.width}x{lay.height}")
ok &= len(lay.nodes) == len(blocks)

# every block must be reachable in the drawing, and rows must index it
covered = {n.id for r in range(lay.height) for n in lay.nodes_at_row(r)}
ok &= covered == {b.id for b in blocks}
if covered != {b.id for b in blocks}:
    print(f"  !! row index misses {sorted({b.id for b in blocks} - covered)[:5]}")

hits = sum(1 for r in range(min(lay.height, 400))
           if lay.painting.cells_at_row(r, 0, lay.width))
print(f"  {hits} of the first {min(lay.height,400)} rows carry edge cells")
ok &= hits > 0

cl.close()
print("VERDICT:", "OK" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
