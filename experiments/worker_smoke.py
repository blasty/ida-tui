"""Runnable read-path smoke: drives the REAL domain.Program through WorkerClient
(our idalib worker over a unix socket). Run when idalib can spawn:
    ~/ida-venv/bin/python experiments/worker_smoke.py
"""
import os, sys, shutil, time
REPO=os.path.expanduser("~/dev/ida-tui-maybe"); sys.path.insert(0, REPO); os.chdir(REPO)
# fresh copy so the worker's idalib doesn't fight any running server
src=f"{REPO}/targets/echo"; tmp="/tmp/echo_worker"
shutil.copy(src, tmp)
for e in ".i64 .id0 .id1 .id2 .nam .til".split(): 
    try: os.remove(tmp+e)
    except OSError: pass

from idatui.worker_client import WorkerClient
from idatui.domain import Program

print("spawning worker + opening echo…", flush=True)
t=time.time()
cl=WorkerClient(tmp)
cl.connect(progress=lambda m: None)
print(f"  worker ready in {time.time()-t:.2f}s  session={cl.resolve_db()}", flush=True)
prog=Program(cl)

# --- drive the REAL domain layer through the worker (read path) ---
main=prog.resolve("main")
print("resolve('main') =", hex(main), flush=True)

idx=prog.functions(); idx.load_all()
print("functions() ->", len(idx), "funcs", flush=True)

fn=prog.function_of(main)
print("function_of(main) ->", fn.name, hex(fn.addr), "size", fn.size, flush=True)

b=prog.read_bytes(main, 16)
print("read_bytes(main,16) ->", b.hex(), flush=True)

lm=prog.listing(main)
for _ in range(3): lm.load_next_page()
rows=[lm.get(i) for i in range(min(6,len(lm)))]
print("listing() first rows:", flush=True)
for h in rows:
    if h: print("   ", hex(h.ea), h.kind, repr(h.text[:44]), flush=True)

d=prog.decompile(main)
print("decompile(main) -> failed?", d.failed, "lines:", len((d.code or '').splitlines()), flush=True)

regs=prog.file_regions()
print("file_regions ->", len(regs), "segments", flush=True)

# xrefs to a called function
callee=next((f.addr for f in idx.all_loaded() if f.name.startswith("sub_")), None)
if callee:
    xr=prog.xrefs_to(callee)
    print("xrefs_to(", hex(callee), ") ->", len(xr), "refs", flush=True)

ok = (fn.name=="main" and len(idx)>100 and b and not d.failed and len(regs)>0)
print("VERDICT:", "OK — domain.Program runs unchanged on the worker" if ok else "FAIL", flush=True)
cl.close()
