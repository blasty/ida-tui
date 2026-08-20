"""Exercise the real domain.Program through an IDA Nexus lease.

A matching registered GUI is reused; otherwise IDA Nexus starts a managed
idalib worker. Usage: ``uv run python experiments/worker_smoke.py FILE``.
"""
from __future__ import annotations

import os
import sys
import time

from idatui.nexus_client import NexusClient
from idatui.domain import Program


def main() -> int:
    target = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "experiments/fibonacci.elf")
    print(f"attaching IDA Nexus to {target}…", flush=True)
    started = time.time()
    client = NexusClient(target)
    client.connect(progress=lambda message: print(f"  {message}", flush=True))
    print(
        f"  ready in {time.time() - started:.2f}s; backend={client.backend}; "
        f"session={client.resolve_db()}",
        flush=True,
    )
    program = Program(client)
    try:
        index = program.functions()
        index.load_all()
        print(f"functions() -> {len(index)}", flush=True)
        first = index.get(0)
        if first is None:
            print("VERDICT: FAIL — no functions", flush=True)
            return 1
        fn = program.function_of(first.addr)
        data = program.read_bytes(first.addr, 16)
        decompilation = program.decompile(first.addr)
        print(f"function_of() -> {fn}", flush=True)
        print(f"read_bytes() -> {data.hex()}", flush=True)
        print(
            f"decompile() -> failed={decompilation.failed}; "
            f"lines={len((decompilation.code or '').splitlines())}",
            flush=True,
        )
        print(f"file_regions() -> {len(program.file_regions())}", flush=True)
        ok = fn is not None and bool(data) and bool(program.file_regions())
        print(f"VERDICT: {'OK' if ok else 'FAIL'}", flush=True)
        return 0 if ok else 1
    finally:
        program.close()
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
