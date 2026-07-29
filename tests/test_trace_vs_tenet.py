#!/usr/bin/env python3
"""Differential test: our trace reader vs Tenet's own.

We wrote our own reader rather than vendoring 3700 lines of packing and mask
compression we don't need. That is only defensible if "our own" doesn't quietly
mean "different", so every answer we give is checked against the reference
implementation on real traces.

Needs ~/dev/tenet/tenet-original (reference) and a trace to compare on; both are
skipped-with-a-message rather than failed if absent, since neither is part of
this repo.

    python3 tests/test_trace_vs_tenet.py [trace.0.log ...]
"""
import os
import random
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.trace import Trace  # noqa: E402

TENET = os.path.expanduser("~/dev/tenet/tenet-original/plugins")
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def _reference():
    """Tenet's TraceReader, with its disassembler dependency stubbed out."""
    sys.path.insert(0, TENET)
    log = types.ModuleType("tenet.util.log")
    log.pmsg = lambda *a, **k: None
    import tenet  # noqa: F401
    import tenet.util  # noqa: F401
    sys.modules["tenet.util.log"] = log
    from tenet.trace.arch import ArchAMD64
    from tenet.trace.reader import TraceReader

    class FakeDctx:
        # The reference only touches the disassembler to guess an ASLR slide.
        # An EMPTY list crashes its analysis (indexes [0] unguarded), so hand it
        # one address that matches nothing: no slide is found and both readers
        # stay in raw trace addresses, which is what we want to compare.
        def get_instruction_addresses(self):
            return [0xDEAD0000]
    return TraceReader, ArchAMD64, FakeDctx


def _truth(path, reg, idx):
    """The register's value at ``idx`` read straight out of the text.

    Slow (re-reads the file) and only used to settle a disagreement, which is
    exactly when being slow and obviously-correct is what you want.
    """
    reg = reg.lower()
    last = None
    with open(path) as f:
        for i, line in enumerate(f):
            if i > idx:
                break
            for part in line.strip().split(","):
                k, _, v = part.partition("=")
                if k.strip().lower() == reg:
                    try:
                        last = int(v, 16)
                    except ValueError:
                        pass
    return last


def compare(path, ref_cls, arch, dctx, samples=200):
    TraceReader, ArchAMD64, FakeDctx = ref_cls, arch, dctx
    ours = Trace.load(path)
    theirs = TraceReader(path, ArchAMD64(), FakeDctx())
    name = os.path.basename(path)

    check(f"{name}: same length",
          ours.length == theirs.trace.length,
          f"{ours.length} vs {theirs.trace.length}")
    n = min(ours.length, theirs.trace.length)
    if not n:
        return

    rnd = random.Random(1234)
    idxs = sorted({0, n - 1, n // 2} | {rnd.randrange(n) for _ in range(samples)})

    bad = [i for i in idxs if ours.raw_ip(i) != theirs.get_ip(i)]
    check(f"{name}: same PC at every sampled timestamp", not bad,
          f"first mismatch at {bad[:1]}")

    # Register reconstruction is the part that is easy to get subtly wrong: a
    # delta belongs to the line that CAUSED it, and an off-by-one here silently
    # shifts every value by one instruction.
    #
    # Where the two disagree, ARBITRATE with the text rather than assume the
    # reference is right. It isn't always: a register written on the last line
    # of a 65535-line segment is missing from the next segment's base state, so
    # the reference returns a stale value until that register is written again
    # (measured: wrong for all 179 timestamps of one such window). Blanket
    # "must agree" would have made us copy that bug to stay green.
    regs = [r.upper() for r in ours.registers if r not in ("rip",)][:8]
    ours_wrong, ref_wrong = [], []
    for i in idxs:
        for r in regs:
            mine, ref = ours.register(r, i), theirs.get_register(r, i)
            if mine == ref:
                continue
            true = _truth(path, r, i)
            (ours_wrong if mine != true else ref_wrong).append((i, r, mine, ref, true))
    check(f"{name}: register state matches the trace text everywhere",
          not ours_wrong, f"{ours_wrong[:3]}")
    if ref_wrong:
        print(f"       (reference disagrees at {len(ref_wrong)} sampled points; "
              f"the text backs us, e.g. idx {ref_wrong[0][0]} {ref_wrong[0][1]})")

    # Execution queries: what painting is built on.
    hot = sorted(ours.by_ip, key=lambda a: -len(ours.by_ip[a]))[:5]
    ex_bad = []
    for ea in hot:
        mine = list(ours.executions(ea))
        ref = list(theirs.get_executions(ea))
        if mine != ref:
            ex_bad.append((hex(ea), len(mine), len(ref)))
    check(f"{name}: same execution timestamps for the hottest addresses",
          not ex_bad, f"{ex_bad[:3]}")

    # Memory STATE at a timestamp — reconstructed from the deltas, which is the
    # hard part and the whole point of reading memory from a trace.
    mem_bad, mem_checked = [], 0
    for i in idxs[::4]:
        for op in ours.memory_ops(i)[:2]:
            n = min(len(op.data), 8)
            mine, known = ours.memory(op.addr, n, i)
            ref = theirs.get_memory(op.addr, n, i)
            if ref is None:
                continue
            refb = bytes(ref.data)
            # Compare only the bytes we claim to know; the reference reports its
            # own coverage separately and a byte neither has seen is not a
            # disagreement.
            for j in range(n):
                if known[j] and refb[j:j + 1] and mine[j] != refb[j]:
                    mem_bad.append((i, hex(op.addr + j), mine[j], refb[j]))
            mem_checked += 1
    check(f"{name}: memory state at a timestamp matches the reference",
          not mem_bad, f"{mem_bad[:3]}")

    # Memory: the bytes an instruction touched, and which way.
    with_mem = [i for i in idxs if ours.memory_ops(i)][:40]
    mem_bad = []
    for i in with_mem:
        for op in ours.memory_ops(i):
            ref = theirs.get_memory(op.addr, len(op.data), i + 1) if op.write else None
            if ref is not None and bytes(ref.data) != op.data:
                mem_bad.append((i, hex(op.addr), op.data.hex(), bytes(ref.data).hex()))
    check(f"{name}: written bytes match the reference's memory state",
          not mem_bad, f"{mem_bad[:2]}")
    print(f"       ({ours.length:,} instructions, {len(idxs)} sampled, "
          f"{len(with_mem)} with memory)")


def main(argv):
    if not os.path.isdir(TENET):
        print(f"  skip: reference not found at {TENET}")
        return 0
    traces = argv or [p for p in ("/tmp/echotrace.0.log", "/tmp/big.0.log")
                      if os.path.exists(p)]
    if not traces:
        print("  skip: no traces to compare (pass one, or run tenet-trace first)")
        return 0
    ref = _reference()
    for path in traces:
        compare(path, *ref)
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
