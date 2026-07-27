#!/usr/bin/env python3
"""Trace model: parsing, queries, and lining a trace up with the database.

Pure stdlib — no IDA, no trace files needed. The differential test
(test_trace_vs_tenet.py) checks our answers against Tenet's on real traces;
this one covers what the reference can't arbitrate: the set-shaped queries
painting needs, and rebasing.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.trace import Trace  # noqa: E402

PASS = FAIL = 0

GPR = ["rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi"]
FULL = ",".join(f"{r}=0x{0x1000 if r == 'rsp' else 0:x}" for r in GPR)

# push rbp / mov rbp,rsp / mov [rbp-4],0x2a / mov eax,[rbp-4] / pop rbp / jmp back
LINES = [
    FULL + ",rip=0x401000",
    "rsp=0xff8,rip=0x401001,mw=0xff8:0000000000000000",
    "rbp=0xff8,rip=0x401004",
    "rip=0x40100b,mw=0xff4:2a000000",
    "rax=0x2a,rip=0x40100e,mr=0xff4:2a000000",
    "rbp=0x0,rsp=0x1000,rip=0x401010,mr=0xff8:0000000000000000",
    "rip=0x401000",          # loop back: 0x401000 executes twice
    "rip=0x401001",
]


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.0.log")
        with open(path, "w") as f:
            f.write("\n".join(LINES) + "\n")
        with open(os.path.join(tmp, "t.info"), "w") as f:
            f.write("arch=x86_64\nmode=user\nstart_code=0x401000\n")
        t = Trace.load(path)

        check("every line is one timestamp", t.length == len(LINES), f"{t.length}")
        check("the sidecar .info is picked up",
              t.info is not None and t.info.arch == "x86_64" and
              t.info.start_code == 0x401000)
        check("PC is tracked per timestamp",
              [t.ip(i) for i in range(6)] ==
              [0x401000, 0x401001, 0x401004, 0x40100b, 0x40100e, 0x401010])

        # -- register reconstruction --------------------------------------- #
        check("a register keeps its value until it changes",
              t.register("rsp", 0) == 0x1000 and t.register("rsp", 1) == 0xff8
              and t.register("rsp", 4) == 0xff8 and t.register("rsp", 5) == 0x1000)
        check("the full first line seeds every register",
              t.register("rbx", 3) == 0)
        check("an unknown register is None, not 0",
              t.register("r15", 0) is None)
        check("changed() is what the INSTRUCTION did, not the state",
              t.changed(4) == {"rax", "rip"}, f"{t.changed(4)}")

        # "which instruction set this register?" — the question a trace exists
        # to answer.
        check("last_write finds the instruction that set a value",
              t.last_write("rax", 5) == 4 and t.last_write("rbp", 4) == 2,
              f"{t.last_write('rax', 5)}, {t.last_write('rbp', 4)}")
        check("next_write looks forward",
              t.next_write("rbp", 2) == 5 and t.next_write("rbp", 5) is None)

        # -- memory --------------------------------------------------------- #
        ops = t.memory_ops(3)
        check("a write is captured with its bytes",
              len(ops) == 1 and ops[0].write and ops[0].addr == 0xff4
              and ops[0].data == bytes.fromhex("2a000000"), f"{ops}")
        check("a read is captured and marked as a read",
              [o.write for o in t.memory_ops(4)] == [False])
        check("an instruction with no memory has none", t.memory_ops(2) == [])

        # -- execution queries: what painting is built on -------------------- #
        check("executions lists every timestamp for an address",
              list(t.executions(0x401000)) == [0, 6], f"{list(t.executions(0x401000))}")
        check("a never-executed address has none", not len(t.executions(0xdead)))
        check("executions_between windows the result",
              t.executions_between(0x401000, 1, 7) == [6])
        check("next/prev execution step between hits",
              t.next_execution(0x401000, 0) == 6
              and t.prev_execution(0x401000, 6) == 0
              and t.next_execution(0x401000, 6) is None)

        # A pseudocode line covers MANY addresses, so the set form is the one
        # decompiler painting will call — per-address lookups would mean one
        # dict hit per instruction per repaint.
        check("hits() counts a whole set of addresses at once",
              t.hits([0x401000, 0x401001, 0x401004, 0xdead]) ==
              {0x401000: 2, 0x401001: 2, 0x401004: 1},
              f"{t.hits([0x401000, 0x401001, 0x401004, 0xdead])}")

        # -- rebasing -------------------------------------------------------- #
        # A traced process is relocated; nothing lines up until the slide is
        # found. Page offsets survive relocation, which is what makes it
        # findable.
        db = [0x1000 + (a - 0x401000) for a in
              (0x401000, 0x401001, 0x401004, 0x40100b, 0x40100e, 0x401010)]
        slide = t.rebase(db)
        check("the slide between trace and database is found",
              slide == 0x1000 - 0x401000, f"{slide:#x}")
        t.apply_slide(slide)
        check("addresses come back in database terms",
              t.ip(0) == 0x1000 and list(t.executions(0x1000)) == [0, 6],
              f"{t.ip(0):#x}")
        check("memory addresses are slid too",
              t.memory_ops(3)[0].addr == 0xff4 + slide)
        check("raw_ip still gives the traced address",
              t.raw_ip(0) == 0x401000)

        t2 = Trace.load(path)
        # Page offsets that appear nowhere in the trace. (0xdead0000/0xdead0004
        # would NOT do: they sit at the same offsets as two traced addresses and
        # so legitimately agree on a slide — a reminder that this matches on
        # offsets, not on addresses looking plausible.)
        check("no match means no slide, not a wrong one",
              t2.rebase([0xdead0555, 0xbeef0777]) == 0,
              f"{t2.rebase([0xdead0555, 0xbeef0777]):#x}")
        check("one lone agreeing address is not enough to claim a slide",
              t2.rebase([0x1000]) == 0, f"{t2.rebase([0x1000]):#x}")
        check("an empty database is harmless", t2.rebase([]) == 0)

        # -- robustness ------------------------------------------------------ #
        p2 = os.path.join(tmp, "odd.0.log")
        with open(p2, "w") as f:
            f.write("\n".join([
                FULL + ",rip=0x401000",
                "",                              # blank line
                "rax=0xnothex,rip=0x401001",     # unparseable value
                "rbx=0x1",                       # no PC at all
                "rip=0x401002,mw=0x10:zz",       # unparseable memory
            ]) + "\n")
        t3 = Trace.load(p2)
        check("a malformed trace loads instead of raising", t3.length == 4,
              f"{t3.length}")
        check("a line with no PC inherits the previous one",
              t3.ip(2) == 0x401001, f"{t3.ip(2):#x}")
        check("an unparseable memory entry is dropped, not fatal",
              t3.memory_ops(3) == [])

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
