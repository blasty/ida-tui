"""Reading Tenet execution traces.

A Tenet trace is a line-per-instruction delta log::

    rax=0x3c,rbx=0x0,...,rip=0x7ffff6faaae0      # full state on the first line
    rip=0x7ffff6faaae4                           # then only what changed
    r9=0x7ffff6762e60,rip=0x7ffff6faaae9,mw=0x7ffff6f9b7c8:08c177f6ff7f0000

Registers that changed, the PC on every line, and every memory access *with its
bytes*. That is enough to reconstruct any register or any memory address at any
point in time, forwards or backwards, which is the whole trick.

This is our own reader, not a port. The reference implementation
(``~/dev/tenet/tenet-original/plugins/tenet/trace/``) packs the trace into
segments with compressed address/mask tables, which earns its keep for its Qt
timeline; we need different queries and would rather own the ~400 lines than
inherit 3700. It is differential-tested against that implementation
(``tests/test_trace_vs_tenet.py``) so "our own" doesn't quietly mean "different".

The index is built around the query the UI actually asks, which the reference
answers one address at a time: **which timestamps executed this set of
addresses**. A listing row is one address, but a pseudocode line covers many, so
``by_ip`` maps address -> timestamps and set queries are unions of those.
"""

from __future__ import annotations

import array
import bisect
import os
import re
from dataclasses import dataclass, field

#: Tenet packs its register delta into a uint32, so a trace arch may name at
#: most 32 registers. Ours is discovered from the trace instead of declared,
#: but the cap is worth knowing when a trace looks short of registers.
MAX_REGISTERS = 32

_MEM_RE = re.compile(r"^m(r|w|rw)$")


@dataclass
class TraceInfo:
    """The sidecar ``<prefix>.info`` written by our QEMU tracer.

    Optional: a trace from another tracer has none, and everything here can be
    recovered or guessed from the log itself.
    """

    arch: str = ""
    mode: str = ""
    binary: str = ""
    start_code: int = 0
    end_code: int = 0
    entry_code: int = 0
    traced: str = ""

    @classmethod
    def load(cls, path: str) -> "TraceInfo | None":
        try:
            with open(path) as f:
                raw = dict(
                    ln.strip().split("=", 1) for ln in f if "=" in ln)
        except OSError:
            return None
        def num(k):
            try:
                return int(raw.get(k, "0"), 0)
            except ValueError:
                return 0
        return cls(arch=raw.get("arch", ""), mode=raw.get("mode", ""),
                   binary=raw.get("binary", ""), start_code=num("start_code"),
                   end_code=num("end_code"), entry_code=num("entry_code"),
                   traced=raw.get("traced", ""))


@dataclass
class MemOp:
    """One memory access made by one instruction."""

    addr: int
    data: bytes
    write: bool

    @property
    def end(self) -> int:
        return self.addr + len(self.data)


@dataclass
class Trace:
    """An indexed Tenet trace.

    Timestamps are indices into the executed-instruction sequence: 0 is the
    first instruction, ``length - 1`` the last.
    """

    path: str = ""
    info: TraceInfo | None = None
    #: PC per timestamp.
    ips: array.array = field(default_factory=lambda: array.array("Q"))
    #: name -> (timestamps of change, value at each change). A register's value
    #: at time t is the last change at or before t; the first line carries a
    #: full state dump, so every register has an entry at 0.
    reg_at: dict[str, tuple[array.array, array.array]] = field(default_factory=dict)
    #: address -> timestamps that executed it (ascending, by construction).
    by_ip: dict[int, array.array] = field(default_factory=dict)
    #: memory accesses, parallel arrays indexed by access number.
    mem_idx: array.array = field(default_factory=lambda: array.array("I"))
    mem_addr: array.array = field(default_factory=lambda: array.array("Q"))
    mem_write: bytearray = field(default_factory=bytearray)
    mem_off: array.array = field(default_factory=lambda: array.array("Q"))
    mem_len: array.array = field(default_factory=lambda: array.array("H"))
    mem_blob: bytearray = field(default_factory=bytearray)
    #: first access number of each timestamp, plus a final sentinel.
    mem_row: array.array = field(default_factory=lambda: array.array("I"))
    #: applied so trace addresses line up with the database (see ``rebase``).
    slide: int = 0

    # -- construction ------------------------------------------------------ #
    @classmethod
    def load(cls, path: str, progress=None, limit: int = 0) -> "Trace":
        """Parse a text trace. ``progress(lines)`` is called every 50k lines."""
        t = cls(path=os.path.abspath(path))
        base = path[:-6] if path.endswith(".0.log") else os.path.splitext(path)[0]
        t.info = TraceInfo.load(base + ".info")
        regs: dict[str, tuple[array.array, array.array]] = {}
        ips, by_ip = t.ips, t.by_ip
        n = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ip = None
                t.mem_row.append(len(t.mem_idx))
                for part in line.split(","):
                    key, _, val = part.partition("=")
                    if not val:
                        continue
                    key = key.strip().lower()
                    if _MEM_RE.match(key):
                        addr_s, _, data_s = val.partition(":")
                        try:
                            addr = int(addr_s, 16)
                            data = bytes.fromhex(data_s)
                        except ValueError:
                            continue
                        # 'mrw' is one access that both reads and writes; record
                        # the write, which is what the memory state follows.
                        t.mem_idx.append(n)
                        t.mem_addr.append(addr)
                        t.mem_write.append(0 if key == "mr" else 1)
                        t.mem_off.append(len(t.mem_blob))
                        t.mem_len.append(len(data))
                        t.mem_blob += data
                        continue
                    try:
                        v = int(val, 16)
                    except ValueError:
                        continue
                    slot = regs.get(key)
                    if slot is None:
                        slot = regs[key] = (array.array("I"), array.array("Q"))
                    slot[0].append(n)
                    slot[1].append(v)
                    ip = v if key in ("rip", "eip", "pc") else ip
                if ip is None:
                    # No PC on this line: the format says always emit it, and
                    # without it the line cannot be placed. Carry the previous
                    # one rather than dropping the instruction.
                    ip = ips[-1] if ips else 0
                ips.append(ip)
                where = by_ip.get(ip)
                if where is None:
                    where = by_ip[ip] = array.array("I")
                where.append(n)
                n += 1
                if progress is not None and n % 50000 == 0:
                    progress(n)
                if limit and n >= limit:
                    break
        t.mem_row.append(len(t.mem_idx))
        t.reg_at = regs
        return t

    # -- basics ------------------------------------------------------------ #
    def __len__(self) -> int:
        return len(self.ips)

    @property
    def length(self) -> int:
        return len(self.ips)

    @property
    def registers(self) -> list[str]:
        """Register names in the trace, PC last (the order tracers emit)."""
        return sorted(self.reg_at, key=lambda r: (r in ("rip", "eip", "pc"), r))

    @property
    def pc_name(self) -> str:
        for n in ("rip", "eip", "pc"):
            if n in self.reg_at:
                return n
        return ""

    def ip(self, idx: int) -> int:
        """PC at ``idx``, in DATABASE addresses (slide applied)."""
        return self.ips[idx] + self.slide

    def raw_ip(self, idx: int) -> int:
        return self.ips[idx]

    # -- register state ----------------------------------------------------- #
    def register(self, name: str, idx: int) -> int | None:
        """Value of ``name`` at ``idx``, or None if the trace never set it."""
        slot = self.reg_at.get(name.lower())
        if slot is None:
            return None
        idxs, vals = slot
        i = bisect.bisect_right(idxs, idx) - 1
        return vals[i] if i >= 0 else None

    def register_state(self, idx: int) -> dict[str, int]:
        return {n: v for n in self.reg_at
                if (v := self.register(n, idx)) is not None}

    def changed(self, idx: int) -> set[str]:
        """Registers written BY the instruction at ``idx`` (what the line said).

        Used to highlight what an instruction actually did, which is the reason
        a delta trace is readable at all.
        """
        out = set()
        for n, (idxs, _vals) in self.reg_at.items():
            i = bisect.bisect_left(idxs, idx)
            if i < len(idxs) and idxs[i] == idx:
                out.add(n)
        return out

    def last_write(self, name: str, idx: int) -> int | None:
        """Timestamp of the write that produced ``name``'s value at ``idx``.

        "Which instruction set this register?" — the question that motivates a
        trace explorer in the first place.
        """
        slot = self.reg_at.get(name.lower())
        if slot is None:
            return None
        i = bisect.bisect_right(slot[0], idx) - 1
        return slot[0][i] if i >= 0 else None

    def next_write(self, name: str, idx: int) -> int | None:
        slot = self.reg_at.get(name.lower())
        if slot is None:
            return None
        i = bisect.bisect_right(slot[0], idx)
        return slot[0][i] if i < len(slot[0]) else None

    # -- memory ------------------------------------------------------------- #
    def memory_ops(self, idx: int) -> list[MemOp]:
        """Accesses made by the instruction at ``idx``."""
        if not (0 <= idx < len(self.mem_row) - 1):
            return []
        lo, hi = self.mem_row[idx], self.mem_row[idx + 1]
        out = []
        for k in range(lo, hi):
            off, ln = self.mem_off[k], self.mem_len[k]
            out.append(MemOp(addr=self.mem_addr[k] + self.slide,
                             data=bytes(self.mem_blob[off:off + ln]),
                             write=bool(self.mem_write[k])))
        return out

    # -- execution queries (what painting is built on) ---------------------- #
    def executions(self, ea: int) -> array.array:
        """Every timestamp that executed ``ea`` (database address)."""
        return self.by_ip.get(ea - self.slide, array.array("I"))

    def executions_between(self, ea: int, lo: int, hi: int) -> list[int]:
        ts = self.executions(ea)
        a = bisect.bisect_left(ts, lo)
        b = bisect.bisect_right(ts, hi)
        return list(ts[a:b])

    def hits(self, eas) -> dict[int, int]:
        """{address: execution count} for a set of addresses.

        The set form is the point: painting a listing row needs one address, but
        a pseudocode line covers many, and asking per-address would mean a
        lookup per instruction per repaint.
        """
        out = {}
        for ea in eas:
            ts = self.by_ip.get(ea - self.slide)
            if ts:
                out[ea] = len(ts)
        return out

    def first_execution(self, ea: int) -> int | None:
        ts = self.executions(ea)
        return ts[0] if ts else None

    def next_execution(self, ea: int, idx: int) -> int | None:
        ts = self.executions(ea)
        i = bisect.bisect_right(ts, idx)
        return ts[i] if i < len(ts) else None

    def prev_execution(self, ea: int, idx: int) -> int | None:
        ts = self.executions(ea)
        i = bisect.bisect_left(ts, idx) - 1
        return ts[i] if i >= 0 else None

    # -- lining the trace up with the database ------------------------------ #
    def rebase(self, db_addresses) -> int:
        """Find the slide between trace addresses and database addresses.

        A traced process is relocated (ASLR, or a PIE base the database doesn't
        share): our echo trace runs at 0x7ffff6faa000 while the database has the
        same code at 0x2490. Nothing lines up until this is solved, so it is not
        optional.

        Page offsets survive relocation — only whole pages move — so the low 12
        bits of an instruction address are invariant. Bucket the database's
        addresses by those bits, and for each trace address the candidate slides
        are the differences to database addresses in its bucket. The slide that
        the most instructions agree on wins.
        """
        buckets: dict[int, list[int]] = {}
        for a in db_addresses:
            buckets.setdefault(a & 0xFFF, []).append(a)
        if not buckets:
            return 0
        votes: dict[int, int] = {}
        # A sample is enough and keeps this O(1)-ish on a 10M trace; unique
        # addresses, because a hot loop shouldn't outvote the rest of the code.
        for ea in list(self.by_ip)[:4096]:
            for cand in buckets.get(ea & 0xFFF, ()):
                votes[cand - ea] = votes.get(cand - ea, 0) + 1
        if not votes:
            return 0
        best, n = max(votes.items(), key=lambda kv: kv[1])
        return best if n > 1 else 0

    def apply_slide(self, slide: int) -> None:
        self.slide = int(slide)
