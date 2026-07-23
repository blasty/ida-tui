"""Domain / paging layer: address-centric models over the raw MCP client.

This is where the "millions of lines" problem is solved, so the TUI widgets only
ever see a viewport-sized slice. Every hard-won constraint from
``docs/PAGING_FINDINGS.md`` is encoded here:

* Per-call caps are silent (over the cap the server returns 10, not a clamp), so
  we clamp page sizes ourselves: ``LIST_PAGE`` / ``DISASM_BLOCK`` <= the caps.
* ``next_offset`` is unreliable; we paginate by advancing ``len(data)``.
* ``disasm offset=N`` is O(N) with no resumable cursor, so windowed disassembly
  is **block-cached** (revisits are free) and **prefetches** the next block on a
  background thread (the client is concurrency-safe).
* ``include_total`` scans the whole function (~200ms on monsters); totals are
  fetched once and cached.
* ``decompile`` can hard-fail on huge functions as a *soft* error (``code`` is
  null); that is surfaced as data, not an exception.

Everything here is synchronous and thread-safe. The TUI runs these calls from
Textual worker threads; the internal prefetch pool is separate and small.
"""

from __future__ import annotations

import bisect
import json
import re
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Callable

from .client import IDAClient, IDAToolError

# Clamps derived from measured caps (list ~700, disasm ~500). Margin included.
LIST_PAGE = 500
DISASM_BLOCK = 256  # instructions per cached/fetched block (<= disasm cap)
HEX_BLOCK = 16384   # bytes per cached/fetched hex block (compact read_raw -> cheap)
DECOMPILE_TIMEOUT = 15.0  # s; cap per decompile so a failing one can't hang the CLI

_TRUNC_RE = re.compile(r"\[(\d+) chars total\]\s*$")


# --------------------------------------------------------------------------- #
# Value models
# --------------------------------------------------------------------------- #
def _as_int(v) -> int:
    if isinstance(v, int):
        return v
    return int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v, 16)


@dataclass(frozen=True)
class Func:
    addr: int
    name: str
    size: int

    @classmethod
    def from_raw(cls, d: dict) -> "Func":
        addr = _as_int(d["addr"])
        name = d.get("name")
        # An unnamed function (server returns null/empty) must still have a
        # usable string name — synthesize IDA's sub_ADDR so every consumer
        # (palette, sort, rename prefill) can treat name as a str.
        if not name:
            name = f"sub_{addr:X}"
        return cls(addr=addr, name=name, size=_as_int(d.get("size", 0)))


@dataclass(frozen=True)
class Line:
    """One rendered disassembly line. ``ea`` is the instruction address."""

    ea: int
    text: str
    label: str | None = None
    raw: bytes | None = None  # opcode bytes; filled in by DisasmModel post-fetch

    @classmethod
    def from_raw(cls, d: dict) -> "Line":
        return cls(
            ea=_as_int(d["addr"]),
            text=d.get("instruction", ""),
            label=d.get("label"),
        )


@dataclass(frozen=True)
class Head:
    """One flat-listing item (from the ``heads`` server tool): a code
    instruction, a data item, or an undefined byte run."""

    ea: int
    kind: str            # 'code' | 'data' | 'unknown' | 'member'
    size: int
    text: str
    name: str | None = None
    raw: bytes | None = None  # opcode/item bytes (filled in for code by the model)

    @property
    def label(self) -> str | None:  # Line-compatible alias
        return self.name

    @classmethod
    def from_raw(cls, d: dict) -> "Head":
        return cls(
            ea=_as_int(d["ea"]),
            kind=d.get("kind", "unknown"),
            size=int(d.get("size", 0) or 0),
            text=d.get("text", ""),
            name=d.get("name"),
        )


@dataclass
class Ref:
    addr: int
    name: str
    string: str | None = None


@dataclass
class Xref:
    frm: int              # the referencing address
    to: int | None        # the referenced address
    type: str             # "code" | "data" | ...
    fn_name: str | None   # function containing `frm`
    fn_addr: int | None


@dataclass(frozen=True)
class LVar:
    name: str
    type: str
    is_arg: bool


@dataclass
class FuncTypes:
    addr: int
    name: str
    prototype: str        # e.g. 'int __fastcall foo(int a, char *b)'
    lvars: list[LVar]


@dataclass(frozen=True)
class Struct:
    name: str
    size: int
    is_union: bool
    members: int          # field count
    ordinal: int

    @classmethod
    def from_raw(cls, d: dict) -> "Struct":
        return cls(
            name=d.get("name", ""),
            size=int(d.get("size", 0) or 0),
            is_union=bool(d.get("is_union", False)),
            members=int(d.get("cardinality", 0) or 0),
            ordinal=int(d.get("ordinal", 0) or 0),
        )


@dataclass
class Decompilation:
    ea: int
    code: str | None
    failed: bool
    error: str | None
    truncated: bool
    total_chars: int | None
    refs: list[Ref] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Query-payload unwrapping (shape: {"result":[{"data":[...],"next_offset":N}]})
# --------------------------------------------------------------------------- #
def _query_data(payload) -> list:
    res = payload.get("result", payload) if isinstance(payload, dict) else payload
    if isinstance(res, list):
        res = res[0] if res else {}
    return res.get("data", []) if isinstance(res, dict) else []


# --------------------------------------------------------------------------- #
# Function index: lazy, clamped, cached, filterable
# --------------------------------------------------------------------------- #
class FunctionIndex:
    """A lazily-paginated, cached view of the function list.

    Loads pages of ``LIST_PAGE`` on demand, advancing by ``len(data)`` (never by
    ``next_offset``). A single index instance corresponds to one server-side
    ``filter`` glob (``None`` = all functions).
    """

    def __init__(self, program: "Program", filter: str | None = None):
        self._prog = program
        self.filter = filter
        self._funcs: list[Func] = []
        self._by_addr: dict[int, Func] = {}
        self._done = False
        self._lock = threading.Lock()

    def _load_next_page(self) -> int:
        with self._lock:
            if self._done:
                return 0
            offset = len(self._funcs)
        query: dict = {"offset": offset, "count": LIST_PAGE}
        if self.filter:
            query["filter"] = self.filter
        data = _query_data(self._prog.client.call("list_funcs", queries=[query]))
        added = 0
        with self._lock:
            for d in data:
                f = Func.from_raw(d)
                if f.addr not in self._by_addr:
                    self._by_addr[f.addr] = f
                    self._funcs.append(f)
                    added += 1
            if len(data) < LIST_PAGE:
                self._done = True
        return len(data)

    def load_next_page(self) -> int:
        """Load one more page; return the number of rows fetched (0 at end)."""
        return self._load_next_page()

    def ensure(self, n: int) -> None:
        """Ensure at least ``n`` functions are loaded (or all, if fewer exist)."""
        while not self._done and len(self._funcs) < n:
            if self._load_next_page() == 0:
                break

    def load_all(self, progress: Callable[[int], None] | None = None) -> None:
        """Fully enumerate (background-friendly). ~3s for 10k funcs."""
        while not self._done:
            self._load_next_page()
            if progress:
                progress(len(self._funcs))

    @property
    def complete(self) -> bool:
        return self._done

    def __len__(self) -> int:
        return len(self._funcs)

    def loaded(self) -> int:
        return len(self._funcs)

    def get(self, i: int) -> Func | None:
        self.ensure(i + 1)
        with self._lock:
            return self._funcs[i] if 0 <= i < len(self._funcs) else None

    def window(self, start: int, count: int) -> list[Func]:
        """Viewport slice ``[start, start+count)`` (loads as needed)."""
        self.ensure(start + count)
        with self._lock:
            return list(self._funcs[start : start + count])

    def by_addr(self, ea: int) -> Func | None:
        with self._lock:
            return self._by_addr.get(ea)

    def all_loaded(self) -> list[Func]:
        with self._lock:
            return list(self._funcs)

    def update_name(self, addr: int, new_name: str) -> None:
        """Reflect a rename in the cached index (Func is frozen -> replace)."""
        with self._lock:
            old = self._by_addr.get(addr)
            if old is None:
                return
            nf = Func(addr=old.addr, name=new_name, size=old.size)
            self._by_addr[addr] = nf
            try:
                self._funcs[self._funcs.index(old)] = nf
            except ValueError:
                pass


# --------------------------------------------------------------------------- #
# Disassembly model: block-cached windowed listing for ONE function
# --------------------------------------------------------------------------- #
class DisasmModel:
    """Windowed, block-cached disassembly of a single function.

    Because ``disasm offset=N`` is O(N) and uncacheable server-side, we fetch and
    cache fixed ``DISASM_BLOCK``-sized blocks; a viewport read slices from cached
    blocks and returns instantly on revisit. The block just past the viewport is
    prefetched on a background thread.
    """

    BLOCK = DISASM_BLOCK

    def __init__(self, program: "Program", ea: int, name: str | None = None):
        self._prog = program
        self.ea = ea
        self.name = name
        self._blocks: dict[int, list[Line]] = {}
        self._total: int | None = None
        self._ea_list: list[int] | None = None
        self._max_raw = 0            # widest opcode length seen (bytes)
        self._func_end: int | None = None
        self._func_end_done = False
        self._lock = threading.Lock()
        self._inflight: set[int] = set()

    def _end_kw(self) -> dict:
        end = self._function_end()
        return {"end": hex(end)} if end is not None else {}

    def total(self) -> int:
        """Instruction/row count of the function (fetched once). Uses disasm's
        ``include_total`` — one fast call, no response-size truncation. For a
        code function this equals the heads row count that backs the lines."""
        if self._total is not None:
            return self._total
        payload = self._prog.client.call(
            "disasm", addr=hex(self.ea), max_instructions=1, include_total=True
        )
        total = payload.get("total_instructions")
        if total is None:
            total = payload.get("instruction_count", 0)
        with self._lock:
            self._total = int(total)
        return self._total

    def _function_end(self) -> int | None:
        """End address (exclusive) of this function; used to size the final
        instruction's opcode bytes. Cached (one lookup per model)."""
        if self._func_end_done:
            return self._func_end
        end: int | None = None
        try:
            fn = self._prog.function_of(self.ea)
            if fn is not None:
                end = fn.addr + fn.size
        except Exception:  # noqa: BLE001 -- best-effort; falls back to a width guess
            end = None
        with self._lock:
            self._func_end = end
            self._func_end_done = True
        return end

    def _attach_bytes(self, lines: list[Line], end_ea: int | None) -> list[Line]:
        """Read the opcode bytes for ``lines`` in one request and slice them per
        instruction using consecutive addresses (variable-length safe)."""
        if not lines:
            return lines
        last_end = end_ea
        if last_end is None or last_end <= lines[-1].ea:
            last_end = lines[-1].ea + 15  # x86 max insn len; only the final line
        start = lines[0].ea
        data = self._prog.read_bytes(start, last_end - start)
        out: list[Line] = []
        biggest = 0
        for i, ln in enumerate(lines):
            nxt = lines[i + 1].ea if i + 1 < len(lines) else last_end
            length = max(nxt - ln.ea, 0)
            off = ln.ea - start
            b = bytes(data[off:off + length])
            biggest = max(biggest, len(b))
            out.append(replace(ln, raw=b))
        with self._lock:
            if biggest > self._max_raw:
                self._max_raw = biggest
        return out

    @staticmethod
    def _line_from_head(r: dict) -> Line:
        """Adapt a ``heads`` row to a disasm Line (label = the head's name)."""
        return Line(ea=_as_int(r["ea"]), text=r.get("text", ""),
                    label=r.get("name"))

    def _fetch_block(self, b: int) -> list[Line]:
        # The function disasm view is a listing filtered to the function: fetch a
        # block of heads (one per instruction for code). Over-fetch one row so
        # the block knows where its last instruction ends (opcode-byte sizing).
        payload = self._prog.client.call(
            "heads", addr=hex(self.ea), offset=b * self.BLOCK,
            count=self.BLOCK + 1, **self._end_kw(),
        )
        rows = payload.get("heads", []) if isinstance(payload, dict) else []
        fetched = [self._line_from_head(r) for r in rows]
        lines = fetched[:self.BLOCK]
        if len(fetched) > self.BLOCK:
            end_ea: int | None = fetched[self.BLOCK].ea
        else:  # this block ends the function
            end_ea = self._function_end()
        lines = self._attach_bytes(lines, end_ea)
        with self._lock:
            self._blocks[b] = lines
            self._inflight.discard(b)
        return lines

    def max_raw_len(self) -> int:
        """Widest opcode length (bytes) across the blocks fetched so far."""
        with self._lock:
            return self._max_raw

    def scan_bytes(self) -> int:
        """Fetch every block (populating opcode bytes) and return the widest
        instruction length across the whole function. Used to size the opcode
        column so its padding doesn't jump as the listing streams in."""
        total = self.total()
        off = 0
        while off < total:
            got = self.lines(off, self.BLOCK, prefetch=False)
            if not got:
                break
            off += len(got)
        return self.max_raw_len()

    def _get_block(self, b: int) -> list[Line]:
        with self._lock:
            hit = self._blocks.get(b)
        if hit is not None:
            return hit
        return self._fetch_block(b)

    def _prefetch_block(self, b: int) -> None:
        if b < 0:
            return
        with self._lock:
            if b in self._blocks or b in self._inflight:
                return
            self._inflight.add(b)
        self._prog.submit(self._fetch_block, b)

    def lines(self, start: int, count: int, prefetch: bool = True) -> list[Line]:
        """Return rendered lines for viewport ``[start, start+count)``."""
        if count <= 0 or start < 0:
            return []
        end = start + count
        b0, b1 = start // self.BLOCK, (end - 1) // self.BLOCK
        out: list[Line] = []
        for b in range(b0, b1 + 1):
            block = self._get_block(b)
            lo = start - b * self.BLOCK if b == b0 else 0
            hi = end - b * self.BLOCK if b == b1 else self.BLOCK
            out.extend(block[max(lo, 0):hi])
        if prefetch:
            self._prefetch_block(b1 + 1)  # forward scroll
            self._prefetch_block(b0 - 1)  # backward scroll
        return out

    def cached_line(self, idx: int) -> Line | None:
        """Non-blocking single-line peek: return the cached Line or None. Never
        touches the network — used by the virtualized view's render path."""
        if idx < 0:
            return None
        b = idx // self.BLOCK
        off = idx - b * self.BLOCK
        with self._lock:
            block = self._blocks.get(b)
        if block is None or off >= len(block):
            return None
        return block[off]

    def is_cached(self, start: int, count: int) -> bool:
        """True if every block covering [start, start+count) is already cached."""
        if count <= 0:
            return True
        b0, b1 = start // self.BLOCK, (start + count - 1) // self.BLOCK
        with self._lock:
            return all(b in self._blocks for b in range(b0, b1 + 1))

    def ensure_async(self, start: int, count: int) -> None:
        """Schedule background fetches for any missing blocks in the range
        (non-blocking). Safe to call every render."""
        if count <= 0:
            return
        b0, b1 = start // self.BLOCK, (start + count - 1) // self.BLOCK
        for b in range(b0, b1 + 1):
            self._prefetch_block(b)

    def cached_blocks(self) -> int:
        with self._lock:
            return len(self._blocks)

    def ensure_ea_index(self) -> list[int]:
        """Build (once) a sorted list of every line's ea, for ea->index lookup.
        Fetches the whole function; cached. Only needed for mid-function jumps."""
        if self._ea_list is not None:
            return self._ea_list
        total = self.total()
        eas: list[int] = []
        off = 0
        while off < total:
            lines = self.lines(off, self.BLOCK, prefetch=False)
            if not lines:
                break
            eas.extend(ln.ea for ln in lines)
            off += len(lines)
        with self._lock:
            self._ea_list = eas
        return eas

    def index_of_ea(self, ea: int) -> int:
        """Instruction index of the line at/containing ``ea`` (0 if before start)."""
        eas = self.ensure_ea_index()
        i = bisect.bisect_right(eas, ea) - 1
        return i if 0 <= i < len(eas) else 0

    def invalidate(self) -> None:
        with self._lock:
            self._blocks.clear()
            self._total = None
            self._ea_list = None
            self._max_raw = 0


# --------------------------------------------------------------------------- #
# Listing model: lazily-grown flat listing (code + data + undefined) per segment
# --------------------------------------------------------------------------- #
class ListingModel:
    """A flat, IDA-style disassembly *listing* over one segment: code, data and
    undefined heads interleaved, unlike ``DisasmModel`` (one function, code only).

    Backed by the injected ``heads`` server tool, which walks item heads and
    renders each via ``generate_disasm_line``. The segment is walked lazily in
    forward pages (``FunctionIndex`` style); line index == position in the walked
    head list. Random access to an address is O(distance-from-seg-start) the
    first time (then cached) — the same tradeoff as ``disasm offset=N``. Grows
    on demand as the viewport scrolls. Synchronous + thread-safe.
    """

    PAGE = 500  # heads per server call (well under the tool's 2000 cap)

    def __init__(self, program: "Program", seg_start: int, seg_end: int,
                 name: str | None = None):
        self._prog = program
        self.seg_start = seg_start
        self.seg_end = seg_end
        self.name = name or f"seg @ {seg_start:#x}"
        self._heads: list[Head] = []
        self._by_ea: dict[int, int] = {}
        self._next: int | None = seg_start  # next address to fetch from
        self._done = False
        self._max_raw = 0  # widest opcode length (bytes) seen, for the op column
        self._lock = threading.Lock()
        # Serializes page loads so a background grower and an in-view search can
        # both drive loading without double-fetching the same page.
        self._load_lock = threading.Lock()

    # Opcode bytes are only worth showing for code; cap the bulk read so a page
    # containing a huge coalesced undefined run doesn't pull megabytes.
    _OP_SPAN_CAP = 1 << 16

    def _attach_opcode_bytes(self, page: list[Head]) -> list[Head]:
        """Fill ``raw`` (opcode bytes) for the code heads in ``page`` via one
        bulk read over their extent (variable-length safe)."""
        code = [h for h in page if h.kind == "code" and h.size > 0]
        if not code:
            return page
        lo = code[0].ea
        hi = code[-1].ea + code[-1].size
        if hi - lo <= 0 or hi - lo > self._OP_SPAN_CAP:
            return page
        data = self._prog.read_bytes(lo, hi - lo)
        biggest = self._max_raw
        out = []
        for h in page:
            if h.kind == "code" and h.size > 0:
                off = h.ea - lo
                b = bytes(data[off:off + h.size])
                biggest = max(biggest, len(b))
                out.append(replace(h, raw=b))
            else:
                out.append(h)
        with self._lock:
            self._max_raw = biggest
        return out

    def max_raw_len(self) -> int:
        with self._lock:
            return self._max_raw

    def load_next_page(self) -> int:
        """Load one more page of heads; returns how many were added."""
        return self._load_next_page()

    def _load_next_page(self) -> int:
        with self._load_lock:
            return self._load_next_page_locked()

    def _load_next_page_locked(self) -> int:
        with self._lock:
            if self._done or self._next is None:
                return 0
            frm = self._next
        payload = self._prog.client.call("heads", addr=hex(frm), count=self.PAGE)
        rows = payload.get("heads", []) if isinstance(payload, dict) else []
        cur = payload.get("cursor", {}) if isinstance(payload, dict) else {}
        page = []
        for r in rows:
            try:
                page.append(Head.from_raw(r))
            except (KeyError, ValueError, TypeError):
                continue
        page = self._attach_opcode_bytes(page)
        with self._lock:
            base = len(self._heads)
            for i, h in enumerate(page):
                self._by_ea.setdefault(h.ea, base + i)
                self._heads.append(h)
            nxt = cur.get("next")
            if nxt is None:
                self._done = True
                self._next = None
            else:
                self._next = _as_int(nxt)
            return len(rows)

    def ensure(self, n: int) -> None:
        """Ensure at least ``n`` heads are loaded (or all, if fewer exist)."""
        while not self._done and len(self._heads) < n:
            if self._load_next_page() == 0:
                break

    def ensure_ea(self, ea: int) -> int:
        """Walk forward until the head containing ``ea`` is loaded; return its
        line index (or the nearest head at/after it), or -1 if past the end."""
        while True:
            idx = self.index_of_ea(ea)
            if idx >= 0:
                return idx
            with self._lock:
                have = len(self._heads)
                last_ea = self._heads[-1].ea if self._heads else -1
                done = self._done
            if done or (have and last_ea >= ea):
                # Loaded past ea without an exact head hit: return the first head
                # at/after ea (a mid-item address lands on its containing head).
                return self._first_at_or_after(ea)
            if self._load_next_page() == 0:
                return self._first_at_or_after(ea)

    def _first_at_or_after(self, ea: int) -> int:
        with self._lock:
            heads = self._heads
            for i, h in enumerate(heads):
                if h.ea <= ea < h.ea + max(h.size, 1):
                    return i
                if h.ea > ea:
                    return i
        return -1

    def load_all(self, progress: Callable[[int], None] | None = None) -> None:
        while not self._done:
            if self._load_next_page() == 0:
                break
            if progress:
                progress(len(self._heads))

    @property
    def complete(self) -> bool:
        with self._lock:
            return self._done

    def loaded(self) -> int:
        with self._lock:
            return len(self._heads)

    def __len__(self) -> int:
        return self.loaded()

    def get(self, i: int) -> Head | None:
        with self._lock:
            return self._heads[i] if 0 <= i < len(self._heads) else None

    def window(self, start: int, count: int) -> list[Head]:
        self.ensure(start + count)
        with self._lock:
            return list(self._heads[start:start + count])

    def index_of_ea(self, ea: int) -> int:
        with self._lock:
            return self._by_ea.get(ea, -1)

    # -- DisasmModel-compatible accessors (unified model) ------------------ #
    def cached_line(self, idx: int) -> Head | None:
        """Alias of get() for the disasm view's Line interface."""
        return self.get(idx)

    def lines(self, start: int, count: int, prefetch: bool = True) -> list[Head]:
        return self.window(start, count)

    def is_cached(self, start: int, count: int) -> bool:
        with self._lock:
            return start + count <= len(self._heads)

    def ensure_async(self, start: int, count: int) -> None:
        pass  # the background grower streams the rest in; nothing to prefetch


# --------------------------------------------------------------------------- #
# Hex model: block-cached byte view over the loaded image (VA-addressed)
# --------------------------------------------------------------------------- #
class HexModel:
    """Windowed, block-cached raw bytes of the loaded image, addressed by virtual
    address. Format-agnostic: the range/segments come from IDA, not from any
    file header. Gaps between segments read back as zeros."""

    BLOCK = HEX_BLOCK

    def __init__(self, program: "Program", start: int, end: int):
        self._prog = program
        self.start = start
        self.end = end
        self.size = max(end - start, 0)
        self._blocks: dict[int, bytes] = {}
        self._lock = threading.Lock()
        self._inflight: set[int] = set()

    def total_rows(self) -> int:
        return (self.size + 15) // 16

    def file_offset(self, va: int) -> int | None:
        return self._prog.file_offset(va)

    def _fetch_block(self, b: int) -> bytes:
        addr = self.start + b * self.BLOCK
        n = min(self.BLOCK, self.end - addr)
        data = self._prog.read_bytes(addr, n) if n > 0 else b""
        with self._lock:
            self._blocks[b] = data
            self._inflight.discard(b)
        return data

    def _prefetch(self, b: int) -> None:
        if b < 0 or b * self.BLOCK >= self.size:
            return
        with self._lock:
            if b in self._blocks or b in self._inflight:
                return
            self._inflight.add(b)
        self._prog.submit(self._fetch_block, b)

    def row(self, r: int, prefetch: bool = True) -> tuple[int, bytes | None]:
        """Return (va, bytes<=16) for row ``r``, or (va, None) if not yet cached.
        Non-blocking; used by the virtualized view's render path."""
        off = r * 16
        va = self.start + off
        b = off // self.BLOCK
        with self._lock:
            block = self._blocks.get(b)
        if block is None:
            return (va, None)
        bo = off - b * self.BLOCK
        return (va, block[bo:bo + 16])

    def ensure(self, r0: int, count: int) -> None:
        """Blocking: fetch the blocks covering rows [r0, r0+count) if missing."""
        if count <= 0:
            return
        b0 = (r0 * 16) // self.BLOCK
        b1 = ((r0 + count) * 16) // self.BLOCK
        for b in range(b0, b1 + 1):
            with self._lock:
                have = b in self._blocks
            if not have:
                self._fetch_block(b)

    def is_cached(self, r0: int, count: int) -> bool:
        if count <= 0:
            return True
        b0 = (r0 * 16) // self.BLOCK
        b1 = ((r0 + count - 1) * 16) // self.BLOCK
        with self._lock:
            return all(b in self._blocks for b in range(b0, b1 + 1))

    def ensure_async(self, r0: int, count: int) -> None:
        b0 = (r0 * 16) // self.BLOCK
        b1 = ((r0 + max(count, 1) - 1) * 16) // self.BLOCK
        for b in range(b0 - 1, b1 + 2):
            self._prefetch(b)


# --------------------------------------------------------------------------- #
# Program: top-level handle, model registry, prefetch pool
# --------------------------------------------------------------------------- #
class Program:
    """The bound analysis session: models, caches, and a small prefetch pool."""

    def __init__(self, client: IDAClient, prefetch_workers: int = 2):
        self.client = client
        self._pool = ThreadPoolExecutor(
            max_workers=prefetch_workers, thread_name_prefix="idatui-prefetch"
        )
        self._indices: dict[str | None, FunctionIndex] = {}
        self._disasm: dict[int, DisasmModel] = {}
        self._listings: dict[int, ListingModel] = {}  # keyed by segment start
        self._decomp: dict[int, tuple[Decompilation, int]] = {}
        self._name_gen = 0  # bumped on rename; invalidates stale name caches
        self._segments_cache: list[tuple[int, int, int, str]] | None = None
        self._sections: list[tuple[int, int, str]] | None = None
        self._fileregions: list[tuple[int, int, int]] | None = None
        self._hexmodel: "HexModel | None" = None
        self._no_read_raw = False  # set if the server lacks the read_raw tool
        self._lock = threading.Lock()

    # -- prefetch plumbing ------------------------------------------------- #
    def submit(self, fn, *args) -> None:
        try:
            self._pool.submit(fn, *args)
        except RuntimeError:
            pass  # pool shut down

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # -- functions --------------------------------------------------------- #
    def functions(self, filter: str | None = None) -> FunctionIndex:
        with self._lock:
            idx = self._indices.get(filter)
            if idx is None:
                idx = FunctionIndex(self, filter)
                self._indices[filter] = idx
            return idx

    # -- sections / segments ---------------------------------------------- #
    def _segments(self) -> list[tuple[int, int, int, str]]:
        """Sorted raw segment map [(start, end, file_off, name)] — the single
        source for sections()/file_regions()/image_range. Cached.

        Uses the injected ``file_regions`` tool (a plain segment walk, ~ms).
        This deliberately AVOIDS ``survey_binary``, which also computes function
        counts / strings / stats and takes *seconds* on a large IDB (it was the
        cause of the multi-second hex-pane open). Falls back to survey_binary
        only if the injected tool is missing.
        """
        if self._segments_cache is not None:
            return self._segments_cache
        segs: list[tuple[int, int, int, str]] = []
        try:
            r = self.client.call("file_regions")
            for d in (r.get("regions", []) if isinstance(r, dict) else []):
                if isinstance(d, dict) and "start" in d:
                    segs.append((_as_int(d["start"]), _as_int(d["end"]),
                                 int(d.get("file_off", -1)), d.get("name", "") or ""))
        except IDAToolError:
            segs = []
        if not segs:  # older server without file_regions -> survey_binary (slow)
            try:
                sb = self.client.call("survey_binary")
                for s in (sb.get("segments", []) if isinstance(sb, dict) else []):
                    try:
                        segs.append((_as_int(s["start"]), _as_int(s["end"]), -1,
                                     s.get("name", "") or ""))
                    except (KeyError, ValueError, TypeError):
                        continue
            except Exception:  # noqa: BLE001 -- best-effort; callers handle empty
                segs = []
        segs.sort()
        with self._lock:
            self._segments_cache = segs
        return segs

    def sections(self) -> list[tuple[int, int, str]]:
        """Sorted, non-overlapping [(start, end, name)] segment map (cached)."""
        if self._sections is not None:
            return self._sections
        secs = [(s, e, nm) for s, e, _fo, nm in self._segments()]
        with self._lock:
            self._sections = secs
        return secs

    def image_range(self) -> tuple[int, int] | None:
        """[start, end) spanning all loaded segments (the hex view's document)."""
        secs = self.sections()
        if not secs:
            return None
        return (min(s[0] for s in secs), max(s[1] for s in secs))

    def hex_model(self) -> "HexModel | None":
        """Cached block-backed byte view over the whole loaded image."""
        if self._hexmodel is not None:
            return self._hexmodel
        rng = self.image_range()  # calls sections() -> don't hold _lock (it re-locks)
        with self._lock:
            if self._hexmodel is None and rng is not None:
                self._hexmodel = HexModel(self, rng[0], rng[1])
            return self._hexmodel

    def file_regions(self) -> list[tuple[int, int, int]]:
        """Sorted [(start, end, file_off)] mapping loaded segments to raw file
        offsets (file_off == -1 for non-file-backed, e.g. .bss). Cached; needs
        the injected ``file_regions`` server tool."""
        if self._fileregions is not None:
            return self._fileregions
        regions = [(s, e, fo) for s, e, fo, _nm in self._segments()]
        with self._lock:
            self._fileregions = regions
        return regions

    def file_offset(self, va: int) -> int | None:
        """Raw on-disk file offset for ``va``, or None if not file-backed."""
        for start, end, fo in self.file_regions():
            if start <= va < end:
                return (fo + (va - start)) if fo >= 0 else None
        return None

    def read_bytes(self, ea: int, n: int) -> bytes:
        """Raw bytes [ea, ea+n) from IDA (gaps read as zero).

        Fast path: the injected ``read_raw`` tool returns one contiguous hex
        string (C-speed both ends). Falls back to the stock ``get_bytes`` (a
        per-byte '0x..'-with-spaces string) on an older server without it.
        """
        if n <= 0:
            return b""
        if not self._no_read_raw:
            try:
                r = self.client.call("read_raw", addr=hex(ea), size=int(n))
                h = r.get("hex") if isinstance(r, dict) else None
                if isinstance(h, str):
                    out = bytes.fromhex(h)
                    return out[:n] if len(out) >= n else out + b"\x00" * (n - len(out))
            except IDAToolError as e:
                # Tool missing on this server: stop trying it, use get_bytes.
                if "read_raw" in str(e) or "Unknown tool" in str(e) or "not found" in str(e):
                    self._no_read_raw = True
                else:
                    return b"\x00" * n
            except (ValueError, KeyError):
                pass  # malformed hex -> fall through to the legacy decoder
        try:
            r = self.client.call("get_bytes", regions=[{"addr": hex(ea), "size": int(n)}])
        except IDAToolError:
            return b"\x00" * n
        res = r.get("result", []) if isinstance(r, dict) else []
        data = res[0].get("data", "") if res and isinstance(res[0], dict) else ""
        out = bytearray()
        for tok in data.split():
            try:
                out.append(int(tok, 16) & 0xFF)
            except ValueError:
                out.append(0)
        if len(out) < n:  # pad short reads (unmapped tail)
            out.extend(b"\x00" * (n - len(out)))
        return bytes(out[:n])

    def section_of(self, ea: int) -> str | None:
        """Name of the segment/section containing ``ea`` (e.g. '.got', '.text',
        '.data.rel.ro', 'LOAD'), or None if unmapped."""
        b = self.segment_bounds(ea)
        return b[2] if b else None

    def segment_bounds(self, ea: int) -> tuple[int, int, str] | None:
        """(start, end, name) of the segment containing ``ea``, or None."""
        secs = self.sections()
        if not secs:
            return None
        i = bisect.bisect_right([s[0] for s in secs], ea) - 1
        if 0 <= i < len(secs) and secs[i][0] <= ea < secs[i][1]:
            return secs[i]
        return None

    def listing(self, ea: int) -> ListingModel | None:
        """Flat listing (code+data+undefined) for the segment containing ``ea``,
        cached per segment. None if ``ea`` is unmapped."""
        seg = self.segment_bounds(ea)
        if seg is None:
            return None
        start, end, name = seg
        with self._lock:
            m = self._listings.get(start)
            if m is None:
                m = ListingModel(self, start, end, name)
                self._listings[start] = m
            return m

    # -- structs / local types -------------------------------------------- #
    def list_structs(self, filter: str = "") -> list[Struct]:
        """All local structs/unions (optionally name-substring filtered), sorted
        by name."""
        payload = self.client.call("search_structs", filter=filter)
        res = payload.get("result", []) if isinstance(payload, dict) else []
        out = [Struct.from_raw(d) for d in res
               if isinstance(d, dict) and d.get("name")
               and not str(d["name"]).startswith("$")]  # skip anonymous UDTs
        out.sort(key=lambda s: s.name.lower())
        return out

    def struct_source(self, name: str) -> str:
        """A C definition for ``name`` reconstructed from its member layout
        (the server exposes members, not printable source). Faithful to IDA's
        field names/types; array dims are moved after the field name."""
        payload = self.client.call(
            "type_inspect", queries=[{"name": name, "include_members": True}])
        res = payload.get("result", []) if isinstance(payload, dict) else []
        info = res[0] if res and isinstance(res[0], dict) else {}
        kw = "union" if info.get("is_union") else "struct"
        lines = [f"{kw} {name}", "{"]
        for m in info.get("members", []) or []:
            if not isinstance(m, dict):
                continue
            t = str(m.get("type", "")).strip()
            fn = m.get("name", "")
            base, arr = t, ""
            am = re.match(r"^(.*?)((?:\s*\[\d+\])+)\s*$", t)
            if am:
                base, arr = am.group(1).rstrip(), am.group(2).replace(" ", "")
            sep = "" if base.endswith("*") else " "
            lines.append(f"    {base}{sep}{fn}{arr};")
        lines.append("};")
        return "\n".join(lines)

    def declare_type(self, decl: str) -> str | None:
        """Create or update a C type. Returns None on success, else the parse
        error. (Re-declaring a name updates it in place.)"""
        payload = self.client.call("declare_type", decls=decl)
        res = payload.get("result", []) if isinstance(payload, dict) else []
        if res and isinstance(res[0], dict):
            return res[0].get("error")
        return None

    # -- function / variable types ---------------------------------------- #
    def func_types(self, ea: int) -> FuncTypes | None:
        """Structured decompiler types for the function at ``ea`` (prototype +
        local variables). None if ``ea`` isn't a decompilable function. Requires
        the injected ``func_types`` server tool."""
        try:
            r = self.client.call("func_types", addr=hex(ea))
        except IDAToolError:
            return None
        if not isinstance(r, dict) or r.get("error"):
            return None
        lvars = [LVar(name=lv.get("name", ""), type=lv.get("type", ""),
                      is_arg=bool(lv.get("is_arg")))
                 for lv in r.get("lvars", []) if isinstance(lv, dict)]
        return FuncTypes(addr=_as_int(r.get("addr", hex(ea))), name=r.get("name", ""),
                         prototype=r.get("prototype", ""), lvars=lvars)

    def set_function_type(self, ea: int, signature: str) -> str | None:
        """Set a function's prototype. None on success, else an error string."""
        r = self.client.call("set_type", edits=[{"addr": hex(ea), "signature": signature}])
        res = r.get("result", []) if isinstance(r, dict) else []
        row = res[0] if res and isinstance(res[0], dict) else {}
        if row.get("ok"):
            return None
        return row.get("error") or "failed to set the prototype"

    def set_lvar_type(self, fn_ea: int, var: str, ty: str) -> str | None:
        """Set a decompiler local variable's type (via the injected server tool).
        None on success, else an error string."""
        r = self.client.call("set_lvar_type", addr=hex(fn_ea), variable=var, type=ty)
        if isinstance(r, dict) and r.get("error"):
            return r["error"]
        if isinstance(r, dict) and not r.get("ok"):
            return "failed to set the variable type"
        return None

    def delete_type(self, name: str) -> str | None:
        """Delete a named type. Returns None on success, else an error string.
        Requires a server-side ``del_type`` tool; if absent, a clear message is
        returned instead of raising."""
        try:
            self.client.call("del_type", name=name)
            return None
        except IDAToolError as e:
            msg = e.message
            if "not found" in msg.lower() and "del_type" in msg:
                return "delete needs a 'del_type' tool on the ida-pro-mcp server"
            return msg

    # -- disassembly ------------------------------------------------------- #
    def disasm(self, ea: int, name: str | None = None) -> DisasmModel:
        with self._lock:
            m = self._disasm.get(ea)
            if m is None:
                m = DisasmModel(self, ea, name)
                self._disasm[ea] = m
            return m

    # -- decompilation ----------------------------------------------------- #
    def decompile(self, ea: int, refresh: bool = False) -> Decompilation:
        """Full pseudocode for a function.

        The server truncates responses over 50KB (strings clipped to 1000
        chars) but caches the full output and exposes it at
        ``_meta.ida_mcp.download_url``. We transparently fetch that so the view
        always gets the complete body, not a 1KB stub.
        """
        if not refresh:
            with self._lock:
                hit = self._decomp.get(ea)
                gen = self._name_gen
            if hit is not None:
                dec, hit_gen = hit
                if hit_gen == gen:
                    return dec
                # Cached before a rename: names may be stale. Drop the server's
                # Hex-Rays cache so the refetch reflects the new names.
                try:
                    self.client.call("force_recompile", items=[{"addr": hex(ea)}])
                except Exception:  # noqa: BLE001
                    pass
        # Bound the decompile: a function Hex-Rays can't handle tends to stall
        # near the client's default 30s timeout, and the transport retries a
        # dropped connection up to max_retries+1 times, re-running the failing
        # decompile each time. Cap it so the worst case stays well under the
        # rpcclient socket timeout, and cache the failure below so a re-request
        # returns instantly instead of re-grinding.
        try:
            envelope = self.client.call_envelope(
                "decompile", addr=hex(ea), timeout=DECOMPILE_TIMEOUT
            )
        except Exception as e:  # noqa: BLE001 -- surface as a failed decompile
            dec = Decompilation(ea, None, True, f"decompile error: {e}", False, None)
            with self._lock:
                self._decomp[ea] = (dec, self._name_gen)
            return dec
        result = envelope.get("result", {})
        payload = result.get("structuredContent")
        if payload is None:  # fall back to text content
            payload = self.client._extract_payload("decompile", result)
        meta = (result.get("_meta") or {}).get("ida_mcp")
        if isinstance(meta, dict) and meta.get("download_url"):
            full = self._fetch_output(meta["download_url"])
            if isinstance(full, dict) and full.get("code"):
                payload = full
        dec = _parse_decompilation(ea, payload)
        with self._lock:
            self._decomp[ea] = (dec, self._name_gen)
        return dec

    def bump_names(self) -> None:
        """Signal that symbol names changed (a rename). Disasm/listing names are
        live in the IDB, so clearing the cached rows is enough for those;
        decompilation is generation-checked and force-recompiled lazily."""
        with self._lock:
            self._name_gen += 1
            models = list(self._disasm.values())
            self._listings.clear()  # listing head rows cache names -> refetch
        for m in models:
            m.invalidate()

    def bump_items(self) -> None:
        """Signal that item/function STRUCTURE changed (define code/data/func,
        undefine). Unlike a rename this can move instruction boundaries and
        change function membership anywhere, so drop the disasm block caches,
        the decompilation cache and the cached function indices outright, and
        bump the name generation too (labels/names may appear or vanish)."""
        with self._lock:
            self._name_gen += 1
            self._indices.clear()
            self._decomp.clear()
            self._listings.clear()
            models = list(self._disasm.values())
            self._disasm.clear()
        for m in models:
            m.invalidate()

    # -- item / function structure edits (IDA c/d/u/p) --------------------- #
    @staticmethod
    def _first_result(payload) -> dict:
        """Unwrap the first row of a batch tool response ({result:[...]} or a
        bare list); soft per-item ``error`` fields ride along in the dict."""
        data = payload.get("result", payload) if isinstance(payload, dict) else payload
        if isinstance(data, list):
            return data[0] if data and isinstance(data[0], dict) else {}
        return data if isinstance(data, dict) else {}

    def define_code(self, ea: int) -> None:
        """Convert the bytes at ``ea`` into a code instruction (IDA's 'c').
        Undefine first so it works even when the bytes are currently part of a
        data/align item — ``create_insn`` refuses to carve into a live item."""
        try:
            self.client.call("undefine", items=[{"addr": hex(ea)}])
        except IDAToolError:
            pass  # nothing defined here yet -> just try to create the insn
        res = self._first_result(
            self.client.call("define_code", items=[{"addr": hex(ea)}]))
        if res.get("error"):
            raise IDAToolError(f"define code @ {ea:#x}: {res['error']}")

    def define_func(self, ea: int) -> None:
        """Create a function starting at ``ea`` (IDA's 'p')."""
        res = self._first_result(
            self.client.call("define_func", items=[{"addr": hex(ea)}]))
        if res.get("error"):
            raise IDAToolError(f"create function @ {ea:#x}: {res['error']}")

    def undefine(self, ea: int, size: int | None = None) -> None:
        """Undefine the item at ``ea`` back to raw bytes (IDA's 'u')."""
        item: dict = {"addr": hex(ea)}
        if size:
            item["size"] = int(size)
        res = self._first_result(self.client.call("undefine", items=[item]))
        if res.get("error"):
            raise IDAToolError(f"undefine @ {ea:#x}: {res['error']}")

    def make_data(self, ea: int, type_decl: str, name: str | None = None) -> None:
        """Create a typed data item at ``ea`` (IDA's 'd', but typed). ``type_decl``
        is a C type, e.g. 'int', 'unsigned __int32', 'char[5]', 'my_struct'."""
        item: dict = {"addr": hex(ea), "type": type_decl}
        if name:
            item["name"] = name
        res = self._first_result(self.client.call("make_data", items=[item]))
        if res.get("ok") is False or res.get("error"):
            raise IDAToolError(
                f"make data @ {ea:#x}: {res.get('error') or 'rejected'}")

    def make_string(self, ea: int, length: int = 0, kind: str = "c") -> str:
        """Create a string literal at ``ea`` (IDA's 'A'); auto-length when 0.
        Returns the decoded contents."""
        r = self.client.call("make_string", addr=hex(ea), length=int(length), kind=kind)
        res = r if isinstance(r, dict) else {}
        if not res.get("ok"):
            raise IDAToolError(
                f"make string @ {ea:#x}: {res.get('error') or 'rejected'}")
        return res.get("text", "")

    def region_label(self, ea: int) -> str:
        """Display name for a non-function address (segment-qualified)."""
        try:
            sec = self.section_of(ea)
        except Exception:  # noqa: BLE001
            sec = None
        return f"{sec} @ {ea:#x}" if sec else f"<no function> @ {ea:#x}"

    @staticmethod
    def _fetch_output(url: str, timeout: float = 15.0):
        """GET the server's cached full-output blob (plain HTTP, not MCP)."""
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 -- fall back to the truncated preview
            return None

    # -- cross-references & containing function --------------------------- #
    def function_of(self, ea: int) -> Func | None:
        """Return the function containing ``ea`` (resolves mid-function addrs)."""
        payload = self.client.call("lookup_funcs", queries=[hex(ea)])
        res = payload.get("result", []) if isinstance(payload, dict) else []
        fn = res[0].get("fn") if res and isinstance(res[0], dict) else None
        return Func.from_raw(fn) if fn else None

    def xrefs_from(self, ea: int) -> list[Xref]:
        payload = self.client.call(
            "xref_query",
            queries=[{"addr": hex(ea), "direction": "from", "include_fn": True}],
        )
        return _parse_xrefs(payload)

    def xrefs_to(self, ea: int, limit: int = 2000) -> list[Xref]:
        payload = self.client.call(
            "xref_query",
            queries=[{"addr": hex(ea), "direction": "to", "include_fn": True,
                      "dedup": True, "count": limit}],
        )
        return _parse_xrefs(payload)

    # -- address resolution ------------------------------------------------ #
    def resolve(self, target: int | str) -> int:
        """Resolve an int/hex-string/symbol name to an address (ea)."""
        if isinstance(target, int):
            return target
        s = target.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            return int(s, 16)
        # Symbol name -> ask the server. lookup_funcs takes an array of strings
        # and returns [{"query":..., "fn": {addr,name,size} | null, "error":...}].
        try:
            payload = self.client.call("lookup_funcs", queries=[s])
        except IDAToolError as e:
            raise KeyError(f"cannot resolve {target!r}: {e}") from e
        res = payload.get("result", []) if isinstance(payload, dict) else []
        fn = res[0].get("fn") if res and isinstance(res[0], dict) else None
        if not fn:
            raise KeyError(f"cannot resolve {target!r}{self._name_suggestion(s)}")
        return _as_int(fn["addr"])

    def _name_suggestion(self, s: str) -> str:
        """Best-effort ' — did you mean …?' hint for a failed name resolve.

        ``lookup_funcs`` matches exact function names only, so a demangled or
        partial name (``QuaziLies`` for ``_Z9QuaziLiesPcS_ii``) or a data symbol
        (``checkKey``) resolves to nothing. Surface the substring matches from
        the function index so the caller can retype the exact name instead of
        getting a bare ``cannot resolve``. Never raises — suggestions are a
        nicety, not a contract.
        """
        try:
            idx = self.functions(filter=s)
            idx.ensure(6)
            cands = idx.window(0, 6)
        except Exception:  # noqa: BLE001 -- suggestions are strictly optional
            return ""
        if not cands:
            return (" (no function name contains it; it may be a data symbol or "
                    "not a function — pass an address like 0x1234)")
        shown = cands[:5]
        names = ", ".join(f"{c.name} @ {c.addr:#x}" for c in shown)
        more = " …" if len(cands) > len(shown) else ""
        return f" — did you mean: {names}{more}?"

    # -- comments ---------------------------------------------------------- #
    def set_comment(self, ea: int, text: str):
        """Set (empty text clears) the comment at ``ea``; affects both the disasm
        and decompiler views. Returns the raw payload so the caller can surface a
        soft per-item error. The caller must invalidate/recompile to see it."""
        return self.client.call("set_comments", items=[{"addr": hex(ea), "comment": text}])

    # -- invalidation (after edits) --------------------------------------- #
    def invalidate(self, ea: int) -> None:
        """Drop caches for a function after a rename/comment/patch/etc."""
        with self._lock:
            self._decomp.pop(ea, None)
            m = self._disasm.get(ea)
        if m is not None:
            m.invalidate()

    def invalidate_functions(self) -> None:
        """Drop the function index caches (after rename/define/undefine)."""
        with self._lock:
            self._indices.clear()


def _parse_xrefs(payload) -> list[Xref]:
    res = payload.get("result", []) if isinstance(payload, dict) else []
    if not res:
        return []
    data = res[0].get("data", []) or []
    out: list[Xref] = []
    for d in data:
        if not isinstance(d, dict):
            continue
        fn = d.get("fn") or {}
        frm = d.get("from", d.get("addr"))
        to = d.get("to")
        out.append(Xref(
            frm=_as_int(frm) if frm is not None else 0,
            to=_as_int(to) if to is not None else None,
            type=d.get("type", "?"),
            fn_name=fn.get("name"),
            fn_addr=_as_int(fn["addr"]) if fn.get("addr") else None,
        ))
    return out


def _parse_decompilation(ea: int, payload) -> Decompilation:
    if not isinstance(payload, dict):
        return Decompilation(ea, None, True, "unexpected payload", False, None)
    code = payload.get("code")
    error = payload.get("error")
    if not code:
        return Decompilation(ea, None, True, error or "decompilation failed",
                             False, None)
    m = _TRUNC_RE.search(code)
    truncated = m is not None
    total_chars = int(m.group(1)) if m else len(code)
    refs = [
        Ref(addr=_as_int(r["addr"]), name=r.get("name", ""), string=r.get("string"))
        for r in payload.get("refs", []) if isinstance(r, dict) and "addr" in r
    ]
    return Decompilation(ea, code, False, error, truncated, total_chars, refs)
