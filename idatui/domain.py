"""Domain / paging layer: address-centric models over IDA Code Mode.

This is where the "millions of lines" problem is solved, so the TUI widgets only
ever see a viewport-sized slice. Every hard-won constraint from
``docs/PAGING_FINDINGS.md`` is encoded here:

* Page sizes remain bounded so remote execution returns viewport-scale JSON.
* Pagination advances by the number of rows actually returned.
* Deep head walks are block-cached (revisits are free) and neighboring blocks
  prefetch through the thread-safe Code Mode client.
* Expensive function totals are fetched once and cached.
* Decompilation failures are surfaced as data, not application crashes.

Everything here is synchronous and thread-safe. The TUI runs these calls from
Textual worker threads; the internal prefetch pool is separate and small.
"""

from __future__ import annotations

import array
import bisect
import re
import threading
from base64 import b64decode
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, NamedTuple

from . import remote_ops
from .errors import IDAToolError

if TYPE_CHECKING:  # type hint only
    from .codemode_client import CodeModeClient

# Clamps derived from measured caps (list ~700, disasm ~500). Margin included.
LIST_PAGE = 500
DISASM_BLOCK = 256  # instructions per cached/fetched block (<= disasm cap)
HEX_BLOCK = 16384  # bytes per cached/fetched hex block (compact read_raw -> cheap)

_TRUNC_RE = re.compile(r"\[(\d+) chars total\]\s*$")


# --------------------------------------------------------------------------- #
# Value models
# --------------------------------------------------------------------------- #
def _as_int(v) -> int:
    # Both arms of the ternary this used to end with were `int(v, 16)`, so the
    # isinstance+startswith test in front of them decided nothing and ran on
    # every address the client parses -- 55k times per 60 listing pages.
    if isinstance(v, int):
        return v
    return int(v, 16)


@dataclass(frozen=True)
class Func:
    addr: int
    name: str
    size: int

    @classmethod
    def from_raw(cls, d: dict) -> "Func":
        addr = _as_int(d["addr"])
        name = d.get("name")
        # An unnamed function must still have a
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


class Head(NamedTuple):
    """One flat-listing item (from the Code Mode ``heads`` operation): a code
    instruction, a data item, or an undefined byte run.

    A ``NamedTuple`` rather than a dataclass because this is by far the
    most-constructed object in the codebase -- a jump to an address near the end
    of a big binary builds one per listing row it walks past, a quarter of a
    million of them -- and ``tuple.__new__`` costs 1.9us where a frozen
    dataclass's ``__init__`` costs 2.9us. Attribute reads are marginally slower
    (10ns vs 20ns), which is the right trade: rows are built far more often than
    they are read, and a viewport only ever reads forty of them.

    Immutable, like the frozen dataclass it replaced.
    """

    ea: int
    kind: str  # 'code' | 'data' | 'unknown' | 'member'
    size: int
    text: str
    name: str | None = None
    raw: bytes | None = None  # opcode/item bytes (filled in for code by the model)
    #: [(kind, text)] from IDA's own colour tags — mnem/reg/num/name/str/punct/…
    #: None when Code Mode didn't provide them (or the spans
    #: disagreed with the plain text, in which case the text wins).
    #:
    #: Held exactly as it came off the wire, and **read-only**. The worker
    #: memoises its per-line render, so one list is shared by every row that
    #: says the same thing — pickle preserves that, and 228 000 rows of bash
    #: reference about 53 000 lists. Copying each row's into a fresh tuple threw
    #: the sharing away and cost 0.9 µs a row for nothing.
    spans: Sequence | None = None
    #: [(start, end, n)] — where each operand sits in ``text``, from IDA's own
    #: COLOR_OPND markers. Lets the view show which operand the cursor is on,
    #: and is the same information the worker maps a column through, so the
    #: highlight and the edit can't disagree. Read-only, as ``spans`` is.
    ops: Sequence | None = None

    @property
    def label(self) -> str | None:  # Line-compatible alias
        return self.name

    def op_at(self, col: int) -> tuple[int, int, int] | None:
        """The operand whose text contains ``col``, or None."""
        for lo, hi, n in self.ops or ():
            if lo <= col < hi:
                return (lo, hi, n)
        return None

    @classmethod
    def from_raw(cls, d: dict, raw: bytes | None = None) -> "Head":
        # Spans and operand extents are stored as they arrive: the worker's own
        # tool emits [str, str] and [int, int, int], so re-coercing them was
        # re-proving that once per listing row -- and copying them into tuples
        # destroyed the sharing the worker's line cache had just created.
        #
        # Built POSITIONALLY, and with the address converted inline. This is the
        # most-constructed object in the codebase (227k of them to stream one
        # bash) and the two together are worth ~40%: keyword construction has to
        # match names against the tuple's fields, and _as_int was a call per row
        # to do one isinstance and an int().
        v = d["ea"]
        return cls(
            v if isinstance(v, int) else int(v, 16),
            d.get("kind", "unknown"),
            int(d.get("size", 0) or 0),
            d.get("text", ""),
            d.get("name"),
            raw,
            d.get("spans") or None,
            d.get("ops") or None,
        )


@dataclass
class BasicBlock:
    """One node of a function's control-flow graph, with the listing rows that
    make up its body (filled in by ``Program.flowchart``)."""

    id: int
    start: int
    end: int
    succs: list[tuple[int, str]] = field(default_factory=list)
    rows: list[Head] = field(default_factory=list)


@dataclass
class Flowchart:
    func_ea: int
    name: str
    entry: int
    blocks: list[BasicBlock]

    def block_at(self, ea: int) -> BasicBlock | None:
        for b in self.blocks:
            if b.start <= ea < b.end:
                return b
        return None


@dataclass
class Ref:
    addr: int
    name: str
    string: str | None = None


@dataclass
class Xref:
    frm: int  # the referencing address
    to: int | None  # the referenced address
    type: str  # coarse: "code" | "data"
    fn_name: str | None  # function containing `frm`
    fn_addr: int | None
    kind: str | None = None  # fine: call/jump/flow/read/write/offset/text/info


@dataclass(frozen=True)
class LVar:
    name: str
    type: str
    is_arg: bool


@dataclass
class FuncTypes:
    addr: int
    name: str
    prototype: str  # e.g. 'int __fastcall foo(int a, char *b)'
    lvars: list[LVar]


@dataclass(frozen=True)
class Struct:
    name: str
    size: int
    is_union: bool
    members: int  # field count
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


@dataclass(frozen=True)
class StrLit:
    """A string literal IDA found in the binary (the Shift+F12 list)."""

    addr: int
    text: str
    length: int
    type: str = ""


def link_name(raw: str) -> str:
    """A linkage name reduced to what actually joins across binaries.

    ELF symbol versioning means the importer sees ``strrchr@@GLIBC_2.2.5`` while
    the provider may export ``strrchr``, ``strrchr@GLIBC_2.2.5`` or the versioned
    spelling — comparing raw names silently resolves almost nothing. Cut at the
    first '@' so both sides meet on the bare symbol.
    """
    n = (raw or "").strip()
    at = n.find("@")
    return n[:at] if at > 0 else n


@dataclass(frozen=True)
class SearchHit:
    """One database-wide search result (Ctrl+F).

    ``addr`` is where the match starts -- for a byte pattern that can be inside
    an instruction, so ``head`` is the item to navigate to and ``line`` is what
    that item renders as.
    """

    addr: int
    head: int
    line: str = ""
    func: str | None = None
    func_addr: int | None = None
    seg: str = ""


@dataclass(frozen=True)
class Comment:
    """One comment somebody wrote into the database.

    ``line`` is the disassembly the comment is attached to, carried along so a
    report can show what was being commented ON without a second round trip.
    ``whole_func`` marks a function comment rather than an instruction one.
    """

    addr: int
    text: str
    repeatable: bool = False
    whole_func: bool = False
    line: str = ""
    seg: str = ""
    func: str | None = None
    func_addr: int | None = None


@dataclass(frozen=True)
class NamedItem:
    """An address carrying a real name -- one you typed, or one the file's own
    symbols supplied. IDA records both as "user" names and does not remember
    which was which, so a report must say so rather than claim authorship."""

    addr: int
    name: str
    is_func: bool = False
    size: int = 0
    proto: str | None = None
    seg: str = ""


@dataclass(frozen=True)
class Linkage:
    """One import or export: a name this binary takes from, or offers to, other
    modules. ``module`` is set for imports (the library IDA attributes it to),
    ``ordinal`` for exports.

    ``name`` is the joinable name; ``raw`` keeps the spelling IDA reported, which
    is what the user sees in the listing.
    """

    addr: int
    name: str
    module: str = ""
    ordinal: int = 0
    raw: str = ""


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
    ``next_offset``). A single index instance corresponds to one remote
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
        data = _query_data(
            self._prog.client.call(remote_ops.list_funcs, queries=[query])
        )
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
        self._max_raw = 0  # widest opcode length seen (bytes)
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
            remote_ops.disasm, addr=hex(self.ea), max_instructions=1, include_total=True
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
            b = bytes(data[off : off + length])
            biggest = max(biggest, len(b))
            out.append(replace(ln, raw=b))
        with self._lock:
            if biggest > self._max_raw:
                self._max_raw = biggest
        return out

    @staticmethod
    def _line_from_head(r: dict) -> Line:
        """Adapt a ``heads`` row to a disasm Line (label = the head's name)."""
        return Line(ea=_as_int(r["ea"]), text=r.get("text", ""), label=r.get("name"))

    def _fetch_block(self, b: int) -> list[Line]:
        # The function disasm view is a listing filtered to the function: fetch a
        # block of heads (one per instruction for code). Over-fetch one row so
        # the block knows where its last instruction ends (opcode-byte sizing).
        payload = self._prog.client.call(
            remote_ops.heads,
            addr=hex(self.ea),
            offset=b * self.BLOCK,
            count=self.BLOCK + 1,
            **self._end_kw(),
        )
        rows = payload.get("heads", []) if isinstance(payload, dict) else []
        fetched = [self._line_from_head(r) for r in rows]
        lines = fetched[: self.BLOCK]
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
            out.extend(block[max(lo, 0) : hi])
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

    Backed by the Code Mode adapter's ``heads`` operation, which walks item heads
    and renders each via ``generate_disasm_line``. The segment is walked lazily in
    forward pages (``FunctionIndex`` style); line index == position in the walked
    head list. Random access to an address is O(distance-from-seg-start) the
    first time (then cached) — the same tradeoff as ``disasm offset=N``. Grows
    on demand as the viewport scrolls. Synchronous + thread-safe.
    """

    PAGE = 500  # viewport-scale heads per Code Mode execution
    #: Generation marker for a skeleton (text-less) page. Never equals a real
    #: _text_gen, which counts up from 0, so such a page always reads as stale.
    _SKELETON_GEN = -1

    def __init__(
        self, program: "Program", seg_start: int, seg_end: int, name: str | None = None
    ):
        self._prog = program
        self.seg_start = seg_start
        self.seg_end = seg_end
        self.name = name or f"seg @ {seg_start:#x}"
        self._heads: list[Head] = []
        self._by_ea: dict[int, int] = {}
        # Logical rows != physical heads. A run of undefined bytes arrives as ONE
        # head ("db 2044 dup(?)") because materialising millions of one-byte rows
        # for a .bss would be absurd — but you must still be able to put the
        # cursor on any byte in it and press `c`, exactly as in IDA. So a run of
        # N bytes PRESENTS as N rows and the text for each is synthesised on
        # demand. _row_at[i] is the logical row where physical head i starts.
        self._row_at: list[int] = []
        self._head_eas: list[int] = []  # parallel to _heads, for bisect
        #: Which name generation each head's TEXT was rendered at, parallel to
        #: _heads. A rename bumps :attr:`_text_gen`; the rows themselves stay
        #: (their addresses and row numbers are unchanged) and are re-rendered a
        #: block at a time when something asks for them. See invalidate_text.
        self._head_gen: list[int] = []
        self._text_gen = 0
        #: Whether a rename has ever staled this model. Until one has, every
        #: read takes exactly the path it always did.
        self._renamed = False
        #: Whether any page was loaded as a text-less skeleton. Same effect as
        #: _renamed -- reads have to check the per-head generation -- so the two
        #: are ORed at every gate rather than duplicating the machinery.
        self._skeleton = False
        #: One entry per loaded PAGE: where its heads start, the address it was
        #: fetched from, the digest it came back with, and how many rows it
        #: held. A stale-text refresh re-asks for exactly that page, so it can
        #: be told "still identical" for the price of the render alone.
        self._page_head: list[int] = []
        self._page_addr: list[int] = []
        self._page_digest: list[object] = []
        self._page_rows: list[int] = []
        #: Set if a text refresh came back with a different head sequence, which
        #: means something DID move the walk. Program.listing() throws the model
        #: away when it sees this, so the next read rebuilds from scratch.
        self.stale_structure = False
        self._rows = 0  # total logical rows loaded
        self._ubytes: dict[int, bytes] = {}  # lazily-read bytes for those rows
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

    def _build_page(self, rows: list, raw: bool = True) -> list[Head]:
        """Turn the tool's raw rows into ``Head``s with their opcode bytes
        already attached, via one bulk read over the code extent.

        The bytes are read BEFORE the Heads are built rather than patched in
        afterwards: ``dataclasses.replace`` re-runs ``__init__`` with every
        field, so filling ``raw`` after the fact meant constructing each code
        head twice -- once per listing row, on the path a jump-to-address walks
        hundreds of thousands of times.
        """
        lo = hi = -1
        for r in rows:
            if r.get("kind") == "code" and r.get("size"):
                ea = _as_int(r["ea"])
                if lo < 0:
                    lo = ea
                hi = ea + int(r["size"])
        data = None
        # A skeleton page shows no text, so it needs no opcode bytes -- and
        # skipping them drops the SECOND round trip a page costs (heads is
        # always followed by a bulk read_raw over the code extent).
        if raw and 0 <= lo < hi and hi - lo <= self._OP_SPAN_CAP:
            try:
                data = self._prog.read_bytes(lo, hi - lo)
            except Exception:  # noqa: BLE001 -- opcode bytes are decoration
                data = None
        page: list[Head] = []
        biggest = self._max_raw
        for r in rows:
            raw = None
            if data is not None and r.get("kind") == "code":
                size = int(r.get("size") or 0)
                if size > 0:
                    off = _as_int(r["ea"]) - lo
                    raw = bytes(data[off : off + size])
                    if len(raw) > biggest:
                        biggest = len(raw)
            try:
                page.append(Head.from_raw(r, raw))
            except (KeyError, ValueError, TypeError):
                continue
        if biggest != self._max_raw:
            with self._lock:
                self._max_raw = biggest
        return page

    def max_raw_len(self) -> int:
        with self._lock:
            return self._max_raw

    def build_from_index(self) -> bool:
        """Populate the whole row index from ONE call instead of streaming it.

        ``segment_index(detail=True)`` walks the segment and returns every row's
        address, kind and size as packed arrays, plus the page boundaries a
        refetch would use. That is everything this model needs to know how many
        rows there are and where each one lives -- all that is missing is the
        rendered text, which is exactly what a skeleton page is missing too.

        So the rows land marked ``_SKELETON_GEN`` and the FIRST read of any page
        materialises it through the existing ``_ensure_text``/``_ensure_page``
        path, the same one a rename uses. Measured on bash: 594ms and one call,
        against 1827ms and 458 for streaming the same thing.

        Returns False if the backend cannot supply it, in which case the caller
        should stream as before -- this is an optimisation, not a new contract.

        IDEMPOTENT, and that is load-bearing: the view re-primes on every switch
        back to the listing, so rebuilding here unconditionally put a ~900ms
        segment_index in front of every Tab out of the decompiler.
        """
        with self._lock:
            if self._done and self._heads:
                return True  # already indexed; re-priming is a no-op
        try:
            idx = self._prog.client.call(
                remote_ops.segment_index,
                addr=hex(self.seg_start),
                end=hex(self.seg_end),
                page_rows=self.PAGE,
                detail=True,
            )
        except Exception:  # noqa: BLE001 -- fall back to streaming
            return False
        if not isinstance(idx, dict) or idx.get("error") or "eas" not in idx:
            return False
        try:
            eas = array.array("Q")
            eas.frombytes(b64decode(idx["eas"]))
            kinds = array.array("B")
            kinds.frombytes(b64decode(idx["kinds"]))
            sizes = array.array("I")
            sizes.frombytes(b64decode(idx["sizes"]))
        except Exception:  # noqa: BLE001
            return False
        names = idx.get("kind_names") or []
        anchors = idx.get("anchors") or []
        n = len(eas)
        if not (n == len(kinds) == len(sizes)) or not anchors:
            return False

        heads: list[Head] = []
        row_at: list[int] = []
        by_ea: dict[int, int] = {}
        rows = 0
        ap = heads.append
        rap = row_at.append
        for i in range(n):
            ea = eas[i]
            kind = names[kinds[i]] if kinds[i] < len(names) else "unknown"
            size = sizes[i]
            ap(Head(ea, kind, size, ""))
            rap(rows)
            # Banner/label rows are display-only; navigation must land on the
            # real head at that address. Same rule as the streaming loader.
            if kind not in ("sep", "funchdr", "label"):
                by_ea.setdefault(ea, rows)
            rows += size if (kind == "unknown" and size > 1) else 1

        with self._lock:
            self._heads = heads
            self._head_eas = list(eas)
            self._head_gen = [self._SKELETON_GEN] * n
            self._row_at = row_at
            self._by_ea = by_ea
            self._rows = rows
            # Anchors are [logical_row, ea, head_index] at the exact boundaries
            # heads(count=PAGE) pages on, so _ensure_page can refetch one page
            # and have it line up head for head.
            self._page_head = [a[2] for a in anchors]
            self._page_addr = [_as_int(a[1]) for a in anchors]
            self._page_digest = [None] * len(anchors)
            self._page_rows = [
                (anchors[k + 1][2] if k + 1 < len(anchors) else n) - anchors[k][2]
                for k in range(len(anchors))
            ]
            self._skeleton = True
            self._done = True
            self._next = None
        return True

    def load_next_page(self, text: bool = True) -> int:
        """Load one more page of heads; returns how many were added.

        ``text=False`` loads a SKELETON page: the same rows at the same
        addresses with the same sizes and kinds, but no rendered disassembly
        and no opcode bytes -- 2.8x cheaper, and one round trip instead of two.

        That is all the background grower needs. It exists to discover how many
        rows the segment has so the scrollbar and paging are right, and it
        renders 227k rows of a 1.2MB bash to do it, essentially all of which are
        never looked at. A skeleton page is marked text-stale, so the FIRST read
        of one goes through exactly the same ``_ensure_text`` path a rename uses
        and materialises it, one page per round trip, only for what is shown.
        """
        return self._load_next_page(text)

    def _load_next_page(self, text: bool = True) -> int:
        with self._load_lock:
            return self._load_next_page_locked(text)

    def _load_next_page_locked(self, text: bool = True) -> int:
        with self._lock:
            if self._done or self._next is None:
                return 0
            frm = self._next
        payload = self._prog.client.call(
            remote_ops.heads, addr=hex(frm), count=self.PAGE, annotate=True, text=text
        )
        rows = payload.get("heads", []) if isinstance(payload, dict) else []
        cur = payload.get("cursor", {}) if isinstance(payload, dict) else {}
        page = self._build_page(rows, raw=text)
        with self._lock:
            # A sentinel generation no _text_gen can ever equal, so the page
            # reads as stale until something asks for it and refreshes it.
            gen = self._text_gen if text else self._SKELETON_GEN
            if not text:
                self._skeleton = True
            self._page_head.append(len(self._heads))
            self._page_addr.append(frm)
            self._page_digest.append(
                payload.get("digest") if isinstance(payload, dict) else None
            )
            self._page_rows.append(len(rows))
            for h in page:
                # Banner/label rows (function headers, separators, code labels)
                # are display-only; don't index them so navigation lands on the
                # real code/data head at that address.
                if h.kind not in ("sep", "funchdr", "label"):
                    self._by_ea.setdefault(h.ea, self._rows)
                self._row_at.append(self._rows)
                self._head_eas.append(h.ea)
                self._head_gen.append(gen)
                self._heads.append(h)
                self._rows += self._span(h)
            nxt = cur.get("next")
            if nxt is None:
                self._done = True
                self._next = None
            else:
                self._next = _as_int(nxt)
            return len(rows)

    @staticmethod
    def _span(h: Head) -> int:
        """How many logical rows head ``h`` occupies."""
        return h.size if (h.kind == "unknown" and h.size > 1) else 1

    def _phys(self, row: int) -> tuple[int, int]:
        """(physical head index, byte offset into it) for logical ``row``."""
        # bisect is imported at module scope; re-importing it here cost a
        # sys.modules lookup on a function that runs once per rendered row and
        # once per row a search reads.
        i = bisect.bisect_right(self._row_at, row) - 1
        if i < 0:
            return (-1, 0)
        return (i, row - self._row_at[i])

    def _unknown_bytes(self, ea: int, n: int) -> bytes:
        """Bytes behind an undefined run, read in blocks and cached.

        Undefined rows are the ones you carve, so their VALUES are the whole
        point — "db ?" with no byte tells you nothing about where an instruction
        stream might start.
        """
        BLK = 1024
        out = bytearray()
        a = ea
        while len(out) < n:
            b0 = (a // BLK) * BLK
            blk = self._ubytes.get(b0)
            if blk is None:
                try:
                    blk = self._prog.read_bytes(b0, BLK)
                except Exception:  # noqa: BLE001
                    blk = b""
                self._ubytes[b0] = blk
            off = a - b0
            take = min(BLK - off, n - len(out))
            chunk = blk[off : off + take] if blk else b""
            if not chunk:
                break
            out += chunk
            a += len(chunk)
        return bytes(out)

    def _row_head(self, i: int, off: int) -> Head:
        """The Head for one logical row: the physical head, or a synthesised
        single-byte row inside an undefined run.

        The run's FIRST row is synthesised too. Leaving "db 2044 dup(?)" there
        would say the row covers 2044 bytes when it now covers one, and the
        column of byte values would start an address late.
        """
        h = self._heads[i]
        if self._span(h) == 1:
            return h
        ea = h.ea + off
        b = self._unknown_bytes(ea, 1)
        text = f"db {b[0]:02X}h" if b else "db ?"
        return Head(
            ea=ea, kind="unknown", size=1, text=text, name=h.name if off == 0 else None
        )

    def ensure(self, n: int) -> None:
        """Ensure at least ``n`` logical rows are loaded (or all, if fewer)."""
        while not self._done and self._rows < n:
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
                have = self._rows
                last_ea = (
                    self._heads[-1].ea + max(self._heads[-1].size, 1) - 1
                    if self._heads
                    else -1
                )
                done = self._done
            if done or (have and last_ea >= ea):
                # Loaded past ea without an exact head hit: return the first head
                # at/after ea (a mid-item address lands on its containing head).
                return self._first_at_or_after(ea)
            if self._load_next_page() == 0:
                return self._first_at_or_after(ea)

    def _first_at_or_after(self, ea: int) -> int:
        with self._lock:
            j = self._head_index_at(ea)
            if j >= 0:
                h = self._heads[j]
                if h.ea <= ea < h.ea + max(h.size, 1):
                    off = (ea - h.ea) if self._span(h) > 1 else 0
                    return self._row_at[j] + off
            for i, h in enumerate(self._heads):
                if h.ea <= ea < h.ea + max(h.size, 1):
                    # Inside an undefined run, land on the exact BYTE.
                    off = (ea - h.ea) if self._span(h) > 1 else 0
                    return self._row_at[i] + off
                if h.ea > ea:
                    return self._row_at[i]
        return -1

    def load_all(self, progress: Callable[[int], None] | None = None) -> None:
        while not self._done:
            if self._load_next_page() == 0:
                break
            if progress:
                progress(self._rows)

    @property
    def complete(self) -> bool:
        with self._lock:
            return self._done

    def loaded(self) -> int:
        with self._lock:
            return self._rows

    def __len__(self) -> int:
        return self.loaded()

    def truncate_from(self, ea: int) -> bool:
        """Drop the walk from the page an edit at ``ea`` could have moved.

        An item edit changes structure, but only *locally*: every head before it
        keeps its address and its row number. Throwing the whole model away made
        the reload re-walk the segment -- 4.9 seconds on bash to make one byte
        into data, for an edit the user made at the row they were looking at.

        Two pages are dropped rather than one, because undefining can coalesce
        backwards into the run in front of it. Beyond that the caller marks the
        kept prefix text-stale, so every kept page is digest-checked on the next
        read and a page that really did move fails its sequence check and forces
        a rebuild. Safe by construction, not by argument.

        Returns False if nothing worth keeping is left.
        """
        with self._lock:
            if not (self.seg_start <= ea < self.seg_end):
                return True  # another segment; nothing moved here
            if len(self._page_head) < 3:
                return False  # barely walked; a rebuild is cheaper
            p = bisect.bisect_right(self._page_addr, ea) - 1
            p = max(p - 1, 0)
            if p <= 0:
                return False  # the edit is in the first pages
            keep = self._page_head[p]
            if keep <= 0:
                return False
            for h in self._heads[keep:]:
                self._by_ea.pop(h.ea, None)
            del self._heads[keep:]
            del self._head_eas[keep:]
            del self._head_gen[keep:]
            del self._row_at[keep:]
            del self._page_head[p:]
            self._next = self._page_addr[p]
            del self._page_addr[p:]
            del self._page_digest[p:]
            del self._page_rows[p:]
            last = self._heads[-1]
            self._rows = self._row_at[-1] + self._span(last)
            self._done = False
            self._ubytes.clear()  # undefined-run bytes behind the drop point
            return True

    def invalidate_text(self) -> None:
        """A rename changed how rows READ, not which rows exist.

        Item boundaries are untouched by a rename, so every row keeps its
        address and its row number — which the edit path already relies on, since
        it restores the cursor by INDEX afterwards. Dropping the whole model
        instead means the next jump re-walks the segment from its start: 6.4
        seconds on bash's .text, after every single rename.

        So keep the walk and mark the rendered text stale; :meth:`_ensure_text`
        re-renders a block at a time, and refuses to splice anything back if the
        head sequence has moved under it (which a rename cannot do, but a
        mis-routed structural edit could).
        """
        with self._lock:
            self._text_gen += 1
            self._renamed = True

    def _ensure_text(self, j0: int, j1: int) -> None:
        """Re-render physical heads [j0, j1) if a rename staled them.

        Works a PAGE at a time -- the same unit the loader fetched. A page is
        exactly what ``heads(addr, count=PAGE)`` produced, so asking again with
        the same arguments reproduces the same row sequence; nothing has to be
        snapped out to whole address groups (a function start emits three banner
        rows sharing one address, and an arbitrary boundary through those never
        lines up again). It also means every head in a page can share one
        generation marker, so "is this fresh?" is a single probe.
        """
        with self._lock:
            n = len(self._heads)
            j1 = min(j1, n)
            j0 = max(j0, 0)
            if j1 <= j0:
                return
            p = max(bisect.bisect_right(self._page_head, j0) - 1, 0)
            last = bisect.bisect_left(self._page_head, j1)
        while p < last:
            p = self._ensure_page(p)

    def _page_bounds(self, p: int) -> tuple[int, int]:
        """[first, last) head index of page ``p`` (caller holds the lock)."""
        lo = self._page_head[p]
        hi = (
            self._page_head[p + 1] if p + 1 < len(self._page_head) else len(self._heads)
        )
        return lo, hi

    def _ensure_page(self, p: int) -> int:
        """Freshen page ``p``; returns the next page to consider."""
        with self._lock:
            if not (0 <= p < len(self._page_head)):
                return p + 1
            gen = self._text_gen
            lo, hi = self._page_bounds(p)
            if hi <= lo or self._head_gen[lo] == gen:
                return p + 1
            addr = self._page_addr[p]
            want_digest = self._page_digest[p]
            want_rows = self._page_rows[p]
            want = [(h.ea, h.kind) for h in self._heads[lo:hi]]
        # Tell the worker what we already hold. It builds the rows either way
        # (there is no knowing a line is unchanged without rendering it), but if
        # they still hash to the same value it keeps them: the pickling, the
        # transfer, the unpickling and the Head rebuild are about 40% of what a
        # page costs, and after a rename almost every page is unchanged. Sending
        # the expectation rather than asking first means a page that HAS changed
        # still costs one round trip.
        try:
            payload = self._prog.client.call(
                remote_ops.heads,
                addr=hex(addr),
                count=self.PAGE,
                annotate=True,
                expect="" if want_digest is None else str(want_digest),
            )
        except Exception:  # noqa: BLE001 -- keep the old text rather than blank
            return p + 1
        if (
            isinstance(payload, dict)
            and "heads" not in payload
            and payload.get("count") == want_rows
        ):
            with self._lock:
                if self._text_gen == gen and len(self._heads) >= hi:
                    for k in range(lo, hi):
                        self._head_gen[k] = gen
            return p + 1
        rows = payload.get("heads", []) if isinstance(payload, dict) else []
        page = self._build_page(rows)
        with self._lock:
            if self._text_gen != gen or len(self._heads) < hi:
                return p + 1
            if [(h.ea, h.kind) for h in page] != want:
                # Something moved the walk, which a rename cannot do -- so this
                # was not one. Say so and let Program.listing() rebuild, rather
                # than sit here re-fetching a page that will never line up (and
                # showing the old names while doing it).
                self.stale_structure = True
                for k in range(lo, hi):
                    self._head_gen[k] = gen
                return p + 1
            self._heads[lo:hi] = page
            # The stored digest has to describe what the client now HOLDS, not
            # what it once loaded. Leaving it stale is how a literal cycling
            # hex -> dec -> hex ends up declared "unchanged" while the row still
            # shows the decimal it was refetched with in between.
            self._page_digest[p] = (
                payload.get("digest") if isinstance(payload, dict) else None
            )
            for k in range(lo, hi):
                self._head_gen[k] = gen
        return p + 1

    def get(self, i: int) -> Head | None:
        with self._lock:
            if not (0 <= i < self._rows):
                return None
            j, off = self._phys(i)
            if j < 0:
                return None
            stale = (self._renamed or self._skeleton) and self._head_gen[
                j
            ] != self._text_gen
            if not stale:
                span = self._span(self._heads[j])
                h = self._heads[j]
        if stale:
            # A rename staled this row's text; re-render its block (one call for
            # the block around it, so a viewport costs one round trip). Only
            # this path re-takes the lock -- the ordinary read stays atomic.
            self._ensure_text(j, j + 1)
            with self._lock:
                if not (0 <= i < self._rows):
                    return None
                j, off = self._phys(i)
                if j < 0:
                    return None
                span = self._span(self._heads[j])
                h = self._heads[j]
        # Synthesis reads bytes, so do it OUTSIDE the lock: an RPC under the
        # model lock deadlocks the page loader that is filling it.
        return self._row_head(j, off) if span > 1 else h

    def window(self, start: int, count: int) -> list[Head]:
        """``count`` logical rows from ``start`` (synthesising undefined ones)."""
        self.ensure(start + count)
        with self._lock:
            # _renamed stays set once a rename has happened; _ensure_text then
            # does the precise, range-limited staleness check. Before the first
            # rename this is one boolean and the read is exactly as it was.
            dirty = self._renamed or self._skeleton
            if dirty:
                j0 = max(self._phys(max(start, 0))[0], 0)
                j1 = self._phys(max(min(self._rows, start + count) - 1, 0))[0] + 1
        if dirty:
            self._ensure_text(j0, j1)
        with self._lock:
            rows = min(self._rows, start + count)
            spans = [self._phys(i) for i in range(max(start, 0), max(rows, 0))]
            heads = self._heads
            plain = [(j, off, heads[j]) for j, off in spans if j >= 0]
        return [
            self._row_head(j, off) if self._span(h) > 1 else h for j, off, h in plain
        ]

    def index_of_ea(self, ea: int) -> int:
        with self._lock:
            hit = self._by_ea.get(ea)
            if hit is not None:
                return hit
            # An address INSIDE an undefined run is a real row now, not a
            # mid-item address: that is what makes `g <addr>` + `c` work
            # anywhere in a blob. Heads are address-ordered, so bisect rather
            # than scan — a big listing has hundreds of thousands of them and
            # this is on the navigation path.
            j = self._head_index_at(ea)
            if j >= 0:
                h = self._heads[j]
                if self._span(h) > 1 and h.ea <= ea < h.ea + h.size:
                    return self._row_at[j] + (ea - h.ea)
        return -1

    def _head_index_at(self, ea: int) -> int:
        """Index of the physical head containing ``ea`` (caller holds the lock)."""
        eas = self._head_eas
        i = bisect.bisect_right(eas, ea) - 1
        return i if 0 <= i < len(self._heads) else -1

    # -- DisasmModel-compatible accessors (unified model) ------------------ #
    def cached_line(self, idx: int) -> Head | None:
        """Alias of get() for the disasm view's Line interface."""
        return self.get(idx)

    def lines(self, start: int, count: int, prefetch: bool = True) -> list[Head]:
        return self.window(start, count)

    def is_cached(self, start: int, count: int) -> bool:
        with self._lock:
            return start + count <= self._rows

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
        return (va, block[bo : bo + 16])

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

    def invalidate(self) -> None:
        """Drop cached bytes so the next viewport read reaches the database."""
        with self._lock:
            self._blocks.clear()


# --------------------------------------------------------------------------- #
# Program: top-level handle, model registry, prefetch pool
# --------------------------------------------------------------------------- #
class Program:
    """The bound analysis session: models, caches, and a small prefetch pool."""

    def __init__(self, client: "CodeModeClient", prefetch_workers: int = 2):
        self.client = client
        self._pool = ThreadPoolExecutor(
            max_workers=prefetch_workers, thread_name_prefix="idatui-prefetch"
        )
        self._indices: dict[str | None, FunctionIndex] = {}
        self._disasm: dict[int, DisasmModel] = {}
        self._listings: dict[int, ListingModel] = {}  # keyed by segment start
        self._decomp: dict[int, tuple[Decompilation, int]] = {}
        #: {func ea: ({line: [(x0, x1, value)]}, name generation)} — literal
        #: positions in the pseudocode, cached alongside the decompilation.
        self._pc_nums: dict[int, tuple[dict, int]] = {}
        self._decomp_maps: dict[int, tuple[list[list[int]], int]] = {}  # line->ea sets
        #: {func ea: (Flowchart, name generation)} — the CFG plus its block rows.
        #: Keyed off _name_gen, which BOTH bump_names and bump_items raise: the
        #: rows carry live symbol names, so a rename must refetch them too.
        self._flowcharts: dict[int, tuple["Flowchart", int]] = {}
        self._strings: list["StrLit"] | None = None  # whole-binary string literals
        self._linkage: tuple[list["Linkage"], list["Linkage"]] | None = None
        self._name_gen = 0  # bumped on rename; invalidates stale name caches
        self._segments_cache: list[tuple[int, int, int, str]] | None = None
        self._sections: list[tuple[int, int, str]] | None = None
        self._fileregions: list[tuple[int, int, int]] | None = None
        self._hexmodel: "HexModel | None" = None
        self._no_read_raw = False  # compatibility fallback for alternate clients
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

        Uses the Code Mode adapter's ``file_regions`` operation (a plain segment
        walk, ~ms), avoiding broad binary surveys on the hex-pane open path.
        """
        if self._segments_cache is not None:
            return self._segments_cache
        segs: list[tuple[int, int, int, str]] = []
        try:
            r = self.client.call(remote_ops.file_regions)
            for d in r.get("regions", []) if isinstance(r, dict) else []:
                if isinstance(d, dict) and "start" in d:
                    segs.append(
                        (
                            _as_int(d["start"]),
                            _as_int(d["end"]),
                            int(d.get("file_off", -1)),
                            d.get("name", "") or "",
                        )
                    )
        except IDAToolError:
            segs = []
        if not segs:  # older server without file_regions -> survey_binary (slow)
            try:
                sb = self.client.call(remote_ops.survey_binary)
                for s in sb.get("segments", []) if isinstance(sb, dict) else []:
                    try:
                        segs.append(
                            (
                                _as_int(s["start"]),
                                _as_int(s["end"]),
                                -1,
                                s.get("name", "") or "",
                            )
                        )
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
        offsets (file_off == -1 for non-file-backed, e.g. .bss). Cached."""
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

        The Code Mode adapter returns one contiguous hex string (C-speed in IDA).
        A legacy ``get_bytes`` decoding fallback remains for alternate clients.
        """
        if n <= 0:
            return b""
        if not self._no_read_raw:
            try:
                r = self.client.call(remote_ops.read_raw, addr=hex(ea), size=int(n))
                h = r.get("hex") if isinstance(r, dict) else None
                if isinstance(h, str):
                    out = bytes.fromhex(h)
                    return out[:n] if len(out) >= n else out + b"\x00" * (n - len(out))
            except IDAToolError as e:
                # Tool missing on this server: stop trying it, use get_bytes.
                if (
                    "read_raw" in str(e)
                    or "Unknown tool" in str(e)
                    or "not found" in str(e)
                ):
                    self._no_read_raw = True
                else:
                    return b"\x00" * n
            except (ValueError, KeyError):
                pass  # malformed hex -> fall through to the legacy decoder
        try:
            r = self.client.call(
                remote_ops.get_bytes, regions=[{"addr": hex(ea), "size": int(n)}]
            )
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
            if m is not None and m.stale_structure:
                m = None  # a refresh found the walk had moved; start over
            if m is None:
                m = ListingModel(self, start, end, name)
                self._listings[start] = m
            return m

    # -- structs / local types -------------------------------------------- #
    def list_structs(self, filter: str = "") -> list[Struct]:
        """All local structs/unions (optionally name-substring filtered), sorted
        by name."""
        payload = self.client.call(remote_ops.search_structs, filter=filter)
        res = payload.get("result", []) if isinstance(payload, dict) else []
        out = [
            Struct.from_raw(d)
            for d in res
            if isinstance(d, dict)
            and d.get("name")
            and not str(d["name"]).startswith("$")
        ]  # skip anonymous UDTs
        out.sort(key=lambda s: s.name.lower())
        return out

    def struct_source(self, name: str) -> str:
        """A C definition for ``name`` reconstructed from its member layout
        (the remote operation exposes members, not printable source). Faithful to IDA's
        field names/types; array dims are moved after the field name."""
        payload = self.client.call(
            remote_ops.type_inspect, queries=[{"name": name, "include_members": True}]
        )
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
        payload = self.client.call(remote_ops.declare_type, decls=decl)
        res = payload.get("result", []) if isinstance(payload, dict) else []
        if res and isinstance(res[0], dict):
            return res[0].get("error")
        return None

    # -- function / variable types ---------------------------------------- #
    def func_types(self, ea: int) -> FuncTypes | None:
        """Structured decompiler types for the function at ``ea`` (prototype +
        local variables). None if ``ea`` isn't a decompilable function."""
        try:
            r = self.client.call(remote_ops.func_types, addr=hex(ea))
        except IDAToolError:
            return None
        if not isinstance(r, dict) or r.get("error"):
            return None
        lvars = [
            LVar(
                name=lv.get("name", ""),
                type=lv.get("type", ""),
                is_arg=bool(lv.get("is_arg")),
            )
            for lv in r.get("lvars", [])
            if isinstance(lv, dict)
        ]
        return FuncTypes(
            addr=_as_int(r.get("addr", hex(ea))),
            name=r.get("name", ""),
            prototype=r.get("prototype", ""),
            lvars=lvars,
        )

    def set_function_type(self, ea: int, signature: str) -> str | None:
        """Set a function's prototype. None on success, else an error string."""
        r = self.client.call(
            remote_ops.set_type, edits=[{"addr": hex(ea), "signature": signature}]
        )
        res = r.get("result", []) if isinstance(r, dict) else []
        row = res[0] if res and isinstance(res[0], dict) else {}
        if row.get("ok"):
            return None
        return row.get("error") or "failed to set the prototype"

    def data_type(self, ea: int) -> dict | None:
        """Current type info for a data item/global: {addr,name,type,size,is_func}.
        None if the operation fails or the address isn't mapped."""
        try:
            r = self.client.call(remote_ops.data_type, addr=hex(ea))
        except IDAToolError:
            return None
        if not isinstance(r, dict) or r.get("error"):
            return None
        return r

    def set_data_type(self, ea: int, decl: str) -> str | None:
        """Set a global/data item's type. None on success, else an error string."""
        r = self.client.call(
            remote_ops.set_type,
            edits=[{"kind": "global", "addr": hex(ea), "type": decl}],
        )
        res = r.get("result", []) if isinstance(r, dict) else []
        row = res[0] if res and isinstance(res[0], dict) else {}
        if row.get("ok"):
            return None
        return row.get("error") or "failed to set the type"

    def set_lvar_type(self, fn_ea: int, var: str, ty: str) -> str | None:
        """Set a decompiler local variable's type through ida-domain pseudocode.
        None on success, else an error string."""
        r = self.client.call(
            remote_ops.set_lvar_type, addr=hex(fn_ea), variable=var, type=ty
        )
        if isinstance(r, dict) and r.get("error"):
            return r["error"]
        if isinstance(r, dict) and not r.get("ok"):
            return "failed to set the variable type"
        return None

    def delete_type(self, name: str) -> str | None:
        """Delete a named type. Returns None on success, else an error string.
        Returns a clear error instead of raising when the runtime cannot do it."""
        try:
            self.client.call(remote_ops.del_type, name=name)
            return None
        except IDAToolError as e:
            msg = e.message
            if "not found" in msg.lower() and "del_type" in msg:
                return "the connected Code Mode runtime cannot delete local types"
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
    def force_recompile(self, ea: int) -> None:
        """Drop local and Hex-Rays caches before an explicit view refresh.

        Normal edit paths use generation-based invalidation. Ctrl+R is also for
        changes made by another Code Mode/IDA client, for which this Program has
        seen no generation bump, so it must explicitly ask Hex-Rays to discard
        its cached cfunc.
        """
        with self._lock:
            self._decomp.pop(ea, None)
            self._pc_nums.pop(ea, None)
            self._decomp_maps.pop(ea, None)
        try:
            self.client.call(remote_ops.force_recompile, items=[{"addr": hex(ea)}])
        except Exception:  # noqa: BLE001 -- refresh still refetches best-effort
            pass

    def decompile(self, ea: int, refresh: bool = False) -> Decompilation:
        """Full pseudocode for a function, returned directly by Code Mode."""
        if not refresh:
            with self._lock:
                hit = self._decomp.get(ea)
                gen = self._name_gen
            if hit is not None:
                dec, hit_gen = hit
                if hit_gen == gen:
                    return dec
                # Cached before a rename: names may be stale. Drop Hex-Rays'
                # cache so the refetch reflects the new names.
                try:
                    self.client.call(
                        remote_ops.force_recompile, items=[{"addr": hex(ea)}]
                    )
                except Exception:  # noqa: BLE001
                    pass
        # The typed remote declaration carries a 15-second transport timeout,
        # so a function Hex-Rays cannot handle does not stall the UI.
        try:
            payload = self.client.call(remote_ops.decompile, addr=hex(ea))
        except Exception as e:  # noqa: BLE001 -- surface as a failed decompile
            dec = Decompilation(ea, None, True, f"decompile error: {e}", False, None)
            with self._lock:
                self._decomp[ea] = (dec, self._name_gen)
            return dec
        dec = _parse_decompilation(ea, payload)
        with self._lock:
            self._decomp[ea] = (dec, self._name_gen)
        return dec

    def bump_names(self) -> None:
        """Signal that symbol names changed (a rename). Disasm/listing names are
        live in the IDB, so the cached rows have to be re-rendered; decompilation
        is generation-checked and force-recompiled lazily.

        The listing keeps its WALK. A rename cannot move an item boundary, so
        every row keeps its address and its row number -- the edit path already
        assumes exactly that, since it restores the cursor by index afterwards.
        Dropping the segment model instead made the reload re-walk it from the
        start, which is 6.4 seconds on bash after every rename.
        """
        with self._lock:
            self._name_gen += 1
            models = list(self._disasm.values())
            listings = list(self._listings.values())
            self._pc_nums.clear()  # a reformat moves every literal on its line
        for m in models:
            m.invalidate()
        for lm in listings:
            lm.invalidate_text()

    def bump_items(self, ea: int | None = None) -> None:
        """Signal that item/function STRUCTURE changed (define code/data/func,
        undefine). Unlike a rename this can move instruction boundaries and
        change function membership, so drop the disasm block caches, the
        decompilation cache and the cached function indices outright, and bump
        the name generation too (labels/names may appear or vanish).

        Given the address that was edited, the segment listing keeps the walk in
        front of it instead of being thrown away: the rows before an edit keep
        their addresses and their row numbers. Without ``ea`` this falls back to
        discarding the listings, as it always did.
        """
        with self._lock:
            self._name_gen += 1
            self._indices.clear()
            self._decomp.clear()
            self._pc_nums.clear()
            models = list(self._disasm.values())
            self._disasm.clear()
            listings = list(self._listings.items())
            if ea is None:
                self._listings.clear()
        for m in models:
            m.invalidate()
        if ea is None:
            return
        for start, lm in listings:
            if lm.truncate_from(ea):
                # Names can move too; the kept prefix is re-rendered on demand,
                # and that is also what catches a page the edit really did move.
                lm.invalidate_text()
            else:
                with self._lock:
                    if self._listings.get(start) is lm:
                        del self._listings[start]

    def invalidate_external(self) -> None:
        """Drop every cached view of an IDB changed by another client.

        An event may describe a rename, a byte patch, a new function, or a
        segment move. Treating an unknown event as text-only risks displaying a
        structurally impossible mix of old rows and new metadata, so the
        external boundary deliberately invalidates all derived state. The app
        debounces event bursts before reaching this method.
        """
        with self._lock:
            self._name_gen += 1
            models = list(self._disasm.values())
            self._indices.clear()
            self._disasm.clear()
            self._listings.clear()
            self._decomp.clear()
            self._pc_nums.clear()
            self._decomp_maps.clear()
            self._flowcharts.clear()
            self._strings = None
            self._linkage = None
            self._segments_cache = None
            self._sections = None
            self._fileregions = None
            self._hexmodel = None
        for model in models:
            model.invalidate()

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
            self.client.call(remote_ops.undefine, items=[{"addr": hex(ea)}])
        except IDAToolError:
            pass  # nothing defined here yet -> just try to create the insn
        res = self._first_result(
            self.client.call(remote_ops.define_code, items=[{"addr": hex(ea)}])
        )
        if res.get("error"):
            raise IDAToolError("define_code", f"@ {ea:#x}: {res['error']}")

    def decomp_error(self, ea: int) -> str:
        """Hex-Rays' own reason for refusing ``ea``, or "" if it won't say."""
        try:
            r = self.client.call(remote_ops.decomp_error, addr=hex(ea))
        except IDAToolError:
            return ""
        if not isinstance(r, dict):
            return ""
        reason = str(r.get("reason") or "")
        if reason and r.get("bitness") == 64 and "64-bit" in reason:
            # Say the FIX, not the diagnosis. Hex-Rays' own sentence ("only
            # 64-bit functions can be decompiled in the current database") is
            # accurate and useless: it describes the database, not what to do,
            # and it's long enough that a status bar cuts off the end — which is
            # exactly where an appended hint would live. This is unfixable in
            # place (bitness is decided at load), so the whole message is the
            # instruction.
            return "this database is 64-bit \u2014 Ctrl+L, pick arm:ARMv7-A"
        return reason

    def thumb_scan(self, start: int, end: int, apply: bool = True) -> dict:
        """Find Thumb entry points from odd pointers in ``[start, end)``."""
        r = self.client.call(
            remote_ops.thumb_scan, start=hex(start), end=hex(end), apply=bool(apply)
        )
        if not isinstance(r, dict) or r.get("error"):
            raise IDAToolError(
                "thumb_scan", f"@ {start:#x}: {(r or {}).get('error', 'failed')}"
            )
        return r

    def set_thumb(self, ea: int, mode: str = "toggle") -> dict:
        """Switch ARM/Thumb decoding at ``ea``. Returns the resulting state."""
        r = self.client.call(remote_ops.set_thumb, addr=hex(ea), mode=mode)
        if not isinstance(r, dict) or r.get("error"):
            raise IDAToolError(
                "set_thumb", f"@ {ea:#x}: {(r or {}).get('error', 'failed')}"
            )
        return r

    def define_code_run(self, ea: int, limit: int = 20000) -> dict:
        """Disassemble consecutively from ``ea`` until something stops it.

        Falls back to a single instruction for alternate clients that do not
        provide the run operation.
        """
        try:
            r = self.client.call(
                remote_ops.define_code_run, addr=hex(ea), limit=int(limit)
            )
        except IDAToolError:
            self.define_code(ea)
            return {"count": 1, "stopped": "single", "end": hex(ea)}
        if not isinstance(r, dict) or r.get("error"):
            raise IDAToolError(
                "define_code_run", f"@ {ea:#x}: {(r or {}).get('error', 'failed')}"
            )
        return r

    def define_func(self, ea: int) -> dict:
        """Create a function starting at ``ea`` (IDA's 'p').

        Prefers the Code Mode operation, which works out the end when IDA can't;
        falls back to a plain create for alternate clients.
        """
        try:
            r = self.client.call(remote_ops.define_func_run, addr=hex(ea))
        except IDAToolError:
            res = self._first_result(
                self.client.call(remote_ops.define_func, items=[{"addr": hex(ea)}])
            )
            if res.get("error"):
                raise IDAToolError("define_func", f"@ {ea:#x}: {res['error']}")
            return {"ok": True, "how": "legacy"}
        if not isinstance(r, dict) or not r.get("ok"):
            raise IDAToolError(
                "define_func", f"@ {ea:#x}: {(r or {}).get('error', 'failed')}"
            )
        return r

    def undefine(self, ea: int, size: int | None = None) -> None:
        """Undefine the item at ``ea`` back to raw bytes (IDA's 'u')."""
        item: dict = {"addr": hex(ea)}
        if size:
            item["size"] = int(size)
        res = self._first_result(self.client.call(remote_ops.undefine, items=[item]))
        if res.get("error"):
            raise IDAToolError("undefine", f"@ {ea:#x}: {res['error']}")

    def make_data(self, ea: int, type_decl: str, name: str | None = None) -> None:
        """Create a typed data item at ``ea`` (IDA's 'd', but typed). ``type_decl``
        is a C type, e.g. 'int', 'unsigned __int32', 'char[5]', 'my_struct'."""
        item: dict = {"addr": hex(ea), "type": type_decl}
        if name:
            item["name"] = name
        res = self._first_result(self.client.call(remote_ops.make_data, items=[item]))
        if res.get("ok") is False or res.get("error"):
            raise IDAToolError(
                "make_data", f"@ {ea:#x}: {res.get('error') or 'rejected'}"
            )

    def make_string(self, ea: int, length: int = 0, kind: str = "c") -> str:
        """Create a string literal at ``ea`` (IDA's 'A'); auto-length when 0.
        Returns the decoded contents."""
        r = self.client.call(
            remote_ops.make_string, addr=hex(ea), length=int(length), kind=kind
        )
        res = r if isinstance(r, dict) else {}
        if not res.get("ok"):
            raise IDAToolError(
                "make_string", f"@ {ea:#x}: {res.get('error') or 'rejected'}"
            )
        return res.get("text", "")

    # -- literal display formats (IDA's 'o': hex / dec / char / offset) ---- #
    def op_format(
        self, ea: int, mode: str = "cycle", col: int = -1, n: int = -1
    ) -> dict:
        """Change how the literal at ``ea`` is DISPLAYED in the listing.

        ``col`` is a column inside the rendered line, which is how the cursor
        says *which* operand it means; ``n`` names one outright. ``mode`` is
        ``cycle``/``back`` (step the stops that make sense for this value) or a
        format by name. ``show`` reports without changing anything.
        """
        r = self.client.call(
            remote_ops.op_format, addr=hex(ea), mode=str(mode), col=int(col), n=int(n)
        )
        res = r if isinstance(r, dict) else {}
        if res.get("error"):
            raise IDAToolError("op_format", f"@ {ea:#x}: {res['error']}")
        if not res:
            raise IDAToolError("op_format", f"@ {ea:#x}: no answer")
        return res

    def pc_nums(self, fn_ea: int) -> dict[int, list[tuple[int, int, str, int, int]]]:
        """{pseudocode line: [(x0, x1, value, ea, opnum), ...]} — every number
        literal in a function's decompilation, so the view can show which one
        the cursor is on. One worker call per decompilation (cached with it);
        the alternative is a round trip per cursor move.

        ``ea``/``opnum`` identify a literal across a reformat: the text reflows
        (``48`` becomes ``0x30``) and a column no longer means the same thing.
        """
        with self._lock:
            hit = self._pc_nums.get(fn_ea)
            gen = self._name_gen
        if hit is not None and hit[1] == gen:
            return hit[0]
        try:
            r = self.client.call(remote_ops.pc_nums, addr=hex(fn_ea))
        except Exception:  # noqa: BLE001 -- an older worker hasn't got the tool
            r = {}
        out: dict[int, list[tuple[int, int, str, int, int]]] = {}
        for rec in (r or {}).get("nums", []):
            try:
                out.setdefault(int(rec["line"]), []).append(
                    (
                        int(rec["x0"]),
                        int(rec["x1"]),
                        str(rec.get("value", "")),
                        _as_int(rec["ea"]),
                        int(rec.get("opnum", 0)),
                    )
                )
            except Exception:  # noqa: BLE001 -- skip a malformed row
                continue
        with self._lock:
            self._pc_nums[fn_ea] = (out, gen)
        return out

    def pc_num_format(
        self, fn_ea: int, mode: str = "cycle", line: int = -1, col: int = -1
    ) -> dict:
        """The same, for a number in the DECOMPILATION of ``fn_ea``.

        Hex-Rays keeps number formats of its own, per (address, operand) — the
        listing's format doesn't reach the pseudocode and vice versa, so this is
        a separate call rather than a flag on ``op_format``.
        """
        r = self.client.call(
            remote_ops.pc_num_format,
            addr=hex(fn_ea),
            mode=str(mode),
            line=int(line),
            col=int(col),
        )
        res = r if isinstance(r, dict) else {}
        if res.get("error"):
            raise IDAToolError("pc_num_format", f"@ {fn_ea:#x}: {res['error']}")
        if not res:
            raise IDAToolError("pc_num_format", f"@ {fn_ea:#x}: no answer")
        return res

    def region_label(self, ea: int) -> str:
        """Display name for a non-function address (segment-qualified)."""
        try:
            sec = self.section_of(ea)
        except Exception:  # noqa: BLE001
            sec = None
        return f"{sec} @ {ea:#x}" if sec else f"<no function> @ {ea:#x}"

    def strings(self, min_len: int = 4, refresh: bool = False) -> list[StrLit]:
        """Every string literal in the binary (IDA's Shift+F12 list), paged in
        full and cached. ``[]`` if the tool is unavailable."""
        if not refresh:
            with self._lock:
                hit = self._strings
            if hit is not None:
                return hit
        out: list[StrLit] = []
        offset, page = 0, 2000
        while True:
            try:
                payload = self.client.call(
                    remote_ops.list_strings,
                    offset=offset,
                    count=page,
                    min_len=min_len,
                    refresh=(refresh and offset == 0),
                )
            except IDAToolError:
                return []
            rows = payload.get("strings", []) if isinstance(payload, dict) else []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                out.append(
                    StrLit(
                        addr=_as_int(r.get("addr", 0)),
                        text=r.get("text", ""),
                        length=int(r.get("len", 0) or 0),
                        type=r.get("type", "") or "",
                    )
                )
            total = (
                int(payload.get("total", 0) or 0) if isinstance(payload, dict) else 0
            )
            if len(rows) < page or len(out) >= total:
                break
            offset += len(rows)
        with self._lock:
            self._strings = out
        return out

    def linkage(self) -> tuple[list[Linkage], list[Linkage]]:
        """``(imports, exports)`` for this binary, cached. ``([], [])`` if the
        operation is unavailable — an alternate client must not break the caller."""
        with self._lock:
            hit = self._linkage
        if hit is not None:
            return hit
        try:
            payload = self.client.call(remote_ops.list_linkage, kind="both")
        except IDAToolError:
            return ([], [])
        if not isinstance(payload, dict):
            return ([], [])
        imps = [
            Linkage(
                addr=_as_int(r.get("addr", 0)),
                name=link_name(r.get("name", "")),
                module=r.get("module", "") or "",
                raw=r.get("name", "") or "",
            )
            for r in payload.get("imports", [])
            if isinstance(r, dict)
        ]
        exps = [
            Linkage(
                addr=_as_int(r.get("addr", 0)),
                name=link_name(r.get("name", "")),
                ordinal=int(r.get("ordinal", 0) or 0),
                raw=r.get("name", "") or "",
            )
            for r in payload.get("exports", [])
            if isinstance(r, dict)
        ]
        out = ([i for i in imps if i.name], [e for e in exps if e.name])
        with self._lock:
            self._linkage = out
        return out

    def annotations(
        self, limit: int = 4000
    ) -> tuple[list["Comment"], list["NamedItem"]]:
        """``(comments, names)`` -- everything a person added to this database.

        Not cached: it is the *current* state of your work, and the one caller
        (the findings export) asks for it once. ``([], [])`` if the backend has
        no such operation, so an alternate client degrades instead of breaking.
        """
        try:
            payload = self.client.call(remote_ops.list_annotations, limit=int(limit))
        except IDAToolError:
            return ([], [])
        if not isinstance(payload, dict):
            return ([], [])
        comments = [
            Comment(
                addr=_as_int(r.get("addr", 0)),
                text=str(r.get("text", "")),
                repeatable=bool(r.get("repeatable")),
                whole_func=bool(r.get("whole_func")),
                line=str(r.get("line", "") or ""),
                seg=str(r.get("seg", "") or ""),
                func=(r.get("func") or None),
                func_addr=(_as_int(r["func_addr"]) if r.get("func_addr") else None),
            )
            for r in payload.get("comments", [])
            if isinstance(r, dict) and r.get("text")
        ]
        names = [
            NamedItem(
                addr=_as_int(r.get("addr", 0)),
                name=str(r.get("name", "")),
                is_func=bool(r.get("func")),
                size=int(r.get("size", 0) or 0),
                proto=(r.get("proto") or None),
                seg=str(r.get("seg", "") or ""),
            )
            for r in payload.get("names", [])
            if isinstance(r, dict) and r.get("name")
        ]
        return (comments, names)

    def search(
        self,
        query: str,
        mode: str = "text",
        *,
        limit: int = 500,
        regex: bool = False,
        case: bool = False,
    ) -> tuple[list["SearchHit"], str | None, bool]:
        """Search the whole database. Returns ``(hits, error, truncated)``.

        A failed search is DATA (a message to show), not an exception: a bad
        regex or an unparsable byte pattern is something the user typed, and
        the palette wants to say so without unwinding.
        """
        operation = (
            remote_ops.search_bytes if mode == "bytes" else remote_ops.search_text
        )
        args: dict = {"limit": int(limit), "case": bool(case)}
        if mode == "bytes":
            # Validate HERE, not just in the UI: IDA's find_bytes answers a
            # malformed pattern with zero hits and no error, which reads as
            # "not present" -- the most misleading answer a search can give.
            from .search import normalise_pattern, pattern_problem

            problem = pattern_problem(query)
            if problem:
                return ([], problem, False)
            args["pattern"] = normalise_pattern(query)
        else:
            args["query"] = query
            args["regex"] = bool(regex)
        try:
            payload = self.client.call(operation, **args)
        except IDAToolError as e:
            return ([], str(e), False)
        if not isinstance(payload, dict):
            return ([], "the backend returned nothing searchable", False)
        hits = [
            SearchHit(
                addr=_as_int(r.get("addr", 0)),
                head=_as_int(r.get("head", r.get("addr", 0))),
                line=str(r.get("line", "") or ""),
                func=(r.get("func") or None),
                func_addr=(_as_int(r["func_addr"]) if r.get("func_addr") else None),
                seg=str(r.get("seg", "") or ""),
            )
            for r in payload.get("hits", [])
            if isinstance(r, dict)
        ]
        return (hits, payload.get("error") or None, bool(payload.get("truncated")))

    def journal_get(self) -> str:
        """The findings journal blob stored in this database ('' if none)."""
        payload = self.client.call(remote_ops.journal_get)
        return str(payload.get("data", "")) if isinstance(payload, dict) else ""

    def journal_put(self, data: str) -> None:
        self.client.call(remote_ops.journal_put, data=str(data))

    def decomp_map(self, ea: int) -> list[list[int]]:
        """Per-pseudocode-line instruction coverage for the split-view region
        highlight: a list aligned to the decompiled lines, each the EAs the
        decompiler attributes to that line (may be empty). Cached per function +
        name generation; ``[]`` if the tool is unavailable."""
        with self._lock:
            hit = self._decomp_maps.get(ea)
            gen = self._name_gen
        if hit is not None and hit[1] == gen:
            return hit[0]
        try:
            payload = self.client.call(remote_ops.decomp_map, addr=hex(ea))
        except IDAToolError:
            return []
        lines = payload.get("lines", []) if isinstance(payload, dict) else []
        out = [
            [_as_int(e) for e in (ln.get("eas") or [])]
            for ln in lines
            if isinstance(ln, dict)
        ]
        with self._lock:
            self._decomp_maps[ea] = (out, gen)
        return out

    # -- control-flow graph ------------------------------------------------ #
    def flowchart(self, ea: int) -> "Flowchart | None":
        """The basic-block CFG of the function containing ``ea``, with each
        block's listing rows attached.

        Two calls, not one per block: ``flowchart`` for the shape, then a single
        ``heads`` walk over the function's extent which is sliced up by address.
        A hundred blocks would otherwise be a hundred round trips.

        Cached per function + item generation, so it survives cursor movement
        but not an edit that changes the code.
        """
        fn = self.function_of(ea)
        key = fn.addr if fn else ea
        with self._lock:
            hit = self._flowcharts.get(key)
            gen = self._name_gen
        if hit is not None and hit[1] == gen:
            return hit[0]
        try:
            payload = self.client.call(remote_ops.flowchart, addr=hex(ea))
        except IDAToolError:
            return None
        if not isinstance(payload, dict) or payload.get("error"):
            return None
        raw = payload.get("blocks") or []
        if not raw:
            return None
        blocks = []
        for b in raw:
            try:
                blocks.append(
                    BasicBlock(
                        id=int(b["id"]),
                        start=_as_int(b["start"]),
                        end=_as_int(b["end"]),
                        succs=[(int(d), str(k)) for d, k in (b.get("succs") or [])],
                    )
                )
            except (KeyError, ValueError, TypeError):
                continue
        if not blocks:
            return None
        f = payload.get("func") or {}
        lo = min(b.start for b in blocks)
        rows = self._block_rows(blocks)
        eas = [h.ea for h in rows]
        for b in blocks:
            # bisect, not a scan per block: a 400-block function against a few
            # thousand rows is a million comparisons done for nothing.
            b.rows = rows[
                bisect.bisect_left(eas, b.start) : bisect.bisect_left(eas, b.end)
            ]
        fcv = Flowchart(
            func_ea=_as_int(f.get("addr", lo)),
            name=str(f.get("name") or f"sub_{lo:X}"),
            entry=int(payload.get("entry", 0) or 0),
            blocks=blocks,
        )
        with self._lock:
            self._flowcharts[key] = (fcv, gen)
        return fcv

    #: Bytes of padding between two blocks that are still worth fetching in one
    #: call. Alignment gaps are a few bytes; a function chunk is far away.
    _BLOCK_GAP = 256

    def _block_rows(self, blocks: list[BasicBlock]) -> list[Head]:
        """Listing rows covering ``blocks``, address-ordered.

        Fetches the blocks' merged extents, NOT their convex hull. IDA puts a
        function's cold/tail chunks a long way from its entry, so the hull of a
        1.4 KB function can be 680 KB wide: walking it fetched 128 000 listing
        rows and took three seconds to draw a graph, all but 300 of them thrown
        away immediately. Adjacent blocks coalesce, so an ordinary contiguous
        function is still exactly one call.
        """
        spans: list[list[int]] = []
        for start, end in sorted((b.start, b.end) for b in blocks):
            if spans and start <= spans[-1][1] + self._BLOCK_GAP:
                if end > spans[-1][1]:
                    spans[-1][1] = end
            else:
                spans.append([start, end])
        out: list[Head] = []
        for start, end in spans:
            out.extend(self._heads_between(start, end))
        return out

    def _heads_between(self, lo: int, hi: int) -> list[Head]:
        """Listing rows for [lo, hi), paged. Same tool and same ``Head`` shape
        the listing view renders, so the graph inherits IDA's colour tags and
        operand marks for free."""
        out: list[Head] = []
        addr = lo
        for _ in range(64):  # bounded: ~128k heads
            if addr >= hi:
                break
            payload = self.client.call(
                remote_ops.heads, addr=hex(addr), end=hex(hi), count=2000
            )
            rows = payload.get("heads", []) if isinstance(payload, dict) else []
            if not rows:
                break
            for r in rows:
                try:
                    h = Head.from_raw(r)
                except (KeyError, ValueError, TypeError):
                    continue
                # Banners and separators are listing furniture; a box already
                # has a border and a label of its own.
                if h.kind in ("sep", "funchdr"):
                    continue
                if lo <= h.ea < hi:
                    out.append(h)
            cur = payload.get("cursor", {}) if isinstance(payload, dict) else {}
            nxt = cur.get("next")
            if nxt is None or cur.get("done"):
                break
            n = _as_int(nxt)
            if n <= addr:
                break
            addr = n
        return out

    # -- cross-references & containing function --------------------------- #
    def function_of(self, ea: int) -> Func | None:
        """Return the function containing ``ea`` (resolves mid-function addrs)."""
        payload = self.client.call(remote_ops.lookup_funcs, queries=[hex(ea)])
        res = payload.get("result", []) if isinstance(payload, dict) else []
        fn = res[0].get("fn") if res and isinstance(res[0], dict) else None
        return Func.from_raw(fn) if fn else None

    def xrefs_from(self, ea: int) -> list[Xref]:
        payload = self.client.call(
            remote_ops.xref_query,
            queries=[{"addr": hex(ea), "direction": "from", "include_fn": True}],
        )
        return _parse_xrefs(payload)

    def xrefs_to(self, ea: int, limit: int = 2000) -> list[Xref]:
        q = [
            {
                "addr": hex(ea),
                "direction": "to",
                "include_fn": True,
                "dedup": True,
                "count": limit,
            }
        ]
        try:
            # xref_types adds a fine-grained `kind` (call/read/write/...) for the
            # xref dialog; fall back to xref_query (code/data only) if absent.
            payload = self.client.call(remote_ops.xref_types, queries=q)
        except IDAToolError:
            payload = self.client.call(remote_ops.xref_query, queries=q)
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
        # Symbol name -> resolve to the address the NAME denotes (get_name_ea via
        # resolve_names). This handles functions, data AND mid-function labels
        # (loc_/locret_): lookup_funcs would map a label to its *containing*
        # function's entry, so double-clicking a label jumped to the wrong place.
        try:
            payload = self.client.call(remote_ops.resolve_names, queries=[s])
            res = payload.get("result", []) if isinstance(payload, dict) else []
            ea = res[0].get("ea") if res and isinstance(res[0], dict) else None
            if ea:
                return _as_int(ea)
        except IDAToolError:
            pass  # alternate client without resolve_names -> fall back below
        # Fall back to function-name resolution (also drives the 'did you mean'
        # suggestion when the name is unknown).
        try:
            payload = self.client.call(remote_ops.lookup_funcs, queries=[s])
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
            return (
                " (no function name contains it; it may be a data symbol or "
                "not a function — pass an address like 0x1234)"
            )
        shown = cands[:5]
        names = ", ".join(f"{c.name} @ {c.addr:#x}" for c in shown)
        more = " …" if len(cands) > len(shown) else ""
        return f" — did you mean: {names}{more}?"

    # -- comments ---------------------------------------------------------- #
    def set_comment(self, ea: int, text: str):
        """Set (empty text clears) the comment at ``ea``; affects both the disasm
        and decompiler views. Returns the raw payload so the caller can surface a
        soft per-item error. The caller must invalidate/recompile to see it."""
        return self.client.call(
            remote_ops.set_comments, items=[{"addr": hex(ea), "comment": text}]
        )

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
        out.append(
            Xref(
                frm=_as_int(frm) if frm is not None else 0,
                to=_as_int(to) if to is not None else None,
                type=d.get("type", "?"),
                fn_name=fn.get("name"),
                fn_addr=_as_int(fn["addr"]) if fn.get("addr") else None,
                kind=d.get("kind"),
            )
        )
    return out


def _parse_decompilation(ea: int, payload) -> Decompilation:
    if not isinstance(payload, dict):
        return Decompilation(ea, None, True, "unexpected payload", False, None)
    code = payload.get("code")
    error = payload.get("error")
    if not code:
        return Decompilation(
            ea, None, True, error or "decompilation failed", False, None
        )
    m = _TRUNC_RE.search(code)
    truncated = m is not None
    total_chars = int(m.group(1)) if m else len(code)
    refs = [
        Ref(addr=_as_int(r["addr"]), name=r.get("name", ""), string=r.get("string"))
        for r in payload.get("refs", [])
        if isinstance(r, dict) and "addr" in r
    ]
    return Decompilation(ea, code, False, error, truncated, total_chars, refs)
