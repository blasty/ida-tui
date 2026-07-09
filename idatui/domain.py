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
from dataclasses import dataclass, field
from typing import Callable

from .client import IDAClient, IDAToolError

# Clamps derived from measured caps (list ~700, disasm ~500). Margin included.
LIST_PAGE = 500
DISASM_BLOCK = 256  # instructions per cached/fetched block (<= disasm cap)

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
        return cls(addr=_as_int(d["addr"]), name=d["name"], size=_as_int(d["size"]))


@dataclass(frozen=True)
class Line:
    """One rendered disassembly line. ``ea`` is the instruction address."""

    ea: int
    text: str
    label: str | None = None

    @classmethod
    def from_raw(cls, d: dict) -> "Line":
        return cls(
            ea=_as_int(d["addr"]),
            text=d.get("instruction", ""),
            label=d.get("label"),
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
        self._lock = threading.Lock()
        self._inflight: set[int] = set()

    def total(self) -> int:
        """Total instruction count (fetched once; ~200ms on huge funcs)."""
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

    def _fetch_block(self, b: int) -> list[Line]:
        payload = self._prog.client.call(
            "disasm", addr=hex(self.ea), offset=b * self.BLOCK,
            max_instructions=self.BLOCK,
        )
        raw = payload.get("asm", {}).get("lines", []) if isinstance(payload, dict) else []
        lines = [Line.from_raw(r) for r in raw]
        with self._lock:
            self._blocks[b] = lines
            self._inflight.discard(b)
        return lines

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
        self._decomp: dict[int, Decompilation] = {}
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
                if hit is not None:
                    return hit
        envelope = self.client.call_envelope("decompile", addr=hex(ea))
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
            self._decomp[ea] = dec
        return dec

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
            raise KeyError(f"cannot resolve {target!r}")
        return _as_int(fn["addr"])

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
