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
HEX_BLOCK = 4096    # bytes per cached/fetched hex block

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
        self._decomp: dict[int, tuple[Decompilation, int]] = {}
        self._name_gen = 0  # bumped on rename; invalidates stale name caches
        self._sections: list[tuple[int, int, str]] | None = None
        self._fileregions: list[tuple[int, int, int]] | None = None
        self._hexmodel: "HexModel | None" = None
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
    def sections(self) -> list[tuple[int, int, str]]:
        """Sorted, non-overlapping [(start, end, name)] segment map (cached).
        Fetched once from ``survey_binary`` (~0.7s) on first use."""
        if self._sections is not None:
            return self._sections
        secs: list[tuple[int, int, str]] = []
        try:
            sb = self.client.call("survey_binary")
            for s in (sb.get("segments", []) if isinstance(sb, dict) else []):
                try:
                    secs.append((_as_int(s["start"]), _as_int(s["end"]),
                                 s.get("name", "")))
                except (KeyError, ValueError, TypeError):
                    continue
        except Exception:  # noqa: BLE001 -- best-effort; callers handle None
            secs = []
        secs.sort()
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
        regions: list[tuple[int, int, int]] = []
        try:
            r = self.client.call("file_regions")
            for d in (r.get("regions", []) if isinstance(r, dict) else []):
                if isinstance(d, dict) and "start" in d:
                    regions.append((_as_int(d["start"]), _as_int(d["end"]),
                                    int(d.get("file_off", -1))))
        except IDAToolError:
            regions = []
        regions.sort()
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
        """Raw bytes [ea, ea+n) from IDA (gaps read as zero)."""
        if n <= 0:
            return b""
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
        secs = self.sections()
        if not secs:
            return None
        i = bisect.bisect_right([s[0] for s in secs], ea) - 1
        if 0 <= i < len(secs) and secs[i][0] <= ea < secs[i][1]:
            return secs[i][2]
        return None

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
            self._decomp[ea] = (dec, self._name_gen)
        return dec

    def bump_names(self) -> None:
        """Signal that symbol names changed (a rename). Disasm names are live in
        the IDB, so clearing the block caches is enough for those; decompilation
        is generation-checked and force-recompiled lazily on next access."""
        with self._lock:
            self._name_gen += 1
            models = list(self._disasm.values())
        for m in models:
            m.invalidate()

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
