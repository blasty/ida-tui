# Paging & scale findings (the "millions of lines" problem)

Measured against a real target: `libcrypto.so.3` (5.7 MB, **10,092 functions**,
biggest function **52,120 instructions**). These constraints drive the domain /
paging layer. Reproduce with `tests/stress_paging.py --db <session>`.

## Response shape (list_* / *_query tools)

A query tool payload is a *list of per-query results*:

```json
{ "result": [ { "data": [ ... ], "next_offset": <int|null> } ] }
```

## Per-call caps are silent and dangerous

Every `count` / `max_instructions` parameter is honored up to a cap, then
**silently collapses to a tiny default (10)** — it does NOT clamp to the max.

| tool        | param            | honored up to | above cap |
|-------------|------------------|---------------|-----------|
| `list_funcs`| `count`          | ~700          | → 10      |
| `disasm`    | `max_instructions`| ~500         | → 10      |

**Rule:** clamp page sizes client-side. Use `list` page ≤ **500**, disasm window
≤ **500**. Never pass a large count hoping for clamping.

## Pagination: advance by `len(data)`, NOT `next_offset`

`next_offset` is just `offset + count`. If `count` exceeds the cap you get 10
rows but `next_offset` still jumps by `count`, **skipping ~99% of the data**.
Correct enumeration:

```python
offset = 0
while True:
    data = call("list_funcs", queries=[{"offset": offset, "count": 500}])[...]
    yield from data
    if len(data) < 500:   # short page => end
        break
    offset += len(data)   # advance by what we actually got
```

Full 10,092-function enumeration = 21 pages, **~3.1 s** (0.31 ms/func). Do this
once in the background with a progress indicator; page lazily otherwise.

## disasm offset paging is **O(offset)** — the main scroll hazard

`disasm addr=F offset=N` re-walks from the function start, so latency grows with
depth (window = 60 instrs):

| offset | latency |
|--------|---------|
| 0      | ~6 ms   |
| 1,000  | ~10 ms  |
| 5,000  | ~23 ms  |
| 20,000 | ~75 ms  |
| 50,000 | ~180 ms |

There is **no resumable cursor**: the payload's `cursor: {"next": N}` is just
informational; `disasm` has no cursor input param. So O(offset) is unavoidable
via this API.

Implications for the domain/paging layer:
- **Cache fetched windows** by `(func, offset)`. Re-scrolling a deep window
  currently re-pays the full ~180 ms (no server-side cache); our cache makes
  revisits instant.
- **Prefetch ahead** in background threads (client is concurrency-safe) so the
  next window is warm before the user reaches it.
- **Over-fetch** up to the ~500 cap per call and slice locally for the viewport,
  amortizing both RTT and the O(offset) walk during fast scrolling.
- **This only bites pathological functions.** The two 52k-insn outliers are
  almost certainly mis-analyzed data/unrolled tables; the next largest real
  function is 2,748 instrs (deepest offset ≈ 10 ms). Typical scrolling is fine.

## `include_total` is expensive — fetch once, cache

Computing `total_instructions` scans the whole function: **~217 ms** on the 52k
monster (vs ~10 ms without). Fetch total once when a function view opens (to size
the scrollbar) and cache it; never request it per-scroll.

disasm totals are **top-level** fields, not under `asm`:
`total_instructions`, `instruction_count`, `cursor`.

## Decompile: can hard-fail on huge functions (soft error)

`decompile` on the 52k-insn function returns, in ~3 ms:
`{"code": null, "error": "Decompilation failed at 0x3349c0"}` with
`isError == false`. The client surfaces this as **data, not an exception**
(correct). The pseudocode view must handle "decompilation failed" gracefully —
fall back to the disassembly view or show an error panel.

Normal decompile bodies are server-truncated with a `[N chars total]` marker
(still to be solved for full-body display — see Phase 2).

## Workers self-exit when idle (`idle_ttl_sec`, default 600s) — SOLVED

### Why it happens
Each idalib worker runs a `WorkerLifecycle` watchdog
(`ida_pro_mcp/worker_lifecycle.py`): if no JSON-RPC request hits its dispatcher
for `idle_ttl_sec` (default **600s**), the worker **self-exits cleanly**. It is
refcount-free — "activity == alive": every forwarded tool call `touch()`es the
timer. This is deliberate resource hygiene for a *shared* supervisor (each worker
holds an IDA license slot + the DB's RAM; default max 4 workers), aimed at
ephemeral/agent usage that opens a DB and wanders off. For an **interactive TUI
that should be able to just chill, it's the wrong default.** The startup binary
passed to `idalib-mcp` on the CLI always gets 600s (no CLI flag to change it).

After self-exit the session lingers in `idb_list` but calls fail with
`"Worker for session <id> is not reachable"` (distinct from `"Session not
found"`).

### The fix (both implemented + verified in `tests/test_keepalive.py`)
1. **`IDAClient.bump_idle_ttl(idle_ttl_sec=1e9)`** — `idb_open` on the
   already-open path is idempotent and re-applies the TTL; `set_idle_ttl` has no
   upper cap, so ~1e9s is effectively 'never'. This is the intended knob and the
   primary fix: the TUI calls it once at startup.
2. **`IDAClient.keepalive(interval=120)` -> `KeepAlive`** — a background
   heartbeat issuing a cheap `server_health` (~2ms) that resets the watchdog.
   Belt-and-suspenders, and it also covers *adopted* sessions whose path we don't
   control / don't want to re-open.

Recommended TUI policy: run a `KeepAlive` heartbeat (interval < TTL) to keep the
*running* session warm, and use a **moderate** idle TTL (not ‘never’) so the
worker is reclaimed after the TUI exits. "Worker not reachable" then only occurs
on a real crash, which the app handles by re-`idb_open`.

## Supervisor worker cap (`max_workers`, default 4)

The supervisor allows at most `max_workers` concurrently-open binaries; a 5th
`idb_open` fails with "Maximum idalib worker count reached". Before counting it
**prunes unreachable workers**, so a dead/killed worker frees its slot on the
next open. Two consequences drove design choices:

* Do **not** make sessions immortal (`bump_idle_ttl(1e9)`) — they pile up to the
  cap and never free. Instead: `KeepAlive` while running + a moderate TTL
  (idatui uses 1800s on `--open`) so idle sessions self-exit after the TUI
  closes and free their slot.
* `spawn.sh` sets `IDA_MCP_MAX_WORKERS` (default raised to 8) for headroom; to
  free a stuck slot immediately, kill the idle worker process (it gets pruned on
  the next open).

## Writable path requirement (operational)

`idb_open` writes the `.i64` next to the input binary, so the path must be
**writable**. Opening from read-only dirs (e.g. `/usr/lib`) fails with
`"Failed to open database"`. Copy targets into a writable dir first
(`targets/` in this repo).
