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

## Workers self-exit when idle (`idle_ttl_sec`, default 600s)

A headless idalib worker self-exits after ~10 min idle. Its session then lingers
in `idb_list` but calls fail with `"Worker for session <id> is not reachable"`
(distinct from `"Session not found"`). Recovery differs: this needs a fresh
`idb_open` of the same `input_path` (new worker), not just a db re-resolve. The
TUI should (a) raise `idle_ttl_sec` when opening, and/or (b) detect
"not reachable" and transparently re-open. Currently surfaced as a clean
`IDAToolError`; auto-reopen is a TODO for the app layer.

## Writable path requirement (operational)

`idb_open` writes the `.i64` next to the input binary, so the path must be
**writable**. Opening from read-only dirs (e.g. `/usr/lib`) fails with
`"Failed to open database"`. Copy targets into a writable dir first
(`targets/` in this repo).
