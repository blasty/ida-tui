# Projects — grouping many binaries under one target

RE'ing a real target means several binaries at once: a daemon, the libraries it
links, maybe a loader. IDA has no notion of this (one IDB, one window); Ghidra
does. A **project** groups binaries so you can switch between them instantly,
search across all of them, and (later) follow calls from one into another.

## The constraint that shapes everything

`idatui/worker.py` is `serve(sock, binpath)` — **one worker process holds exactly
one database** (idalib is main-thread-only and single-DB). So N binaries = N
worker processes, each with the analyzed DB resident.

Measured cost (this box, `targets/`):

| binary | size | `.i64` | worker RSS / PSS |
|--------|------|--------|------------------|
| `bash` | 1.2 MB | 14 MB | **126 MB / 117 MB** |
| `libcrypto.so.3` | 5.9 MB | 72 MB | several hundred MB (DB working set dominates) |

PSS ≈ RSS, so workers share almost nothing — the Nth worker costs roughly its
full footprint. A ~120 MB baseline (Python + the idalib kernel) dominates for
small binaries; the DB working set dominates for big ones.

**Therefore residency is budgeted by memory, not by a fixed worker count** — a
count is the wrong knob when one project holds both a 50 KB helper and a 6 MB
crypto library.

## The key split

Two capabilities that feel like one, but aren't:

1. **Switching** to a binary needs a *live worker*.
2. **Searching across** binaries does *not* — if a per-binary index (functions,
   strings, imports/exports) is cached on disk.

That split is the unlock: project-wide search stays instant across every binary,
including ones never opened this session, and only *jumping* to a hit costs a
worker spawn.

## Layout

The project file is explicit (`--project router-fw.json`); everything IDA
generates lives in a sidecar dir beside it, so **source trees stay pristine**:

```
router-fw.json               # the project file
router-fw.idatui.d/
  bin/httpd                  # staged copy of the source binary
  bin/httpd.i64              # IDA's DB + scratch land here automatically
  idx/httpd.json             # cached index (phase 2)
```

Binaries are **staged** into `bin/` and IDA opens the staged file, so the `.i64`
and all the `.id0/.id1/.id2/.nam/.til` scratch are created there rather than next
to the original. (Today they pile up beside the source: `targets/` holds ~244 MB
of IDA litter around ~13 MB of binaries, much of it stale wedge files from
hard-killed workers.) A source whose size/mtime no longer matches the staged copy
is re-staged, and its now-stale DB dropped.

Staging **copies** rather than hardlinks. A hardlink is free, but source and
staged would be one inode: an in-place rebuild (`cp newbuild /path/bin`
truncates rather than replacing) would silently swap the bytes under an already
analysed database, with nothing to detect it. A copy costs a fraction of the
`.i64` it will grow, and leaves the sidecar self-contained — the project still
opens after the sources go away (an unmounted firmware image, a cleaned build
tree). *The unit test caught this: with hardlinks an in-place rewrite never went
stale.*

```json
{
  "name": "router-fw",
  "binaries": [
    {"path": "/abs/sbin/httpd", "label": "httpd"},
    {"path": "../lib/libauth.so"}
  ],
  "memory_pct": 25
}
```

Relative paths resolve against the project file. `label` defaults to the
basename and must be unique (it names the staged file).

## Runtime

- **`WorkerPool`** — one `WorkerClient` per binary, spawned lazily on first
  switch, kept resident until the memory budget is exceeded, then LRU-evicted.
  Eviction **saves the DB first**, so returning to a binary is a DB load, not a
  re-analysis. Binaries can be pinned to stay resident.
- **`BinaryState`** — per binary: `client, program, nav, cur, func_index,
  pref/active/split, filter`. Switching snapshots the current state and restores
  the target's. `_after_reconnect` already does exactly this swap (client +
  program, reload the index, re-open the entry) — switching reuses that seam.
- **Clean shutdown** — the worker currently does `close_database(save=False)` and
  is hard-killed on exit, which is why wedge files accumulate. Projects need
  save-on-evict and an orderly close anyway, so that gets fixed here.

## UI

- **Binary switcher** — a palette (mirroring `SymbolPalette`/`StringsPalette`)
  listing each binary with resident/cold state and function count; Enter
  switches.
- **Status bar** shows the active binary.
- **Scope toggle** — the existing symbol (`Ctrl+N`) and strings (`"`) palettes
  gain a this-binary ↔ whole-project toggle rather than new keys, so there's one
  mental model. Project-scope hits are prefixed with the binary label; Enter
  switches binary *and* jumps.

## Phases

**Phase 1 — project model + switching. DONE.** Project file + staging
(`idatui/project.py`), `WorkerPool` with budget eviction / save-on-evict /
clean shutdown (`idatui/pool.py`), `BinaryState` snapshot+restore and the switch
itself, the `Ctrl+O` switcher palette, the active binary in the status line, and
`--project` (which creates the project when given binaries). One active binary;
no cross-binary search yet.

Project mode is **additive**: with no `--project` the app is byte-for-byte the
single-binary tool it was, which is what keeps the 167-check pilot honest.
Switching reuses the `_after_reconnect` shape — swap client+program, rebuild the
index, reopen the entry. A binary whose worker is still resident restores
instantly (its `Program` and index are still in memory); an evicted one comes
back with a fresh worker but keeps its nav history, since that is just addresses.

**Phase 2 — index cache + project-wide search.** Per-binary index (functions,
strings) persisted after first open, keyed by source size+mtime. Scope toggle in
the symbol/strings palettes, working for never-opened binaries.

**Phase 3 — cross-binary linking.** Import/export index; "who in the project
calls this export"; follow an import stub in A into its implementation in B.
Subsumes the standing PLT/import-stub backlog item — today following a libc call
dead-ends on `extrn X:near`.

**Phase 4 — polish.** Background pre-warm, nav-history policy (per-binary to
start; a global stack is a later question), RPC/`drive` verbs (`binaries`,
`switch`), project-level persistence.

## Decisions

- Residency is a **memory budget** (default 25% of RAM, `memory_pct`), not a
  worker count; pinning supported.
- **Nav history is per-binary** to start.
- Search scope is a **toggle inside the existing palettes**.
- The project file is **explicit** (`--project`), not auto-discovered.
- IDA artifacts are **centralized** in the sidecar dir via staging.

## Open questions

- Re-staging a changed source drops its DB (renames included) — right call, but
  it should warn loudly.
- Should `Esc`/back ever cross binaries (global history)? Deferred.
- Pre-warm policy: analyze the whole project up front, or purely on demand?
