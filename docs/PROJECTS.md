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

**Phase 2 — index cache + project-wide search. (symbols done)**
`idatui/index.py` keeps one **SQLite FTS5 trigram** index at
`<sidecar>/idx/project.db`, populated per binary after its functions load and
re-done only when the source's size/mtime changes.

Why that and not a library: nothing needed installing (FTS5 + the trigram
tokenizer are stdlib), and trigram indexes arbitrary *substrings*, which is what
symbol names and string bodies need. Measured on 300k entries: **1.9 ms** per
query vs 11.8 ms for a Python scan and 28.9 ms for plain `LIKE`; 0.2 ms per
incremental insert.

Size turned out to be a non-issue. Real binaries: `bash` = 5.9k entries /
0.15 MB of text, `libcrypto.so.3` = 30.7k / 0.52 MB. The index runs ~5.7x the
text, so a 20-binary project lands around 12-23 MB — next to the `.i64` files
already in the sidecar (libcrypto's alone is 72 MB) that is ~1% of what the
project already costs. The reason to keep it on disk is **residency, not size**:
search has to work for binaries whose worker isn't running.

Querying is two-stage: the trigram index narrows across every binary, then the
existing `_fuzzy` ranks what's left, so project scope keeps the same
fuzzy-subsequence feel as local scope. Queries shorter than 3 characters fall
back to `LIKE` — a trigram index silently returns *nothing* below that, which
would make incremental typing look broken until the third keystroke.

Both palettes gain a scope toggle on **F2** (not `ctrl+a`: the focused `Input`
binds that to `home`) — `Ctrl+N` for symbols and `"` for strings. Project-scope
hits are prefixed with their binary, and choosing one in another binary switches
to it and jumps. Project scope caps at 60 rows; it saturates any cap because
every binary contributes, and a long list is what makes arrowing feel sluggish.

Ranking, both palettes: the index already guarantees the match, so ordering only
sorts — earliest match, then shortest, then `(binary, addr)`. That last tiebreak
is load-bearing: without it, a name shared by two binaries (`main`, `textdomain`,
most of libc) ties on every other field and Python falls through to comparing the
hit objects, which raises `TypeError`.

**Phase 3 — cross-binary linking (done).** Each binary's imports and exports go
into the project index alongside its functions and strings (`KIND_IMPORT`,
`KIND_EXPORT`), and following an import resolves it to the binary that provides
it.

Following a call to `strcmp` used to reach the PLT/extern entry and stop:
Hex-Rays has nothing to decompile because the code lives in a library this
binary only references. Now `_follow_import` checks whether the target address is
one of this binary's import stubs, asks the index who exports that name, and
switches there. From an `echo` + `libc` project, Enter on `strrchr(a1, 47)` lands
on `strrchr` at `0xaf960` in libc.

Three things this depends on:

*ELF symbol versioning.* The importer sees `strrchr@@GLIBC_2.2.5`; the provider
may export `strrchr`, `strrchr@GLIBC_2.2.5`, or the versioned spelling. Comparing
raw names resolves almost nothing, so `domain.link_name()` cuts at the first `@`
and both sides meet on the bare symbol. `Linkage.raw` keeps what IDA reported,
which is what the listing shows.

*Exact match, not substring.* The join uses `ProjectIndex.exact()`, not
`search()`: an import must bind to its own name, or `read` picks up `pread`,
`read_line` and `thread_start`. Exact match also works below the 3-character
trigram floor, which matters — plenty of real exports are one or two characters.

*Resolution reads the index, not a worker.* A provider resolves while its worker
is evicted; that is the reason the index is on disk. The switch itself then pages
the provider in through the normal pool path.

The reverse direction is in the xrefs dialog. `xrefs_to` only ever sees the
current database, so an exported function looks unused from the inside even when
half the project calls it. `_foreign_importers` appends the project binaries that
IMPORT the symbol — read from the on-disk index, so a caller shows up whether or
not its worker is resident — and choosing one carries a `(binary, addr)` payload
through the same switch path as a search hit, hop included. From libc's
`strrchr`: `0000C318  import  [echo] strrchr`.

It only fires for a symbol this binary actually exports. A local name that
happens to collide with another binary's import is not a caller of ours.

When nothing in the project provides the symbol, `_follow_import` declines and
the local navigation proceeds — landing on the stub is still the honest answer,
and a single-binary session behaves exactly as before.

This does not retire the **PLT/import-stub** backlog item. An import whose
provider isn't in the project still lands on a stub, and that case wants the
original fix — recognise the thunk and present it as an import ("strcmp —
imported, provider not in project") rather than surfacing a decompiler error.
Phase 3 covers the valuable half; stub *presentation* stays worth doing.

**Phase 4 — polish (mostly done).**

*Nav history is per-binary, with a cross-binary way back.* Each binary keeps its
own stack in `BinaryState`; switching restores it (addresses outlive the worker,
so it survives eviction). But phase 3 made a cross-binary jump an ordinary
action, and arriving in a binary whose history is empty made it a one-way door.
`_switch_then_goto` now records the binary it came FROM, and `action_back` falls
through to that hop once local history is spent. So Esc walks back through the
function you were in, then the binary you were in. Manual switching (Ctrl+O)
records nothing — that's not navigation.

*Pre-warm follows the linkage graph, not list order.* When a binary finishes
indexing, `_prewarm_provider` warms the binary that provides the most of its
imports — where a follow is most likely to take you, so its startup is paid
before you ask. `WorkerPool.prewarm()` refuses rather than evicting: spending a
binary you visited on one you haven't is a straight downgrade, and it would throw
away that binary's caches too. At a tight budget pre-warm simply does nothing. It
estimates the cost of a not-yet-spawned worker from the largest resident one,
which is the only evidence available; if the estimate proves wrong, the
speculative worker is the one that goes.

*Driving a project.* `pane spawn --project FILE [--open BIN]` opens a project
pane. `binaries` lists the inventory (active / resident / indexed count / where
Esc returns to) and `switch {binary,addr?}` makes another one active — with an
address it goes through the same path as a search hit, so it records a hop. The
state snapshot now carries `binary` and `hops`.

Still open: project-level persistence (remember the active binary and each
binary's position across sessions — today a fresh launch auto-lands).


## Headerless blobs

An ELF/PE/Mach-O says what it is, so IDA figures it out. A raw firmware dump
says nothing, and IDA falls back to **x86 at address 0** — which on an ARM image
analyses to zero functions. It doesn't fail; it just quietly gives you nothing.

Open one without saying anything and idatui asks, the way interactive IDA does
when no loader matches:

    ┌ unrecognised file — processor? (20) ────────────────┐
    │ fw.bin  (32,768 bytes) — no loader matched; without │
    │ a processor IDA assumes x86 at 0                    │
    │ arm                                                 │
    │   arm          ARM / AArch64 — little-endian        │
    │   armb         ARM — big-endian                     │
    │ load address, e.g. 0x8000000 (blank = 0)            │
    │ Enter accept · Tab base address · Esc load as IDA   │
    └─────────────────────────────────────────────────────┘

`formats.sniff()` decides whether to ask, and only recognises formats IDA
definitely handles (ELF, PE, Mach-O, dex, wasm, ar, COFF, Intel HEX, S-records).
Being cautious the wrong way costs one dismissible dialog; being cautious the
other way is the silent-nothing case we're trying to kill. Esc loads it the way
IDA would have, because the sniff can be wrong.

A text container is only accepted when the whole header is printable — a raw
image whose first byte happens to be `:` is far likelier than Intel HEX.

The dialog is skipped when the answer already exists: options on the command
line, options in the project, or a database that already records them.

Or say it up front:

    ida-tui fw.bin --processor arm --base 0x8000000

or per binary in a project, which is where it belongs for a multi-image firmware:

    {"binaries": [
       {"path": "bootloader.bin", "processor": "arm",  "base": "0x0"},
       {"path": "app.bin",        "processor": "arm",  "base": "0x8000000"},
       {"path": "dsp.bin",        "processor": "mipsb", "base": "0x10000000"}
    ]}

`base` is written the way you'd say it (`0x8000000`, any base, int or string).
IDA's own `-b` switch is in **paragraphs** — `-b1000` loads at 0x10000 — so the
conversion happens in `BinaryRef.load_args`, and a base that isn't 16-byte
aligned is rejected rather than silently landing somewhere else. `ida_args`
passes anything else through untouched.

Two things worth knowing:

* The options apply to the **first** open only. Afterwards the `.i64` records how
  the image was loaded, and passing the switches again makes IDA refuse to open
  it — so the worker skips them once a database exists.
* Changing the processor or base of a binary you've already analysed does
  nothing, because the database wins. Delete its `.i64` from the sidecar to
  reload with new options.

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
