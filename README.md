# ida-tui

A minimal, keyboard-first (mouse-capable) **TUI frontend for IDA Pro**, built with
[Textual](https://textual.textualize.io/) and driving **idalib** (IDA headless).

Opening a binary spawns our own **idalib worker** — a private subprocess talking a
unix socket (`idatui/worker.py` + `WorkerClient`), ~50–100× cheaper per call than
an HTTP transport. It reuses [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)'s
tool implementations in-process; the old ida-pro-mcp HTTP server/supervisor path
has been **removed**.

## ⚠️ Status: not ready for public consumption

This is a personal, actively-hacked-on project. It is **not** packaged, polished,
or supported for general use. Expect sharp edges:

- Hardcoded paths and assumptions (e.g. a venv at `~/ida-venv`, a specific
  IDA/idalib layout).
- No stable API, no versioning promises, no changelog — things move and break.
- Requires a working IDA Pro + idalib install, which you must license and set up
  yourself.
- Known open bugs (see the backlog below), including no handling of PLT/import
  stubs.
- Basically undocumented beyond this file and `docs/`.

If you found this expecting a finished tool: it isn't one yet. Poke around, but
don't file expectations. **Use at your own risk.**

## What it does

- A unified **IDA-style listing** (continuous disassembly interleaved with data /
  undefined heads) as the default code view; `F5`/`Tab` drops into the
  **decompiler (pseudocode)** for the function under the cursor. Both are
  line-virtualized and page lazily over the worker.
- A **Ghidra-style split view** (`s`): listing and pseudocode side by side, kept
  in cursor sync — the focused pane drives and the other highlights the linked
  region (every instruction a C line owns), following you across functions.
  `Tab` or a click switches which pane leads.
- Keyboard navigation: follow (`enter`), xrefs (`x`, tagged call/read/write/
  offset), rename (`n`), retype (`y`), comment (`;`), incremental search (`/`
  `?`), history (`back`), hex view (`\`), and `home`/`end`/`shift+home` line
  motions.
- A **functions panel** (fuzzy symbol palette on `Ctrl+N`), a **strings browser**
  (`"`, filterable, Enter jumps to the literal), **hex viewer**, **struct
  editor**, and inline **make code/data/function/string** edits.
- A **command palette** (`Ctrl+P`) with the real ida-tui actions.
- An optional unix-socket **RPC layer** to puppeteer the live TUI from another
  process (agent-driven RE / livestreaming). See `docs/RPC.md`.

## Architecture (three layers, kept separate)

- **`idatui/worker.py` + `idatui/worker_client.py`** — the backend. `worker.py`
  opens one DB with idalib (on its main thread) and serves ida-pro-mcp's tool
  functions over a unix socket; `WorkerClient` spawns it and is a stdlib-only
  drop-in client (length-prefixed pickle, calls serialized under a lock). Shared
  error types + the `Session` model live in `idatui/errors.py`.
- **`idatui/domain.py`** — paging/caching over the worker client (`FunctionIndex`,
  `DisasmModel`, `ListingModel`, `decompile`, xrefs, resolve). Synchronous,
  thread-safe. Tools ida-pro-mcp lacks (`heads`, `read_raw`, `resolve_names`,
  `xref_types`, …) are injected by `server/patch_server.py`, which the worker
  runs itself on startup.
- **`idatui/app.py`** — the Textual app (virtualized `ScrollView`s, shared cursor/
  search/nav mixins, modals).

The domain + worker-client layers are intentionally **stdlib-only** (the worker
process links idalib); only the TUI layer pulls in Textual + Pygments.

## Requirements

- Python ≥ 3.11
- A working **IDA Pro** with **idalib** and **ida-pro-mcp** installed (the worker
  reuses ida-pro-mcp's tool implementations in-process — no server runs).
- Textual ≥ 8 and Pygments ≥ 2 for the TUI (`pip install -e '.[tui]'`).

Two python environments are expected: one with **textual + idapro** for the TUI
(`~/ida-venv`, override `$IDATUI_PYTHON`) and one with **idapro + ida_pro_mcp**
for the worker (auto-detected, override `$IDATUI_WORKER_PYTHON`).

## Running

One command — it spawns a private idalib worker for the binary (which opens +
auto-analyzes it in its own process over a unix socket) and drops you into the
TUI behind a loading overlay:

```sh
./ida-tui /path/to/binary        # open a binary and drive it — that's it
```

It uses `~/ida-venv/bin/python` for the TUI (override with `$IDATUI_PYTHON`) and
resolves binary paths against your real cwd. The binary's directory must be
writable (idalib writes a `.i64` there).

> Recovering a wedged database: if a worker was hard-killed it leaves unpacked
> `foo.id0/.id1/.id2/.nam/.til` next to `foo.i64`, and the `.i64` then refuses to
> reopen. Delete those stale files (never the `.i64`) and retry — `ida-tui` does
> this automatically.

## RPC / driving the TUI

Give the TUI `--rpc <sock>` to expose a unix-socket control channel, then drive
it from another pane:

```sh
./ida-tui /abs/path/bin --rpc /tmp/ida.sock
python -m idatui.drive where                 # ergonomic terse-text helper
python -m idatui.drive pc main               # pseudocode of main
python -m idatui.drive rename sub_5BE0 foo   # goto + rename
```

Or let `idatui.pane` spawn + manage TUI panes in tmux (see the idatui-rpc skill):

```sh
python -m idatui.pane spawn --open /abs/path/bin   # -> {sock, pane, ready}
python -m idatui.pane list
python -m idatui.pane stop --sock <sock>
```

See `docs/RPC.md` for the full protocol.

## Tests

A headless Textual `Pilot` suite lives in `tests/`; it spawns a worker on the
given binary (default `targets/echo`):

```sh
python tests/test_scenarios.py targets/echo              # full UI suite
python tests/test_scenarios.py --only hex,rename
```

## Docs

- `docs/RPC.md` — the RPC protocol
- `docs/PAGING_FINDINGS.md` — idalib tool paging/scale quirks
- `docs/TEXTUAL_NOTES.md` — Textual pitfalls encountered
- `docs/TUI_DRIVING_BLUEPRINT.md` — generalizing the driving layer
