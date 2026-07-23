# ida-tui

A minimal, keyboard-first (mouse-capable) **TUI frontend for IDA Pro**, built with
[Textual](https://textual.textualize.io/) and driving **idalib** (IDA headless).

Opening a binary now spawns our own **idalib worker** — a private subprocess
talking a unix socket (`idatui/worker.py` + `WorkerClient`), ~50–100× cheaper per
call than the old transport. The
[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) HTTP path is **deprecated**
(kept behind `--backend mcp` / `--db` attach) and slated for removal.

## ⚠️ Status: not ready for public consumption

This is a personal, actively-hacked-on project. It is **not** packaged, polished,
or supported for general use. Expect sharp edges:

- Hardcoded paths and assumptions (e.g. a venv at `~/ida-venv`, a supervisor on
  `127.0.0.1:8745`).
- No stable API, no versioning promises, no changelog — things move and break.
- Requires a working IDA Pro + idalib install, which you must license and set up
  yourself.
- Known open bugs (see the backlog below), including wonky xref navigation and no
  handling of PLT/import stubs.
- Basically undocumented beyond this file and `docs/`.

If you found this expecting a finished tool: it isn't one yet. Poke around, but
don't file expectations. **Use at your own risk.**

## What it does

- Virtualized **disassembly** and **decompilation (pseudocode)** views that page
  lazily over the MCP server.
- Keyboard navigation: follow (`enter`), xrefs (`x`), rename (`n`), incremental
  search (`/` `?`), history (`back`), view toggle.
- A **functions panel**, **hex viewer**, **struct editor**, and **(re-)typing**.
- An optional unix-socket **RPC layer** to puppeteer the live TUI from another
  process (agent-driven RE / livestreaming). See `docs/RPC.md`.

## Architecture (three layers, kept separate)

- **`idatui/client.py`** — stdlib-only persistent MCP client (`http.client` pool,
  warm handshake, session recovery, keep-alive). No third-party deps.
- **`idatui/domain.py`** — paging/caching over the client (`FunctionIndex`,
  `DisasmModel`, `decompile`, xrefs, resolve). Synchronous, thread-safe.
- **`idatui/app.py`** — the Textual app (virtualized `ScrollView`s, shared cursor/
  search/nav mixins, modals).

The client and domain layers are intentionally **stdlib-only**; only the TUI layer
pulls in Textual + Pygments.

## Requirements

- Python ≥ 3.11
- A working **IDA Pro** with **idalib** and **ida-pro-mcp** installed.
- Textual ≥ 8 and Pygments ≥ 2 for the TUI (`pip install -e '.[tui]'`).

## Running

The caveman way — one command does all the plumbing (starts the supervisor if
it's down, recovers a binary wedged by a crashed worker, opens/adopts the
session, launches the TUI):

```sh
./ida-tui /path/to/binary        # open a binary and drive it — that's it
./ida-tui                        # attach to the sole open session
./ida-tui --db <session>         # attach to a specific session
```

It uses `~/ida-venv/bin/python` for the TUI (override with `$IDATUI_PYTHON`) and
resolves binary paths against your real cwd. The binary's directory must be
writable (idalib writes a `.i64` there).

The manual way (if you want the pieces separate):

```sh
# 1. Start the ida-pro-mcp supervisor (opens bin/ls by default).
./spawn.sh                       # supervisor on 127.0.0.1:8745

# 2. Launch the TUI (use a python that has textual + idapro).
python -m idatui.tui                       # auto-resolve the sole session
python -m idatui.tui --db <session>
python -m idatui.tui --open /abs/path/bin  # dir must be WRITABLE (.i64)
```

> Recovering a wedged database by hand: if a worker was hard-killed it leaves
> unpacked `foo.id0/.id1/.id2/.nam/.til` next to `foo.i64`, and the `.i64` then
> refuses to reopen. Delete those stale files (never the `.i64`) and retry —
> `ida-tui` does this automatically.

The `spawn.sh` host/port/target are overridable via `IDA_MCP_HOST`,
`IDA_MCP_PORT`, `IDA_MCP_TARGET`, `IDA_MCP_MAX_WORKERS`. A systemd unit is in
`systemd/`.

## RPC / driving the TUI

Give the TUI `--rpc <sock>` to expose a unix-socket control channel, then drive
it from another pane:

```sh
python -m idatui.tui --db <s> --rpc /tmp/ida.sock
python -m idatui.drive where                 # ergonomic terse-text helper
python -m idatui.drive pc main               # pseudocode of main
python -m idatui.drive rename sub_5BE0 foo   # goto + rename
```

See `docs/RPC.md` for the full protocol.

## Tests

Headless Textual `Pilot` suites live in `tests/` and need a live session id:

```sh
python tests/test_scenarios.py --db <session>            # UI suite
python tests/test_scenarios.py --db <s> --only hex,rename
python tests/test_domain.py --db <session>               # domain/paging (stdlib)
```

## Docs

- `docs/RPC.md` — the RPC protocol
- `docs/PAGING_FINDINGS.md` — ida-pro-mcp/idalib paging quirks
- `docs/TEXTUAL_NOTES.md` — Textual pitfalls encountered
- `docs/TUI_DRIVING_BLUEPRINT.md` — generalizing the driving layer
