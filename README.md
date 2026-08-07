# ida-tui

A minimal, keyboard-first (mouse-capable) **TUI frontend for IDA Pro**, built with
[Textual](https://textual.textualize.io/) and using
[ida-codemode-mcp](../ida-codemode-mcp) as a Python library.

ida-tui attaches to databases through `ida_codemode.client.DatabaseHandle`. A
matching database already open in the IDA GUI is reused; otherwise Code Mode
reuses or starts a shared managed idalib worker. The TUI owns only a client lease,
never the GUI or worker process.

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
  line-virtualized and page lazily over the Code Mode database.
- The startup splash draws the **real logo image** on terminals that speak the
  kitty graphics protocol (~10× the resolution of the block art), and falls back
  to `logo.ans` everywhere else. Support is detected by *asking the terminal*,
  not by sniffing `$TERM` — under a multiplexer that passes the protocol through,
  every environment variable you'd test is empty while the protocol works fine.
- A **control-flow graph** (`space`, IDA's own key): the current function's basic
  blocks as boxes with routed, colour-coded edges (green taken / red fall-through
  / blue unconditional / purple loop), laid out with a proper layered
  (Sugiyama) algorithm. The boxes hold the *same listing rows* as the text view,
  so highlighting, renames, xrefs and comments all work inside them. `z` cycles
  three zoom levels, `m` toggles a minimap, `J`/`K` walk edges, and the mode is
  sticky — following a call lands in the callee's graph. Above 400 blocks it
  declines and says so, because nothing readable comes out at that size.
  Details in [`docs/GRAPH_VIEW.md`](docs/GRAPH_VIEW.md).
- A **Ghidra-style split view** (`s`): listing and pseudocode side by side, kept
  in cursor sync — the focused pane drives and the other highlights the linked
  region (every instruction a C line owns), following you across functions.
  `Tab` or a click switches which pane leads.
- Keyboard navigation: follow (`enter`), xrefs (`x`, tagged call/read/write/
  offset), rename (`n`), retype (`y`), comment (`;`), incremental search (`/`
  `?`), history (`back`), hex view (`\`), and `home`/`end`/`shift+home` line
  motions.
- **Literal formats** (`o`, IDA's own key): cycle how the number under the
  cursor is displayed — hex → decimal → binary → character → offset → IDA's
  own choice, `O` to go the other way. Only the stops that make sense for that
  value are visited (no `char` unless it prints as one, no `offset` unless the
  target is something you could name), so no press is a silent no-op. It works
  in the pseudocode too, on Hex-Rays' separate number formats. The opcode-bytes
  column, which used to own `o`, moved to `B`.

  A line usually holds more than one literal (`test byte ptr [rsi+rax*2+1], 20h`
  has two), so **the one the cursor is on is marked** — that mark is what `o`
  changes, and it keeps up as the text reflows (`0x30` ↔ `48` move everything
  after them). Land on something with no format of its own — a register — and it
  says so and names the operand that does, rather than quietly reformatting a
  different one.
- A **functions panel** (fuzzy symbol palette on `Ctrl+N`), a **strings browser**
  (`"`, filterable, Enter jumps to the literal), **hex viewer**, **struct
  editor**, and inline **make code/data/function/string** edits.
- A **command palette** (`Ctrl+P`) with the real ida-tui actions.
- An optional unix-socket **RPC layer** to puppeteer the live TUI from another
  process (agent-driven RE / livestreaming). See `docs/RPC.md`.

## Architecture (three layers, kept separate)

- **`idatui/codemode_client.py`** — lifecycle and execution adapter. It leases a
  registered GUI/idalib instance with `DatabaseHandle`, waits for autoanalysis,
  normalizes errors, saves, and releases the lease. Address-centric operations
  are sent through Code Mode's `execute_python` surface and use its preloaded
  `ida-domain` `db` object.
- **`idatui/domain.py`** — synchronous, thread-safe paging/caching
  (`FunctionIndex`, `DisasmModel`, `ListingModel`, decompile, xrefs, resolve).
  It has no process/database ownership logic.
- **`idatui/app.py`** — the Textual app (virtualized `ScrollView`s, shared cursor/
  search/nav mixins, modals).

`idatui/pool.py` retains LRU project leases. Releasing an entry never kills a GUI
or another client's worker. See `docs/CODEMODE_PORT.md` for what maps to public
ida-domain APIs and which remaining features require IDAPython inside the Code
Mode execution sandbox.

## Requirements

- Python ≥ 3.11
- IDA Pro 9.4+ with idalib configured
- `ida-codemode-mcp` installed in the TUI environment (this checkout uses the
  editable sibling path `../ida-codemode-mcp`)
- The ida-codemode IDA plugin installed so GUI databases register themselves
- Textual ≥ 8 and Pygments ≥ 2 (`uv sync` installs both)

Code Mode's own worker launcher carries the correct Python environment; ida-tui
no longer searches for a second Python or imports `ida_pro_mcp`.

## Running

Install the project and its TUI dependencies:

```sh
uv sync
```

Pass an executable/IDB path. If the plugin has registered a matching GUI session,
ida-tui attaches to it; otherwise Code Mode opens a managed idalib database:

```sh
./ida-tui /path/to/binary
```

With exactly one registered database, the path may be omitted:

```sh
./ida-tui
```

When several databases are registered, the launcher lists their paths and asks
for one explicitly. A newly managed single-binary database still needs a writable
output location; projects stage binaries and IDBs in their sidecar directory.

Headerless blobs need to be told what they are — a raw firmware dump has no
format to detect, and IDA falls back to x86 at address 0, which analyses to
nothing:

```sh
./ida-tui fw.bin --processor arm --base 0x8000000
```

ARM images that use Thumb need one more thing: press `t` on the listing to switch
ARM/Thumb decoding at the cursor (it sets IDA's `T` register, and the segment to
32-bit, since Thumb doesn't exist in AArch64).

`--base` is a real address (Code Mode's typed loading address is also natural,
so no paragraph conversion crosses the dependency boundary). In a project the
options are recorded per binary. They apply only when Code Mode must create the
first database; a registered or existing IDB already records them. Arbitrary
`--ida-args` are rejected because `DatabaseHandle.open()` has no equivalent;
processor, base, and loader/file type are the supported import surface.

ida-tui never deletes unpacked IDA scratch files during discovery: those files
may belong to a registered GUI or another Code Mode client. Registry locks and
health probes are the ownership authority.

## Execution traces

Load a [Tenet](https://github.com/gaasedelen/tenet) trace alongside the binary
and explore it in time:

```sh
./ida-tui /path/to/binary --trace trace.0.log
```

A docked pane on the right shows the registers at the current timestamp (the
ones the current instruction wrote are highlighted) and a timeline. `]` and `[`
step one instruction forward and back; `}` and `{` step over a call by following
the stack pointer. The code view follows.

Both code views are painted with the execution trail: where you just came from,
where you're about to go, and the instruction you're standing on. The pseudocode
view is painted too — a trace records instructions, but `decomp_map` says which
instructions each C line covers, so the same trail lands on the decompilation.

The dock also shows the **stack as of that instant**, read out of the trace.
Bytes the trace never observed print as `??` rather than zeros — a trace knows
what it saw and nothing else. The hex view (`\`) gets the same treatment: bytes
the trace saw at this timestamp are shown in green over the file's own contents.

Trace addresses are rebased onto the database automatically — a traced process
is relocated, so nothing lines up until that's solved.

Traces are recorded separately; see `~/dev/tenet/tenet-original/tracers/` for the
QEMU tracer.

## RPC / driving the TUI

Give the TUI `--rpc <sock>` to expose a unix-socket control channel, then drive
it from another pane:

```sh
./ida-tui /abs/path/bin --rpc /tmp/ida.sock
python -m idatui.drive where                 # ergonomic terse-text helper
python -m idatui.drive pc main               # pseudocode of main
python -m idatui.drive rename sub_5BE0 foo   # goto + rename
python -m idatui.drive fmt dec               # show this literal in decimal
```

Or let `idatui.pane` spawn + manage TUI panes in tmux (see the idatui-rpc skill):

```sh
python -m idatui.pane spawn --open /abs/path/bin   # -> {sock, pane, ready}
python -m idatui.pane list
python -m idatui.pane stop --sock <sock>
```

See `docs/RPC.md` for the full protocol.

## Tests

`tests/run.py` is the front door — it runs every suite and prints one table.
The live suites attach through Code Mode (a registered GUI database, or a managed
idalib worker started on demand) for the given binary:

```sh
python3 tests/run.py --fast     # 257 checks, ~0.5s, any python3 — between edits
python3 tests/run.py trace -x   # only files matching "trace", stop at first failure
python3 tests/run.py            # all 733 checks, ~2m20s — before a commit
python3 tests/run.py --list     # what would run, and whether it needs IDA
```

It runs the suites **serially on purpose**: idalib contends hard enough that
running them 4-up took the suite from 153s to 296s and got three of them killed
mid-analysis. See the note in `tests/run.py`.

Test files come in two kinds and **each one declares which** with a module-level
`NEEDS_IDA` marker (`run.py` reads it without importing the file, and refuses to
run if a file doesn't have one):

- **pure** — stdlib only, no IDA, no worker, no binary. Seconds. This is what
  you run between edits.
- **IDA** — spawns a real idalib worker on a real target and drives the headless
  Textual `Pilot` against it. Minutes, and needs a licensed IDA.

The individual suites still run standalone, which is how you iterate on one:

```sh
~/ida-venv/bin/python tests/test_scenarios.py targets/echo   # full UI suite
~/ida-venv/bin/python tests/test_scenarios.py --only hex,rename
```

## Docs

- `docs/RPC.md` — the RPC protocol
- `docs/CODEMODE_PORT.md` — port coverage, API gaps, and lifecycle semantics
- `docs/PAGING_FINDINGS.md` — historical paging/scale findings
- `docs/TEXTUAL_NOTES.md` — Textual pitfalls encountered
- `docs/TUI_DRIVING_BLUEPRINT.md` — generalizing the driving layer
