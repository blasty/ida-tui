![ida-tui](logo-trans.png)

**IDA Pro in a terminal.** Listing, decompiler, graph — keyboard-first, mouse-capable.

`disasm` · `pseudocode` · `cfg` · `hex` · `strings` · `structs` · `traces` · `rpc`

---

```
┌ ida-tui ─────────────────────────────────────────────────────────────────────┐
│ .text:00002490 ; ---------- S U B R O U T I N E ----------                   │
│ .text:00002490 main            proc near                                     │
│ .text:00002490                 endbr64                                       │
│ .text:00002494                 push    rbp                ; ← cursor         │
│ .text:00002495                 mov     rbp, rsp                              │
│ .text:00002498                 sub     rsp, 0B0h          ; `o` → 176        │
└──────────────────────────────────────────────────────────────────────────────┘
```

> **Status: personal project, actively hacked on.** No packaging, no versioning,
> no support. It assumes a licensed IDA Pro and a venv at `~/ida-venv`. Things
> move and break. Poke around; don't file expectations.

## Why

IDA's own UI is excellent and it is a GUI. This is for the times you're in a
terminal over SSH, in a tmux pane next to your notes, or driving RE from a
script — and still want the listing, Hex-Rays, and a real control-flow graph.

It is **not** a reimplementation of IDA. It's a frontend: IDA does the analysis,
this draws it.

## Install

Needs **Python ≥ 3.11** and **IDA Pro 9.4+ with idalib**.

```sh
uv sync
```

That pulls [ida-codemode](https://github.com/HexRaysSA/ida-codemode) from PyPI,
which is how ida-tui talks to IDA. To also attach to databases you have open in
the IDA GUI, install its plugin:

```sh
uvx --prerelease=allow --from ida-codemode ida-codemode-mcp --install-plugin
```

Hacking on ida-codemode itself? Point at a checkout instead:

```sh
uv add --editable ../ida-codemode
```

## Run

```sh
./ida-tui /path/to/binary        # attach to a GUI session, or open a managed database
./ida-tui                        # attach, when exactly one database is registered
```

ida-tui never owns an IDA process. It takes a **lease**: a matching database open
in the IDA GUI is reused, otherwise Code Mode starts or shares a managed idalib
worker. Quitting drops the lease and leaves everyone else alone.

Headerless blobs have no format to detect — IDA falls back to x86 at address 0
and analyses nothing, so say what it is:

```sh
./ida-tui fw.bin --processor arm --base 0x8000000
```

`--base` is a real address. These apply only when a database is being **created**;
an existing IDB already records them. On ARM, `t` toggles ARM/Thumb decoding at
the cursor and `T` scans a vector table for Thumb entry points.

## Keys

| | |
|---|---|
| `enter` `escape` | follow / back |
| `tab` `F5` | listing ↔ pseudocode |
| `space` | control-flow graph (`z` zoom, `m` minimap, `J`/`K` walk edges) |
| `s` | split view — listing and pseudocode, cursor-synced |
| `g` `/` `?` | goto · search · search back |
| `x` `n` `y` `;` | xrefs · rename · retype · comment |
| `c` `d` `p` `u` `a` | make code · data · function · undefine · string |
| `o` `O` `B` | cycle this literal's format · reverse · opcode bytes |
| `\` `"` `ctrl+t` | hex · strings · structs |
| `ctrl+n` `ctrl+p` | symbol palette · command palette |
| `ctrl+s` `ctrl+l` `q` | save · reload as… · quit |
| `F1` | all of them |

## What's in it

**Listing** — one continuous IDA-style view: code, data and undefined runs
together, with IDA's own colour tags and per-operand marks. Line-virtualized, so
a 400 MB binary scrolls like a text file.

**Decompiler** — Hex-Rays pseudocode with syntax highlighting, per-line address
anchors, and rename/retype/comment that write back.

**Graph** (`space`) — the current function's basic blocks, laid out with a real
layered (Sugiyama) algorithm and routed edges: green taken, red fall-through,
blue unconditional, purple loop. The boxes hold the *same rows* as the listing,
so highlighting, renames and xrefs work inside them. Above 400 blocks it declines
and says so, because nothing readable comes out at that size.
→ [`docs/GRAPH_VIEW.md`](docs/GRAPH_VIEW.md)

**Split view** (`s`) — listing and pseudocode side by side. The focused pane
drives; the other highlights every instruction the current C line owns.

**Literal formats** (`o`) — hex → decimal → binary → char → offset, IDA's own
key. Only stops that change what you see are visited, so no press is a silent
no-op. The literal under the cursor is *marked*, and the mark is what changes —
it keeps up as the text reflows. Works on Hex-Rays' separate number formats too.

**Execution traces** — load a [Tenet](https://github.com/gaasedelen/tenet) trace
and move through time:

```sh
./ida-tui /path/to/binary --trace trace.0.log
```

`]`/`[` step, `}`/`{` step over. Both code views are painted with the execution
trail — including the pseudocode, since `decomp_map` knows which instructions
each C line covers. The dock shows registers and the stack *as of that instant*;
bytes the trace never saw print as `??`, not zeros. Trace addresses are rebased
onto the database automatically.

**RPC** — drive the live TUI from another process (agent-driven RE, livestreams):

```sh
./ida-tui /abs/path/bin --rpc /tmp/ida.sock
python -m idatui.drive where                 # terse-text helper
python -m idatui.drive pc main               # pseudocode of main
python -m idatui.drive rename sub_5BE0 foo   # goto + rename
```

→ [`docs/RPC.md`](docs/RPC.md)

**Splash** — the logo renders as a real image on terminals that speak the kitty
graphics protocol, `logo.ans` everywhere else. Support is detected by *asking the
terminal*, not by sniffing `$TERM` (under a multiplexer, every variable you'd
test is empty while the protocol works fine).

## Tests

```sh
python3 tests/run.py --fast     # 302 checks, <1s, any python3 — between edits
python3 tests/run.py --list     # what runs, and what needs IDA
python3 tests/run.py            # 788 checks, ~2m — before a commit
```

Every suite declares `NEEDS_IDA`; `--fast` runs only the pure ones (stdlib, no
IDA, no database). The rest drive a headless Textual `Pilot` against a real
database. Iterate on one with `--only`:

```sh
~/ida-venv/bin/python tests/test_scenarios.py targets/echo --only hex,rename
```

Before optimising or debugging a slow run, read
[`.fastfeedback/SPEED.md`](.fastfeedback/SPEED.md) — per-suite timings, the known
flake, and the four ways a test here wastes minutes.

## Docs

- [`docs/RPC.md`](docs/RPC.md) — the RPC protocol, verb by verb
- [`docs/GRAPH_VIEW.md`](docs/GRAPH_VIEW.md) — how the graph is laid out

—

[sl0p.foo](https://sl0p.foo)
