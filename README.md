<p align="center">
  <img src="logo-trans.png" alt="ida-tui" width="480">
</p>

<p align="center">
  <b>IDA Pro, right in your terminal.</b><br>
  Disassembly, decompiler and graphs, driven by the keyboard (the mouse works too).
</p>

<p align="center">
  <code>disasm</code> · <code>pseudocode</code> · <code>graph</code> · <code>hex</code> · <code>strings</code> · <code>structs</code> · <code>traces</code> · <code>rpc</code>
</p>

---

> [!NOTE]
> **This is a personal project and it changes often.** There are no releases and no
> support promises, and things will sometimes break. You need your own licensed copy
> of IDA Pro. Feel free to poke around.

## Why?

IDA's own interface is great, but it's a desktop app. ida-tui is for the times you'd
rather stay in the terminal: working over SSH, sitting in a tmux pane next to your
notes, or scripting your reverse engineering.

It doesn't replace IDA. **IDA still does all the analysis.** ida-tui just gives you
a different window onto it.

## Getting started

You'll need **Python 3.11+** and **IDA Pro 9.4+** (with idalib).

**1. Install**

```sh
uv sync
```

**2. Optional: connect to IDA windows you already have open**

```sh
uvx ida-hcli plugin install ida-nexus
```

**3. Open a binary**

```sh
./ida-tui /path/to/binary
```

If the binary is already open in IDA, ida-tui connects to that copy. If it isn't,
ida-tui opens it in the background. Edits made in either place show up in the other,
and quitting ida-tui never closes anyone else's session.

> [!TIP]
> **Raw firmware or other headerless files:** tell IDA what it's looking at, or it
> will guess wrong:
>
> ```sh
> ./ida-tui fw.bin --processor arm --base 0x8000000
> ```
>
> These settings only matter the first time a file is opened. On ARM, `t` switches
> between ARM and Thumb at the cursor, and `T` finds Thumb code by reading the vector table.

## Keys

| Key | What it does |
|---|---|
| `enter` / `esc` | Follow a reference / go back |
| `tab` or `F5` | Switch between disassembly and pseudocode |
| `space` | Graph view (`z` zoom · `m` minimap · `J`/`K` walk edges) |
| `s` | Split view: disassembly and pseudocode side by side |
| `g` · `/` · `?` | Go to address · search · search backwards |
| `x` · `n` · `y` · `;` | Cross-references · rename · change type · comment |
| `c` · `d` · `p` · `u` · `a` | Mark as code · data · function · undefined · string |
| `o` · `O` · `B` | Change number format · go back a format · show opcode bytes |
| `\` · `"` · `ctrl+t` | Hex · strings · structs |
| `ctrl+n` · `ctrl+p` | Jump to a symbol · command palette |
| `ctrl+r` · `ctrl+s` · `ctrl+l` · `q` | Refresh · save · reload as… · quit |
| **`F1`** | **Show every key** |

## What's inside

| | |
|---|---|
| 📜 **Disassembly** | Code and data in one smooth scrolling view, in IDA's own colours. Huge binaries scroll just as easily as small ones. |
| 🧠 **Pseudocode** | Hex-Rays decompiler output with syntax highlighting. Anything you rename, retype or comment is saved back to IDA. |
| 🕸️ **Graph** | A proper control-flow graph with colour-coded arrows. Each box holds the same lines as the disassembly, so renaming and xrefs work inside it too. |
| 🪞 **Split view** | Disassembly and pseudocode side by side. Move through one and the other highlights the matching lines. |
| 🔎 **Search** | Search the whole database for text or byte patterns like `48 8b ?? c3`. ida-tui works out which one you mean. |
| 🧱 **Structs & types** | Your types shown as plain C. Edit them and press `ctrl+s` to save them back into IDA. |
| 🔢 **Number formats** | Press `o` to cycle a number through hex, decimal, binary, character and offset. |
| 📝 **Findings export** | Press `ctrl+e` to write up your session as markdown: your names, comments and function signatures, grouped by function. |
| ⏱️ **Execution traces** | Load a [Tenet](https://github.com/gaasedelen/tenet) trace and step backwards and forwards through time, with registers and stack shown at each step. |
| 🤖 **Remote control** | Let scripts or AI agents drive a running ida-tui. Handy for automation and livestreams. |

There's also a hex view, a strings list, projects with several binaries, and a
splash screen that shows a real image in terminals that support it (kitty and friends).

<details>
<summary><b>Traces, remote control & demo mode</b></summary>

**Replay a trace.** Use `]` / `[` to step and `}` / `{` to step over calls:

```sh
./ida-tui /path/to/binary --trace trace.0.log
```

**Drive it from another program** (more in [docs/RPC.md](docs/RPC.md)):

```sh
./ida-tui /abs/path/bin --rpc /tmp/ida.sock
python -m idatui.drive pc main               # show pseudocode for main
python -m idatui.drive rename sub_5BE0 foo   # jump there and rename it
```

**Run a scripted tour** for screen recordings:

```sh
python tools/demo.py --spawn
```

</details>

## Contributing

Bug reports and patches are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) explains how
ida-tui works under the hood and how to run the tests. The quick check needs only
plain Python, no IDA:

```sh
python3 tests/run.py --fast
```

---

<p align="center"><a href="https://sl0p.foo">sl0p.foo</a></p>
