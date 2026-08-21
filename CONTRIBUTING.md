# Contributing to ida-tui

Thanks for taking a look. Bug reports, patches and ideas are all welcome.

## What you need

- **Python ≥ 3.11**
- **IDA Pro 9.4+ with idalib** — ida-tui is a frontend; IDA does the analysis.

There is no way around the IDA requirement for most of the codebase. However,
a good chunk of the test suite is *pure* (stdlib only, no IDA) and runs
anywhere — see below. Small fixes to the pure layers are perfectly reviewable
without a licence.

## Setup

```sh
uv sync
```

That pulls [ida-nexus](https://github.com/HexRaysSA/ida-nexus) from PyPI,
which is how ida-tui talks to IDA. To also attach to databases open in the IDA
GUI:

```sh
uvx ida-hcli plugin install ida-nexus
```

## Running the tests

This repo does **not** use pytest. Every suite is a standalone script with its
own runner and its own tally line. `tests/run.py --list` prints `pure` or `ida`
for each file.

```sh
python3 tests/run.py --fast          # every pure suite — stdlib only, ~1s
python3 tests/run.py graph -x        # one suite by substring, fail-fast
python3 tests/run.py                 # everything (needs IDA)
```

The IDA-backed suites need an interpreter that has `textual`, `idapro` and
`ida_nexus` on it:

```sh
<ida-python> tests/test_scenarios.py /path/to/binary --only rename
<ida-python> tests/test_scenarios.py --list        # scenario names
```

**House rule:** a suite marked `pure` must keep running under a plain system
`python3`. This is why `idatui/nexus_client.py` defers its `ida_nexus`
import instead of doing it at module top. Please don't break that — it's what
keeps the fast gate fast and lets people without IDA contribute at all.

## Sending a change

- Run at least `python3 tests/run.py --fast` before you push. If your change
  touches an IDA-backed path, run the relevant scenario suite too and say so
  in the PR.
- Keep commits focused, and write a subject line that says what changed and
  why. Look at `git log` for the house style — it favours a concrete claim
  ("listing: `c` disassembles until something stops it") over a vague one.
- If you found a behaviour by measuring it, put the numbers in the commit
  message. Several of the perf commits here are only reviewable because they
  did.

## Reporting bugs

Include the binary/architecture if you can share it, the IDA version, and what
you expected the pane to show versus what it showed. A screenshot of the TUI
is worth a lot — it's a terminal app, so a copy-pasted pane usually works fine.

## Licence

By contributing you agree that your contributions are licensed under the MIT
Licence, the same as the rest of the project.
