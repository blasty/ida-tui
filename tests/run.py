#!/usr/bin/env python3
"""The front door for the test suite.

There are two kinds of test file here and the difference matters a lot:

  * **pure** — stdlib (sometimes + textual), no IDA, no worker, no binary.
    Runs anywhere in about a second. ``tests/run.py --fast`` is exactly this
    set, and it's what you run between edits.
  * **IDA** — spawns a real idalib worker on a real target and drives the
    Textual pilot against it. Minutes, needs a licensed IDA, and gets CPU
    starved on a loaded box (a SIGKILLed worker looks like a hang, not a bug —
    check ``uptime`` before believing a regression).

Rather than keep that classification in a table here, where it would rot the
first time someone adds a test, **each test file declares it**::

    NEEDS_IDA = True   # or False

``run.py`` reads that marker with :mod:`ast` (it never imports the file — these
modules run their suite at import time). A test file with no marker is a hard
error, so a new test can't quietly join the fast set and start needing IDA.

Deliberately **serial**. Running the IDA suites concurrently looks like the
obvious win (they are independent processes with their own worker and temp dir,
on a 12-core box) and it is measurably a loss: 4 at a time took the suite from
153s to 296s and killed three of them with broken-pipe worker failures --
thumb_ui alone went 10.4s to 287.8s. idalib contends hard enough that the extra
processes only starve each other, and a starved worker gets reaped mid-analysis,
which reads as a flaky test rather than as load. Don't re-add --jobs.

Usage::

    python3 tests/run.py              # everything
    python3 tests/run.py --fast       # only the no-IDA files (seconds)
    python3 tests/run.py --list       # what would run, and why
    python3 tests/run.py trace graph  # only files matching these substrings
    python3 tests/run.py --fast -x    # stop at the first failing file

Exit code is 0 only if every file selected ran and passed.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")

#: The IDA-capable interpreter. The pilot tests need textual AND the IDA Nexus
#: library in one python; the database process is IDA Nexus's to place.
DEFAULT_PY = os.path.expanduser("~/ida-venv/bin/python")

#: Both shapes the suites print: "N passed, M failed" and "N checks, M failed".
_TALLY = re.compile(r"^\s*(\d+)\s+(?:passed|checks),\s*(\d+)\s+failed\s*$", re.M)
_SKIP = re.compile(r"^\s*skip(?:ped|ping)?\b[:.]", re.M | re.I)


class Marker(Exception):
    """A test file didn't declare NEEDS_IDA."""


def needs_ida(path: str) -> bool:
    """Read the module-level ``NEEDS_IDA`` without importing the module.

    Importing is not an option: every one of these files runs its whole suite
    under ``if __name__ == "__main__"`` but also defines its checks at module
    scope, and some spawn workers on import of a helper. AST it is.
    """
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "NEEDS_IDA":
                value = ast.literal_eval(node.value)
                if not isinstance(value, bool):
                    raise Marker(
                        f"{os.path.basename(path)}: "
                        f"NEEDS_IDA must be a bool, got {value!r}"
                    )
                return value
    raise Marker(
        f"{os.path.basename(path)}: no NEEDS_IDA marker.\n"
        f"  Add `NEEDS_IDA = True` (spawns a worker / drives the pilot) or\n"
        f"  `NEEDS_IDA = False` (pure: stdlib, no IDA, runs anywhere) at module\n"
        f"  scope, so tests/run.py --fast knows whether it can run you."
    )


def discover() -> list[tuple[str, bool]]:
    """Every ``tests/test_*.py``, with its IDA requirement. Sorted: fast first,
    so ``run.py`` fails on a cheap file before burning minutes on a pilot."""
    out = []
    problems = []
    for name in sorted(os.listdir(TESTS)):
        if not (name.startswith("test_") and name.endswith(".py")):
            continue
        path = os.path.join(TESTS, name)
        try:
            out.append((path, needs_ida(path)))
        except Marker as exc:
            problems.append(str(exc))
    if problems:
        raise Marker("\n".join(problems))
    out.sort(key=lambda p: (p[1], p[0]))
    return out


def tally(output: str) -> tuple[int, int] | None:
    """The last ``N passed, M failed`` line a suite printed.

    The last one, not the first: test_graph prints a per-section tally on the
    way through and the total at the end.
    """
    found = _TALLY.findall(output)
    if not found:
        return None
    passed, failed = found[-1]
    return int(passed), int(failed)


def run_one(path: str, python: str, extra: list[str], echo: bool) -> dict:
    """Run one test file as a subprocess and summarise it."""
    name = os.path.basename(path)[len("test_") : -len(".py")]
    started = time.time()
    proc = subprocess.run(
        [python, path, *extra], cwd=ROOT, capture_output=not echo, text=True
    )
    took = time.time() - started
    out = "" if echo else (proc.stdout or "") + (proc.stderr or "")
    counts = tally(out)
    skipped = bool(_SKIP.search(out)) and (counts is None or counts == (0, 0))
    return {
        "name": name,
        "path": path,
        "code": proc.returncode,
        "took": took,
        "passed": counts[0] if counts else 0,
        "failed": counts[1] if counts else 0,
        "counted": counts is not None,
        "skipped": skipped,
        "output": out,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="tests/run.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "only",
        nargs="*",
        metavar="SUBSTR",
        help="only run test files whose name contains one of these",
    )
    ap.add_argument(
        "--fast",
        action="store_true",
        help="skip every file that needs IDA (seconds, runs anywhere)",
    )
    ap.add_argument(
        "--ida-only", action="store_true", help="only the files that need IDA"
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="show what would run, and whether it needs IDA",
    )
    ap.add_argument(
        "-x",
        "--exitfirst",
        action="store_true",
        help="stop after the first failing file",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="stream each suite's output instead of capturing it",
    )
    ap.add_argument(
        "--python",
        default=os.environ.get("IDATUI_PYTHON", DEFAULT_PY),
        help=f"interpreter for the IDA suites (default {DEFAULT_PY})",
    )
    args, extra = ap.parse_known_args(argv)

    try:
        files = discover()
    except Marker as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    selected = []
    for path, ida in files:
        if args.fast and ida:
            continue
        if args.ida_only and not ida:
            continue
        if args.only and not any(s in os.path.basename(path) for s in args.only):
            continue
        selected.append((path, ida))

    if not selected:
        print("nothing selected", file=sys.stderr)
        return 2

    if args.list:
        for path, ida in selected:
            print(f"{'ida ' if ida else 'pure'}  {os.path.basename(path)}")
        return 0

    # A pure file runs under whatever python invoked us (it needs nothing);
    # an IDA file needs the interpreter that has textual + idapro.
    pure_py = sys.executable
    if any(ida for _, ida in selected) and not os.path.exists(args.python):
        print(
            f"error: {args.python} not found — the IDA suites need an "
            f"interpreter with textual + idapro.\n"
            f"       Pass --python, set $IDATUI_PYTHON, or use --fast.",
            file=sys.stderr,
        )
        return 2

    results = []
    started = time.time()
    for path, ida in selected:
        label = os.path.basename(path)
        print(f"\033[1m>> {label}\033[0m{' (ida)' if ida else ''}", flush=True)
        res = run_one(path, args.python if ida else pure_py, extra, args.verbose)
        results.append(res)
        bad = res["code"] != 0 or res["failed"]
        if bad and not args.verbose:
            print(res["output"].rstrip())
        elif res["skipped"]:
            print("   skipped")
        else:
            print(f"   {res['passed']} passed  ({res['took']:.1f}s)")
        if bad and args.exitfirst:
            print("\nstopping at the first failure (-x)", file=sys.stderr)
            break

    total = time.time() - started
    print("\n" + "=" * 62)
    width = max(len(r["name"]) for r in results)
    passed = failed = 0
    for r in results:
        passed += r["passed"]
        failed += r["failed"]
        if r["skipped"]:
            state = "\033[33mSKIP\033[0m"
        elif r["code"] != 0 or r["failed"]:
            state = "\033[31mFAIL\033[0m"
        elif not r["counted"]:
            state = "\033[33m ?  \033[0m"  # exit 0 but printed no tally
        else:
            state = "\033[32m ok \033[0m"
        detail = f"{r['passed']:4d} passed"
        if r["failed"]:
            detail += f", \033[31m{r['failed']} failed\033[0m"
        if r["code"] != 0 and not r["failed"]:
            detail += f", \033[31mexit {r['code']}\033[0m"
        print(f" {state}  {r['name']:<{width}}  {detail}   {r['took']:6.1f}s")
    print("=" * 62)

    ran, total_files = len(results), len(selected)
    skipped = sum(1 for r in results if r["skipped"])
    hurt = [r["name"] for r in results if r["code"] != 0 or r["failed"]]
    summary = f"{passed} passed"
    if failed:
        summary += f", {failed} failed"
    if skipped:
        summary += f", {skipped} file(s) skipped"
    if ran != total_files:
        summary += f", {total_files - ran} file(s) not reached"
    print(f"{summary}   [{ran} file(s), {total:.1f}s]")
    if hurt:
        print(f"\033[31mfailing files: {', '.join(hurt)}\033[0m")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
