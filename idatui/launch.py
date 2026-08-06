"""One-shot launcher: ``ida-tui foo.elf`` and you're in the TUI.

Spawns a private idalib worker (``idatui.worker``) that opens + auto-analyzes
THIS binary in its own process, talking to the TUI over a unix socket. No shared
supervisor, no HTTP: everything slow (open + analysis) happens behind the TUI's
loading overlay.

Usage:

    ida-tui /path/to/binary          # open a binary and drive it

Extras: --ttl, --no-keepalive, --rpc (all forwarded to the TUI).
"""
from __future__ import annotations

import argparse
import os
import sys

# The unpacked working-copy files IDA writes next to a `.i64` while a database is
# open. A hard-killed worker leaves them behind and the `.i64` then refuses to
# reopen ("Failed to open database"). Safe to delete when nothing holds the DB.
_LOCK_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


def _load_args(load: dict) -> str:
    """``load`` as IDA switches, for the single-binary path (no project ref)."""
    from .formats import load_args
    return load_args(load.get("processor", ""), int(load.get("base", 0) or 0),
                     str(load.get("ida_args", "") or ""))


def _log(msg: str) -> None:
    print(f"ida-tui: {msg}", file=sys.stderr)


def _sweep_locks(binary: str) -> int:
    """Remove stale unpacked DB files next to ``binary``. Returns how many."""
    stem = os.path.splitext(binary)[0]
    n = 0
    for base in (binary, stem):  # IDA may key on the full name or the stem
        for suf in _LOCK_SUFFIXES:
            try:
                os.remove(base + suf)
                n += 1
            except OSError:
                pass
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ida-tui",
        description="Open a binary in the IDA TUI (private idalib worker).")
    p.add_argument("binary", nargs="*",
                   help="binary to open and analyze (several with --project "
                        "creates/extends that project)")
    p.add_argument("--project", metavar="FILE",
                   help="open a multi-binary project (created from the given "
                        "binaries if FILE doesn't exist)")
    p.add_argument("--ttl", type=int, default=1800,
                   help="worker idle-TTL seconds (default 1800)")
    p.add_argument("--no-keepalive", action="store_true",
                   help="do not run the keepalive heartbeat")
    p.add_argument("--rpc", metavar="PATH",
                   help="listen for RPC on this unix socket (puppeteer the TUI)")
    p.add_argument("--trace", metavar="FILE",
                   help="Tenet execution trace to explore alongside the binary")
    g = p.add_argument_group(
        "loading a headerless blob",
        "An ELF/PE/Mach-O says what it is. A raw firmware dump doesn't, and IDA "
        "falls back to x86 at address 0 — which analyses to nothing. These say "
        "how to read it, and are recorded per binary in a project.")
    g.add_argument("--processor", metavar="NAME",
                   help="IDA processor: arm, armb (big-endian), mipsb, metapc, …")
    g.add_argument("--base", metavar="ADDR",
                   help="load address, e.g. 0x8000000 (any base; NOT paragraphs)")
    g.add_argument("--ida-args", metavar="STR", dest="ida_args",
                   help="extra IDA command-line switches, passed through as-is")
    args = p.parse_args(argv)

    load: dict = {}
    if args.processor:
        load["processor"] = args.processor
    if args.base:
        try:
            base = int(args.base, 0)
        except ValueError:
            _log(f"--base must be a number (got {args.base!r})")
            return 2
        if base % 16:
            # -b is in paragraphs, so an unaligned base cannot be expressed and
            # would silently load somewhere else.
            _log(f"--base must be 16-byte aligned (got {base:#x})")
            return 2
        load["base"] = base
    if args.ida_args:
        load["ida_args"] = args.ida_args

    project = None
    binary = None
    if args.project:
        from .project import Project, ProjectError
        ppath = os.path.abspath(os.path.expanduser(args.project))
        try:
            if os.path.isfile(ppath):
                project = Project.load(ppath)
                if args.binary:  # extend an existing project, skipping repeats
                    before = len(project.refs)
                    for b in args.binary:
                        project.add(b, load=load or None)
                    added = len(project.refs) - before
                    dupes = len(args.binary) - added
                    if added:
                        project.save()
                        _log(f"added {added} binary(ies) to {ppath}")
                    if dupes:
                        _log(f"{dupes} already in the project (matched by path) "
                             f"— left alone")
            elif args.binary:
                project = Project.create(ppath, args.binary, load=load or None)
                _log(f"created project {ppath} with {len(project.refs)} binaries")
            else:
                _log(f"no such project: {ppath} (pass binaries to create it)")
                return 2
        except ProjectError as e:
            _log(str(e))
            return 2
        # Everything IDA writes lives in the project's sidecar, so the source
        # tree is never touched and never needs to be writable.
        try:
            project.stage_all(progress=lambda m: _log(m))
        except ProjectError as e:
            _log(str(e))
            return 2
    else:
        if len(args.binary) != 1:
            _log("give exactly one binary, or use --project for several")
            return 2
        binary = os.path.abspath(os.path.expanduser(args.binary[0]))
        if not os.path.isfile(binary):
            _log(f"no such file: {binary}")
            return 2
        if not os.access(os.path.dirname(binary), os.W_OK):
            _log(f"directory not writable (IDA writes a .i64 there): "
                 f"{os.path.dirname(binary)}")
            return 2
        swept = _sweep_locks(binary)  # a crashed worker can leave the DB wedged
        if swept:
            _log(f"cleared {swept} stale lock file(s) from a crashed worker")

    # Hand off to the TUI (imported late so --help works without textual). It
    # spawns the worker behind its loading overlay while auto-analysis runs.
    try:
        from .app import IdaTui
    except ImportError as e:
        _log(f"the TUI needs textual; run with ~/ida-venv/bin/python  ({e})")
        return 1
    # Ask the terminal about graphics support NOW: the query needs a reply from
    # stdin, and once Textual starts it reads stdin on its own thread and would
    # swallow it. Only the ANSWER is wanted here -- the image itself is uploaded
    # later, by the splash, because an image uploaded to the primary screen
    # cannot be placed once Textual has switched to the alternate one. Costs one
    # round trip, and only when attached to a tty.
    try:
        from . import kittygfx
        kittygfx.supported()
    except Exception:  # noqa: BLE001 -- graphics are decoration, never fatal
        pass

    rpc_path = os.path.abspath(os.path.expanduser(args.rpc)) if args.rpc else None
    IdaTui(open_path=binary, keepalive=not args.no_keepalive,
           rpc_path=rpc_path, ttl=args.ttl, project=project,
           load_args=_load_args(load),
           trace_path=(os.path.abspath(os.path.expanduser(args.trace))
                       if args.trace else "")).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
