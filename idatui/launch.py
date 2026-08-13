"""One-shot launcher for the IDA Code Mode-backed TUI.

A path first resolves to a registered GUI database; when none matches, Code Mode
reuses or starts a managed idalib worker. With no path, a single registered
database is selected automatically.

Usage::

    ida-tui /path/to/binary
    ida-tui                         # attach when exactly one database is registered
"""
from __future__ import annotations

import argparse
import os
import sys

def _load_args(load: dict) -> str:
    """``load`` as IDA switches, for the single-binary path (no project ref).

    The base goes through project._as_addr rather than bare int(): our own CLI
    hands over an int, but a project file writes "0x8000000" as a string and
    int() raises on that. One parser, so the two paths can't disagree about what
    an address looks like.
    """
    from .formats import load_args
    from .project import _as_addr
    return load_args(load.get("processor", ""), _as_addr(load.get("base", 0)),
                     str(load.get("ida_args", "") or ""))


def _log(msg: str) -> None:
    print(f"ida-tui: {msg}", file=sys.stderr)


def _registered_databases() -> tuple[list[dict], list[dict]]:
    """Ready and blocked Code Mode registrations, with normalized errors."""
    try:
        from ida_codemode import InstanceState, discover_databases

        ready: list[dict] = []
        blocked: list[dict] = []
        for discovered in discover_databases():
            instance = discovered.instance
            item = {
                "record_id": instance.record_id,
                "backend": instance.backend,
                "pid": instance.pid,
                "exe_path": instance.exe_path,
                "idb_path": instance.idb_path,
            }
            if discovered.state is InstanceState.READY:
                ready.append(item)
            else:
                item["error"] = discovered.detail or "instance is unavailable"
                blocked.append(item)
        return ready, blocked
    except Exception as exc:  # discovery diagnostics belong at the CLI boundary
        return [], [{"error": str(exc)}]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ida-tui",
        description="Open a registered GUI or managed idalib database in the IDA TUI.")
    p.add_argument("binary", nargs="*",
                   help="binary to open and analyze (several with --project "
                        "creates/extends that project)")
    p.add_argument("--project", metavar="FILE",
                   help="open a multi-binary project (created from the given "
                        "binaries if FILE doesn't exist)")
    p.add_argument("--ttl", type=int, default=1800,
                   help="deprecated compatibility option (Code Mode uses leases)")
    p.add_argument("--no-keepalive", action="store_true",
                   help="deprecated compatibility option (the lease is the heartbeat)")
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
                   help="legacy switches; only Code Mode-representable -p/-b/-T are accepted")
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
        ready, blocked = _registered_databases()
        if len(args.binary) > 1:
            _log("give at most one binary, or use --project for several")
            return 2
        if args.binary:
            binary = os.path.abspath(os.path.expanduser(args.binary[0]))
            key = os.path.normcase(os.path.realpath(binary))
            registered = any(
                key == os.path.normcase(os.path.realpath(str(item.get(field) or "")))
                for item in ready for field in ("exe_path", "idb_path")
                if item.get(field)
            )
            if not os.path.isfile(binary) and not registered:
                _log(f"no such file or registered database: {binary}")
                return 2
        elif len(ready) == 1:
            item = ready[0]
            binary = str(item.get("exe_path") or item.get("idb_path") or "")
            _log(f"attaching to registered {item.get('backend')} database: {binary}")
        elif not ready:
            detail = f" ({blocked[0].get('error')})" if blocked else ""
            _log(f"no registered Code Mode database; pass a binary path{detail}")
            return 2
        else:
            _log("several Code Mode databases are registered; pass one of these paths:")
            for item in ready:
                _log(f"  {item.get('exe_path') or item.get('idb_path')} "
                     f"[{item.get('backend')}, {item.get('record_id')}]")
            return 2

    # Hand off to the TUI (imported late so --help works without Textual). Code
    # Mode discovery/opening happens behind its loading overlay.
    try:
        from .app import IdaTui
    except ImportError as e:
        _log(f"TUI dependencies are missing; run `uv sync` ({e})")
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
