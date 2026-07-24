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
    p.add_argument("binary", help="binary to open and analyze")
    p.add_argument("--ttl", type=int, default=1800,
                   help="worker idle-TTL seconds (default 1800)")
    p.add_argument("--no-keepalive", action="store_true",
                   help="do not run the keepalive heartbeat")
    p.add_argument("--rpc", metavar="PATH",
                   help="listen for RPC on this unix socket (puppeteer the TUI)")
    args = p.parse_args(argv)

    binary = os.path.abspath(os.path.expanduser(args.binary))
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
    rpc_path = os.path.abspath(os.path.expanduser(args.rpc)) if args.rpc else None
    IdaTui(open_path=binary, keepalive=not args.no_keepalive,
           rpc_path=rpc_path, ttl=args.ttl).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
