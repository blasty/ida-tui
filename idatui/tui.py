"""Launcher for the idatui TUI.

  # attach to the single open session on a running server
  python -m idatui.tui

  # attach to a specific session
  python -m idatui.tui --db 80d83396

  # open (or reopen) an arbitrary binary, then drive it
  python -m idatui.tui --open /path/to/binary

The server (supervisor) must already be running (see spawn.sh). --open creates a
session via idb_open; the binary's directory must be writable (idalib writes a
.i64 next to it).
"""
from __future__ import annotations

import argparse
import os

from .app import IdaTui
from .client import DEFAULT_URL


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="idatui", description="Minimal TUI for IDA over MCP")
    p.add_argument("--url", default=os.environ.get("IDA_MCP_URL", DEFAULT_URL),
                   help=f"MCP server URL (default {DEFAULT_URL})")
    p.add_argument("--db", default=os.environ.get("IDA_MCP_DB"),
                   help="attach to an existing session id")
    p.add_argument("--open", metavar="PATH",
                   help="open (or reopen) a binary and drive it (dir must be writable)")
    p.add_argument("--no-keepalive", action="store_true",
                   help="Do not bump idle-TTL / run the keepalive heartbeat")
    p.add_argument("--rpc", metavar="PATH",
                   help="listen for RPC on this unix socket path (puppeteer the TUI)")
    args = p.parse_args(argv)
    rpc_path = os.path.abspath(os.path.expanduser(args.rpc)) if args.rpc else None
    IdaTui(url=args.url, db=args.db, open_path=args.open,
           keepalive=not args.no_keepalive, rpc_path=rpc_path).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
