"""Launcher:  python -m idatui.tui [--url URL] [--db SESSION] [--no-keepalive]"""
from __future__ import annotations

import argparse
import os

from .app import IdaTui
from .client import DEFAULT_URL


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="idatui", description="Minimal TUI for IDA over MCP")
    p.add_argument("--url", default=os.environ.get("IDA_MCP_URL", DEFAULT_URL))
    p.add_argument("--db", default=os.environ.get("IDA_MCP_DB"))
    p.add_argument("--no-keepalive", action="store_true",
                   help="Do not bump idle-TTL / run the keepalive heartbeat")
    args = p.parse_args(argv)
    IdaTui(url=args.url, db=args.db, keepalive=not args.no_keepalive).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
