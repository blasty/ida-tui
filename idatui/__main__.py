"""``python -m idatui`` -> client self-check (until the TUI app lands)."""
import sys

from .client import _main

raise SystemExit(_main(sys.argv[1:]))
