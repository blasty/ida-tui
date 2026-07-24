"""``python -m idatui`` -> the one-shot launcher (open a binary in the TUI)."""
import sys

from .launch import main

raise SystemExit(main(sys.argv[1:]))
