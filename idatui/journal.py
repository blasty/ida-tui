"""A record of the edits idatui makes, kept inside the database.

**Why this has to exist.** A findings report wants to say "here is what *you*
worked out", and the database cannot answer that. IDA's own analyzer writes
comments with the same `set_cmt` a person uses (`; s1` on an argument setup,
`; switch 73 cases` on a jump table), and the loader writes both comments and
names for the file header. Four separate probes agree that nothing tells them
apart: the `FF_COMM` flag is identical, `get_cmt` returns them all, the colour
tag in `generate_disasm_line` is `COLOR_REGCMT` for every one of them, and they
survive with auto-comments switched off. So authorship is not recoverable after
the fact -- it has to be recorded as it happens, which is what this does.

It lives in an IDA **netnode**, so it is saved into the `.i64` with everything
else and is still there next session. The entries are small and additive; the
journal is metadata *about* edits that themselves live in the database, so
losing it degrades the report to a heuristic rather than losing work.
"""

from __future__ import annotations

import json
import threading
import time

#: Where the blob lives inside the database.
NODE = "$ idatui.journal"

#: Cap: a long session is hundreds of edits, not hundreds of thousands, and the
#: blob is rewritten whole. Oldest entries fall off first.
MAX_ENTRIES = 20000


class Journal:
    """Append-only log of what was edited, with lazy load and explicit flush.

    Writing through to the database on every keystroke-sized edit would put a
    round trip in the way of the user; the in-memory list is authoritative
    during a session and :meth:`flush` persists it at the points that already
    mean "keep this": saving, exporting, and quitting.
    """

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self._dirty = False
        self._loaded = False
        self._lock = threading.Lock()

    # -- recording ---------------------------------------------------------- #
    def record(
        self,
        kind: str,
        ea: int | None = None,
        detail: str = "",
        extra: dict | None = None,
    ) -> None:
        """Note one edit: ``kind`` is 'rename' / 'comment' / 'retype' / …"""
        entry = {"k": str(kind), "t": int(time.time())}
        if ea is not None:
            entry["ea"] = int(ea)
        if detail:
            entry["d"] = str(detail)[:400]
        if extra:
            entry.update(extra)
        with self._lock:
            self.entries.append(entry)
            if len(self.entries) > MAX_ENTRIES:
                del self.entries[: len(self.entries) - MAX_ENTRIES]
            self._dirty = True

    def addresses(self, kinds: tuple[str, ...] | None = None) -> set[int]:
        """Every address touched (optionally only by certain kinds of edit)."""
        with self._lock:
            return {
                e["ea"]
                for e in self.entries
                if "ea" in e and (kinds is None or e.get("k") in kinds)
            }

    def __len__(self) -> int:
        return len(self.entries)

    # -- persistence -------------------------------------------------------- #
    def load(self, program) -> None:
        """Read the journal out of the database, once. Never raises."""
        if self._loaded:
            return
        self._loaded = True
        try:
            raw = program.journal_get()
        except Exception:  # noqa: BLE001 -- an old database simply has none
            return
        if not raw:
            return
        try:
            data = json.loads(raw)
        except Exception:  # noqa: BLE001
            return
        if isinstance(data, list):
            with self._lock:
                # Prepend: what is already in memory happened later.
                self.entries = [e for e in data if isinstance(e, dict)] + self.entries

    def flush(self, program) -> bool:
        """Write the journal back if it changed. Returns whether it wrote."""
        with self._lock:
            if not self._dirty:
                return False
            payload = json.dumps(self.entries, separators=(",", ":"))
        try:
            program.journal_put(payload)
        except Exception:  # noqa: BLE001 -- never let bookkeeping break an edit
            return False
        with self._lock:
            self._dirty = False
        return True
