"""ProjectIndex — one searchable index over every binary in a project.

Phase 2 of docs/PROJECTS.md: searching across binaries must work for binaries
whose worker isn't running, so the index lives on disk rather than in the
Programs' caches.

SQLite FTS5 with the **trigram** tokenizer, which is stdlib (no dependency) and
indexes arbitrary *substrings* rather than just word prefixes — the right shape
for symbol names and string literals. Measured on a 300k-entry corpus: 1.9 ms per
substring query (vs 11.8 ms for a Python scan and 28.9 ms for plain LIKE), 0.2 ms
per incremental insert.

Sizing, from real binaries: libcrypto.so.3 (5.9 MB, ~10k functions + ~20k
strings) contributes 0.52 MB of text, and the index runs ~5.7x the text it
covers. A 20-binary project therefore lands around 12-23 MB — against the ``.i64``
files already in the sidecar, where libcrypto's alone is 72 MB. The index is
roughly 1% of what the project already costs on disk.

Caveat baked into ``search``: a trigram index cannot answer queries shorter than
three characters — it silently returns nothing rather than erroring — so short
queries fall back to LIKE. Without that, typing "e" then "er" would show "no
matches" until the third keystroke.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass

#: Trigram indexes can't match fewer than 3 characters; below this we scan.
MIN_TRIGRAM = 3

KIND_FUNC = "func"
KIND_STRING = "string"
#: Cross-binary linkage: what a binary takes from, and offers to, other modules.
KIND_IMPORT = "import"
KIND_EXPORT = "export"


@dataclass(frozen=True)
class Hit:
    """One index match."""

    binary: str
    kind: str
    addr: int
    text: str


def _fts_phrase(query: str) -> str:
    """``query`` as an FTS5 phrase: quoted so operators are literal, with any
    embedded quote doubled."""
    return '"' + query.replace('"', '""') + '"'


class ProjectIndex:
    """Symbol/string index for a whole project, keyed by binary label."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # check_same_thread=False: the TUI indexes from a worker thread and
        # queries from the UI thread. Writes are serialised by the caller.
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS entries USING fts5(
                text,
                binary UNINDEXED, kind UNINDEXED, addr UNINDEXED,
                tokenize='trigram');
            CREATE TABLE IF NOT EXISTS stamps(
                binary TEXT PRIMARY KEY,
                size INTEGER, mtime INTEGER, n INTEGER);
            """
        )
        self._db.commit()

    # -- freshness --------------------------------------------------------- #
    def stamp(self, label: str) -> tuple[int, int, int] | None:
        """(size, mtime, entry count) recorded when ``label`` was last indexed."""
        row = self._db.execute(
            "SELECT size, mtime, n FROM stamps WHERE binary = ?", (label,)
        ).fetchone()
        return tuple(row) if row else None  # type: ignore[return-value]

    def is_stale(self, label: str, source: str) -> bool:
        """True when ``label`` has never been indexed, or its source changed."""
        st = self.stamp(label)
        if st is None:
            return True
        try:
            s = os.stat(source)
        except OSError:
            return False  # source gone: keep what we have rather than wipe it
        return (st[0], st[1]) != (s.st_size, int(s.st_mtime))

    # -- population -------------------------------------------------------- #
    def reindex(self, label: str, entries, source: str | None = None) -> int:
        """Replace ``label``'s entries with ``entries`` — (kind, addr, text)
        triples. Per-binary, so re-indexing one never touches the others."""
        rows = [(text, label, kind, int(addr)) for kind, addr, text in entries if text]
        self._db.execute("DELETE FROM entries WHERE binary = ?", (label,))
        self._db.executemany(
            "INSERT INTO entries(text, binary, kind, addr) VALUES(?,?,?,?)", rows
        )
        size = mtime = 0
        if source:
            try:
                s = os.stat(source)
                size, mtime = s.st_size, int(s.st_mtime)
            except OSError:
                pass
        self._db.execute(
            "INSERT INTO stamps(binary, size, mtime, n) VALUES(?,?,?,?) "
            "ON CONFLICT(binary) DO UPDATE SET size=?, mtime=?, n=?",
            (label, size, mtime, len(rows), size, mtime, len(rows)),
        )
        self._db.commit()
        return len(rows)

    def forget(self, label: str) -> None:
        """Drop a binary from the index (removed from the project)."""
        self._db.execute("DELETE FROM entries WHERE binary = ?", (label,))
        self._db.execute("DELETE FROM stamps WHERE binary = ?", (label,))
        self._db.commit()

    # -- query -------------------------------------------------------------- #
    def search(
        self, query: str, kind: str | None = None, limit: int = 500
    ) -> list[Hit]:
        """Substring search across every indexed binary, newest-agnostic.

        Uses the trigram index at >= 3 characters and falls back to a LIKE scan
        below that (the index can't answer shorter queries and would silently
        return nothing).
        """
        q = (query or "").strip()
        if not q:
            return []
        sql = ["SELECT binary, kind, addr, text FROM entries WHERE "]
        args: list = []
        if len(q) >= MIN_TRIGRAM:
            sql.append("text MATCH ?")
            args.append(_fts_phrase(q))
        else:
            sql.append("text LIKE ?")
            args.append(f"%{q}%")
        if kind:
            sql.append(" AND kind = ?")
            args.append(kind)
        sql.append(" LIMIT ?")
        args.append(int(limit))
        try:
            rows = self._db.execute("".join(sql), args).fetchall()
        except sqlite3.OperationalError:
            return []  # malformed FTS expression: treat as no matches
        return [Hit(binary=b, kind=k, addr=int(a), text=t) for b, k, a, t in rows]

    def exact(self, name: str, kind: str, exclude: str | None = None) -> list[Hit]:
        """Every entry whose text is EXACTLY ``name``, for the linkage join.

        Deliberately not ``search()``: an import must resolve to the export of
        that name, not to everything containing it (``read`` would otherwise
        match ``pread``, ``read_line``, ``thread_start``). Exact match also
        works below the trigram floor, which matters — plenty of real exports
        are one or two characters.
        """
        n = (name or "").strip()
        if not n:
            return []
        sql = "SELECT binary, kind, addr, text FROM entries WHERE text = ? AND kind = ?"
        args: list = [n, kind]
        if exclude:
            sql += " AND binary <> ?"
            args.append(exclude)
        rows = self._db.execute(sql + " ORDER BY binary, addr", args).fetchall()
        return [Hit(binary=b, kind=k, addr=int(a), text=t) for b, k, a, t in rows]

    def providers(self, name: str, exclude: str | None = None) -> list[Hit]:
        """Binaries in the project that EXPORT ``name`` (skip ``exclude``, the
        binary asking). This is the 'follow an import to its implementation'
        half of the join."""
        return self.exact(name, KIND_EXPORT, exclude)

    def importers(self, name: str, exclude: str | None = None) -> list[Hit]:
        """Binaries in the project that IMPORT ``name`` — 'who in the project
        calls this export'."""
        return self.exact(name, KIND_IMPORT, exclude)

    # -- introspection ------------------------------------------------------ #
    def counts(self) -> dict[str, int]:
        """Indexed entry count per binary."""
        return {
            b: n for b, n in self._db.execute("SELECT binary, n FROM stamps").fetchall()
        }

    def total(self) -> int:
        return int(self._db.execute("SELECT count(*) FROM entries").fetchone()[0])

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:  # noqa: BLE001
            pass

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<ProjectIndex {self.total()} entries {self.path}>"
