"""DatabasePool — LRU leases on Code Mode databases for a project.

Code Mode may bind a lease to an existing IDA GUI or to a shared managed idalib
worker. The pool therefore owns *client interest*, never an IDA process. Releasing
an LRU entry persists managed IDBs but does not implicitly save a GUI, then closes
only this TUI's lease; other clients and GUI sessions remain alive. Managed workers exit themselves after their final lease.

The historical memory budget remains useful for managed idalib instances, while
GUI process memory is only advisory. The active and pinned databases are never
released to satisfy it.
"""
from __future__ import annotations

from .project import BinaryRef, Project

#: Fallback budget if /proc/meminfo can't be read (MB).
_FALLBACK_BUDGET_MB = 2048


def _total_ram_mb() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _pss_mb(pid: int | None) -> int:
    """Proportional set size of the leased instance process, in MB.

    PSS is useful for managed idalib workers. For GUI/shared processes it is only
    advisory because the TUI neither owns all that memory nor controls process
    exit.
    """
    if not pid:
        return 0
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if line.startswith("Pss:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _default_spawn(ref: BinaryRef, ttl: int, *, new_database: bool = False):  # pragma: no cover - needs IDA
    from .codemode_client import CodeModeClient
    return CodeModeClient(
        ref.staged,
        ttl=ttl,
        load_args=ref.load_args,
        output_database=ref.db,
        new_database=new_database,
    )


class DatabasePool:
    """Live Code Mode database leases, keyed by project label."""

    def __init__(self, project: Project, *, budget_mb: int | None = None,
                 ttl: int = 1800, spawn=None, mem_fn=None) -> None:
        self.project = project
        self._ttl = ttl
        self._spawn = spawn or _default_spawn
        self._mem = mem_fn or (lambda c: _pss_mb(getattr(c, "pid", None)))
        self._clients: dict[str, object] = {}
        self._lru: list[str] = []       # least-recently-used first
        self._pinned: set[str] = set()
        self._recreate: set[str] = set()  # Ctrl+L: next attachment creates a fresh IDB
        self.active: str | None = None  # never evicted
        if budget_mb is None:
            ram = _total_ram_mb()
            budget_mb = (ram * project.memory_pct // 100) if ram else _FALLBACK_BUDGET_MB
        self.budget_mb = max(budget_mb, 256)
        self.evicted: list[str] = []    # labels evicted, most recent last

    # -- residency --------------------------------------------------------- #
    def resident(self) -> list[str]:
        """Labels with a live worker, least-recently-used first."""
        return list(self._lru)

    def is_resident(self, label: str) -> bool:
        return label in self._clients

    def memory_mb(self) -> int:
        return sum(self._mem(c) for c in self._clients.values())

    def pin(self, label: str, on: bool = True) -> None:
        """Keep ``label`` resident regardless of the budget."""
        self._pinned.add(label) if on else self._pinned.discard(label)

    def is_pinned(self, label: str) -> bool:
        return label in self._pinned

    # -- acquire ----------------------------------------------------------- #
    def get(self, label: str, progress=None):
        """A live client for ``label``, attaching or spawning as needed.

        Do not sweep IDA scratch files here: a registered GUI or another Code
        Mode client may own the database. Code Mode's registry locks and health
        probes are the authority for safe discovery and stale-record cleanup.
        """
        client = self._clients.get(label)
        if client is not None:
            self._touch(label)
            return client
        ref = self.project.by_label(label)
        if ref is None:
            raise KeyError(f"no such binary in the project: {label}")

        def note(msg: str) -> None:
            if progress is not None:
                progress(msg)

        note(f"staging {ref.label}\u2026")
        self.project.stage(ref)
        note(f"opening {ref.label}\u2026")
        fresh = label in self._recreate
        client = (_default_spawn(ref, self._ttl, new_database=fresh)
                  if self._spawn is _default_spawn else self._spawn(ref, self._ttl))
        connect = getattr(client, "connect", None)
        if connect is not None:
            connect(progress=progress) if progress is not None else connect()
        self._clients[label] = client
        self._recreate.discard(label)
        self._lru.append(label)
        self._enforce_budget(protect=label)
        return client

    def prewarm(self, label: str, progress=None) -> bool:
        """Attach a database for ``label`` only if it fits the current budget.

        Pre-warming must never cost residency: evicting a binary the user
        actually visited to speculatively load one they haven't is a straight
        downgrade, and the eviction would also throw away that binary's caches.
        So this refuses rather than making room, and returns False.

        The cost of a database not attached yet can only be estimated; the
        largest resident instance is the best evidence available. With nothing resident we have
        no evidence at all, so we allow one — that is the case where the budget
        is certainly free.
        """
        if label in self._clients:
            return False
        if self.project.by_label(label) is None:
            return False
        used = self.memory_mb()
        est = max((self._mem(c) for c in self._clients.values()), default=0)
        if used + est > self.budget_mb:
            return False
        self.get(label, progress=progress)
        # get() enforces the budget protecting the NEW label; if that had to
        # evict, our estimate was wrong and the speculative lease is the one
        # that should go — never a binary the user chose.
        if self.memory_mb() > self.budget_mb and label != self.active:
            self.evict(label)
            return False
        return True

    def recreate_on_next_open(self, label: str) -> None:
        """Request a fresh IDB after the current lease has been released."""
        if self.project.by_label(label) is None:
            raise KeyError(f"no such binary in the project: {label}")
        self._recreate.add(label)

    def _touch(self, label: str) -> None:
        if label in self._lru:
            self._lru.remove(label)
            self._lru.append(label)

    def set_active(self, label: str | None) -> None:
        self.active = label
        if label:
            self._touch(label)

    # -- release ----------------------------------------------------------- #
    def evict(self, label: str, save: bool = True,
              save_gui: bool = False) -> bool:
        """Release a resident lease, persisting a managed database first.

        A budget-driven eviction must not save somebody's GUI implicitly. GUI
        saves are reserved for an explicit/defensive ``close_all(save=True)``.
        """
        client = self._clients.pop(label, None)
        if client is None:
            return False
        if label in self._lru:
            self._lru.remove(label)
        if save and (save_gui or getattr(client, "backend", None) != "gui"):
            try:  # persist analysis + edits so the next open is a load
                client.save_database()
            except Exception:  # noqa: BLE001 -- evict regardless
                pass
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        self.evicted.append(label)
        return True

    def _evictable(self, protect: str | None) -> str | None:
        for label in self._lru:  # least-recently-used first
            if label == protect or label == self.active or label in self._pinned:
                continue
            return label
        return None

    def _enforce_budget(self, protect: str | None = None) -> int:
        """Release LRU leases until the pool fits its budget. Returns how many."""
        n = 0
        while self.memory_mb() > self.budget_mb:
            victim = self._evictable(protect)
            if victim is None:  # everything left is active/pinned/protected
                break
            self.evict(victim)
            n += 1
        return n

    def close_all(self, save: bool = True) -> None:
        for label in list(self._clients):
            self.evict(label, save=save, save_gui=save)
        self.active = None

    # -- introspection ------------------------------------------------------ #
    def status(self) -> list[dict]:
        """Per-binary residency for the switcher UI."""
        out = []
        for ref in self.project.refs:
            client = self._clients.get(ref.label)
            out.append({
                "label": ref.label,
                "source": ref.source,
                "resident": client is not None,
                "pinned": ref.label in self._pinned,
                "active": ref.label == self.active,
                "analysed": self.project.has_db(ref),
                "memory_mb": self._mem(client) if client is not None else 0,
            })
        return out

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (f"<DatabasePool {len(self._clients)}/{len(self.project.refs)} resident "
                f"{self.memory_mb()}/{self.budget_mb}MB active={self.active}>")


# Source compatibility for callers that imported the pre-Code-Mode name.
WorkerPool = DatabasePool
