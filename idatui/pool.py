"""WorkerPool — keeps a live idalib worker per project binary, within a budget.

One worker process holds exactly one database (idalib is single-DB and
main-thread-only), so a project with N binaries means up to N processes. They are
not cheap and they do not share: a worker on ``bash`` measures ~126 MB RSS /
117 MB PSS, and the database working set dominates for anything larger
(``libcrypto.so.3``'s ``.i64`` alone is 72 MB).

Residency is therefore bounded by a **memory budget**, not a worker count — a
count is the wrong knob when one project holds both a 50 KB helper and a 6 MB
crypto library. Workers are spawned lazily on first use, kept resident while they
fit, and least-recently-used ones evicted when they don't. Eviction **saves the
database first**, so coming back is a load rather than a re-analysis.

The pool never evicts the active binary, nor anything pinned.
"""
from __future__ import annotations

import os

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
    """Proportional set size of a worker, in MB.

    PSS (not RSS) is the honest per-worker cost: it splits shared pages between
    the processes mapping them. In practice workers share very little, so the two
    are close, but PSS is what makes summing across workers meaningful.
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


def _default_spawn(ref: BinaryRef, ttl: int):  # pragma: no cover - needs idalib
    from .worker_client import WorkerClient
    return WorkerClient(ref.staged, ttl=ttl, load_args=ref.load_args)


class WorkerPool:
    """Live workers for a project's binaries, keyed by label."""

    def __init__(self, project: Project, *, budget_mb: int | None = None,
                 ttl: int = 1800, spawn=None, mem_fn=None) -> None:
        self.project = project
        self._ttl = ttl
        self._spawn = spawn or _default_spawn
        self._mem = mem_fn or (lambda c: _pss_mb(getattr(c, "pid", None)))
        self._clients: dict[str, object] = {}
        self._lru: list[str] = []       # least-recently-used first
        self._pinned: set[str] = set()
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
        """A live client for ``label``, spawning it (and making room) if needed.

        Staging and the scratch sweep happen here: a worker killed hard last time
        leaves unpacked ``.id0/.id1/...`` behind, and the database then refuses to
        reopen. Nothing else holds this DB (one worker per label), so it is safe.
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
        self.project.sweep_scratch(ref)
        note(f"opening {ref.label}\u2026")
        client = self._spawn(ref, self._ttl)
        connect = getattr(client, "connect", None)
        if connect is not None:
            connect(progress=progress) if progress is not None else connect()
        self._clients[label] = client
        self._lru.append(label)
        self._enforce_budget(protect=label)
        return client

    def prewarm(self, label: str, progress=None) -> bool:
        """Spawn a worker for ``label`` only if it fits the budget AS IT STANDS.

        Pre-warming must never cost residency: evicting a binary the user
        actually visited to speculatively load one they haven't is a straight
        downgrade, and the eviction would also throw away that binary's caches.
        So this refuses rather than making room, and returns False.

        The cost of a worker that doesn't exist yet can only be estimated; the
        largest resident one is the best evidence available (they are all the
        same program with a different database). With nothing resident we have
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
        # evict, our estimate was wrong and the speculative worker is the one
        # that should go — never a binary the user chose.
        if self.memory_mb() > self.budget_mb and label != self.active:
            self.evict(label)
            return False
        return True

    def _touch(self, label: str) -> None:
        if label in self._lru:
            self._lru.remove(label)
            self._lru.append(label)

    def set_active(self, label: str | None) -> None:
        self.active = label
        if label:
            self._touch(label)

    # -- release ----------------------------------------------------------- #
    def evict(self, label: str, save: bool = True) -> bool:
        """Drop a resident worker, persisting its database first."""
        client = self._clients.pop(label, None)
        if client is None:
            return False
        if label in self._lru:
            self._lru.remove(label)
        if save:
            try:  # persist analysis + edits so the next open is a load
                client.call("idb_save")
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
        """Evict LRU workers until the pool fits its budget. Returns how many."""
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
            self.evict(label, save=save)
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
        return (f"<WorkerPool {len(self._clients)}/{len(self.project.refs)} resident "
                f"{self.memory_mb()}/{self.budget_mb}MB active={self.active}>")
