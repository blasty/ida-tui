#!/usr/bin/env python3
"""Unit tests for idatui.pool (IDA Nexus lease residency and LRU budget).

A fake client keeps the policy testable without IDA or Textual.

    python tests/test_pool.py
"""

#: worker residency policy, with a fake client injected.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.pool import DatabasePool  # noqa: E402
from idatui.project import Project  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


class FakeClient:
    """Stands in for a NexusClient lease and records saves/closes."""

    def __init__(self, ref, mem=100, backend="idalib", discardable=True):
        self.ref = ref
        self.mem = mem
        self.backend = backend
        self.saved = 0
        self.discarded = 0
        self.discardable = discardable
        self.closed = False
        self.connected = False

    def connect(self, progress=None, **kw):
        self.connected = True
        return self

    def save_database(self):
        self.saved += 1
        return {"saved": True}

    def discard_database(self):
        self.discarded += 1
        return self.discardable

    def close(self, grace=None):
        self.closed = True


def _mkproject(tmp, n=4, size=64):
    src = os.path.join(tmp, "src")
    os.makedirs(src, exist_ok=True)
    paths = []
    for i in range(n):
        p = os.path.join(src, f"bin{i}")
        with open(p, "wb") as f:
            f.write(b"\x7fELF" + bytes(size))
        paths.append(p)
    return Project.create(os.path.join(tmp, "p.json"), paths, name="p")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        proj = _mkproject(tmp)
        made = {}

        def spawn(ref, ttl):
            c = FakeClient(ref, mem=100)
            made[ref.label] = c
            return c

        pool = DatabasePool(proj, budget_mb=350, spawn=spawn, mem_fn=lambda c: c.mem)

        # -- lazy spawn + reuse -------------------------------------------- #
        a = pool.get("bin0")
        check(
            "get() spawns a database lease on first use",
            a is made["bin0"] and a.connected,
        )
        check(
            "get() stages the binary first",
            os.path.isfile(proj.by_label("bin0").staged),
        )
        check("get() reuses the resident lease", pool.get("bin0") is a)
        check("resident() reports it", pool.resident() == ["bin0"], pool.resident())

        # -- LRU ordering ---------------------------------------------------- #
        pool.get("bin1")
        pool.get("bin2")
        pool.get("bin0")  # touch: bin0 becomes most-recent
        check(
            "LRU order tracks use",
            pool.resident() == ["bin1", "bin2", "bin0"],
            pool.resident(),
        )

        # -- budget eviction -------------------------------------------------- #
        check("pool reports its memory", pool.memory_mb() == 300, pool.memory_mb())
        pool.get("bin3")  # 400MB > 350MB budget -> evict LRU (bin1)
        check(
            "exceeding the budget evicts the least-recently-used",
            pool.evicted == ["bin1"] and not pool.is_resident("bin1"),
            f"evicted={pool.evicted} resident={pool.resident()}",
        )
        check("the just-attached lease is never the victim", pool.is_resident("bin3"))
        check("eviction saves the database first", made["bin1"].saved == 1)
        check("eviction closes the lease", made["bin1"].closed)
        check(
            "pool is back within budget",
            pool.memory_mb() <= pool.budget_mb,
            f"{pool.memory_mb()}/{pool.budget_mb}",
        )

        # -- the active binary is never evicted ------------------------------- #
        pool.set_active("bin2")
        check(
            "set_active touches the LRU", pool.resident()[-1] == "bin2", pool.resident()
        )
        pool.get("bin1")  # over budget again -> must evict, but not bin2
        check(
            "the active binary survives eviction",
            pool.is_resident("bin2"),
            f"resident={pool.resident()}",
        )

        # -- pinning ---------------------------------------------------------- #
        pool.close_all()
        pool2 = DatabasePool(proj, budget_mb=250, spawn=spawn, mem_fn=lambda c: c.mem)
        pool2.get("bin0")
        pool2.pin("bin0")
        pool2.get("bin1")
        pool2.get("bin2")  # 300 > 250 -> evict, but bin0 is pinned
        check(
            "pinned binaries are never evicted",
            pool2.is_resident("bin0"),
            f"resident={pool2.resident()} evicted={pool2.evicted}",
        )
        check("an unpinned one went instead", "bin1" in pool2.evicted, pool2.evicted)

        # -- everything pinned/active: stop evicting rather than thrash -------- #
        pool2.pin("bin2")
        pool2.set_active("bin2")
        n_before = len(pool2.evicted)
        pool2._enforce_budget()
        check(
            "nothing evictable -> gives up instead of thrashing",
            len(pool2.evicted) == n_before,
            pool2.evicted,
        )

        # -- status for the switcher UI ---------------------------------------- #
        st = {s["label"]: s for s in pool2.status()}
        check("status() covers every project binary", len(st) == 4, list(st))
        check(
            "status() marks resident/pinned/active",
            st["bin0"]["resident"]
            and st["bin0"]["pinned"]
            and st["bin2"]["active"]
            and not st["bin3"]["resident"],
            f"{st}",
        )

        # -- teardown ----------------------------------------------------------- #
        pool2.close_all()
        check(
            "close_all() closes every lease",
            not pool2.resident() and all(c.closed for c in made.values()),
        )
        check("close_all() clears the active binary", pool2.active is None)

        # -- unknown label -------------------------------------------------------- #
        try:
            pool2.get("nope")
            check("an unknown label raises KeyError", False, "no raise")
        except KeyError:
            check("an unknown label raises KeyError", True)

        # -- discard delegates shared/GUI finalization ------------------------ #
        discard_made = {}

        def spawn_discard(ref, ttl):
            client = FakeClient(ref, discardable=ref.label != "bin1")
            discard_made[ref.label] = client
            return client

        discard_pool = DatabasePool(proj, spawn=spawn_discard, mem_fn=lambda c: c.mem)
        discard_pool.get("bin0")
        discard_pool.get("bin1")
        delegated = discard_pool.discard_changes(["bin0", "bin1"])
        check(
            "discard asks every dirty resident database",
            discard_made["bin0"].discarded == 1 and discard_made["bin1"].discarded == 1,
            {k: c.discarded for k, c in discard_made.items()},
        )
        check(
            "discard reports leases whose finalization transferred",
            delegated == ["bin1"],
            delegated,
        )
        old = discard_made["bin0"]
        replacement = FakeClient(proj.by_label("bin0"))
        check(
            "replace_client refuses a stale lease generation",
            discard_pool.replace_client("bin0", object(), replacement) is False
            and discard_pool.get("bin0") is old,
        )
        check(
            "replace_client installs the reattached lease",
            discard_pool.replace_client("bin0", old, replacement) is True
            and discard_pool.get("bin0") is replacement,
        )
        discard_pool.close_all(save=False)

        # -- default budget comes from the project's memory_pct ------------------- #
        pool3 = DatabasePool(proj, spawn=spawn, mem_fn=lambda c: c.mem)
        check(
            "default budget is derived, not a fixed lease count",
            pool3.budget_mb >= 256,
            pool3.budget_mb,
        )

    # -- prewarm: speculative, and never at the cost of a real binary ------ #
    with tempfile.TemporaryDirectory() as tmp:
        proj = _mkproject(tmp, n=3)
        made2 = {}

        def spawn2(ref, ttl):
            c = FakeClient(ref, mem=100)
            made2[ref.label] = c
            return c

        pool = DatabasePool(proj, budget_mb=250, spawn=spawn2, mem_fn=lambda c: c.mem)
        labels = [r.label for r in proj.refs]
        a, b, c_ = labels[0], labels[1], labels[2]
        pool.get(a)
        pool.set_active(a)
        check(
            "prewarm warms a binary when the budget has room",
            pool.prewarm(b) is True and b in pool.resident(),
            f"{pool.resident()}",
        )
        check(
            "prewarm is a no-op for something already resident",
            pool.prewarm(b) is False,
        )
        # 2 x 100MB resident, estimate 100 more -> 300 > 250: must refuse
        check(
            "prewarm refuses rather than making room",
            pool.prewarm(c_) is False and c_ not in pool.resident(),
            f"resident={pool.resident()} mem={pool.memory_mb()}/{pool.budget_mb}",
        )
        check(
            "refusing to prewarm evicts nothing",
            set(pool.resident()) == {a, b},
            f"{pool.resident()}",
        )
        check(
            "prewarm ignores a label outside the project", pool.prewarm("nope") is False
        )

    # Budget eviction releases GUI leases but must not save somebody's open IDA
    # implicitly. An explicit save-and-close remains authoritative.
    with tempfile.TemporaryDirectory() as tmp:
        proj = _mkproject(tmp, n=1)
        made_gui = []

        def spawn_gui(ref, ttl):
            client = FakeClient(ref, backend="gui")
            made_gui.append(client)
            return client

        pool = DatabasePool(proj, spawn=spawn_gui, mem_fn=lambda c: c.mem)
        label = proj.refs[0].label
        pool.get(label)
        pool.evict(label)
        check(
            "LRU release does not implicitly save a GUI database",
            made_gui[-1].saved == 0,
        )
        pool.get(label)
        pool.close_all(save=True)
        check(
            "explicit close_all(save=True) does save a GUI database",
            made_gui[-1].saved == 1,
        )

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
