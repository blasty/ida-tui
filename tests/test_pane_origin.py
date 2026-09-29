#!/usr/bin/env python3
"""Which pane a spawn thinks it is next to (pure stdlib, no IDA, no slosh).

The bug being pinned: the slosh backend used to work out "where do I live" from
`panes[].focused`. Exactly one pane in a slosh session is focused, it is always
in the tab currently on screen, and it belongs to whoever is looking -- so a
TUI spawned "beside the agent" landed in whatever tab the human had wandered
into, and in a session running several agents it was reliably a stranger's.

The rule now: identity comes from the environment ($SLOSH_PANE), or from our own
process ancestry against `panes[].pid`, or from a purpose we were told to look
for -- and if none of those can answer, the pane stays in the tab it was built
in rather than being placed on a guess.

slosh is faked here on purpose: these are decisions the backend makes about a
`panes` reply, so the reply is the input. tests/test_own_pane.py in the slosh
repo covers the other side (that slosh really does export $SLOSH_PANE, report
pids, and honour `beside`/`focus:false`).
"""

#: origin resolution + spawn placement, pure stdlib.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui import pane as P  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}  <- {detail}")


# The session every test below reasons about: the agent is pane 1 in tab 1, the
# human is pane 2 in tab 2 and holds the session's only focus.
AGENT = {
    "id": 1,
    "tab_id": 1,
    "pid": 4242,
    "focused": False,
    "purpose": "",
    "alive": True,
    "w": 80,
    "h": 24,
}
HUMAN = {
    "id": 2,
    "tab_id": 2,
    "pid": 5252,
    "focused": True,
    "purpose": "",
    "alive": True,
    "w": 80,
    "h": 24,
}


class FakeSlosh:
    """Records every call, and answers `panes` from a list we control."""

    def __init__(self, rows, spawned_id=9):
        self.rows = [dict(r) for r in rows]
        self.calls = []
        self.spawned_id = spawned_id

    def __call__(self, cmd, **params):
        self.calls.append((cmd, params))
        if cmd == "panes":
            return {"ok": True, "panes": self.rows}
        if cmd == "apply-layout":
            # slosh builds the pane in a tab of its own; give it back with the
            # purpose the caller declared, which is how the backend finds it.
            kdl = params.get("kdl", "")
            purpose = kdl.split('purpose="', 1)[-1].split('"', 1)[0]
            self.rows.append(
                {
                    "id": self.spawned_id,
                    "tab_id": 99,
                    "pid": 6262,
                    "focused": False,
                    "purpose": purpose,
                    "alive": True,
                    "w": 80,
                    "h": 24,
                }
            )
            return {"ok": True}
        if cmd == "move-pane":
            for r in self.rows:
                if r["id"] == params.get("id"):
                    r["tab_id"] = params.get("tab")
            return {"ok": True, "tab": params.get("tab")}
        return {"ok": True}

    def of(self, cmd):
        return [p for c, p in self.calls if c == cmd]


def with_fake(rows, env=None, ancestry=(), spawned_id=9):
    """Install a fake slosh + environment; returns (fake, restore callable)."""
    fake = FakeSlosh(rows, spawned_id=spawned_id)
    saved = {
        "slosh": P._slosh,
        "ancestry": P._proc_ancestry,
        "caps": dict(P._SLOSH_CAPS),
        "env": {
            k: os.environ.get(k)
            for k in (
                "SLOSH_PANE",
                "IDATUI_SLOSH_PANE",
                "IDATUI_ORIGIN_PURPOSE",
                "SLOSH_PANE_PURPOSE",
            )
        },
    }
    P._slosh = fake
    P._proc_ancestry = lambda: list(ancestry)
    P._SLOSH_CAPS.clear()
    for k in saved["env"]:
        os.environ.pop(k, None)
    for k, v in (env or {}).items():
        os.environ[k] = v

    def restore():
        P._slosh = saved["slosh"]
        P._proc_ancestry = saved["ancestry"]
        P._SLOSH_CAPS.clear()
        P._SLOSH_CAPS.update(saved["caps"])
        for k, v in saved["env"].items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    return fake, restore


def origin_with(**kw):
    fake, restore = with_fake(**kw)
    try:
        return P._slosh_origin()
    finally:
        restore()


def test_origin_is_never_the_focused_pane():
    o = origin_with(rows=[AGENT, HUMAN], env={"SLOSH_PANE": "1"})
    check(
        "$SLOSH_PANE wins over the focused pane",
        o and o["id"] == 1,
        f"got {o}",
    )

    o = origin_with(rows=[AGENT, HUMAN], ancestry=(1111, 4242, 1))
    check(
        "our own pid's ancestry finds our pane",
        o and o["id"] == 1,
        f"got {o}",
    )

    o = origin_with(
        rows=[AGENT, HUMAN],
        env={"IDATUI_ORIGIN_PURPOSE": "agent:me"},
    )
    check("an unset purpose does not match an empty one", o is None, f"got {o}")

    tagged = dict(AGENT, purpose="agent:me")
    o = origin_with(rows=[tagged, HUMAN], env={"IDATUI_ORIGIN_PURPOSE": "agent:me"})
    check("a declared purpose is the last resort", o and o["id"] == 1, f"got {o}")

    # What pi's slosh-status extension publishes for its own pane.
    tagged = dict(AGENT, purpose="agent:pi.1234")
    o = origin_with(rows=[tagged, HUMAN], env={"SLOSH_PANE_PURPOSE": "agent:pi.1234"})
    check("$SLOSH_PANE_PURPOSE works too", o and o["id"] == 1, f"got {o}")

    o = origin_with(rows=[AGENT, HUMAN])
    check(
        "with nothing to go on the answer is None, never the focused pane",
        o is None,
        f"got {o} (the focused pane is the human's)",
    )


def test_an_override_beats_everything():
    o = origin_with(
        rows=[AGENT, HUMAN],
        env={"IDATUI_SLOSH_PANE": "2", "SLOSH_PANE": "1"},
        ancestry=(4242,),
    )
    check("$IDATUI_SLOSH_PANE overrides $SLOSH_PANE", o and o["id"] == 2, f"got {o}")

    o = origin_with(rows=[AGENT, HUMAN], env={"SLOSH_PANE": "777"}, ancestry=(4242,))
    check(
        "an id that is not in the session falls through to the pid",
        o and o["id"] == 1,
        f"got {o}",
    )


def test_a_spawn_lands_beside_us_and_takes_no_focus():
    fake, restore = with_fake(rows=[AGENT, HUMAN], env={"SLOSH_PANE": "1"})
    try:
        got = P._pane_split(
            ["/bin/true"], mux="slosh", vertical=False, size=None, detached=True
        )
    finally:
        restore()

    check("the spawn returns the new pane's id", got == "9", f"got {got!r}")

    layouts = fake.of("apply-layout")
    check(
        "the layout is applied without taking the view",
        layouts and layouts[0].get("focus") is False,
        f"{layouts}",
    )

    moves = fake.of("move-pane")
    check("the pane is moved once", len(moves) == 1, f"{moves}")
    if moves:
        check(
            "into the tab of the pane we are in, not the focused tab",
            moves[0].get("tab") == AGENT["tab_id"],
            f"went to tab {moves[0].get('tab')}, human is in {HUMAN['tab_id']}",
        )
        check(
            "beside our own pane, not that tab's focus",
            moves[0].get("beside") == AGENT["id"],
            f"{moves[0]}",
        )
        check(
            "and without taking focus",
            moves[0].get("focus") is False,
            f"{moves[0]}",
        )
    check(
        "nothing is focused on the way out",
        not fake.of("focus"),
        f"{fake.of('focus')}",
    )


def test_focus_is_restored_only_when_slosh_moved_it():
    """`--detached` on an older slosh: it ignores `focus`, so we put it back."""
    rows = [AGENT, HUMAN]
    fake, restore = with_fake(rows=rows, env={"SLOSH_PANE": "1"})
    # An older slosh: no `pid` in the rows, so the backend must not pass the
    # newer arguments -- and must fix up focus itself.
    old = [{k: v for k, v in r.items() if k != "pid"} for r in rows]
    fake.rows = old
    P._slosh = fake
    P._SLOSH_CAPS.clear()
    try:
        P._pane_split(
            ["/bin/true"], mux="slosh", vertical=False, size=None, detached=True
        )
        moves = fake.of("move-pane")
        check(
            "an older slosh is not sent arguments it would ignore",
            moves and "beside" not in moves[0] and "focus" not in moves[0],
            f"{moves}",
        )
        check(
            "the layout is applied the old way too",
            fake.of("apply-layout") and "focus" not in fake.of("apply-layout")[0],
            f"{fake.of('apply-layout')}",
        )
        check(
            "focus is not put back when it never moved",
            not fake.of("focus"),
            f"{fake.of('focus')}",
        )
    finally:
        restore()

    # Now the same, with the new pane holding focus afterwards: put it back.
    fake2, restore2 = with_fake(rows=rows, env={"SLOSH_PANE": "1"})
    fake2.rows = [{k: v for k, v in r.items() if k != "pid"} for r in rows]
    P._slosh = fake2
    P._SLOSH_CAPS.clear()
    orig_call = fake2.__call__

    def stealing(cmd, **params):
        out = orig_call(cmd, **params)
        if cmd == "move-pane":  # slosh focuses what it moves
            for r in fake2.rows:
                r["focused"] = r["id"] == params.get("id")
        return out

    P._slosh = stealing
    try:
        P._pane_split(
            ["/bin/true"], mux="slosh", vertical=False, size=None, detached=True
        )
        check(
            "focus is put back when slosh did move it",
            [p.get("id") for p in fake2.of("focus")] == [AGENT["id"]],
            f"{fake2.of('focus')}",
        )
    finally:
        restore2()


def test_without_an_identity_it_stays_put():
    fake, restore = with_fake(rows=[AGENT, HUMAN])  # nothing to go on
    try:
        got = P._pane_split(
            ["/bin/true"], mux="slosh", vertical=False, size=None, detached=True
        )
    finally:
        restore()
    check("the pane is still created", got == "9", f"got {got!r}")
    check(
        "but never moved into somebody else's tab",
        not fake.of("move-pane"),
        f"{fake.of('move-pane')}",
    )
    check("and focus is left alone", not fake.of("focus"), f"{fake.of('focus')}")


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
