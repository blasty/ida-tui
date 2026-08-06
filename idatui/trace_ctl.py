"""Execution-trace navigation: the controller behind `--trace FILE`.

`idatui.trace` is the *reader* (parse the Tenet delta log, answer questions about
it). This is the half that used to live in `IdaTui`: the trace's position in
time, the trail painted onto the listing/pseudocode/hex, and every key that
moves through it (`[` `]` `{` `}` `<` `>` `W`).

Why it's a plain object and not a mixin: Textual only merges ``BINDINGS`` from
``DOMNode`` subclasses, so a mixin's bindings are silently dropped. The keys
therefore stay declared on ``IdaTui``, whose ``action_*`` methods are one-line
delegates into here. Same reason the ``@work(thread=True)`` entry point stays on
the app -- Textual's worker machinery wants a ``DOMNode`` host.

The controller owns the trace state. ``IdaTui`` keeps forwarding properties
(``app._trace``, ``app._t``, ``app._trail_map``...) because the pilot suite and
the RPC layer read them by those names; see ``IdaTui._trace``.
"""
from __future__ import annotations

import bisect
import os
from typing import TYPE_CHECKING

from . import diag

if TYPE_CHECKING:                                    # pragma: no cover
    from .app import IdaTui

_app_mod = None


def _views():
    """The widget classes, imported lazily.

    ``app.py`` imports this module at the top, so importing it back at module
    scope would be a cycle. Nothing here needs the classes until a trace is
    actually driven, by which point ``app`` is fully imported.
    """
    global _app_mod
    if _app_mod is None:
        from . import app as _m
        _app_mod = _m
    return _app_mod


class TraceController:
    """Where we are in the trace, and everything that moves us."""

    def __init__(self, app: "IdaTui", path: str = "") -> None:
        self.app = app
        self.path = path or ""       # the Tenet trace to explore, if any
        self.trace = None            # the loaded Trace, once analysed
        self.t = 0                   # current timestamp in that trace
        self.trail_map = []          # decomp_map for trail_map_ea
        self.trail_map_ea = None
        self.trail_line_of: dict[int, int] = {}   # ea -> pseudocode line
        self.trail_eas: list[int] = []            # sorted keys of trail_line_of
        self.trail_span = None                    # ea span of that function
        self.pending_line = None     # step waiting on a re-decompile

    @property
    def armed(self) -> bool:
        """A trace was asked for but hasn't been parsed yet."""
        return bool(self.path) and self.trace is None

    def _need_trace(self) -> bool:
        """Complain once, in one voice, rather than at four call sites."""
        if self.trace is None:
            self.app._status("no trace loaded (--trace FILE)")
            return False
        return True

    # -- loading ------------------------------------------------------------ #
    def load(self) -> None:
        """Parse the trace and line it up with the database.

        Runs after the function index exists: rebasing needs the database's
        addresses, and without it nothing in the trace matches anything on
        screen (our echo trace runs at 0x7ffff6faa000; the database has that
        code at 0x2000).

        Called on a worker thread, so every touch of the UI hops back.
        """
        from .trace import Trace
        app = self.app
        path = self.path
        try:
            def note(n):
                app.call_from_thread(
                    app._status, f"trace: {n:,} instructions\u2026")
            trace = Trace.load(path, progress=note)
        except OSError as e:
            app.call_from_thread(app._status, f"trace: {e}")
            return
        if not trace.length:
            app.call_from_thread(
                app._status, f"trace: {os.path.basename(path)} is empty")
            return
        idx = app._func_index
        addrs = [f.addr for f in idx.all_loaded()] if idx is not None else []
        slide = trace.rebase(addrs)
        trace.apply_slide(slide)
        hit = sum(1 for f in (idx.all_loaded() if idx else [])
                  if trace.executions(f.addr))
        app.call_from_thread(self.ready, trace, slide, hit)

    def ready(self, trace, slide: int, hit: int) -> None:
        app = self.app
        self.trace = trace
        self.t = 0
        dock = app.query_one(_views().TraceDock)
        dock.display = True
        dock.show(trace, 0)
        where = (f"rebased {slide:+#x}" if slide else "no rebase needed")
        app._status(f"trace: {trace.length:,} instructions, {hit} functions "
                    f"touched ({where})", priority=True)
        self.seek(0, follow=True)

    # -- trace navigation --------------------------------------------------- #
    def seek(self, idx: int, follow: bool = True) -> None:
        """Move to timestamp ``idx``; ``follow`` takes the code view with it."""
        app = self.app
        t = self.trace
        if t is None or not t.length:
            return
        # A seek invalidates any navigation still in flight. They run in workers
        # and finish out of order: the trace's opening seek lands on the entry
        # point, takes a while, and used to arrive AFTER later seeks — dragging
        # the cursor back to _start while the trace was elsewhere, permanently.
        #
        # Bumped HERE and not in _goto_ea. Doing it for every navigation is the
        # more general rule ("the last thing you asked for wins") but it also
        # lets an ordinary follow be dropped by whatever navigates next, and the
        # only evidence I have is about seeks. Narrow fix for the measured bug.
        app._nav_seq += 1
        self.t = max(0, min(int(idx), t.length - 1))
        app.query_one(_views().TraceDock).show(t, self.t)
        self.paint_trail()
        if not follow:
            return
        pc = t.ip(self.t)
        if app._split and self.seek_split(pc):
            return
        # Stay in whichever view you're reading. Without prefer_decomp a step
        # from the pseudocode navigates to an address, which opens the listing —
        # so stepping through C threw you out of C on the first keypress.
        app._goto_ea(pc, push=False,
                     prefer_decomp=(app.is_decomp))

    def seek_split(self, pc: int) -> bool:
        """Put BOTH panes on ``pc``. True if handled.

        Normal navigation moves one pane and gives the companion a band, never a
        cursor — that rule exists so the two can't chase each other. A trace step
        isn't navigation though: time is a single global position, and both views
        are showing the same instant, so both cursors belong on it.

        The scroll anchoring is unchanged: after placing the cursors, the usual
        _sync_split still bands the companion and aligns it to the driver's
        screen row, so the eye tracks straight across.
        """
        app = self.app
        M = _views()
        lst = app.query_one(M.ListingView)
        if lst.model is None:
            return False
        row = lst.model.ensure_ea(pc)
        if row is None or row < 0:
            return False        # not in this listing (other segment): full nav
        lst.cursor = row
        lst._scroll_cursor_into_view()

        # Has execution actually left the decompiled function? Ask the map the
        # trail painting keeps, which is keyed to what the decompiler currently
        # HOLDS. _split_range comes from the guarded async path and lags, so a
        # stale one made every step look like a function change: the decompiler
        # bounced main -> PLT stub -> main, each bounce costing a synchronous
        # 769-line map fetch on the UI thread.
        span = self.trail_span
        inside = (pc in self.trail_line_of
                  or (span is not None and span[0] <= pc <= span[1]))
        if not inside:
            self.pending_line = pc
            app._resync_decomp_async(pc)
            return True
        self.place_decomp_at(pc)
        app._sync_split(app._active)
        return True

    def place_decomp_at(self, pc: int) -> None:
        """Move the pseudocode cursor to the line covering ``pc``.

        Uses the map the trail painting already keeps (keyed to the decompiler's
        CURRENTLY loaded function), not the split view's _split_ea2line. That one
        is refreshed by a guarded async path — it drops a result if _cur moved
        while it was in flight — and a burst of steps moves _cur constantly, so
        during stepping it is frequently a map of the function you just left.
        """
        app = self.app
        dec = app.query_one(_views().DecompView)
        line = None
        if self.trail_map_ea == dec.loaded_ea and self.trail_line_of:
            # EXACT match only. The decompiler doesn't attribute every
            # instruction to a line (about half of main's aren't), and the
            # tempting fallback — the nearest mapped instruction at or before
            # the pc — is unsound: C lines are not monotonic in address, so
            # 0x24a8 early in main resolved to line 708, "sub_2040();", near the
            # end. A cursor that jumps to an unrelated statement is worse than
            # one that waits; the trail still marks where we are.
            line = self.trail_line_of.get(pc)
        if line is None:
            line = app._split_ea2line.get(pc)
        if line is None:
            line = dec.line_for_ea(pc)
        if line is not None:
            dec.goto(line, dec.cursor_x)

    # -- painting ----------------------------------------------------------- #
    def paint_trail(self) -> None:
        """Push the execution trail into the code views.

        Recomputed per seek rather than per repaint: it's ~200 lookups, and a
        repaint happens far more often than a step.
        """
        app = self.app
        M = _views()
        t = self.trace
        if t is None:
            return
        hx = app._try_view(M.HexView)     # None until it's mounted
        if hx is not None:
            hx.trace, hx.trace_idx = t, self.t
            if hx.display:
                hx.refresh()
        trail = t.trail(self.t)
        lst = app._try_view(M.ListingView)
        if lst is not None:
            lst.trail = trail
            lst.refresh()
        self.paint_trail_decomp(trail)

    def paint_trail_decomp(self, trail: dict) -> None:
        """Map the instruction trail onto pseudocode lines.

        This is the thing Tenet can't do: it paints disassembly, because that's
        where a trace's addresses live. We already have decomp_map (built for
        the split view) saying which instructions each pseudocode line covers,
        so the same trail lands on C.

        A line covers many instructions, so it takes the strongest kind present:
        'now' wins over 'past' wins over 'future' — if the instruction you are
        standing on is part of this line, this line is where you are.
        """
        app = self.app
        dec = app._try_view(_views().DecompView)
        if dec is None:
            return
        ea = dec.loaded_ea
        if not dec.display or ea is None or app.program is None:
            dec.trail = {}
            return
        if self.trail_map_ea != ea:
            # One index, built once per decompiled function and shared with the
            # split view (_apply_split_map fills the same fields). decomp_map is
            # an RPC and stepping is interactive, so paying it per keystroke —
            # or twice, once for each of two parallel maps — would be felt.
            try:
                app._apply_split_map(ea, app.program.decomp_map(ea))
            except Exception as e:  # noqa: BLE001
                # The pseudocode simply stops being painted with the trail, with
                # nothing on screen to say why.
                diag.note(f"trail: decomp_map({ea:#x})", e)
                self.trail_map, self.trail_map_ea = [], ea
                self.trail_line_of, self.trail_eas = {}, []
                self.trail_span = None
        rank = {"future": 0, "past": 1, "now": 2}
        lines: dict[int, str] = {}
        for i, eas in enumerate(self.trail_map or []):
            best = None
            for a in eas:
                k = trail.get(a)
                if k is not None and (best is None or rank[k] > rank[best]):
                    best = k
            if best is not None:
                lines[i] = best
        dec.trail = lines
        dec.refresh()
        pend, self.pending_line = self.pending_line, None
        if pend is not None and app._split:
            # The function was still decompiling when the step happened; land
            # now that its line map exists.
            self.place_decomp_at(pend)
            app._sync_split(app._active)

    def adopt_map(self, ea: int, m: list, ea2line: dict, span) -> None:
        """Take the line map the split view just built.

        ONE index, shared with the split view: the trace path used to keep a
        parallel copy of exactly this, fetched separately and keyed differently,
        which is how the two ended up describing different functions.
        """
        self.trail_map, self.trail_map_ea = m, ea
        self.trail_line_of = dict(ea2line)
        self.trail_eas = sorted(self.trail_line_of)
        self.trail_span = span

    # -- stepping ----------------------------------------------------------- #
    def step(self, delta: int) -> None:
        if not self._need_trace():
            return
        self.seek(self.t + delta)

    def step_over(self, direction: int) -> None:
        """Step over a call by following the stack pointer.

        A call pushes, so the callee runs with SP BELOW where we started;
        stepping until SP comes back up lands after the call returns. Cheaper
        and more robust than recognising call instructions per architecture,
        which is what the mode makes it: if this instruction doesn't call
        anything, SP is already >= the start and it degenerates to one step.
        """
        if not self._need_trace():
            return
        t = self.trace
        sp_name = "rsp" if "rsp" in t.reg_at else ("esp" if "esp" in t.reg_at else "sp")
        sp0 = t.register(sp_name, self.t)
        i = self.t + direction
        limit = 200000          # a runaway search must not hang the UI
        while 0 <= i < t.length and limit > 0:
            sp = t.register(sp_name, i)
            if sp0 is None or sp is None or sp >= sp0:
                break
            i += direction
            limit -= 1
        self.seek(max(0, min(i, t.length - 1)))

    def seek_hit(self, direction: int) -> None:
        """Seek to the next/previous time the focused view's subject was touched.

        Two different questions with one pair of keys, because the answer to
        "which thing?" is already on screen: in a code view it's the instruction
        under the cursor ("when else did this run?"), in hex it's the byte under
        the cursor ("who else touched this?").
        """
        app = self.app
        M = _views()
        if not self._need_trace():
            return
        t = self.trace
        if app.is_hex:
            hx = app._try_view(M.HexView)
            va = hx.cursor_va() if hx is not None else None
            if va is None:
                return
            stamps = t.memory_accesses(va, 1)
            what = f"access to {va:#x}"
        else:
            view = app._active_code_view()
            if isinstance(view, M.DecompView):
                # A C line is not one address, so ask about the whole statement:
                # "when else did this line run?" is the question, and it's the
                # union of its instructions' executions. Falling back to the
                # line's single /*ea*/ marker would answer a narrower question
                # and often no question at all, since most lines have no marker.
                line = view.cursor
                eas = []
                if (self.trail_map_ea == view.loaded_ea
                        and 0 <= line < len(self.trail_map or [])):
                    eas = list(self.trail_map[line])
                if not eas:
                    one = view._line_ea(line)
                    eas = [one] if one is not None else []
                if not eas:
                    app._status("this line has no instructions to seek on",
                                priority=True)
                    return
                stamps = sorted({x for e in eas for x in t.executions(e)})
                what = f"execution of C line {line + 1}"
            else:
                ea = view._cursor_ea() if view is not None else None
                if ea is None:
                    app._status("no address on this line", priority=True)
                    return
                stamps = list(t.executions(ea))
                what = f"execution of {ea:#x}"
        if not stamps:
            app._status(f"no {what} in this trace", priority=True)
            return
        if direction > 0:
            i = bisect.bisect_right(stamps, self.t)
        else:
            i = bisect.bisect_left(stamps, self.t) - 1
        if not (0 <= i < len(stamps)):
            edge = "last" if direction > 0 else "first"
            app._status(f"already at the {edge} {what} "
                        f"({len(stamps)} in the trace)", priority=True)
            return
        self.seek(stamps[i])
        app._status(f"{what}: {i + 1} of {len(stamps)}  @ t={stamps[i]:,}",
                    priority=True)

    def seek_reg_write(self) -> None:
        """W: which instruction set each register to its current value."""
        app = self.app
        if not self._need_trace():
            return
        t = self.trace
        rows = []
        for name in t.registers:
            v = t.register(name, self.t)
            if v is None:
                continue
            rows.append((name, v, t.last_write(name, self.t),
                         t.next_write(name, self.t)))
        if rows:
            app.push_screen(_views().RegWriteScreen(rows, self.t),
                            self._on_reg_write_chosen)

    def _on_reg_write_chosen(self, idx) -> None:  # type: ignore[no-untyped-def]
        if idx is not None:
            self.seek(int(idx))
