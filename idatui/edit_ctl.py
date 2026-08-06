"""Everything that writes to the database: rename, comment, retype, define.

Six edits with the same shape -- work out what the cursor is on, ask for a
value, apply it in a worker, then invalidate the right caches and put the view
back where it was -- and that last step is the one that is easy to get subtly
wrong. The rules are collected here rather than rediscovered per edit:

* An edit that only changes *names* (rename, comment, retype, literal format)
  goes through :meth:`reload_active_code`, which reloads in place from indices.
* An edit that changes *item structure* (make data, define code/func/string,
  undefine) goes through a :class:`~idatui.app.ViewAnchor`, because row indices
  do not survive it -- defining code collapses four undefined byte rows into
  one instruction row.
* Every one of them bumps a cache generation, sets ``_dirty``, and hands its
  message over as a flash rather than writing it directly, because the reload
  it just triggered will write its own status afterwards.

The message handlers and the ``@work`` entry points stay on ``IdaTui``: Textual
dispatches ``on_<message>`` by name on the DOMNode, and its worker machinery
wants a DOMNode host. They are one-line delegates into here.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from textual.widgets import DataTable

from .errors import IDAToolError

if TYPE_CHECKING:                                    # pragma: no cover
    from .app import IdaTui

_app_mod = None


def _M():
    """The widget classes, imported lazily to avoid a cycle with app.py."""
    global _app_mod
    if _app_mod is None:
        from . import app as _m
        _app_mod = _m
    return _app_mod


#: A C type wide enough for N bytes, for prefilling a retype/define prompt.
_BY_SIZE = {1: "unsigned __int8", 2: "unsigned __int16",
            4: "unsigned __int32", 8: "unsigned __int64"}


class EditController:
    """The database edits, and the bookkeeping each one owes afterwards."""

    def __init__(self, app: "IdaTui") -> None:
        self.app = app

    # -- shared aftermath --------------------------------------------------- #
    def reload_active_code(self) -> None:
        """Refresh whichever code view is showing after an edit (comment/rename/
        retype), in place: re-decompile if in the decompiler, else reload the
        listing."""
        app = self.app
        M = _M()
        cur = app._cur
        if cur is None:
            return
        if app.is_decomp:
            # Snapshot the LIVE pseudocode position before forcing a recompile.
            # dec_scroll_y isn't tracked on every move, so without this the reload
            # falls into show()'s derive path (a bare scroll_to) and leaves a
            # stale frame until the next cursor move; capturing the real scroll
            # makes show() take the robust _apply_scroll path and repaint now.
            dec = app.query_one(M.DecompView)
            if cur.ea == dec.loaded_ea:
                cur.dec_cursor = dec.cursor
                cur.dec_cursor_x = dec.cursor_x
                cur.dec_scroll_y = round(dec.scroll_offset.y)
                cur.dec_scroll_x = round(dec.scroll_offset.x)
            dec.loaded_ea = None  # force re-decompile
            app._show_active()
        else:
            # Capture the LIVE position from the widget (the source of truth)
            # rather than trusting nav-entry tracking, which goes stale. Capture
            # it as ADDRESSES via the anchor: bump_names() discards the segment
            # model so the reload rebuilds it, and an edit that changes how many
            # rows an item takes makes the old indices point somewhere else.
            # Index capture is CORRECT here and an anchor is not: a rename or
            # comment doesn't change how many rows anything takes, and the model
            # this rebuilds is constructed empty — index_of_ea on it returns -1
            # until pages load, so an anchor would resolve to nothing while
            # costing an extra model build on the UI thread. Address anchoring is
            # for the edit paths that DO change row structure (see do_edit_item).
            lst = app.query_one(M.ListingView)
            cur.view = "listing"
            if lst.model is not None:
                cur.cursor = lst.cursor
                cur.cursor_x = lst.cursor_x
                cur.scroll_y = round(lst.scroll_offset.y)
            app._open_entry(cur, push=False)

    def edit_done(self, anchor) -> None:  # type: ignore[no-untyped-def]
        """One place where an edit's aftermath is settled.

        The reload this edit triggered will write its own status when it lands —
        after this — so the message is handed over as a flash rather than
        written and lost.
        """
        app = self.app
        app._dirty = True
        if anchor.flash:
            app._status(anchor.flash, priority=True)
        if anchor.refresh_functions:
            # Creating (or destroying) a function changes the index that the
            # names pane, Ctrl+N and the "no functions" hint all read. Without
            # this, `p` gave you a function the rest of the app couldn't see.
            app._reindex_functions()

    def _rename_index(self, addr: int, new: str) -> None:
        """Point the function index, the nav history and the names table at a
        function's new name. All three are caches of it, and a rename that
        updates only some of them is how `functions`/resolve/the palette end up
        reporting that the rename never happened."""
        app = self.app
        if app._func_index is not None:
            app._func_index.update_name(addr, new)
        for e in app._nav:
            if e.ea == addr:
                e.name = new
        # Update the one cell in place (a full rebuild would race the initial
        # streaming load and duplicate row keys).
        try:
            table = app.query_one("#func-table", DataTable)
            name_col = list(table.columns.keys())[1]
            table.update_cell(str(addr), name_col, new)
        except Exception:  # noqa: BLE001 -- row filtered out / not yet streamed
            pass

    # -- rename (IDA 'n') --------------------------------------------------- #
    @staticmethod
    def is_pseudocode_label(view, name: str) -> bool:
        """True if ``name`` is a Hex-Rays goto label in ``view``. The rename tool
        has no label category (only func/global/local/stack), so renaming one
        fails with a misleading 'local variable not found'; detect it up front
        and explain instead. A label is the default ``LABEL_n`` or any token used
        as a ``goto`` target."""
        if not isinstance(view, _M().DecompView):
            return False
        if re.fullmatch(r"LABEL_\d+", name):
            return True
        body = "\n".join(getattr(view, "_texts", []) or [])
        return re.search(rf"\bgoto\s+{re.escape(name)}\b", body) is not None

    def request_rename(self, msg) -> None:  # type: ignore[no-untyped-def]
        app = self.app
        M = _M()
        # In the flat listing, 'n' names the ADDRESS under the cursor (create a
        # label), not a symbol-by-name. This is what lets you name a bare/
        # undefined byte — e.g. the free byte at addr+1 after shrinking a u16 to
        # a u8 — which the word-under-cursor path can't do (no symbol to rename).
        if isinstance(msg.view, (M.ListingView, M.GraphView)):
            ea = msg.view._cursor_ea()
            if ea is None:
                app._status("no address on this line to name")
                return
            head = msg.view.cur_head()
            word = msg.view.word_under_cursor()
            mnem = head.text.split(" ", 1)[0] if (head and head.text) else ""
            # If the cursor is on a symbol token (a call/branch target, a data
            # reference, or this head's own label) rename THAT symbol; otherwise
            # create/rename a label at the head's address (bare/undefined bytes).
            if (word and app._looks_like_symbol(word) and word != mnem
                    and word.lower() not in M._ASM_KEYWORDS):
                app.prompts.rename.show(
                    f"rename '{word}' —  Enter=apply  Esc=cancel",
                    word, ctx=(msg.view, word, None))
            else:
                cur = head.name if (head is not None and head.name) else ""
                app.prompts.rename.show(
                    f"name @ {ea:#x} —  Enter=apply  Esc=cancel",
                    cur, ctx=(msg.view, cur, ea))
            return
        if not msg.name:
            app._status("nothing to rename under the cursor")
            return
        if self.is_pseudocode_label(msg.view, msg.name):
            app._status(
                f"can't rename pseudocode label '{msg.name}' "
                "(Hex-Rays goto labels aren't renamable via the API)")
            return
        app.prompts.rename.show(
            f"rename '{msg.name}' —  Enter=apply  Esc=cancel",
            msg.name, ctx=(msg.view, msg.name, None))

    def submit_rename(self, ctx, value: str) -> None:  # type: ignore[no-untyped-def]
        view, old, addr = ctx
        if addr is not None:  # listing: name this address (create a label)
            if value and value != old:
                self.app._do_name_addr(addr, value)
            return
        if view is not None and value and value != old:
            self.app._do_rename(view, old, value)

    def do_rename(self, view, old: str, new: str) -> None:  # worker context
        app = self.app
        assert app.program is not None
        prog, cur = app.program, app._cur
        kind = "data"
        addr: int | None = None
        batch: dict = {"data": {"old": old, "new": new}}
        resolved: int | None = None
        try:
            resolved = prog.resolve(old)
        except Exception:  # noqa: BLE001
            resolved = None
        if resolved is not None:
            fn = prog.function_of(resolved)
            if fn is not None and fn.addr == resolved:
                kind, addr = "func", resolved
                batch = {"func": {"addr": hex(resolved), "name": new}}
            else:
                kind, batch = "data", {"data": {"old": old, "new": new}}
        elif isinstance(view, _M().DecompView) and cur is not None:
            dec = prog.decompile(cur.ea)
            ref = next((r for r in dec.refs if r.name == old), None)
            if ref is not None:
                fn = prog.function_of(ref.addr)
                if fn is not None and fn.addr == ref.addr:
                    kind, addr = "func", ref.addr
                    batch = {"func": {"addr": hex(ref.addr), "name": new}}
                else:
                    kind, batch = "data", {"data": {"old": old, "new": new}}
            else:
                kind = "local"
                batch = {"local": {"func_addr": hex(cur.ea), "old": old, "new": new}}
        elif cur is not None:  # disasm view
            if old.startswith(("var_", "arg_")):
                kind = "stack"
                batch = {"stack": {"func_addr": hex(cur.ea), "old": old, "new": new}}
        try:
            res = prog.client.call("rename", batch=batch)
        except IDAToolError as e:
            app.call_from_thread(app._status, f"rename failed: {e.message}")
            return
        summary = res.get("summary", {}) if isinstance(res, dict) else {}
        if not (summary.get("ok", 0) > 0 and summary.get("failed", 0) == 0):
            msg = "rename failed"
            for catk in ("func", "data", "local", "stack"):
                items = res.get(catk) if isinstance(res, dict) else None
                if isinstance(items, list) and items and items[0].get("error"):
                    msg = f"rename failed: {items[0]['error']}"
            app.call_from_thread(app._status, msg)
            return
        app.call_from_thread(self.after_rename, kind, addr, old, new)

    def after_rename(self, kind: str, addr: int | None, old: str, new: str) -> None:
        app = self.app
        # A renamed symbol can appear in many functions, so invalidate globally;
        # each function refreshes its names the next time it's viewed.
        app.program.bump_names()
        self.reload_active_code()
        if kind == "func" and addr is not None:
            self._rename_index(addr, new)
        app._dirty = True
        app._status(f"renamed  {old} → {new}   (Ctrl+S to save)")

    def do_name_addr(self, addr: int, name: str) -> None:  # worker context
        """Set a label at ``addr`` (listing 'n'). Works on a bare/undefined byte
        — unlike the symbol-by-name path, this names the address directly."""
        app = self.app
        assert app.program is not None
        try:
            res = app.program.client.call(
                "rename", batch={"data": {"addr": hex(addr), "new": name}})
        except IDAToolError as e:
            app.call_from_thread(app._status, f"name failed: {e.message}")
            return
        summary = res.get("summary", {}) if isinstance(res, dict) else {}
        if not (summary.get("ok", 0) > 0 and summary.get("failed", 0) == 0):
            err = "name failed"
            items = res.get("data") if isinstance(res, dict) else None
            if isinstance(items, list) and items and items[0].get("error"):
                err = f"name failed: {items[0]['error']}"
            app.call_from_thread(app._status, err)
            return
        # The label shows in the listing's head rows -> invalidate + reopen.
        app.program.bump_items()
        # Naming the address *of a function start* is a function rename by any
        # other name. Without this the cached index kept the old name, so
        # `functions`/`names`/resolve/the palette all reported the rename had
        # not happened -- and a driver that trusts those readbacks redoes work
        # it already did.
        try:
            fn = app.program.function_of(addr)
        except Exception:  # noqa: BLE001
            fn = None
        is_func_start = fn is not None and fn.addr == addr
        lm = app.program.listing(addr)
        label = name if is_func_start else app.program.region_label(addr)
        idx = max(lm.ensure_ea(addr), 0) if lm is not None else 0
        app.call_from_thread(self.open_at_named, label, addr, idx, name,
                             is_func_start)

    def open_at_named(self, label: str, addr: int, idx: int, name: str,
                      is_func_start: bool = False) -> None:
        app = self.app
        if is_func_start:
            app.program.bump_names()
            self._rename_index(addr, name)
        app._open_at(addr, label, idx, False, -1, 0, True)
        app._dirty = True
        app._status(f"named {addr:#x} → {name}   (Ctrl+S to save)")

    # -- comments (IDA ';') ------------------------------------------------- #
    @staticmethod
    def existing_comment(view) -> str:
        """Current line comment (for prefill), parsed from the rendered text. In
        pseudocode a comment is `// text` before the trailing /*0xEA*/ markers;
        C has no `//` operator, so the last `//` is unambiguously the comment."""
        if isinstance(view, _M().DecompView) and 0 <= view.cursor < len(view._texts):
            s = re.sub(r"(?:/\*\s*0x[0-9A-Fa-f]+\s*\*/\s*)+$", "",
                       view._texts[view.cursor])
            i = s.rfind("//")
            return s[i + 2:].strip() if i >= 0 else ""
        return ""

    def request_comment(self, msg) -> None:  # type: ignore[no-untyped-def]
        app = self.app
        ea = app._line_ea_for(msg.view)
        # Signature / local-declaration lines carry no address; fall back to the
        # function's entry ea so commenting the header annotates the function.
        func_level = ea is None
        if func_level:
            ea = app._cur.ea if app._cur else None
        if ea is None:
            app._status("no address on this line to comment")
            return
        existing = "" if func_level else self.existing_comment(msg.view)
        what = "function comment" if func_level else "comment"
        app.prompts.comment.show(
            f"{what} @ {ea:#x} —  Enter=apply (empty=clear)  Esc=cancel",
            existing, ctx=(msg.view, ea, existing))

    def submit_comment(self, ctx, value: str) -> None:  # type: ignore[no-untyped-def]
        view, ea, existing = ctx
        if view is not None and value != existing:  # empty value clears it
            self.app._do_comment(ea, value)

    def do_comment(self, ea: int, text: str) -> None:  # worker context
        app = self.app
        assert app.program is not None
        # The prompt is single-line, so a literal '\n' (backslash-n) means a real
        # newline — Hex-Rays renders each as its own '//' line. Lets long notes
        # wrap instead of running off the right edge and clipping.
        text = text.replace("\\n", "\n")
        try:
            res = app.program.set_comment(ea, text)
        except IDAToolError as e:
            app.call_from_thread(app._status, f"comment failed: {e.message}")
            return
        data = res.get("result") if isinstance(res, dict) else None
        if (isinstance(data, list) and data and isinstance(data[0], dict)
                and data[0].get("error")):
            app.call_from_thread(app._status,
                                 f"comment failed: {data[0]['error']}")
            return
        app.call_from_thread(self.after_comment, ea, text)

    def after_comment(self, ea: int, text: str) -> None:
        app = self.app
        # A comment shows in both views but only after Hex-Rays recompiles, so
        # reuse the name-generation invalidation (bumps gen -> decompile is
        # force_recompiled lazily; disasm/listing caches are cleared).
        app.program.bump_names()
        self.reload_active_code()
        app._dirty = True
        verb = "cleared comment" if not text else "commented"
        app._status(f"{verb} @ {ea:#x}   (Ctrl+S to save)")

    # -- retype (set type, IDA 'y') ---------------------------------------- #
    @staticmethod
    def guess_data_type(size: int) -> str:
        """A sensible prefill when a global carries no type yet."""
        return _BY_SIZE.get(size, f"char[{size}]" if size > 0 else "void *")

    def prepare_retype(self, view, word: str | None) -> None:  # worker context
        """Work out whether the cursor is on a local variable or a function, and
        fetch the current type/prototype to prefill the prompt."""
        app = self.app
        assert app.program is not None and app._cur is not None
        ft = app.program.func_types(app._cur.ea)
        kind: str | None = None
        subject: int = app._cur.ea
        prefill = ""
        # 1) a local variable (or arg) of the current function
        if word and ft is not None:
            lv = next((v for v in ft.lvars if v.name == word), None)
            if lv is not None:
                kind, prefill = "lvar", lv.type
        # 2) a symbol under the cursor: a function (retype its prototype) or a
        #    global/data item (retype the variable). Without the data case a
        #    global fell through to (3) and silently retyped the ENCLOSING
        #    function's prototype instead.
        if kind is None and app._looks_like_symbol(word):
            try:
                tgt = app.program.resolve(word)
            except Exception:  # noqa: BLE001
                tgt = None
            if tgt is not None:
                tft = app.program.func_types(tgt)
                if tft is not None:
                    kind, subject, prefill = "func", tgt, tft.prototype
                else:
                    dt = app.program.data_type(tgt)
                    if dt is not None and not dt.get("is_func"):
                        kind, subject = "data", tgt
                        prefill = dt.get("type") or self.guess_data_type(
                            dt.get("size") or 0)
        # 3) fall back to the current function itself
        if kind is None and ft is not None:
            kind, subject, prefill = "func", app._cur.ea, ft.prototype
        if kind is None:
            app.call_from_thread(app._status,
                                 "nothing to retype under the cursor")
            return
        app.call_from_thread(self.open_retype, view, kind, subject,
                             word or "", prefill)

    def open_retype(self, view, kind: str, subject: int, word: str,
                    prefill: str) -> None:  # type: ignore[no-untyped-def]
        label = "prototype" if kind == "func" else f"type for '{word}'"
        self.app.prompts.retype.show(f"{label} —  Enter=apply  Esc=cancel",
                                     prefill, ctx=(view, kind, subject, word))

    def submit_retype(self, ctx, value: str) -> None:  # type: ignore[no-untyped-def]
        view, kind, subject, word = ctx
        if view is not None and value:
            self.app._do_retype(kind, subject, word, value)

    def do_retype(self, kind: str, subject: int, word: str,
                  new: str) -> None:  # worker context
        app = self.app
        assert app.program is not None
        if kind == "func":
            err = app.program.set_function_type(subject, new)
        elif kind == "data":  # a global / data item referenced in the body
            err = app.program.set_data_type(subject, new)
        else:  # lvar of the current function
            err = app.program.set_lvar_type(app._cur.ea, word, new)
        if err:
            app.call_from_thread(app._status, f"retype failed: {err}")
            return
        app.call_from_thread(self.after_retype, kind, word)

    def after_retype(self, kind: str, word: str) -> None:
        app = self.app
        # A type change alters the pseudocode (and disasm operand types), so
        # recompile via the name-generation invalidation and reopen in place.
        app.program.bump_names()
        self.reload_active_code()
        app._dirty = True
        what = "prototype" if kind == "func" else f"'{word}'"
        app._status(f"retyped {what}   (Ctrl+S to save)")

    # -- typed data definition (make_data, IDA 'd') ------------------------ #
    @staticmethod
    def default_data_type(head) -> str:  # type: ignore[no-untyped-def]
        """A sensible prefill C type for defining data over ``head``."""
        sz = getattr(head, "size", 0) or 0
        return _BY_SIZE.get(sz, f"char[{sz}]" if sz > 0 else "unsigned __int8")

    def request_make_data(self, msg) -> None:  # type: ignore[no-untyped-def]
        app = self.app
        view = msg.view
        is_listing = isinstance(view, _M().ListingView)
        ea = view._cursor_ea() if is_listing else None
        if ea is None:
            app._status("no address on this line to define data")
            return
        head = view.cur_head() if is_listing else None
        app.prompts.makedata.show(
            f"data type @ {ea:#x} (e.g. int, char[16], my_struct)"
            "  —  Enter=apply  Esc=cancel",
            self.default_data_type(head) if head is not None else "int",
            ctx=(view, ea))

    def submit_make_data(self, ctx, value: str) -> None:  # type: ignore[no-untyped-def]
        view, ea = ctx
        if view is not None and value:
            self.app._do_make_data(ea, value, self.app._anchor())

    def do_make_data(self, ea: int, type_decl: str,
                     anchor=None) -> None:  # worker context
        app = self.app
        assert app.program is not None
        try:
            app.program.make_data(ea, type_decl)
        except Exception as e:  # noqa: BLE001
            app.call_from_thread(app._status, f"make data: {e}")
            return
        app.program.bump_items()
        anchor = anchor or _M().ViewAnchor()
        anchor.flash = f"data ({type_decl}) @ {ea:#x}   (Ctrl+S to save)"
        name = app.program.region_label(ea)
        lm = app.program.listing(ea)
        idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
        _cur, top = app._anchor_rows(anchor, lm, ea)
        app.call_from_thread(
            app._open_at, ea, name, idx, False, -1, 0, True, None, top)
        app.call_from_thread(self.edit_done, anchor)

    # -- literal display formats (IDA 'o') --------------------------------- #
    def request_op_format(self, msg) -> None:  # type: ignore[no-untyped-def]
        app = self.app
        M = _M()
        if app.program is None or app._cur is None:
            return
        view = msg.view
        if isinstance(view, M.ListingView):
            ea = view._cursor_ea()
            if ea is None:
                app._status("no address on this line to reformat")
                return
            head = view.cur_head()
            if head is not None and head.kind in ("sep", "funchdr", "label"):
                # A banner/label row carries the NEXT item's address so that
                # navigation lands somewhere real — but it has no operands of
                # its own, and a column measured against it would point into
                # that item at random.
                app._status("no literal on this line to reformat", priority=True)
                return
            app._do_op_format(msg.mode, "listing", ea, view.op_col())
            return
        if isinstance(view, M.DecompView):
            # The pseudocode's formats are keyed on the FUNCTION Hex-Rays
            # decompiled, not on the line's own address.
            fn = view.loaded_ea if view.loaded_ea is not None else app._cur.ea
            app._do_op_format(msg.mode, "decomp", fn, view.cursor_x, view.cursor)

    def do_op_format(self, mode: str, where: str, ea: int, col: int,
                     line: int = -1) -> None:  # worker context
        app = self.app
        assert app.program is not None
        try:
            if where == "listing":
                r = app.program.op_format(ea, mode=mode, col=col)
                what = f"op{r.get('n', 0)} "
            else:
                r = app.program.pc_num_format(ea, mode=mode, line=line, col=col)
                what = ""
        # These are the RESULT of a keypress, so they go on the bar with
        # priority. Without it a refusal is swallowed by the previous edit's
        # flash and both the screen and the RPC snapshot still show the last
        # success -- a call that did nothing reads as one that worked.
        except IDAToolError as e:
            app.call_from_thread(app._status, f"format: {e.message}", True)
            return
        except Exception as e:  # noqa: BLE001 -- surface transport failures too
            app.call_from_thread(app._status, f"format: {e}", True)
            return
        text = " ".join((r.get("text") or "").split())
        prev, fmt = r.get("prev", ""), r.get("format", "?")
        if mode == "show":
            # A question, not an edit: say what this literal is and what it
            # could be, and leave the database (and the view) alone.
            app.call_from_thread(
                app._status,
                f"{what}{fmt} {r.get('value') or ''}"
                f"   [{', '.join(r.get('choices', []))}]", True)
            return
        step = f"{prev} \u2192 {fmt}" if prev and prev != fmt else fmt
        desc = f"{what}{step}: {text[:96]}"
        if r.get("warn"):
            desc += f"   \u26a0 {r['warn']}"
        # Which literal this was, so the cursor can be put back on it after the
        # reload: the line reflows and the old column stops meaning the same
        # thing (48 -> 0x30 shifts everything to its right).
        keep: tuple | None = None
        if where == "listing":
            if r.get("n") is not None:
                keep = ("listing", int(r["n"]))
        elif r.get("ea"):
            keep = ("decomp", int(str(r["ea"]), 0), int(r.get("opnum", 0)))
        app.call_from_thread(self.after_op_format, desc, keep)

    def after_op_format(self, desc: str, keep: tuple | None = None) -> None:
        app = self.app
        M = _M()
        # Only the rendering changed, but it changed in the database: drop the
        # cached rows (and bump the generation, so the decompiler re-runs and
        # picks up its own new number format) and reopen where we are.
        app.program.bump_names()
        if keep is not None:
            # Set before the reload: both views consume this one-shot when their
            # new content lands, which is always after this handler returns.
            if keep[0] == "listing":
                app.query_one(M.ListingView)._pending_op = keep[1]
            else:
                app.query_one(M.DecompView)._keep_lit = (keep[1], keep[2])
        self.reload_active_code()
        app._dirty = True
        app._status(f"{desc}   (Ctrl+S to save)", priority=True)

    # -- item structure edits (IDA c/p/u) ---------------------------------- #
    def request_edit_item(self, msg) -> None:  # type: ignore[no-untyped-def]
        app = self.app
        view = msg.view
        ea = view._cursor_ea() if isinstance(view, _M().ListingView) else None
        if ea is None:
            app._status("no address on this line to (re)define")
            return
        app._do_edit_item(msg.kind, ea, app._anchor())

    def do_edit_item(self, kind: str, ea: int,
                     anchor=None) -> None:  # worker context
        app = self.app
        assert app.program is not None
        verb = {"code": "defined code", "func": "created function",
                "undef": "undefined", "string": "made string",
                "thumb": "switched decoding", "thumbscan": "scanned"}[kind]
        try:
            if kind == "code":
                # Keep going until something stops it: one instruction is rarely
                # what you want, and on a raw image it means pressing `c` once
                # per opcode for the length of a function.
                r = app.program.define_code_run(ea)
                n, why = int(r.get("count", 0)), r.get("stopped", "")
                if n == 0 and why == "defined":
                    # Already code/data here — a no-op, not a failure. Saying
                    # "failed to create instruction" for it would be a lie.
                    app.call_from_thread(
                        app._status, f"already defined @ {ea:#x}")
                    return
                if n == 0:
                    raise IDAToolError("define_code",
                                       f"@ {ea:#x}: Failed to create instruction")
                end = int(str(r.get("end", hex(ea))), 0)
                reason = {"undecodable": "hit bytes that don't decode",
                          "flow": "control flow ends here",
                          "defined": "ran into existing code/data",
                          "segment": "end of segment",
                          "limit": "instruction limit"}.get(why, why)
                verb = (f"defined {n} instruction{'s' if n != 1 else ''} "
                        f"({ea:#x}\u2013{end:#x}) \u2014 {reason}")
            elif kind == "thumbscan":
                # A vector table is a list of Thumb entry points that IDA won't
                # follow on a headerless image, because nothing tells it those
                # words are pointers. Scan from the cursor.
                anchor.refresh_functions = True
                r = app.program.thumb_scan(ea, ea + 0x400)
                n, applied = int(r.get("n", 0)), int(r.get("applied", 0))
                if not n:
                    verb = (f"no Thumb entry pointers in {ea:#x}\u2013{ea+0x400:#x}"
                            " (odd words pointing into the image)")
                else:
                    verb = (f"{n} Thumb entr{'y' if n == 1 else 'ies'} found, "
                            f"{applied} disassembled")
            elif kind == "thumb":
                # Switch the mode, then disassemble in it: flipping T and
                # leaving the bytes undefined shows nothing, and the reason you
                # flipped it was to read the code.
                r = app.program.set_thumb(ea)
                run = app.program.define_code_run(ea)
                n = int(run.get("count", 0))
                mode = "Thumb" if r.get("thumb") else "ARM"
                verb = f"{mode} @ {ea:#x}"
                if r.get("forced_32bit"):
                    verb += " (segment set to 32-bit; Thumb needs ARM32)"
                if r.get("db_64bit"):
                    # Disassembly will look right and F5 will never work.
                    verb += ("  \u26a0 this database is 64-bit, so Hex-Rays "
                             "won't decompile it \u2014 Ctrl+L and pick "
                             "arm:ARMv7-A")
                verb += (f" \u2014 {n} instruction{'s' if n != 1 else ''}"
                         if n else " \u2014 still doesn't decode")
                # falls through to the shared reload: same cache bump, same
                # anchor restore, same flash. That is the whole point of having
                # one path.
            elif kind == "func":
                anchor.refresh_functions = True
                r = app.program.define_func(ea)
                if r.get("start") and r.get("end"):
                    verb = (f"created function {r['start']}\u2013{r['end']}"
                            + (" (end worked out from the code)"
                               if r.get("how") == "explicit-end" else ""))
            elif kind == "string":
                s = app.program.make_string(ea)
                verb = f"made string ({s[:24]!r})" if s else verb
            else:
                # Undefining can destroy a function as easily as `p` creates one.
                anchor.refresh_functions = True
                app.program.undefine(ea)
        except Exception as e:  # noqa: BLE001 -- surface soft/hard tool errors
            app.call_from_thread(app._status, f"{kind}: {e}")
            return
        # Structure changed everywhere: drop all item/function/decomp caches.
        app.program.bump_items()
        # Re-resolve: a define_func upgrades the region to a real function view;
        # anything else re-reads the (still function-less) listing in place.
        anchor = anchor or _M().ViewAnchor()
        anchor.flash = f"{verb} @ {ea:#x}   (Ctrl+S to save)"
        fn = app.program.function_of(ea)
        if fn is not None:
            model = app.program.disasm(fn.addr, fn.name)
            idx = 0 if ea == fn.addr else model.index_of_ea(ea)
            _cur, top = app._anchor_rows(anchor, model, ea)
            app.call_from_thread(
                app._open_at, fn.addr, fn.name, idx, False, -1, 0, False,
                None, top)
        else:
            name = app.program.region_label(ea)
            lm = app.program.listing(ea)
            idx = max(lm.ensure_ea(ea), 0) if lm is not None else 0
            _cur, top = app._anchor_rows(anchor, lm, ea)
            app.call_from_thread(
                app._open_at, ea, name, idx, False, -1, 0, True, None, top)
        app.call_from_thread(self.edit_done, anchor)
