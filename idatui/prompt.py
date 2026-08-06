"""The one-line prompts along the bottom of the app.

There are six (`search` `rename` `comment` `retype` `makedata` `goto`) and every
one of them was opened, closed and escaped by its own copy of the same six
lines. The copies had drifted: some restored focus to the view, some didn't;
some cleared their context on close, some left it for the next caller to trip
over.

Opening a prompt is: hide the status bar (they share a row), set the
placeholder and prefill, make it focusable, show it, focus it. Closing is the
same in reverse, plus handing focus back to whatever view asked for it. That is
all `Prompt` is -- but having it in one place is what makes "Esc closes whatever
is open" a loop instead of a six-branch ladder in `on_key`.

Note the `can_focus` toggling: a hidden `Input` that stays focusable still takes
part in Tab focus-nav, so tabbing around a closed prompt used to land the cursor
in an invisible widget and swallow every subsequent keystroke.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from textual.widgets import Input, Static

if TYPE_CHECKING:                                     # pragma: no cover
    from textual.app import App


class Prompt:
    """One `Input` at the bottom of the screen, plus who to give focus back to.

    ``ctx`` is whatever the opener needs when the value is submitted (the view
    that asked, the address being commented, the kind of retype...). It is held
    here rather than in a parallel ``_rename_ctx`` attribute on the app so that
    it cannot outlive the prompt that owns it.
    """

    def __init__(self, app: "App", ident: str) -> None:
        self.app = app
        self.id = ident
        self.ctx: object = None

    @property
    def input(self) -> Input:
        return self.app.query_one(f"#{self.id}", Input)

    @property
    def open(self) -> bool:
        """Is this prompt on screen? Cheap enough to poll in `on_key`."""
        try:
            return bool(self.input.display)
        except Exception:  # noqa: BLE001 -- a modal owns the screen
            return False

    def show(self, placeholder: str, value: str = "", ctx: object = None) -> Input:
        """Put the prompt up, prefilled and focused."""
        self.ctx = ctx
        self.app.query_one("#status", Static).display = False
        inp = self.input
        inp.placeholder = placeholder
        inp.can_focus = True
        inp.display = True
        inp.value = value
        inp.focus()
        return inp

    def close(self, refocus: bool = True) -> object:
        """Take the prompt down and return the context it was holding.

        Returned rather than left readable, because every caller wants it
        exactly once and the old parallel-attribute version kept handing the
        next caller a stale one (the listing's `_rename_addr` had to be captured
        by hand before `_end_rename` cleared it, or the name went to address 0).
        """
        ctx, self.ctx = self.ctx, None
        inp = self.input
        inp.display = False
        inp.can_focus = False
        self.app.query_one("#status", Static).display = True
        if refocus:
            view = ctx[0] if isinstance(ctx, tuple) and ctx else None
            if view is not None and hasattr(view, "focus"):
                view.focus()
        return ctx


class PromptBar:
    """Every prompt the app owns, so "close whatever is open" is one call."""

    def __init__(self, app: "App", *idents: str) -> None:
        self.app = app
        self._order = list(idents)
        self._by_id = {i: Prompt(app, i) for i in idents}

    def __getitem__(self, ident: str) -> Prompt:
        return self._by_id[ident]

    def __getattr__(self, name: str) -> Prompt:
        try:
            return self.__dict__["_by_id"][name]
        except KeyError:
            raise AttributeError(name) from None

    def active(self) -> Prompt | None:
        """The prompt currently on screen, in declaration order.

        Only one is ever up -- they share the row above the footer -- but the
        order is fixed anyway so this can't depend on dict iteration.
        """
        for ident in self._order:
            p = self._by_id[ident]
            if p.open:
                return p
        return None

    def any_open(self) -> bool:
        return self.active() is not None
