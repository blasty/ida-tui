"""idatui Phase 1 TUI: a two-pane, keyboard-first IDA frontend.

Left  : function list (lazy-loaded, filterable).
Right : virtualized disassembly listing for the selected function.

Design notes:
* The disassembly view is a real virtualized ``ScrollView``: it only ever renders
  the visible ~viewport of lines, painting instantly from the domain block cache
  and scheduling background fetches for misses. A 52k-instruction function scrolls
  without ever materializing 52k lines in a widget.
* All network/domain work runs in Textual worker threads; the UI never blocks.
* An address-history stack backs Enter (follow) / Esc (back), IDA-style.
* On startup we bump the worker idle-TTL and run a keepalive heartbeat so the
  session never gets reaped while we chill.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.segment import Segment
from rich.style import Style
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.geometry import Size
from textual.message import Message
from textual.reactive import reactive
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import DataTable, Footer, Header, Input, Static

from .client import IDAClient
from .domain import DisasmModel, Func, Program

# Styles for the disassembly listing.
_S_ADDR = Style(color="grey58")
_S_LABEL = Style(color="yellow", bold=True)
_S_INSN = Style(color="white")
_S_MNEM = Style(color="cyan")
_S_CURSOR = Style(bgcolor="grey30")
_S_DIM = Style(color="grey42", italic=True)


@dataclass
class NavEntry:
    ea: int
    name: str
    cursor: int = 0


# --------------------------------------------------------------------------- #
# Virtualized disassembly view
# --------------------------------------------------------------------------- #
class DisasmView(ScrollView, can_focus=True):
    """A line-virtualized disassembly listing for a single function."""

    BINDINGS = [
        Binding("j,down", "cursor_down", "Down", show=False),
        Binding("k,up", "cursor_up", "Up", show=False),
        Binding("ctrl+d", "half_page(1)", "½↓", show=False),
        Binding("ctrl+u", "half_page(-1)", "½↑", show=False),
        Binding("pagedown,f", "page(1)", "PgDn", show=False),
        Binding("pageup,b", "page(-1)", "PgUp", show=False),
        Binding("home", "goto_top", "Top", show=False),
        Binding("G,end", "goto_bottom", "Bottom", show=False),
    ]

    cursor = reactive(0)

    class CursorMoved(Message):
        """Posted when the disasm cursor moves; carries the instruction ea."""

        def __init__(self, index: int, ea: int | None) -> None:
            super().__init__()
            self.index = index
            self.ea = ea

    def __init__(self) -> None:
        super().__init__()
        self.model: DisasmModel | None = None
        self.total = 0
        self._name = ""

    # -- public API -------------------------------------------------------- #
    def load(self, model: DisasmModel, name: str, cursor: int = 0) -> None:
        self.model = model
        self._name = name
        self.total = 0
        self.cursor = cursor
        self.virtual_size = Size(0, 0)
        self._prime()

    @work(thread=True, exclusive=True, group="disasm-prime")
    def _prime(self) -> None:
        model = self.model
        if model is None:
            return
        total = model.total()
        height = max(self.size.height, 1)
        model.lines(0, min(total, height + DisasmModel.BLOCK), prefetch=True)
        if self.cursor:
            model.lines(max(self.cursor - 2, 0), height, prefetch=True)
        self.app.call_from_thread(self._on_primed, total)

    def _on_primed(self, total: int) -> None:
        self.total = total
        self.virtual_size = Size(0, total)
        self._scroll_cursor_into_view()
        self.refresh()

    # -- rendering --------------------------------------------------------- #
    def render_line(self, y: int) -> Strip:
        model = self.model
        width = self.size.width
        if model is None or self.total == 0:
            return Strip([Segment("".ljust(width), _S_DIM)])
        top = round(self.scroll_offset.y)
        if y == 0:  # once per refresh: warm the visible window + a little ahead
            self._ensure_window(top)
        idx = top + y
        if idx >= self.total:
            return Strip([Segment("".ljust(width), _S_INSN)])
        line = model.cached_line(idx)
        cursor = idx == self.cursor
        base = _S_CURSOR if cursor else None
        if line is None:
            seg = Segment(f"  {idx:>8}  …".ljust(width), (base or Style()) + _S_DIM)
            return Strip([seg])
        segs: list[Segment] = []
        addr = f"{line.ea:08X}"
        segs.append(Segment(f"{addr}  ", _join(base, _S_ADDR)))
        if line.label:
            segs.append(Segment(f"{line.label}: ", _join(base, _S_LABEL)))
        text = line.text
        mnem, _, rest = text.partition(" ")
        segs.append(Segment(mnem, _join(base, _S_MNEM)))
        if rest:
            segs.append(Segment(" " + rest, _join(base, _S_INSN)))
        strip = Strip(segs)
        return strip.adjust_cell_length(width, _join(base, _S_INSN) or _S_INSN)

    def _ensure_window(self, top: int) -> None:
        if self.model is None:
            return
        height = max(self.size.height, 1)
        start = max(top - DisasmModel.BLOCK, 0)
        count = height + 2 * DisasmModel.BLOCK
        if not self.model.is_cached(top, height):
            self._fetch_window(start, count)
        else:
            self.model.ensure_async(start, count)  # warm neighbors

    @work(thread=True, exclusive=False, group="disasm-fetch")
    def _fetch_window(self, start: int, count: int) -> None:
        model = self.model
        if model is None:
            return
        model.lines(start, count, prefetch=True)
        self.app.call_from_thread(self.refresh)

    # -- navigation -------------------------------------------------------- #
    def _visible_height(self) -> int:
        return max(self.size.height, 1)

    def _scroll_cursor_into_view(self) -> None:
        height = self._visible_height()
        top = round(self.scroll_offset.y)
        if self.cursor < top:
            self.scroll_to(y=self.cursor, animate=False)
        elif self.cursor >= top + height:
            self.scroll_to(y=max(self.cursor - height + 1, 0), animate=False)

    def _move(self, delta: int) -> None:
        if self.total == 0:
            return
        self.cursor = max(0, min(self.total - 1, self.cursor + delta))
        self._scroll_cursor_into_view()
        self.refresh()
        self.post_message(DisasmView.CursorMoved(self.cursor, self._cursor_ea()))

    def _cursor_ea(self) -> int | None:
        if self.model is None:
            return None
        line = self.model.cached_line(self.cursor)
        return line.ea if line else None

    def action_cursor_down(self) -> None:
        self._move(1)

    def action_cursor_up(self) -> None:
        self._move(-1)

    def action_half_page(self, direction: int) -> None:
        self._move(direction * (self._visible_height() // 2))

    def action_page(self, direction: int) -> None:
        self._move(direction * self._visible_height())

    def action_goto_top(self) -> None:
        self._move(-self.total)

    def action_goto_bottom(self) -> None:
        self._move(self.total)


def _join(base: Style | None, style: Style) -> Style:
    return (base + style) if base is not None else style


# --------------------------------------------------------------------------- #
# Function list panel
# --------------------------------------------------------------------------- #
class FunctionsPanel(Vertical):
    def compose(self) -> ComposeResult:
        self._filter = Input(placeholder="filter (glob, e.g. sub_*)  —  Enter to apply", id="func-filter")
        self._filter.display = False
        yield self._filter
        table = DataTable(id="func-table", cursor_type="row", zebra_stripes=True)
        table.add_column("Address", width=12)
        table.add_column("Function", width=28)
        table.add_column("Size", width=8)
        yield table


# --------------------------------------------------------------------------- #
# The app
# --------------------------------------------------------------------------- #
class IdaTui(App):
    CSS = """
    Screen { layout: vertical; }
    #panes { height: 1fr; }
    #left { width: 42%; border-right: solid $panel; }
    #func-table { height: 1fr; }
    #func-filter { dock: top; }
    DisasmView { width: 1fr; padding: 0 1; }
    #status { dock: bottom; height: 1; background: $panel; color: $text; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "filter", "Filter"),
        Binding("g", "goto", "Goto"),
        Binding("ctrl+b", "toggle_functions", "Names"),
        Binding("tab", "toggle_focus", "Switch pane"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, url: str, db: str | None, keepalive: bool = True,
                 open_path: str | None = None) -> None:
        super().__init__()
        self._url = url
        self._db = db
        self._open_path = open_path
        self._do_keepalive = keepalive
        self.client: IDAClient | None = None
        self.program: Program | None = None
        self._ka = None
        self._nav: list[NavEntry] = []
        self._cur_filter: str | None = None

    # -- layout ------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="panes"):
            with FunctionsPanel(id="left"):
                pass
            yield DisasmView()
        yield Static("connecting…", id="status")
        yield Footer()

    def on_mount(self) -> None:
        # Keep the hidden command input out of the focus chain until summoned.
        inp = self.query_one("#func-filter", Input)
        inp.can_focus = False
        self.query_one("#func-table", DataTable).focus()
        self._connect()

    # -- status helper ----------------------------------------------------- #
    def _status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    # -- connection + initial load ---------------------------------------- #
    @work(thread=True, exclusive=True, group="connect")
    def _connect(self) -> None:
        try:
            client = IDAClient(self._url, db=self._db)
            client.connect()
            if self._open_path is not None:
                self.app.call_from_thread(self._status, f"opening {self._open_path}…")
                import os
                path = os.path.abspath(os.path.expanduser(self._open_path))
                res = client.call("idb_open", input_path=path,
                                  idle_ttl_sec=1_000_000_000, timeout=1800.0)
                if not (isinstance(res, dict) and res.get("success")):
                    err = res.get("error") if isinstance(res, dict) else res
                    self.app.call_from_thread(self._status, f"open failed: {err}")
                    return
                client.set_db(res["session"]["session_id"])
            elif self._db is None:
                client.set_db(client.resolve_db())
            health = client.health()
            module = health.get("module", "?")
            if self._do_keepalive:
                try:
                    client.bump_idle_ttl()
                except Exception:
                    pass
                self._ka = client.keepalive(interval=120.0).start()
            program = Program(client)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"connect failed: {e}")
            return
        self.client = client
        self.program = program
        self.app.call_from_thread(self._status, f"{module} — loading functions…")
        self._load_functions()

    @work(thread=True, exclusive=True, group="load-funcs")
    def _load_functions(self, filter: str | None = None) -> None:
        assert self.program is not None
        idx = self.program.functions(filter=filter)
        # Stream rows in as pages arrive so the UI fills progressively.
        table_reset = {"done": False}

        def reset_table():
            t = self.query_one("#func-table", DataTable)
            t.clear()
            table_reset["done"] = True

        self.app.call_from_thread(reset_table)
        last = 0
        module = self._module()
        while not idx.complete:
            idx.load_next_page()
            rows = idx.window(last, len(idx) - last)
            last = len(idx)
            if rows:
                self.app.call_from_thread(self._append_rows, rows)
                self.app.call_from_thread(
                    self._status, f"{module} — {last} functions…"
                )
        self.app.call_from_thread(self._status, f"{module} — {len(idx)} functions")

    def _module(self) -> str:
        try:
            return self.client.health().get("module", "?") if self.client else "?"
        except Exception:  # noqa: BLE001
            return "?"

    def _append_rows(self, rows: list[Func]) -> None:
        table = self.query_one("#func-table", DataTable)
        for f in rows:
            table.add_row(f"{f.addr:08X}", f.name, f"{f.size:#x}", key=str(f.addr))

    # -- actions ----------------------------------------------------------- #
    def action_toggle_functions(self) -> None:
        """Show/hide the functions pane; give the disasm view all the width."""
        left = self.query_one("#left", FunctionsPanel)
        left.display = not left.display
        if not left.display:
            self.query_one(DisasmView).focus()
        else:
            self.query_one("#func-table", DataTable).focus()

    def action_toggle_focus(self) -> None:
        table = self.query_one("#func-table", DataTable)
        if self.focused is table:
            self.query_one(DisasmView).focus()
        else:
            table.focus()

    def action_filter(self) -> None:
        inp = self.query_one("#func-filter", Input)
        inp.placeholder = "filter (glob, e.g. sub_*)  —  Enter to apply"
        inp.can_focus = True
        inp.display = True
        inp.value = self._cur_filter or ""
        inp.focus()

    def action_goto(self) -> None:
        inp = self.query_one("#func-filter", Input)
        inp.display = True
        inp.placeholder = "goto: name or 0xADDR — Enter"
        inp.can_focus = True
        inp.value = ""
        inp.focus()
        self._goto_mode = True

    def action_back(self) -> None:
        if len(self._nav) > 1:
            self._nav.pop()
            self._open_entry(self._nav[-1], push=False)
        else:
            self.query_one("#func-table", DataTable).focus()

    # -- input submit (filter / goto) ------------------------------------- #
    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        inp = event.input
        inp.display = False
        inp.can_focus = False
        if getattr(self, "_goto_mode", False):
            self._goto_mode = False
            inp.placeholder = "filter (glob, e.g. sub_*)  —  Enter to apply"
            self.query_one("#func-table", DataTable).focus()
            if value:
                self._goto(value)
            return
        # filter mode
        self._cur_filter = value or None
        self.query_one("#func-table", DataTable).focus()
        self._load_functions(filter=self._cur_filter)

    @work(thread=True, exclusive=True, group="goto")
    def _goto(self, target: str) -> None:
        assert self.program is not None
        try:
            ea = self.program.resolve(target)
        except Exception as e:  # noqa: BLE001
            self.app.call_from_thread(self._status, f"goto: {e}")
            return
        f = self.program.functions().by_addr(ea)
        name = f.name if f else target
        self.app.call_from_thread(self._open_function, ea, name)

    # -- opening functions ------------------------------------------------- #
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ea = int(event.row_key.value)
        table = self.query_one("#func-table", DataTable)
        row = table.get_row(event.row_key)
        name = row[1] if row else hex(ea)
        self._open_function(ea, name)

    def _open_function(self, ea: int, name: str, push: bool = True) -> None:
        entry = NavEntry(ea=ea, name=name, cursor=0)
        if push:
            self._nav.append(entry)
        self._open_entry(entry, push=False)

    def _open_entry(self, entry: NavEntry, push: bool) -> None:
        if self.program is None:
            return
        view = self.query_one(DisasmView)
        model = self.program.disasm(entry.ea, entry.name)
        view.load(model, entry.name, cursor=entry.cursor)
        view.focus()
        self._status(f"{entry.name}  @ {entry.ea:#x}")

    def on_disasm_view_cursor_moved(self, msg: DisasmView.CursorMoved) -> None:
        if self._nav:
            self._nav[-1].cursor = msg.index
        ea = msg.ea
        if ea is not None:
            name = self._nav[-1].name if self._nav else ""
            self._status(f"{name}  @ {ea:#x}   (line {msg.index})")

    # -- teardown ---------------------------------------------------------- #
    def on_unmount(self) -> None:
        if self._ka is not None:
            self._ka.stop()
        if self.program is not None:
            self.program.close()
        if self.client is not None:
            self.client.close()
