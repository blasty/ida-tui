"""Render a modal's chrome headless, with fake data, and print it.

    python3 experiments/modal_shot.py [name] [cols] [rows]
    python3 experiments/modal_shot.py --list

Chrome (borders, titles, spacing) is the one thing you cannot judge from the
pane you are working in, and opening a binary just to look at a dialog costs a
full auto-analysis. Every modal here is fed a stub, so this needs NO worker, NO
IDA and no .i64 -- it runs under any python with textual, in about a second.

The app it boots is a bare `App` carrying `IdaTui.CSS` and the app theme, which
is exactly what the modals resolve their styles against.
"""
import asyncio
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from textual.app import App, ComposeResult                    # noqa: E402
from textual.widgets import Static                            # noqa: E402

from idatui.app import (                                      # noqa: E402
    IDATUI_THEME, IdaTui, BusyScreen, ConfirmScreen, HelpScreen, LoadingScreen,
    QuitScreen, StructEditor, XrefsScreen,
)
from idatui.domain import Struct                              # noqa: E402
from idatui.rpc import screen_text                            # noqa: E402
from idatui._sync import wait_for                             # noqa: E402


class _StubProgram:
    """Just enough Program for the struct editor to render."""

    _STRUCTS = [
        Struct(name="timespec", size=0x10, members=2, is_union=False, ordinal=1),
        Struct(name="stat", size=0x90, members=15, is_union=False, ordinal=2),
        Struct(name="pthread_mutex_t", size=0x28, members=4, is_union=True,
               ordinal=3),
    ]
    _SRC = ("struct timespec\n"
            "{\n"
            "    __time_t tv_sec;   /* seconds */\n"
            "    __syscall_slong_t tv_nsec;\n"
            "};\n")

    def list_structs(self):
        return list(self._STRUCTS)

    def struct_source(self, name):
        return self._SRC.replace("timespec", name)


def _make(name: str):
    """name -> a mounted-ready modal screen."""
    if name == "structs":
        return StructEditor(_StubProgram())
    if name == "confirm":
        return ConfirmScreen("Delete struct 'timespec' ?",
                             "This cannot be undone.")
    if name == "quit":
        return QuitScreen(["echo", "libc.so.6"])
    if name == "help":
        return HelpScreen()
    if name == "busy":
        return BusyScreen("decompiling sub_2297\u2026")
    if name == "loading":
        return LoadingScreen("echo", "opening database\u2026")
    if name == "xrefs":
        return XrefsScreen(" xrefs to main", [
            (0x1234, "  sub_2297+0x1c    call    main"),
            (0x5678, "  _start+0x21      mov     rdi, main"),
        ])
    raise SystemExit(f"unknown modal {name!r}; --list to see them")


NAMES = ["structs", "confirm", "quit", "help", "busy", "loading", "xrefs"]


class _Shot(App):
    CSS = IdaTui.CSS

    def compose(self) -> ComposeResult:
        # A little content underneath, so the modal's edge is visible against
        # something rather than floating on an empty screen.
        yield Static("\n".join("  .... the view behind the dialog ...."
                               for _ in range(60)))

    def on_mount(self) -> None:
        self.register_theme(IDATUI_THEME)
        self.theme = IDATUI_THEME.name


async def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--list" in sys.argv:
        print(" ".join(NAMES))
        return
    names = [args[0]] if args else NAMES
    cols = int(args[1]) if len(args) > 1 else 100
    rows = int(args[2]) if len(args) > 2 else 32

    for name in names:
        app = _Shot()
        async with app.run_test(size=(cols, rows)) as pilot:
            app.push_screen(_make(name))
            await pilot.pause()
            if name == "structs":
                await wait_for(
                    lambda: bool(getattr(app.screen, "_structs", None)),
                    pilot.pause, 5)
                app.screen.on_option_list_option_selected(
                    type("E", (), {"option_index": 0})())
                await wait_for(lambda: "{" in app.screen.query_one(
                    "#se-edit").text, pilot.pause, 5)
            await pilot.pause()
            print(f"\n=== {name} " + "=" * (cols - len(name) - 5))
            print(screen_text(app)["text"])


if __name__ == "__main__":
    asyncio.run(main())
