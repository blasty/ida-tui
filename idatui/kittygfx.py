"""Kitty graphics protocol: detect it, upload an image, place it on screen.

Used for the startup splash, which otherwise falls back to the block-art
``logo.ans``. Two things about this were expensive to find out, so they are
written down here rather than rediscovered.

**Support cannot be sniffed from the environment.** A multiplexer that passes
the protocol through (recent zellij, tmux with allow-passthrough) leaves TERM as
``xterm-256color`` with ``KITTY_WINDOW_ID``, ``TERM_PROGRAM`` and ``COLORTERM``
all empty, while the protocol answers perfectly. Detection by terminal name
would disable graphics on exactly the terminals that support them. So we ask:
send a 1x1 graphics query together with a Primary Device Attributes request.
Every terminal answers DA1, so that reply is the sync point -- a ``_G...OK``
before it means yes, DA1 alone means no. No timeouts to tune, no allowlist.

**Unicode placeholders are not usable.** The tidy way to put an image in a TUI
is a virtual placement (``U=1``) plus U+10EEEE placeholder cells, which the
compositor then moves and clips like ordinary text. It is also what every
Textual image library is built on -- and this terminal answers
``ENOTSUPPORTED:unicode placeholders are not supported`` while supporting
everything else. So we use ordinary placement: the image is anchored at a screen
cell and stays there until deleted, which means the caller owns its lifetime
(place on mount and resize, delete on unmount) and must reserve blank cells
underneath. That is fine for a splash and deliberately not built up into a
general image widget.

**Uploading and drawing happen on opposite sides of the alternate screen.** The
detection query must run BEFORE the app starts, because it needs a reply and
Textual reads stdin on its own thread. The IMAGE, though, must be uploaded AFTER
Textual has switched to the alternate screen: an image uploaded to the primary
screen cannot be placed from the alternate one -- placement reports no error, it
simply draws nothing. That combination is why the splash calls ``supported()``
from the launcher and ``upload()`` from its own ``on_mount``.
"""
from __future__ import annotations

import base64
import os
import re
import select
import struct
import sys
import time

#: One id for the splash. Ids are a terminal-wide namespace shared with whatever
#: else the user is running, so this is deliberately not 1.
LOGO_ID = 0x1DA7

_supported: bool | None = None
_uploaded: dict[int, tuple[int, int]] = {}   # image id -> (pixel w, pixel h)
#: Terminal cell size in pixels, asked for in the same round trip as the
#: graphics query. Cells are nothing like a fixed 1:2 -- this box reports 9x22,
#: i.e. 1:2.44 -- and getting it wrong stretches the image.
_cell: tuple[int, int] | None = None


def log(msg: str) -> None:
    """Trace to ``$IDATUI_KITTY_LOG``. The splash lives inside a full-screen TUI
    on a tty we can't print to, so this is the only way to see what it decided."""
    path = os.environ.get("IDATUI_KITTY_LOG")
    if not path:
        return
    try:
        with open(path, "a") as f:
            f.write(f"{time.time():.3f} {msg}\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def _query_tty(timeout: float = 2.0) -> bool:
    # ``termios`` and ``/dev/tty`` are POSIX-only. Native Windows terminals
    # generally don't expose the synchronous reply channel this probe needs;
    # use the ANSI-art splash there instead of making graphics fatal to the
    # whole application. IDATUI_KITTY=1 still permits an explicit override.
    try:
        import termios
        import tty as ttymod
    except ImportError:
        log("supported: tty queries are unavailable on this platform")
        return False

    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return False
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        os.close(fd)
        return False
    try:
        ttymod.setraw(fd)
        # graphics query + cell-size query + DA1. DA1 is answered by everything,
        # so it marks the end of the replies and nothing has to be timed.
        os.write(fd, b"\033_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\033\\\033[16t\033[c")
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r, _, _ = select.select([fd], [], [], 0.15)
            if not r:
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buf += chunk
            if re.search(rb"\033\[\?[0-9;]*c", buf):    # DA1: the answers are in
                break
        global _cell
        m = re.search(rb"\033\[6;(\d+);(\d+)t", buf)    # CSI 6 ; height ; width t
        if m:
            ch, cw = int(m.group(1)), int(m.group(2))
            if 0 < cw < 100 and 0 < ch < 200:
                _cell = (cw, ch)
                log(f"cell size {cw}x{ch}px")
        return bool(re.search(rb"\033_G[^\033]*;OK\033\\", buf))
    except OSError:
        return False
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, old)
        finally:
            os.close(fd)


def supported() -> bool:
    """True if the terminal speaks the kitty graphics protocol.

    ``$IDATUI_KITTY=0/1`` forces the answer, for a terminal that swallows the
    query and for tests. Cached: the query costs a round trip and must not run
    once Textual owns stdin.
    """
    global _supported
    if _supported is not None:
        return _supported
    env = os.environ.get("IDATUI_KITTY", "").strip().lower()
    if env in ("1", "yes", "true", "on"):
        _supported = True
    elif env in ("0", "no", "false", "off"):
        _supported = False
    elif not (sys.__stdout__ and sys.__stdout__.isatty()):
        _supported = False        # pilot tests, pipes, redirected output
        log("supported: stdout is not a tty")
    else:
        try:
            _supported = _query_tty()
        except Exception as exc:  # graphics are optional on every platform
            log(f"supported: terminal query failed ({type(exc).__name__}: {exc})")
            _supported = False
    log(f"supported() -> {_supported}")
    return _supported


# --------------------------------------------------------------------------- #
# Upload / place / delete
# --------------------------------------------------------------------------- #
def png_size(path: str) -> tuple[int, int] | None:
    """(width, height) from a PNG's IHDR, without decoding it."""
    try:
        with open(path, "rb") as f:
            head = f.read(26)
    except OSError:
        return None
    if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    w, h = struct.unpack(">II", head[16:24])
    return (w, h)


def _write(data: str) -> bool:
    """Write escapes to the same stream Textual writes frames to, so the two
    can't be reordered. Called only from the app's own loop."""
    out = sys.__stdout__
    if out is None:
        return False
    try:
        out.write(data)
        out.flush()
        return True
    except (OSError, ValueError):
        return False


def upload(path: str, image_id: int = LOGO_ID) -> bool:
    """Send the PNG to the terminal WITHOUT placing it (``a=t``).

    Must be called once the app is already on the ALTERNATE screen -- an image
    uploaded to the primary screen can't be placed from the alternate one, and
    the placement fails silently. Idempotent, so callers can just ask.
    """
    if image_id in _uploaded:
        return True
    size = png_size(path)
    if size is None:
        return False
    try:
        with open(path, "rb") as f:
            payload = base64.standard_b64encode(f.read())
    except OSError:
        return False
    parts = [payload[i:i + 4096] for i in range(0, len(payload), 4096)]
    if not parts:
        return False
    buf = []
    for i, part in enumerate(parts):
        more = 1 if i < len(parts) - 1 else 0
        ctrl = (f"a=t,f=100,t=d,i={image_id},q=2,m={more}" if i == 0
                else f"m={more}")
        buf.append("\033_G" + ctrl + ";" + part.decode("ascii") + "\033\\")
    if not _write("".join(buf)):
        log("upload: write failed")
        return False
    _uploaded[image_id] = size
    log(f"upload -> ok id={image_id} px={size} chunks={len(parts)}")
    return True


def is_uploaded(image_id: int = LOGO_ID) -> bool:
    return image_id in _uploaded


def place(row: int, col: int, cols: int, rows: int,
          image_id: int = LOGO_ID) -> bool:
    """Draw the uploaded image at (``row``, ``col``), 0-based, sized in cells.

    Saves and restores the cursor, and asks the terminal not to move it
    (``C=1``), so Textual's idea of where the cursor is stays true.
    """
    size = _uploaded.get(image_id)
    if size is None or cols <= 0 or rows <= 0:
        log(f"place: refused size={size} cols={cols} rows={rows}")
        return False
    w, h = size
    log(f"place row={row} col={col} c={cols} r={rows}")
    return _write(
        f"\033[s\033[{row + 1};{col + 1}H"
        f"\033_Ga=p,i={image_id},s={w},v={h},c={cols},r={rows},C=1,q=2\033\\"
        f"\033[u")


def clear(image_id: int = LOGO_ID) -> None:
    """Remove the image's placements from the screen (it stays uploaded)."""
    _write(f"\033_Ga=d,d=i,i={image_id},q=2\033\\")


def delete(image_id: int = LOGO_ID) -> None:
    """Remove the placements AND free the image data in the terminal."""
    _write(f"\033_Ga=d,d=I,i={image_id},q=2\033\\")
    _uploaded.pop(image_id, None)


def cell_size() -> tuple[int, int]:
    """(width, height) of a terminal cell in pixels.

    Measured during the graphics query when the terminal answers CSI 16 t;
    otherwise a 10x20 guess, which is only ever used to keep the aspect ratio
    honest.
    """
    return _cell or (10, 20)


def fit(px: tuple[int, int], max_cols: int, max_rows: int,
        cell: tuple[int, int] | None = None) -> tuple[int, int]:
    """Cell size that fits ``max_cols`` x ``max_rows`` keeping the aspect ratio.

    Cells are far from square -- this box reports 9x22 px -- so a naive
    cols==rows box stretches the image; ``cell`` is that ratio in pixels and
    defaults to what the terminal actually said.
    """
    if cell is None:
        cell = cell_size()
    w, h = px
    if w <= 0 or h <= 0:
        return (max_cols, max_rows)
    cw, ch = cell
    cols = max_cols
    rows = max(int(round((h / w) * cols * cw / ch)), 1)
    if rows > max_rows:
        rows = max_rows
        cols = max(int(round((w / h) * rows * ch / cw)), 1)
    return (max(cols, 1), max(rows, 1))
