"""Where swallowed errors go.

A TUI must not die because one background load failed, so this codebase catches
broadly -- around fifty ``except Exception`` sites, two dozen of which resolve
to ``pass``. That is the right policy and it has one bad consequence: with
forty-odd ``@work(thread=True)`` workers, a failure in a background load leaves
no trace at all. The view just stays empty, and there is nothing to read
afterwards because the app owns the screen.

``kittygfx`` already solved this for itself with ``$IDATUI_KITTY_LOG``. This is
the same idea for everything else:

* ``$IDATUI_LOG=/tmp/x.log`` writes every swallowed error to a file. Unset (the
  default) it costs an ``os.environ`` lookup and nothing else.
* The last few are kept in memory regardless, so ``drive diag`` can ask a live
  app "what went wrong recently?" -- which is the question you actually have
  when a driver reports success and the pane shows nothing.

Use it where an exception would otherwise vanish::

    with swallow("decomp_map(%#x)" % ea):
        self._apply_split_map(ea, self.program.decomp_map(ea))

NOT for expected control flow. ``query_one`` raising because a modal owns the
screen is normal and happens constantly; wrapping that would bury the real
entries in noise. The test for whether it belongs here is "would I want to see
this after the fact?".
"""
from __future__ import annotations

import contextlib
import os
import threading
import time
import traceback
from collections import deque

#: Bounded on purpose: this is a debugging aid inside a long-running TUI, not an
#: audit log. Old entries are worth less than the memory.
_MAX = 50
_ring: deque[dict] = deque(maxlen=_MAX)
_lock = threading.Lock()


def _logfile() -> str | None:
    """Read the env var per call, not once at import.

    The pilot suite and the RPC tests set it after importing the app, and a
    cached value would silently disable the thing being tested.
    """
    return os.environ.get("IDATUI_LOG") or None


def log(msg: str) -> None:
    """Append a line to ``$IDATUI_LOG``. No-op when it isn't set."""
    path = _logfile()
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass          # a broken log path must never break the app


def note(what: str, exc: BaseException) -> None:
    """Record a swallowed exception: in the ring always, in the log if enabled."""
    entry = {
        "when": time.time(),
        "what": what,
        "error": f"{type(exc).__name__}: {exc}",
        "where": _origin(exc),
        "thread": threading.current_thread().name,
    }
    with _lock:
        _ring.append(entry)
    log(f"[swallowed] {what}: {entry['error']}  ({entry['where']})")
    if _logfile():
        log("".join(traceback.format_exception(
            type(exc), exc, exc.__traceback__)).rstrip())


def _origin(exc: BaseException) -> str:
    """file:line where it was actually raised (the deepest frame we have)."""
    tb = exc.__traceback__
    last = None
    while tb is not None:
        last = tb
        tb = tb.tb_next
    if last is None:
        return "?"
    f = last.tb_frame
    return f"{os.path.basename(f.f_code.co_filename)}:{last.tb_lineno}"


@contextlib.contextmanager
def swallow(what: str, *, reraise: tuple = ()):
    """Run a block, record anything it raises, and carry on.

    ``reraise`` lets a caller keep the exceptions it genuinely handles -- most
    usefully ``IDAConnectionError``, which the app turns into a reconnect and
    must not have eaten here.
    """
    try:
        yield
    except reraise:
        raise
    except Exception as e:  # noqa: BLE001 -- the whole point
        note(what, e)


def recent(n: int = 10) -> list[dict]:
    """The last ``n`` swallowed errors, newest last."""
    with _lock:
        items = list(_ring)
    return items[-n:] if n > 0 else items


def clear() -> None:
    with _lock:
        _ring.clear()
