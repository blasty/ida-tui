"""Where the database goes when the binary's own directory can't hold it.

IDA puts its database beside the binary: ``/bin/ls`` becomes ``/bin/ls.i64``,
plus ``.id0/.id1/.id2/.nam/.til`` scratch files unpacked into the same directory
while it is open. For anything the user doesn't own -- ``/bin``, ``/usr/lib``, a
read-only mount, a root-owned firmware drop -- that write is denied, and the only
thing to see is the backend's account of it::

    idalib worker launcher 2425195 exited with status 1
    [ida-nexus] Failed to open database /usr/bin/ls

which names neither the file it failed to create nor the reason. Worse, the
failure costs a full analysis wait first. So: check whether the database can be
written BEFORE opening anything, and when it can't, propose a path that works.

IDA Nexus takes ``output_database`` for exactly this, and project mode already
relies on it (everything lands in the project's sidecar). This is the
single-binary equivalent, and the proposed location is *stable per binary* --
reopening ``/bin/ls`` tomorrow finds yesterday's names and comments, which a
temporary directory would not.

Pure stdlib: no IDA, no IDA Nexus, no Textual. Nothing here writes anything.
"""

from __future__ import annotations

import hashlib
import os

#: Overrides where relocated databases are kept.
DB_DIR_ENV = "IDATUI_DB_DIR"

#: Deliberately under XDG_DATA_HOME, not XDG_CACHE_HOME. An .i64 looks like a
#: cache -- it is derived from the binary and can be rebuilt -- but it also holds
#: every name, comment and type the session produced, and cache directories are
#: something cleaners are entitled to empty.
_XDG_DEFAULT = os.path.join("~", ".local", "share", "idatui", "db")


def expected_idb(binary: str) -> str:
    """The database IDA would create for ``binary``, byte for byte as Nexus does.

    Mirrors ``ida_nexus._resolver.expected_idb_path``: a path that is already an
    ``.i64`` is the database, anything else gets ``.i64`` appended (IDA 9 is
    64-bit only, so there is no ``.idb`` case to consider).
    """
    path = os.path.abspath(os.path.expanduser(binary))
    return path if path.lower().endswith(".i64") else path + ".i64"


def db_root() -> str:
    """Directory holding relocated databases."""
    override = os.environ.get(DB_DIR_ENV)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return os.path.join(os.path.abspath(os.path.expanduser(xdg)), "idatui", "db")
    return os.path.abspath(os.path.expanduser(_XDG_DEFAULT))


def _slug(name: str) -> str:
    """``name`` reduced to something safe to paste into a shell command."""
    out = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    return out.strip("._-")[:64] or "binary"


def relocated_idb(binary: str) -> str:
    """A writable database path for ``binary``, stable across runs.

    Keyed by the resolved source path so the same binary always maps to the same
    database (your work comes back), and hashed so two ``busybox``es from
    different directories cannot collide. Flat rather than one directory per
    binary: IDA unpacks its scratch files alongside the ``.i64`` under the same
    stem, and the hash already makes that stem unique.
    """
    real = os.path.normcase(os.path.realpath(os.path.expanduser(binary)))
    digest = hashlib.sha1(real.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    stem = os.path.basename(real.rstrip(os.sep) or real)
    if stem.lower().endswith(".i64"):
        stem = stem[:-4]
    return os.path.join(db_root(), f"{_slug(stem)}-{digest}.i64")


def blocked_reason(binary: str) -> str | None:
    """Why IDA could not write ``binary``'s database here, or None if it can.

    A short phrase that completes "can't open this binary because ...", meant to
    be shown to a human. ``None`` is the common answer and must stay cheap: only
    ``os.access`` calls, no probe files in the user's directories.

    ``os.access`` is not the whole truth (ACLs, an NFS mount that lies, a full
    disk), which is why the caller also treats a failed open as a candidate for
    relocation. It is right about the case that actually happens -- a binary in a
    system directory -- and being right there is worth a syscall.
    """
    idb = expected_idb(binary)
    src = os.path.abspath(os.path.expanduser(binary))
    if not os.path.exists(src):
        return None  # not ours to judge: a registered database, or a typo
    parent = os.path.dirname(idb) or "."
    if not os.path.isdir(parent):
        return f"{parent} is not a directory"
    if not os.access(parent, os.W_OK | os.X_OK):
        return f"{parent} is not writable"
    if os.path.exists(idb) and not os.access(idb, os.W_OK):
        # The directory is fine but the database itself isn't ours -- someone
        # else's analysis, or a root-owned .i64 shipped with the firmware. IDA
        # rewrites the .i64 on save, so read-only is a dead end, not a view.
        return f"{idb} exists but is not writable"
    return None


def can_create(target: str) -> bool:
    """Whether ``target`` can really be created right now, by trying it.

    The truthful version of ``blocked_reason``'s ``os.access`` check, and the
    only one that knows about ACLs, a read-only remount or a full disk. It costs
    a create + unlink in the user's directory, so it is for the path where an
    open has ALREADY failed and the question is what to blame -- never for the
    pre-flight check, which must not touch anything.

    An existing ``target`` is left strictly alone: this must never truncate a
    database.
    """
    target = os.path.abspath(os.path.expanduser(target))
    if os.path.exists(target):
        return True
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return False
    os.close(fd)
    try:
        os.unlink(target)
    except OSError:  # created it but cannot remove it: still "creatable"
        pass
    return True


def describe(binary: str, target: str) -> str:
    """One line about what relocating ``binary`` to ``target`` will do."""
    if os.path.exists(target):
        return "resuming the database already kept there (your names and comments)"
    return f"a new database; the original {expected_idb(binary)} is never written"


def ensure_parent(target: str) -> str:
    """Create ``target``'s directory (private) and return ``target``.

    0700 because a database exposes the whole binary plus whatever the session
    recorded about it, and this directory accumulates one for every binary
    opened from a place that could not hold its own.
    """
    parent = os.path.dirname(os.path.abspath(os.path.expanduser(target)))
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    return os.path.abspath(os.path.expanduser(target))
