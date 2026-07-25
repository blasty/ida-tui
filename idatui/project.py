"""Multi-binary projects: group the binaries of one target under a project file.

A project is an explicit JSON file plus a sidecar directory beside it::

    router-fw.json               # the project file
    router-fw.idatui.d/
      bin/httpd                  # hardlink (or copy) of the source binary
      bin/httpd.i64              # IDA's DB + scratch land here automatically
      idx/httpd.json             # cached index (phase 2)

Binaries are **staged** into ``bin/`` and IDA opens the staged file, so the
``.i64`` and every ``.id0/.id1/.id2/.nam/.til`` scratch file are created inside
the sidecar instead of next to the original. Source trees stay pristine.

Staging **copies** rather than hardlinks. A hardlink would be free, but source
and staged would be one inode: an in-place rebuild (``cp newbuild /path/bin``
truncates instead of replacing) would silently swap the bytes under an already
analysed database, with nothing to detect it. A copy costs a fraction of the
``.i64`` it will grow, decouples the two completely, and leaves the sidecar
self-contained — the project still opens after the sources go away (an unmounted
firmware image, a cleaned build tree).

A source whose size/mtime no longer matches the staged copy is re-staged, and its
now-stale database is dropped (the DB describes the old bytes).

stdlib-only, like the domain/worker layers — the TUI is the only Textual consumer.
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass

SIDECAR_SUFFIX = ".idatui.d"
DEFAULT_MEMORY_PCT = 25

#: The database plus the working files IDA unpacks beside it while it's open.
DB_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")
#: Just the unpacked scratch — safe to delete when no worker holds the DB.
SCRATCH_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


class ProjectError(Exception):
    """A malformed project file, or a binary that can't be staged."""


@dataclass(frozen=True)
class BinaryRef:
    """One binary in a project: where it came from, and where IDA works on it."""

    label: str    # unique within the project; names the staged file
    source: str   # absolute path to the original binary
    staged: str   # absolute path IDA actually opens (inside the sidecar)

    @property
    def db(self) -> str:
        """The database IDA creates for the staged file."""
        return self.staged + ".i64"


def _stat_key(path: str) -> tuple[int, int] | None:
    """(size, mtime) identity used to spot a source that changed under us."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_size, int(st.st_mtime))


def _unlink(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False


class Project:
    """A set of binaries analysed together, with all IDA artifacts corralled."""

    def __init__(self, path: str, name: str, entries: list[dict],
                 memory_pct: int = DEFAULT_MEMORY_PCT) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        self.name = name
        self.memory_pct = memory_pct
        self._entries = entries          # raw, as written to the file
        self._refs = self._build_refs()

    # -- construction ------------------------------------------------------ #
    @classmethod
    def load(cls, path: str) -> "Project":
        path = os.path.abspath(os.path.expanduser(path))
        try:
            with open(path) as f:
                raw = json.load(f)
        except OSError as e:
            raise ProjectError(f"cannot read project {path}: {e}") from e
        except ValueError as e:
            raise ProjectError(f"malformed project {path}: {e}") from e
        if not isinstance(raw, dict):
            raise ProjectError(f"malformed project {path}: expected an object")
        entries = raw.get("binaries")
        if not isinstance(entries, list) or not entries:
            raise ProjectError(f"project {path} lists no binaries")
        norm: list[dict] = []
        for e in entries:
            if isinstance(e, str):
                e = {"path": e}
            if not isinstance(e, dict) or not e.get("path"):
                raise ProjectError(f"project {path}: bad binary entry {e!r}")
            norm.append({k: e[k] for k in ("path", "label") if e.get(k)})
        name = raw.get("name") or os.path.splitext(os.path.basename(path))[0]
        try:
            pct = int(raw.get("memory_pct", DEFAULT_MEMORY_PCT))
        except (TypeError, ValueError):
            pct = DEFAULT_MEMORY_PCT
        return cls(path, str(name), norm, max(1, min(pct, 90)))

    @classmethod
    def create(cls, path: str, binaries: list[str], name: str | None = None,
               memory_pct: int = DEFAULT_MEMORY_PCT) -> "Project":
        """Write a new project file listing ``binaries`` (an ad-hoc project)."""
        if not binaries:
            raise ProjectError("a project needs at least one binary")
        entries = [{"path": os.path.abspath(os.path.expanduser(b))}
                   for b in binaries]
        path = os.path.abspath(os.path.expanduser(path))
        proj = cls(path, name or os.path.splitext(os.path.basename(path))[0],
                   entries, memory_pct)
        proj.save()
        return proj

    def save(self) -> None:
        data = {"name": self.name, "memory_pct": self.memory_pct,
                "binaries": self._entries}
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, self.path)

    # -- layout ------------------------------------------------------------ #
    @property
    def sidecar(self) -> str:
        """The directory holding staged binaries, databases and indexes."""
        return os.path.splitext(self.path)[0] + SIDECAR_SUFFIX

    @property
    def bin_dir(self) -> str:
        return os.path.join(self.sidecar, "bin")

    @property
    def index_dir(self) -> str:
        return os.path.join(self.sidecar, "idx")

    def index_path(self, ref: BinaryRef) -> str:
        """Where the cached per-binary index lives (phase 2)."""
        return os.path.join(self.index_dir, ref.label + ".json")

    # -- binaries ---------------------------------------------------------- #
    def _build_refs(self) -> tuple[BinaryRef, ...]:
        base = os.path.dirname(self.path)
        refs: list[BinaryRef] = []
        used: set[str] = set()
        for e in self._entries:
            src = os.path.expanduser(str(e["path"]))
            if not os.path.isabs(src):  # relative to the project file
                src = os.path.join(base, src)
            src = os.path.abspath(src)
            label = str(e.get("label") or os.path.basename(src)) or "binary"
            label = label.replace("/", "_").replace(os.sep, "_")
            if label in used:  # labels name files; keep them unique + stable
                n = 2
                while f"{label}_{n}" in used:
                    n += 1
                label = f"{label}_{n}"
            used.add(label)
            refs.append(BinaryRef(label=label, source=src,
                                  staged=os.path.join(self.bin_dir, label)))
        return tuple(refs)

    @property
    def refs(self) -> tuple[BinaryRef, ...]:
        return self._refs

    def by_label(self, label: str) -> BinaryRef | None:
        return next((r for r in self._refs if r.label == label), None)

    def add(self, binary: str, label: str | None = None) -> BinaryRef:
        entry = {"path": os.path.abspath(os.path.expanduser(binary))}
        if label:
            entry["label"] = label
        self._entries.append(entry)
        self._refs = self._build_refs()
        return self._refs[-1]

    def remove(self, label: str) -> bool:
        ref = self.by_label(label)
        if ref is None:
            return False
        i = self._refs.index(ref)
        del self._entries[i]
        self._refs = self._build_refs()
        return True

    # -- staging ----------------------------------------------------------- #
    def is_stale(self, ref: BinaryRef) -> bool:
        """True when the staged file is missing or no longer matches its source."""
        staged = _stat_key(ref.staged)
        return staged is None or staged != _stat_key(ref.source)

    def stage(self, ref: BinaryRef) -> str:
        """Ensure ``ref`` is staged in the sidecar; returns the staged path.

        Re-staging a changed source drops its database: the DB describes the old
        bytes, so keeping it would silently mismatch the disassembly (any renames
        in it are lost, which is why callers should say so out loud).
        """
        if not os.path.isfile(ref.source):
            raise ProjectError(f"no such binary: {ref.source}")
        if not self.is_stale(ref):
            return ref.staged
        os.makedirs(self.bin_dir, exist_ok=True)
        tmp = ref.staged + ".staging"
        _unlink(tmp)
        # copy2 (not link): keeps size+mtime so freshness compares cleanly, while
        # leaving the staged bytes immune to an in-place rewrite of the source.
        shutil.copy2(ref.source, tmp)
        os.replace(tmp, ref.staged)
        for suf in DB_SUFFIXES:            # the old DB describes the old bytes
            _unlink(ref.staged + suf)
        return ref.staged

    def stage_all(self, progress=None) -> list[BinaryRef]:
        out = []
        for ref in self._refs:
            if progress is not None:
                progress(f"staging {ref.label}\u2026")
            self.stage(ref)
            out.append(ref)
        return out

    def sweep_scratch(self, ref: BinaryRef) -> int:
        """Delete IDA's unpacked working files (never the ``.i64``) for ``ref``.

        A hard-killed worker leaves them behind and the database then refuses to
        reopen. Only safe when no worker holds it.
        """
        return sum(1 for suf in SCRATCH_SUFFIXES if _unlink(ref.staged + suf))

    def has_db(self, ref: BinaryRef) -> bool:
        """True once the binary has been analysed and saved at least once."""
        return os.path.isfile(ref.db)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Project {self.name!r} {len(self._refs)} binaries {self.path}>"
