#!/usr/bin/env python3
"""Unit tests for idatui.project (the multi-binary project model + staging).

Pure stdlib: no IDA, no textual, no worker — runs anywhere in under a second.

    python tests/test_project.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.project import Project, ProjectError, SIDECAR_SUFFIX  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def _bin(path, content=b"\x7fELF fake binary"):
    with open(path, "wb") as f:
        f.write(content)
    return path


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        httpd = _bin(os.path.join(src, "httpd"))
        libauth = _bin(os.path.join(src, "libauth.so"), b"\x7fELF lib")
        pfile = os.path.join(tmp, "router-fw.json")

        # -- create / load round-trip ------------------------------------- #
        proj = Project.create(pfile, [httpd, libauth], name="router-fw")
        check("create() writes the project file", os.path.isfile(pfile))
        proj = Project.load(pfile)
        check("load() round-trips name + binaries",
              proj.name == "router-fw" and len(proj.refs) == 2,
              f"name={proj.name} n={len(proj.refs)}")
        check("labels default to the basename",
              [r.label for r in proj.refs] == ["httpd", "libauth.so"],
              f"{[r.label for r in proj.refs]}")

        # -- layout -------------------------------------------------------- #
        check("sidecar sits beside the project file",
              proj.sidecar == os.path.join(tmp, "router-fw" + SIDECAR_SUFFIX),
              proj.sidecar)
        ref = proj.by_label("httpd")
        check("staged path lives in the sidecar, not the source tree",
              ref.staged.startswith(proj.bin_dir) and src not in ref.staged,
              ref.staged)
        check("db path hangs off the staged file", ref.db == ref.staged + ".i64")

        # -- staging: hardlink, freshness ---------------------------------- #
        check("a binary starts out stale (not yet staged)", proj.is_stale(ref))
        proj.stage(ref)
        check("stage() materialises the binary in the sidecar",
              os.path.isfile(ref.staged))
        check("stage() copies (distinct inode) so the source can't be mutated "
              "through it",
              os.stat(ref.staged).st_ino != os.stat(ref.source).st_ino
              and open(ref.staged, "rb").read() == open(ref.source, "rb").read())
        check("a staged binary is no longer stale", not proj.is_stale(ref))
        check("source tree stays clean (no IDA artifacts beside it)",
              sorted(os.listdir(src)) == ["httpd", "libauth.so"],
              f"{sorted(os.listdir(src))}")

        # -- a changed source re-stages and drops the stale DB ------------- #
        open(ref.db, "wb").write(b"fake i64")
        open(ref.staged + ".id0", "wb").write(b"scratch")
        check("has_db() sees the analysed database", proj.has_db(ref))
        # rewritten IN PLACE (same inode) — the case a hardlink would miss
        _bin(ref.source, b"\x7fELF fake binary v2 (longer)")
        os.utime(ref.source, (1, 1))
        check("a source rebuilt in place goes stale", proj.is_stale(ref))
        proj.stage(ref)
        check("re-staging refreshes the staged bytes",
              open(ref.staged, "rb").read().endswith(b"v2 (longer)"))
        check("re-staging drops the now-stale database", not proj.has_db(ref))
        check("re-staging drops the stale scratch too",
              not os.path.exists(ref.staged + ".id0"))

        # -- scratch sweep keeps the DB ------------------------------------ #
        open(ref.db, "wb").write(b"fake i64")
        for suf in (".id0", ".id1", ".nam"):
            open(ref.staged + suf, "wb").write(b"x")
        n = proj.sweep_scratch(ref)
        check("sweep_scratch() removes the unpacked working files", n == 3, f"n={n}")
        check("sweep_scratch() never touches the .i64", proj.has_db(ref))

        # -- relative paths + label collisions ----------------------------- #
        sub = os.path.join(tmp, "other")
        os.makedirs(sub)
        dup = _bin(os.path.join(sub, "httpd"), b"\x7fELF other httpd")
        with open(pfile, "w") as f:
            json.dump({"name": "p", "binaries": [
                {"path": "src/httpd"},            # relative to the project file
                {"path": dup},                    # same basename -> collision
                {"path": libauth, "label": "auth"},
            ]}, f)
        proj2 = Project.load(pfile)
        check("relative paths resolve against the project file",
              proj2.refs[0].source == httpd, proj2.refs[0].source)
        check("colliding labels are disambiguated",
              [r.label for r in proj2.refs] == ["httpd", "httpd_2", "auth"],
              f"{[r.label for r in proj2.refs]}")
        check("explicit labels are honoured", proj2.by_label("auth") is not None)
        proj2.stage_all()
        check("stage_all() stages every binary to a distinct file",
              len({r.staged for r in proj2.refs}) == 3
              and all(os.path.isfile(r.staged) for r in proj2.refs))

        # -- add / remove ---------------------------------------------------- #
        extra = _bin(os.path.join(src, "extra"))
        proj2.add(extra, label="extra")
        check("add() appends a binary", proj2.by_label("extra") is not None)
        check("remove() drops one", proj2.remove("extra")
              and proj2.by_label("extra") is None)

        # -- bad input ------------------------------------------------------- #
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w") as f:
            f.write("{not json")
        try:
            Project.load(bad)
            check("malformed JSON raises ProjectError", False, "no raise")
        except ProjectError:
            check("malformed JSON raises ProjectError", True)
        with open(bad, "w") as f:
            json.dump({"binaries": []}, f)
        try:
            Project.load(bad)
            check("an empty project raises ProjectError", False, "no raise")
        except ProjectError:
            check("an empty project raises ProjectError", True)
        missing = proj2.add(os.path.join(tmp, "nope"))
        try:
            proj2.stage(missing)
            check("staging a missing binary raises ProjectError", False, "no raise")
        except ProjectError:
            check("staging a missing binary raises ProjectError", True)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
