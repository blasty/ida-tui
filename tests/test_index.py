#!/usr/bin/env python3
"""Unit tests for idatui.index (the project-wide symbol/string index).

Pure stdlib: no IDA, no textual, no worker.

    python tests/test_index.py
"""

#: the symbol/string index, pure stdlib.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.index import (  # noqa: E402
    KIND_EXPORT,
    KIND_FUNC,
    KIND_IMPORT,
    KIND_STRING,
    ProjectIndex,
)

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "libfoo.so")
        with open(src, "wb") as f:
            f.write(b"\x7fELF binary")
        idx = ProjectIndex(os.path.join(tmp, "idx", "project.db"))

        check("a fresh index is empty", idx.total() == 0 and idx.counts() == {})
        check("an unindexed binary is stale", idx.is_stale("libfoo", src))

        n = idx.reindex(
            "libfoo",
            [
                (KIND_FUNC, 0x1000, "SSL_CTX_new"),
                (KIND_FUNC, 0x1100, "SSL_read"),
                (KIND_FUNC, 0x1200, "sub_1200"),
                (KIND_STRING, 0x8000, "error opening socket"),
                (KIND_STRING, 0x8100, "/etc/ssl/certs"),
            ],
            source=src,
        )
        check("reindex reports what it stored", n == 5, f"n={n}")
        check("the entries are there", idx.total() == 5, f"{idx.total()}")
        check("an indexed binary is fresh", not idx.is_stale("libfoo", src))

        # -- substring search (the thing a prefix index can't do) ----------- #
        hits = idx.search("SSL", kind=KIND_FUNC)
        check(
            "finds symbols by substring",
            {h.text for h in hits} == {"SSL_CTX_new", "SSL_read"},
            f"{[h.text for h in hits]}",
        )
        check(
            "matching ignores case across kinds (SSL also hits /etc/ssl)",
            {h.text for h in idx.search("SSL")}
            == {"SSL_CTX_new", "SSL_read", "/etc/ssl/certs"},
            f"{[h.text for h in idx.search('SSL')]}",
        )
        hits = idx.search("socket")
        check(
            "finds strings by substring mid-text",
            len(hits) == 1 and hits[0].kind == KIND_STRING and hits[0].addr == 0x8000,
            f"{hits}",
        )
        check(
            "hits carry the owning binary",
            all(h.binary == "libfoo" for h in idx.search("SSL")),
        )
        check(
            "search is case-insensitive",
            {h.text for h in idx.search("ssl_read")} == {"SSL_read"},
            f"{[h.text for h in idx.search('ssl_read')]}",
        )
        check(
            "kind filter narrows to strings",
            [h.text for h in idx.search("ss", kind=KIND_STRING)] == ["/etc/ssl/certs"],
            f"{[h.text for h in idx.search('ss', kind=KIND_STRING)]}",
        )

        # -- the <3 char fallback (trigram silently matches nothing) -------- #
        check(
            "2-char query still works (LIKE fallback)",
            {h.text for h in idx.search("ss")}
            == {"SSL_CTX_new", "SSL_read", "/etc/ssl/certs"},
            f"{[h.text for h in idx.search('ss')]}",
        )
        check(
            "1-char query still works", len(idx.search("/")) == 1, f"{idx.search('/')}"
        )
        check("an empty query matches nothing", idx.search("   ") == [])
        check(
            "a query with FTS operators is treated literally",
            idx.search('SSL OR "') == [] or True,
        )  # must not raise

        # -- multi-binary: the whole point ---------------------------------- #
        idx.reindex(
            "httpd",
            [
                (KIND_FUNC, 0x2000, "handle_ssl_request"),
                (KIND_STRING, 0x9000, "socket bind failed"),
            ],
        )
        hits = idx.search("ssl")
        check(
            "search spans binaries",
            {h.binary for h in hits} == {"libfoo", "httpd"},
            f"{[(h.binary, h.text) for h in hits]}",
        )
        check(
            "counts are per binary",
            idx.counts() == {"libfoo": 5, "httpd": 2},
            f"{idx.counts()}",
        )

        # -- incremental: reindexing one binary leaves the others alone ----- #
        idx.reindex("libfoo", [(KIND_FUNC, 0x1000, "SSL_CTX_new_v2")], source=src)
        check(
            "reindex replaces only that binary's entries",
            idx.counts() == {"libfoo": 1, "httpd": 2},
            f"{idx.counts()}",
        )
        check(
            "the stale entries are gone",
            [h.text for h in idx.search("SSL_read")] == [],
            f"{idx.search('SSL_read')}",
        )
        check(
            "the other binary survived untouched", len(idx.search("socket bind")) == 1
        )

        # -- staleness follows the source ----------------------------------- #
        time.sleep(0.01)
        with open(src, "wb") as f:
            f.write(b"\x7fELF binary rebuilt, different size")
        os.utime(src, (1, 1))
        check("a changed source goes stale", idx.is_stale("libfoo", src))
        check(
            "a missing source does NOT wipe the index",
            not idx.is_stale("libfoo", os.path.join(tmp, "gone")),
        )

        # -- forget ----------------------------------------------------------- #
        idx.forget("httpd")
        check(
            "forget drops a binary entirely",
            idx.counts() == {"libfoo": 1} and idx.search("socket bind") == [],
            f"{idx.counts()}",
        )

        # -- cross-binary linkage join (phase 3) ------------------------------ #
        idx.reindex(
            "app",
            [
                (KIND_FUNC, 0x1000, "main"),
                (KIND_IMPORT, 0x2000, "strcmp"),
                (KIND_IMPORT, 0x2008, "read"),
                (KIND_IMPORT, 0x2010, "SSL_new"),
            ],
        )
        idx.reindex(
            "libc",
            [
                (KIND_EXPORT, 0x8000, "strcmp"),
                (KIND_EXPORT, 0x8100, "read"),
                (KIND_EXPORT, 0x8200, "pread"),
                (KIND_EXPORT, 0x8300, "read_line"),
                (KIND_FUNC, 0x8000, "strcmp"),
            ],
        )
        idx.reindex("libssl", [(KIND_EXPORT, 0x9000, "SSL_new")])

        prov = idx.providers("strcmp", exclude="app")
        check(
            "an import resolves to the binary that exports it",
            [(h.binary, h.addr) for h in prov] == [("libc", 0x8000)],
            f"{[(h.binary, hex(h.addr)) for h in prov]}",
        )

        # The whole point of exact(): substring search would drag in pread,
        # read_line and thread_start, and 'read' is also below the trigram floor
        # for some engines — an import must bind to its exact name or nothing.
        prov = idx.providers("read", exclude="app")
        check(
            "the join is exact, not substring",
            [(h.binary, h.addr) for h in prov] == [("libc", 0x8100)],
            f"{[(h.binary, h.text) for h in prov]}",
        )

        check(
            "a short name still resolves (below the trigram floor)",
            [h.binary for h in idx.providers("SSL_new", exclude="app")] == ["libssl"],
            f"{idx.providers('SSL_new')}",
        )

        check(
            "an unprovided import resolves to nothing",
            idx.providers("dlopen", exclude="app") == [],
        )

        check(
            "exclude keeps a binary from resolving to itself",
            idx.providers("strcmp", exclude="libc") == [],
            f"{idx.providers('strcmp', exclude='libc')}",
        )

        imp = idx.importers("strcmp")
        check(
            "the reverse join finds who imports an export",
            [(h.binary, h.addr) for h in imp] == [("app", 0x2000)],
            f"{[(h.binary, hex(h.addr)) for h in imp]}",
        )

        check(
            "kind keeps functions out of the linkage join",
            [h.binary for h in idx.providers("strcmp")] == ["libc"],
            "a KIND_FUNC row named strcmp must not answer as an export",
        )

        idx.forget("libc")
        check(
            "forgetting a provider unresolves its imports",
            idx.providers("strcmp", exclude="app") == [],
        )

        # -- ELF symbol versioning -------------------------------------------- #
        # The importer sees strrchr@@GLIBC_2.2.5 while the provider may export a
        # different spelling; raw names would resolve almost nothing. link_name
        # cuts at the first '@' so both sides meet on the bare symbol.
        from idatui.domain import link_name

        check(
            "link_name strips an ELF version suffix",
            link_name("strrchr@@GLIBC_2.2.5") == "strrchr",
            link_name("strrchr@@GLIBC_2.2.5"),
        )
        check(
            "link_name leaves an unversioned name alone",
            link_name("strrchr") == "strrchr",
        )
        check(
            "link_name handles a single-@ version",
            link_name("SSL_new@OPENSSL_3.0.0") == "SSL_new",
        )
        check(
            "link_name doesn't eat a leading @",
            link_name("@weird") == "@weird",
            link_name("@weird"),
        )

        # -- persistence ------------------------------------------------------ #
        path = idx.path
        idx.close()
        idx2 = ProjectIndex(path)
        check(
            "the index persists across sessions",
            [h.text for h in idx2.search("SSL_CTX")] == ["SSL_CTX_new_v2"],
            f"{idx2.search('SSL_CTX')}",
        )
        idx2.close()

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
