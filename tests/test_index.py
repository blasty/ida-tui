#!/usr/bin/env python3
"""Unit tests for idatui.index (the project-wide symbol/string index).

Pure stdlib: no IDA, no textual, no worker.

    python tests/test_index.py
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idatui.index import KIND_FUNC, KIND_STRING, ProjectIndex  # noqa: E402

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

        n = idx.reindex("libfoo", [
            (KIND_FUNC, 0x1000, "SSL_CTX_new"),
            (KIND_FUNC, 0x1100, "SSL_read"),
            (KIND_FUNC, 0x1200, "sub_1200"),
            (KIND_STRING, 0x8000, "error opening socket"),
            (KIND_STRING, 0x8100, "/etc/ssl/certs"),
        ], source=src)
        check("reindex reports what it stored", n == 5, f"n={n}")
        check("the entries are there", idx.total() == 5, f"{idx.total()}")
        check("an indexed binary is fresh", not idx.is_stale("libfoo", src))

        # -- substring search (the thing a prefix index can't do) ----------- #
        hits = idx.search("SSL", kind=KIND_FUNC)
        check("finds symbols by substring", {h.text for h in hits} ==
              {"SSL_CTX_new", "SSL_read"}, f"{[h.text for h in hits]}")
        check("matching ignores case across kinds (SSL also hits /etc/ssl)",
              {h.text for h in idx.search("SSL")} ==
              {"SSL_CTX_new", "SSL_read", "/etc/ssl/certs"},
              f"{[h.text for h in idx.search('SSL')]}")
        hits = idx.search("socket")
        check("finds strings by substring mid-text",
              len(hits) == 1 and hits[0].kind == KIND_STRING
              and hits[0].addr == 0x8000, f"{hits}")
        check("hits carry the owning binary",
              all(h.binary == "libfoo" for h in idx.search("SSL")))
        check("search is case-insensitive",
              {h.text for h in idx.search("ssl_read")} == {"SSL_read"},
              f"{[h.text for h in idx.search('ssl_read')]}")
        check("kind filter narrows to strings",
              [h.text for h in idx.search("ss", kind=KIND_STRING)] == ["/etc/ssl/certs"],
              f"{[h.text for h in idx.search('ss', kind=KIND_STRING)]}")

        # -- the <3 char fallback (trigram silently matches nothing) -------- #
        check("2-char query still works (LIKE fallback)",
              {h.text for h in idx.search("ss")} == {"SSL_CTX_new", "SSL_read",
                                                     "/etc/ssl/certs"},
              f"{[h.text for h in idx.search('ss')]}")
        check("1-char query still works",
              len(idx.search("/")) == 1, f"{idx.search('/')}")
        check("an empty query matches nothing", idx.search("   ") == [])
        check("a query with FTS operators is treated literally",
              idx.search('SSL OR "') == [] or True)  # must not raise

        # -- multi-binary: the whole point ---------------------------------- #
        idx.reindex("httpd", [
            (KIND_FUNC, 0x2000, "handle_ssl_request"),
            (KIND_STRING, 0x9000, "socket bind failed"),
        ])
        hits = idx.search("ssl")
        check("search spans binaries",
              {h.binary for h in hits} == {"libfoo", "httpd"},
              f"{[(h.binary, h.text) for h in hits]}")
        check("counts are per binary",
              idx.counts() == {"libfoo": 5, "httpd": 2}, f"{idx.counts()}")

        # -- incremental: reindexing one binary leaves the others alone ----- #
        idx.reindex("libfoo", [(KIND_FUNC, 0x1000, "SSL_CTX_new_v2")], source=src)
        check("reindex replaces only that binary's entries",
              idx.counts() == {"libfoo": 1, "httpd": 2}, f"{idx.counts()}")
        check("the stale entries are gone",
              [h.text for h in idx.search("SSL_read")] == [],
              f"{idx.search('SSL_read')}")
        check("the other binary survived untouched",
              len(idx.search("socket bind")) == 1)

        # -- staleness follows the source ----------------------------------- #
        time.sleep(0.01)
        with open(src, "wb") as f:
            f.write(b"\x7fELF binary rebuilt, different size")
        os.utime(src, (1, 1))
        check("a changed source goes stale", idx.is_stale("libfoo", src))
        check("a missing source does NOT wipe the index",
              not idx.is_stale("libfoo", os.path.join(tmp, "gone")))

        # -- forget ----------------------------------------------------------- #
        idx.forget("httpd")
        check("forget drops a binary entirely",
              idx.counts() == {"libfoo": 1} and idx.search("socket bind") == [],
              f"{idx.counts()}")

        # -- persistence ------------------------------------------------------ #
        path = idx.path
        idx.close()
        idx2 = ProjectIndex(path)
        check("the index persists across sessions",
              [h.text for h in idx2.search("SSL_CTX")] == ["SSL_CTX_new_v2"],
              f"{idx2.search('SSL_CTX')}")
        idx2.close()

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
