#!/usr/bin/env python3
"""The raw-image workflow over the RPC socket: spawn with load options, define,
bulk-apply a symbol file.

A headerless firmware image is the case where driving IDA from an agent used to
fall apart:

  * ``pane spawn`` could not pass ``--processor``/``--base``, so the pane came up
    ready-but-empty (x86 at 0, zero functions) and the only way through was to
    hand-write a project file;
  * ``c``/``p``/``t`` (make code / make function / ARM-Thumb) existed as key
    bindings but had no verb, so a driver had to guess raw keys and hope no
    modal was on top;
  * every name had to go through the typed rename prompt — a navigation plus two
    prompt round-trips each, which is tens of minutes for a 400-symbol map.

This test spawns a real pane on a real Thumb blob and checks all three.

Requires: tmux or zellij, IDA (idalib). ~2min.

    ~/ida-venv/bin/python tests/test_rawimage_rpc.py
"""

#: spawns a real mux pane on a firmware image.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = True
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.rpcclient import RpcClient, RpcError  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOB = os.path.join(REPO, "experiments", "fibonacci.bin")  # real Thumb code

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   [{name}]")
    else:
        FAIL += 1
        print(f"  FAIL [{name}]   {detail}")


def spawn_pane(target, processor, timeout=420):
    cmd = [
        sys.executable,
        "-m",
        "idatui.pane",
        "spawn",
        "--open",
        target,
        "--processor",
        processor,
        "--detached",
        "--size",
        "60%",
        "--timeout",
        str(timeout),
    ]
    r = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout + 60, cwd=REPO
    )
    if not r.stdout.strip():
        print(f"  spawn produced no JSON: {r.stderr.strip()}", file=sys.stderr)
        return None
    return json.loads(r.stdout)


def stop_pane(sock, timeout=60):
    subprocess.run(
        [
            sys.executable,
            "-m",
            "idatui.pane",
            "stop",
            "--sock",
            sock,
            "--timeout",
            str(timeout),
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 10,
        cwd=REPO,
    )


def main() -> int:
    if not os.environ.get("TMUX") and not os.environ.get("ZELLIJ"):
        print("SKIP: not inside tmux or zellij (test spawns a pane)")
        return 0
    if not os.path.exists(BLOB):
        print(f"SKIP: no blob at {BLOB}")
        return 0

    # Work on a copy: the .i64 lands next to the binary and the load options
    # only apply to a FIRST open, so a leftover database would silently decide
    # what this test measures.
    with tempfile.TemporaryDirectory() as tmp:
        blob = os.path.join(tmp, "fib.bin")
        with open(BLOB, "rb") as src, open(blob, "wb") as dst:
            dst.write(src.read())

        info = spawn_pane(blob, "arm:ARMv7-A")
        if not info:
            print("SKIP: could not spawn a pane")
            return 0
        sock = info["sock"]
        try:
            # -- load options actually reached IDA --------------------------- #
            # Wrong processor => the disassembly is nonsense or absent; ARMv7-A
            # also means a 32-bit database, without which Hex-Rays refuses.
            check("spawn forwarded --processor", info.get("ok"), json.dumps(info))
            with RpcClient(sock) as c:
                st = c.call("state")
                check(
                    "pane is drivable",
                    st.get("active") in ("listing", "decomp", "hex"),
                    json.dumps(st)[:200],
                )

                # -- define ------------------------------------------------- #
                # fibonacci.bin is Thumb at 0x0; as ARM it does not decode.
                r = c.call("define", kind="thumb", target="0x0")
                d = r.get("define", {})
                check("define thumb ran", "define" in r, json.dumps(r)[:200])
                check(
                    "define thumb decoded instructions",
                    "instruction" in d.get("status", ""),
                    d.get("status", ""),
                )

                r = c.call("define", kind="func", target="0x0")
                check(
                    "define func created a function",
                    "function" in r["define"]["status"]
                    or "already" in r["define"]["status"],
                    r["define"]["status"],
                )

                bad = None
                try:
                    c.call("define", kind="nonsense")
                except RpcError as e:
                    bad = str(e)
                check(
                    "define rejects an unknown kind",
                    bad is not None and "unknown define kind" in bad,
                    str(bad),
                )

                # -- opfmt (how a literal is displayed) --------------------- #
                # Thumb code is full of small immediates -- the thing 'o' exists
                # for -- but the ENTRY POINT hasn't got one, so find a line that
                # has. `show` asks without editing, which is how a driver does
                # that: the rendered text alone can't be trusted (a listing read
                # before an ARM/Thumb switch shows the old decoding).
                c.call("goto", target="0x0", delay_ms=0)
                seen = c.call("view", lines=40).get("lines", [])
                lit = None
                for ln in seen:
                    m = re.match(r"([0-9A-F]{8})\s+(.*)", ln.get("text", ""))
                    if not (
                        m and re.search(r"#(0x[0-9A-Fa-f]{2,}|[1-9]\d+)\b", m.group(2))
                    ):
                        continue
                    ea_s = "0x" + m.group(1)
                    st = (
                        c.call("opfmt", mode="show", target=ea_s, delay_ms=0)
                        .get("opfmt", {})
                        .get("status", "")
                    )
                    if "no literal" not in st:
                        lit = (ea_s, st)
                        break
                check(
                    "the blob has an immediate to reformat",
                    lit is not None,
                    json.dumps([ln.get("text") for ln in seen[:8]]),
                )
                if lit is not None:
                    tgt, st0 = lit
                    check(
                        "opfmt show reports the stops without editing",
                        "[" in st0 and "dec" in st0,
                        st0,
                    )
                    r = c.call("opfmt", mode="dec", target=tgt, delay_ms=0)
                    st1 = r.get("opfmt", {}).get("status", "")
                    check("opfmt sets a named format", "dec" in st1, st1)
                    r = c.call("opfmt", mode="cycle")
                    st2 = r.get("opfmt", {}).get("status", "")
                    check("opfmt cycles on from there", "\u2192" in st2, st2)
                    r = c.call("opfmt", mode="default")
                    check(
                        "opfmt hands the operand back to IDA",
                        "default" in r.get("opfmt", {}).get("status", ""),
                        r.get("opfmt", {}).get("status", ""),
                    )
                badfmt = None
                try:
                    c.call("opfmt", mode="roman")
                except RpcError as e:
                    badfmt = str(e)
                check(
                    "opfmt rejects an unknown mode",
                    badfmt is not None and "unknown opfmt mode" in badfmt,
                    str(badfmt),
                )

                # -- rename_many -------------------------------------------- #
                fns = c.call("functions", limit=200)
                ea = min(f["ea"] for f in fns) if fns else None
                check("a function exists to rename", ea is not None)

                symfile = os.path.join(tmp, "syms.json")
                with open(symfile, "w") as f:
                    # 'start' (not 'addr') on purpose: symbol files in the wild
                    # use it, and accepting only one spelling is how a bulk
                    # import silently renames nothing.
                    json.dump(
                        [
                            {"start": hex(ea), "name": "bulk_named_fn"},
                            {"start": "0xdeadbe", "name": "nowhere"},
                        ],
                        f,
                    )
                r = c.call("rename_many", file=symfile)
                m = r.get("rename_many", {})
                check(
                    "rename_many applied the good entry",
                    m.get("ok") == 1,
                    json.dumps(m),
                )
                check(
                    "rename_many reports the bad entry",
                    m.get("failed") == 1 and m.get("errors"),
                    json.dumps(m),
                )

                # The readback matters more than the return value: a driver
                # trusts resolve/functions to decide what work is left.
                check(
                    "renamed symbol resolves",
                    c.call("resolve", name="bulk_named_fn").get("ea") == ea,
                    json.dumps(c.call("resolve", name="bulk_named_fn")),
                )
                names = {f["name"] for f in c.call("functions", limit=200)}
                check(
                    "function table shows the new name",
                    "bulk_named_fn" in names,
                    str(sorted(names)[:10]),
                )

                r = c.call(
                    "rename_many", items=[{"addr": hex(ea), "name": "inline_named_fn"}]
                )
                check(
                    "rename_many takes inline items",
                    r["rename_many"]["ok"] == 1,
                    json.dumps(r["rename_many"]),
                )

                # -- the stale-pseudocode trap ------------------------------ #
                # Hex-Rays caches per function and does not notice that a
                # CALLEE was renamed -- and that cache is persisted in the
                # .i64. Decompile first, then rename, then read it back: the
                # call site must show the new name. (fibonacci is recursive, so
                # the function's own body cites it.)
                before = c.call("pseudocode", target=hex(ea))
                pc_before = json.dumps(before)
                r = c.call(
                    "rename_many", items=[{"addr": hex(ea), "name": "after_cache_fn"}]
                )
                pc_after = json.dumps(c.call("pseudocode", target=hex(ea)))
                check(
                    "pseudocode was cached before the rename",
                    "inline_named_fn" in pc_before,
                    pc_before[:200],
                )
                check(
                    "rename_many invalidates the decompile cache",
                    "after_cache_fn" in pc_after and "inline_named_fn" not in pc_after,
                    pc_after[:300],
                )

                empty = None
                try:
                    c.call("rename_many")
                except RpcError as e:
                    empty = str(e)
                check(
                    "rename_many without items errors",
                    empty is not None and "items" in empty,
                    str(empty),
                )
        finally:
            stop_pane(sock)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
