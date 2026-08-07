"""Ergonomic RE driver over the idatui RPC socket — terse text, auto socket.

A thin, opinionated layer over ``idatui.rpcclient`` for reverse-engineering
sessions. It removes the friction of raw driving: it resolves the socket
automatically (the single live pane), prints compact text instead of JSON
blobs, and bundles the common composite gestures (goto+rename, batch rename,
function comment, filtered pseudocode). Use it for low-overhead tool-calls.

    python3 -m idatui.drive where                 # where am I
    python3 -m idatui.drive pc main strrchr        # SHOW main's pseudocode on screen, lines matching 'strrchr'
    python3 -m idatui.drive callees main           # what main calls
    python3 -m idatui.drive rename sub_5BE0 stdout_isatty
    python3 -m idatui.drive mv sub_A=foo sub_B=bar # batch rename
    python3 -m idatui.drive note main "entry point"# function comment

Socket: --sock, else IDATUI_RPC_SOCK, else the one live pane (from `pane list`).
'.' or omitted as a target means the current function. `raw <method> k=v` is a
passthrough to rpcclient (pretty JSON).
"""
from __future__ import annotations

import json
import os
import sys

from .pane import _load_registry, _pane_alive
from .rpcclient import RpcClient, RpcError


def _resolve_sock(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("IDATUI_RPC_SOCK")
    if env:
        return env
    live = [r for r in _load_registry()
            if _pane_alive(r.get("pane", "")) and r.get("sock")
            and os.path.exists(r["sock"])]
    if len(live) == 1:
        return live[0]["sock"]
    if not live:
        raise SystemExit("no live idatui pane — pass --sock, set IDATUI_RPC_SOCK, "
                         "or `python -m idatui.pane spawn ...`")
    raise SystemExit("multiple live panes — pass --sock <one of>:\n"
                     + "\n".join("  " + r["sock"] for r in live))


def _tgt(a: str | None) -> str | None:
    return None if a in (None, ".", "") else a


def _coerce(v: str):
    low = v.lower()
    return {"true": True, "false": False, "null": None}.get(low, v)


# --------------------------------------------------------------------------- #
# commands  (each: (client, args) -> text)
# --------------------------------------------------------------------------- #
def _fmt_where(st: dict) -> str:
    fn = st.get("function") or {}
    cur = st.get("cursor") or {}
    name = fn.get("name")
    ea = fn.get("ea")
    loc = f"{name} @ {ea:#x}" if isinstance(ea, int) else "(none)"
    extra = ""
    if cur.get("kind") in ("decomp", "listing"):
        extra = f"  L{cur.get('line')} C{cur.get('col')} word={cur.get('word')!r}"
    elif cur.get("kind") == "hex":
        extra = f"  va={cur.get('va'):#x}" if isinstance(cur.get("va"), int) else ""
    modal = st.get("modal")
    m = f"  [modal:{modal['kind']}]" if modal else ""
    return f"{loc}  [{st.get('active')}]{extra}{m}"


def cmd_where(c, args):
    return _fmt_where(c.call("state"))


def cmd_go(c, args):
    if not args:
        raise SystemExit("usage: go <fn>")
    c.call("goto", target=args[0], delay_ms=0)
    return _fmt_where(c.call("state"))


def _show_view(c, want):
    """Make the requested code pane the visibly-active view (best effort).

    Tab toggles listing<->decomp, and leaves hex back to the preferred code
    view; so at most two toggles reach either code view from any state. If
    the decompiler fails for the current function the view falls back to the
    listing and we simply stop — the caller still returns its text as before.
    """
    for _ in range(2):
        if c.call("state").get("active") == want:
            return
        try:
            c.call("toggle_view")
        except RpcError:
            return


def cmd_pc(c, args):
    target = _tgt(args[0]) if args else None
    needle = args[1] if len(args) > 1 else None
    # Drive the real UI so viewers see the pseudocode, not just the driver.
    if target is not None:
        c.call("goto", target=target, delay_ms=0)
    _show_view(c, "decomp")
    if needle is not None:
        # Incremental-search in the now-visible pane so the cursor lands on
        # the first hit (best effort: the term may not be a single token).
        try:
            c.call("search", term=needle, direction=1)
        except RpcError:
            pass
    d = c.call("pseudocode", target=target)
    if not d.get("code"):
        return f"(no pseudocode: {d.get('error')})"
    lines = d["code"].splitlines()
    if needle:
        nlow = needle.lower()
        lines = [f"{i:4} {line}" for i, line in enumerate(lines)
                 if nlow in line.lower()]
        return "\n".join(lines) or f"(no line matches {needle!r})"
    return d["code"]


def cmd_dis(c, args):
    target = _tgt(args[0]) if args else None
    n = int(args[1]) if len(args) > 1 else 60
    # Drive the real UI so viewers see the disassembly, not just the driver.
    if target is not None:
        c.call("goto", target=target, delay_ms=0)
    _show_view(c, "listing")
    d = c.call("disassembly", target=target, max=n)
    return "\n".join(f"{ln['ea']:#010x}  {ln['text']}" for ln in d.get("lines", []))


def cmd_callees(c, args):
    xs = c.call("xrefs_from", target=_tgt(args[0]) if args else None)
    funcs = [x for x in xs if x.get("is_func")]
    data = [x for x in xs if not x.get("is_func")]
    out = [f"  {x['to']:#x}  {x.get('name')}" for x in funcs]
    for x in data:
        s = f" {x['string']!r}" if x.get("string") else ""
        out.append(f"  {x['to']:#x}  {x.get('name')}{s}")
    return "\n".join(out) or "(no outgoing refs)"


def cmd_callers(c, args):
    if not args:
        raise SystemExit("usage: callers <fn>")
    xs = c.call("xrefs_to", target=args[0])
    return "\n".join(f"  {x['frm']:#x}  in {x.get('fn_name')}" for x in xs) \
        or "(no callers)"


def cmd_names(c, args):
    if not args:
        raise SystemExit("usage: names <substr> [limit]")
    lim = int(args[1]) if len(args) > 1 else 40
    fs = c.call("functions", filter=args[0], limit=lim)
    return "\n".join(f"  {f['ea']:#x}  {f['name']}  ({f['size']})" for f in fs) \
        or "(no match)"


def cmd_binaries(c, args):
    """Project inventory: which binaries, which is active, which have a live
    worker, how much of each is indexed."""
    r = c.call("binaries")
    out = []
    for b in r["binaries"]:
        mark = "*" if b["active"] else ("~" if b["resident"] else " ")
        out.append(f"  {mark} {b['label']:<28} indexed={b['indexed']:<7} {b['source']}")
    if r.get("hops"):
        out.append(f"  (Esc returns to: {' <- '.join(r['hops'])})")
    return "\n".join(out) + "\n  * active   ~ worker resident"


def cmd_switch(c, args):
    if not args:
        raise SystemExit("usage: switch <binary> [addr|name]")
    p = {"binary": args[0]}
    if len(args) > 1:
        a = args[1]
        p["addr"] = a if a.lower().startswith("0x") else c.call("resolve", name=a)["ea"]
    r = c.call("switch", **p)
    fn = (r.get("function") or {}).get("name")
    return f"  now on {r.get('binary') or args[0]}" + (f" @ {fn}" if fn else "")


def _rename_one(c, old, new):
    c.call("goto", target=old, delay_ms=0)
    st = c.call("rename", name=new, word=old, delay_ms=0)
    got = (st.get("function") or {}).get("name")
    return f"  {old} -> {got}"


def cmd_rename(c, args):
    if len(args) != 2:
        raise SystemExit("usage: rename <old> <new>")
    return _rename_one(c, args[0], args[1])


def cmd_mv(c, args):
    out = []
    for pair in args:
        if "=" not in pair:
            raise SystemExit(f"usage: mv old=new ...  (bad: {pair!r})")
        old, new = pair.split("=", 1)
        try:
            out.append(_rename_one(c, old, new))
        except RpcError as e:
            out.append(f"  {old} -> FAILED: {e}")
    return "\n".join(out)


def cmd_note(c, args):
    if len(args) < 2:
        raise SystemExit("usage: note <fn> <text...>")
    st = c.call("goto", target=args[0], delay_ms=0)
    # goto already lands on the function's first line. The old `cursor line=0`
    # meant "the top of the function" only in the decompiler; in the listing
    # line 0 is the top of the whole SEGMENT, so the note landed at address 0 --
    # and on a 42k-line firmware listing the scroll to get there timed the
    # caller out, which read as "comments are broken".
    c.call("comment", text=" ".join(args[1:]), delay_ms=0)
    cur = (st.get("function") or {}).get("name") or args[0]
    return f"  noted {cur} @ {(st.get('cursor') or {}).get('ea', 0):#x}"


def cmd_retype(c, args):
    if len(args) < 2:
        raise SystemExit("usage: retype <fn> <prototype...>")
    c.call("goto", target=args[0], delay_ms=0)
    st = c.call("retype", proto=" ".join(args[1:]), word=args[0], delay_ms=0)
    return _fmt_where(st)


def cmd_define(c, args):
    """define <kind> [target ...] — the raw-image workflow (thumb/code/func).

    Several targets are common on a firmware image (a list of entry points from
    a symbol file), so take them all and report per-target.
    """
    if not args:
        raise SystemExit("usage: define <code|func|undef|thumb|thumbscan|data|"
                         "string> [target ...]")
    kind, targets = args[0], (args[1:] or [None])
    out = []
    for t in targets:
        try:
            st = c.call("define", kind=kind, **({"target": t} if t else {}))
            out.append(f"  {t or '.'}: {st.get('status', '')}")
        except RpcError as e:
            out.append(f"  {t or '.'}: FAILED: {e}")
    return "\n".join(out)


def cmd_fmt(c, args):
    """fmt [mode] [word] — how the literal under the cursor is DISPLAYED.

    ``fmt`` alone cycles (IDA's 'o'); a mode name sets it outright. A trailing
    word puts the cursor on that token first, so you can name the literal
    instead of steering the column there.

        fmt                # cycle the literal under the cursor
        fmt dec            # show it in decimal
        fmt hex 18h        # find '18h' on screen, then make it hex
    """
    mode = args[0] if args else "cycle"
    params = {"mode": mode}
    if len(args) > 1:
        params["word"] = args[1]
    st = c.call("opfmt", **params)
    return "  " + (st.get("opfmt", {}).get("status") or st.get("status", ""))


def cmd_syms(c, args):
    """syms <file.json> — bulk-apply a symbol file ([{addr|start|ea, name}])."""
    if len(args) != 1:
        raise SystemExit("usage: syms <symbols.json>")
    r = c.call("rename_many", file=os.path.abspath(os.path.expanduser(args[0])))
    m = r.get("rename_many", {})
    out = [f"  {m.get('ok', 0)}/{m.get('requested', 0)} renamed"
           f" (skipped {m.get('skipped', 0)}, failed {m.get('failed', 0)})"]
    for e in m.get("errors", []):
        out.append(f"    {e.get('addr')}: {e.get('error')}")
    return "\n".join(out)


def cmd_save(c, args):
    c.call("save")
    return "  saved"


def cmd_export(c, args):
    """export [path] -- write the session's findings as markdown."""
    r = c.call("export", **({"path": args[0]} if args else {}))
    return (f"  {r.get('path')}  ({r.get('bytes', 0)} bytes: "
            f"{r.get('comments', 0)} comments, {r.get('names', 0)} names, "
            f"{r.get('types', 0)} types)")


def cmd_screen(c, args):
    return c.call("screen").get("text", "")


def cmd_raw(c, args):
    if not args:
        raise SystemExit("usage: raw <method> [k=v ...]")
    params = {}
    for tok in args[1:]:
        k, _, v = tok.partition("=")
        params[k] = _coerce(v)
    return json.dumps(c.call(args[0], **params), indent=2)


COMMANDS = {
    "where": cmd_where, "go": cmd_go, "pc": cmd_pc, "dis": cmd_dis,
    "callees": cmd_callees, "callers": cmd_callers, "names": cmd_names,
    "rename": cmd_rename, "mv": cmd_mv, "note": cmd_note, "retype": cmd_retype,
    "save": cmd_save, "screen": cmd_screen, "raw": cmd_raw, "define": cmd_define,
    "syms": cmd_syms, "fmt": cmd_fmt, "export": cmd_export,
    "binaries": cmd_binaries, "switch": cmd_switch,
}


def main(argv: list[str]) -> int:
    args = list(argv)
    sock = None
    if args and args[0] == "--sock":
        sock, args = args[1], args[2:]
    if not args or args[0] in ("-h", "--help", "help"):
        print("commands: " + " ".join(COMMANDS), file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 0 if args[:1] in (["help"], ["-h"], ["--help"]) else 2
    cmd, rest = args[0], args[1:]
    fn = COMMANDS.get(cmd)
    if fn is None:
        print(f"unknown command: {cmd!r} (try: {' '.join(COMMANDS)})", file=sys.stderr)
        return 2
    try:
        with RpcClient(_resolve_sock(sock)) as c:
            out = fn(c, rest)
    except (OSError, RpcError, ConnectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
