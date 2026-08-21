"""Tool-level checks for op_format / pc_num_format against a live idalib
database, run on the REAL tool sources (server/patch_server.py's injected BODY,
exec'd here with the @tool/@idasync decorators stubbed out).

Faster than the pilot suite and independent of the TUI, so it is the right place
for the IDA-side edge cases: which stops a value gets offered, what an offset
does to the database, what Hex-Rays will and won't render.

    python3 experiments/opfmt_tools.py        # 29 checks, ~40s
"""

import importlib.util
import os
import shutil
import sys
from typing import Annotated  # noqa: F401  (the BODY annotates with it)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

src = os.path.join(REPO, "targets", "echo")
tmp = "/tmp/opfmt_tools_echo"
shutil.copy(src, tmp)
for e in ".i64 .id0 .id1 .id2 .nam .til".split():
    try:
        os.remove(tmp + e)
    except OSError:
        pass
seed = src + ".pristine.i64"
if os.path.exists(seed):
    shutil.copy(seed, tmp + ".i64")

import idapro  # noqa: E402

idapro.enable_console_messages(False)
assert idapro.open_database(tmp, run_auto_analysis=True) == 0
import ida_auto  # noqa: E402

ida_auto.auto_wait()

import ida_bytes
import ida_lines
import ida_typeinf  # noqa: E402,F401
import idaapi

spec = importlib.util.spec_from_file_location(
    "_patch", os.path.join(REPO, "server", "patch_server.py")
)
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


def parse_address(s):
    if isinstance(s, int):
        return s
    s = str(s).strip()
    try:
        return int(s, 0)
    except ValueError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, s)
        if ea == idaapi.BADADDR:
            raise ValueError(f"bad address {s!r}")
        return ea


NS = {
    "Annotated": Annotated,
    "tool": lambda f: f,
    "idasync": lambda f: f,
    "ida_typeinf": ida_typeinf,
    "parse_address": parse_address,
    "_parse_type_tinfo": lambda s: None,
}
exec(compile(patch.BODY, "<idatui-ext>", "exec"), NS)
op_format = NS["op_format"]
pc_num_format = NS["pc_num_format"]
heads = NS["heads"]

OK = FAIL = 0


def check(name, cond, detail=""):
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def line(ea):
    return NS["_idatui_line_text"](ea)


print("\n=== listing: cycle an immediate ===")
ea = parse_address("main")
# an instruction with a >9 literal, so hex and decimal actually look different
target = None
e = ea
while e < ea + 0x400:
    c = NS["_idatui_op_candidates"](e)
    for n in c:
        v, _w = NS["_idatui_op_value"](e, n)
        if v and v > 9 and not ida_bytes.is_mapped(v):
            target = (e, n, v)
            break
    if target:
        break
    e = ida_bytes.next_head(e, ea + 0x800)
print(
    "target:",
    hex(target[0]),
    "n=",
    target[1],
    "value",
    hex(target[2]),
    "|",
    line(target[0]),
)
tea, tn, tv = target

r = op_format(addr=hex(tea), mode="show")
print("  show:", r)
check(
    "show reports the operand and its choices",
    r.get("n") == tn and "hex" in r.get("choices", []),
    str(r),
)
check("show doesn't change anything", r.get("applied") is False, str(r))

seen = []
for i in range(8):
    r = op_format(addr=hex(tea), mode="cycle")
    seen.append((r.get("format"), r.get("text")))
    print(f"  cycle -> {r.get('prev')} -> {r.get('format')}: {r.get('text')}")
check(
    "cycling returns to where it started",
    seen[0][0] == seen[len(r.get("choices", []))][0]
    if len(seen) > len(r.get("choices", []))
    else True,
    str(seen),
)
check(
    "decimal renders differently from hex",
    any(s[1] != seen[0][1] for s in seen),
    str(seen),
)

r = op_format(addr=hex(tea), mode="dec")
check(
    "explicit dec sticks",
    r.get("format") == "dec" and str(tv) in r.get("text", ""),
    str(r),
)
r = op_format(addr=hex(tea), mode="back")
print("  back ->", r.get("format"), r.get("text"))
check("back steps the ring the other way", r.get("format") == "hex", str(r))
r = op_format(addr=hex(tea), mode="default")
check("default clears the user format", r.get("format") == "default", str(r))

print("\n=== listing: a literal that IS an address becomes a reference ===")
e, off_target = ea, None
while e < ea + 0x800:
    for n in NS["_idatui_op_candidates"](e):
        v, _w = NS["_idatui_op_value"](e, n)
        if v and ida_bytes.is_mapped(v):
            off_target = (e, n)
            break
    if off_target:
        break
    e = ida_bytes.next_head(e, ea + 0x800)
print(
    "target:",
    off_target and hex(off_target[0]),
    "|",
    off_target and line(off_target[0]),
)
if off_target:
    import ida_name  # noqa: E402

    oe, on = off_target
    v, _w = NS["_idatui_op_value"](oe, on)
    named = bool(ida_name.get_ea_name(v))
    r = op_format(addr=hex(oe), n=on, mode="show")
    print(
        "  ",
        hex(oe),
        "n=",
        on,
        "|",
        r.get("text"),
        r.get("choices"),
        "target named:",
        named,
    )
    check(
        "an unnamed target is not a cycle stop (it would invent a name)",
        ("offset" in r.get("choices", [])) == named,
        str(r),
    )
    r = op_format(addr=hex(oe), n=on, mode="offset")
    print("  offset ->", r.get("text"))
    check(
        "but asking explicitly makes the reference",
        r.get("format") == "offset" and "offset" in r.get("text", ""),
        str(r),
    )
    r = op_format(addr=hex(oe), n=on, mode="show")
    check(
        "and from then on the ring includes it",
        "offset" in r.get("choices", []),
        str(r),
    )
    r = op_format(addr=hex(oe), n=on, mode="hex")
    print("  hex ->", r.get("text"))
    check(
        "and back to a number",
        r.get("format") == "hex" and "offset" not in r.get("text", ""),
        str(r),
    )
    op_format(addr=hex(oe), n=on, mode="default")
else:
    print("  (no literal-that-is-an-address in this function)")

print("\n=== listing: column -> operand ===")
txt = line(tea)
spans = NS["_idatui_op_spans"](tea, txt)
print("  text:", repr(txt), "spans:", spans)
if len(spans) >= 2:
    r = op_format(addr=hex(tea), col=spans[0][0], mode="show")
    check(
        "a column inside operand 0 picks operand 0 (or the first literal)",
        r.get("n") in (spans[0][2], NS["_idatui_op_candidates"](tea)[0]),
        str(r),
    )
    r = op_format(addr=hex(tea), col=spans[-1][0], mode="show")
    check(
        "a column inside the last operand picks it", r.get("n") == spans[-1][2], str(r)
    )

print("\n=== listing: an unmapped value refuses to become an offset ===")
r = op_format(addr=hex(tea), n=tn, mode="offset")
print(" ", r.get("error") or r)
check(
    "offset on a non-address is refused, not invented",
    bool(r.get("error")) or ida_bytes.is_mapped(tv),
    str(r),
)

print("\n=== listing: char is only offered when it renders as one ===")
r = op_format(addr=hex(tea), n=tn, mode="show")
check(
    "0x%x isn't offered as a char" % tv,
    ("char" in r["choices"]) == NS["_idatui_printable"](tv),
    str(r),
)

print("\n=== listing: a stack variable can be cycled AND put back ===")
stk = None
for f in (parse_address("main"),):
    e = f
    while e < f + 0x600 and stk is None:
        for n in NS["_idatui_op_candidates"](e):
            if NS["_idatui_op_fmt"](e, n) == "stack":
                stk = (e, n)
                break
        e = ida_bytes.next_head(e, f + 0x600)
print("  stkvar operand:", stk and hex(stk[0]), "|", stk and line(stk[0]))
if stk:
    se, sn = stk
    orig = line(se)
    r = op_format(addr=hex(se), n=sn, mode="cycle")
    print("  cycle ->", r.get("format"), r.get("text"), "|", r.get("warn"))
    check(
        "leaving a stack variable says so, and how to undo it",
        "stack" in (r.get("warn") or ""),
        str(r),
    )
    ring = [
        op_format(addr=hex(se), n=sn, mode="cycle") for _ in range(len(r["choices"]))
    ]
    print("  ring:", [(x["format"], x["text"]) for x in ring])
    check(
        "the ring is the same at every step (a lap comes home)",
        [x["format"] for x in ring] == r["choices"][1:] + r["choices"][:1],
        f"{[x['format'] for x in ring]} vs {r['choices']}",
    )
    r = op_format(addr=hex(se), n=sn, mode="stack")
    check(
        "'stack' puts the frame variable back",
        r.get("format") == "stack" and r.get("text") == orig,
        f"{r.get('text')!r} want {orig!r}",
    )
else:
    print("  (no stack-variable operand found)")

print("\n=== data item ===")
import ida_segment  # noqa: E402

seg = ida_segment.get_segm_by_name(".data")
if seg:
    de = seg.start_ea
    picked = None
    for _ in range(24):
        f = ida_bytes.get_flags(de)
        if ida_bytes.is_data(f) and NS["_idatui_op_fmt"](de, 0) == "default":
            v, _w = NS["_idatui_op_value"](de, 0)
            if v:
                picked = de
                break
        de = ida_bytes.next_head(de, seg.end_ea)
        if de == idaapi.BADADDR:
            break
    print("  data item:", picked and hex(picked), "|", picked and line(picked))
    if picked:
        r = op_format(addr=hex(picked), mode="dec")
        print("  dec ->", r.get("text"))
        check("a data value reformats too", r.get("format") == "dec", str(r))
        op_format(addr=hex(picked), mode="default")

print("\n=== undefined bytes say what to do instead ===")
seg = ida_segment.get_segm_by_name(".rodata") or ida_segment.getnseg(0)
ue, e = None, seg.start_ea
while e < seg.end_ea and ue is None:
    f = ida_bytes.get_flags(e)
    if not (ida_bytes.is_code(f) or ida_bytes.is_data(f)):
        ue = e
    e += 1
if ue is not None:
    r = op_format(addr=hex(ue), mode="cycle")
    print("  ", hex(ue), "->", r.get("error"))
    check(
        "undefined bytes are refused with the fix, not a silent no-op",
        "define" in (r.get("error") or ""),
        str(r),
    )
else:
    print("  (no undefined bytes)")

print("\n=== pseudocode ===")
r = pc_num_format(addr="main", mode="show", line=-1)
print("  show without a line:", r.get("error"))
check("no line is an error, not a guess", bool(r.get("error")), str(r))

import ida_hexrays  # noqa: E402

cf = ida_hexrays.decompile(parse_address("main"))
sv = cf.get_pseudocode()
pcline = None
for i in range(len(sv)):
    nums = NS["_idatui_pc_nums"](cf, sv[i])
    if nums and nums[0]["value"] > 9:
        pcline = (i, nums[0])
        break
print(
    "  line",
    pcline[0],
    repr(ida_lines.tag_remove(sv[pcline[0]].line).strip()),
    "num:",
    pcline[1],
)
i, num = pcline
r = pc_num_format(addr="main", line=i, mode="show")
check("show finds the literal", r.get("ea") == hex(num["ea"]), str(r))
r = pc_num_format(addr="main", line=i, mode="hex")
print("  hex ->", r.get("text"))
check("hex renders 0x in the pseudocode", "0x" in r.get("text", ""), str(r))
r = pc_num_format(addr="main", line=i, mode="cycle")
print("  cycle ->", r.get("format"), r.get("text"))
r = pc_num_format(addr="main", line=i, mode="char")
print("  char ->", r.get("format"), r.get("text"))
r = pc_num_format(addr="main", line=i, mode="bin")
print("  bin ->", r.get("error"))
check("binary is refused with a reason", bool(r.get("error")), str(r))
r = pc_num_format(addr="main", line=i, mode="default")
print("  default ->", r.get("text"))
check(
    "default restores Hex-Rays' own choice",
    r.get("text") == ida_lines.tag_remove(sv[i].line).strip(),
    str(r),
)
r = pc_num_format(addr="main", line=i, mode="show")
check("and the format reads back as default", r.get("format") == "default", str(r))
print("\n=== pseudocode: the ring visits every stop ===")
ring = []
for _ in range(len(r.get("choices", [])) * 2):
    rr = pc_num_format(addr="main", line=i, mode="cycle")
    ring.append((rr.get("format"), rr.get("text")))
print("  ", [x[0] for x in ring])
check(
    "every stop in the ring is reached",
    set(x[0] for x in ring) == set(r["choices"]),
    f"{ring} vs {r['choices']}",
)
check(
    "the ring's renderings are distinct",
    len({x[1] for x in ring}) >= len(r["choices"]) - 1,
    str(ring),
)
pc_num_format(addr="main", line=i, mode="default")

print("\n=== pseudocode: col picks the literal ===")
multi = None
for k in range(len(sv)):
    nums = NS["_idatui_pc_nums"](cf, sv[k])
    if len(nums) >= 2:
        multi = (k, nums)
        break
if multi:
    k, nums = multi
    plain = ida_lines.tag_remove(sv[k].line)
    print("  line", k, repr(plain.strip()), [(x["x0"], x["value"]) for x in nums])
    compact = NS["_idatui_compact"](plain)
    # a column in the compacted text that lands on the SECOND number
    x = nums[1]["x0"]
    # map forward: find where that char went in the compacted line
    col = len(NS["_idatui_compact"](plain[:x]).rstrip()) if x else 0
    r = pc_num_format(addr="main", line=k, col=col, mode="show")
    print("   col", col, "->", r.get("ea"), r.get("value"))
    check(
        "a column selects the number under it",
        r.get("value") == hex(nums[1]["value"])
        or r.get("value") == hex(nums[0]["value"]),
        str(r),
    )
else:
    print("  (no line with two literals)")

print("\n=== operand extents ship with every listing row ===")
r = NS["heads"](addr=hex(tea), count=6, annotate=False)
row = next((h for h in r["heads"] if int(h["ea"], 16) == tea), None)
print("  row:", {k: v for k, v in (row or {}).items() if k in ("ea", "text", "ops")})
check("a code row carries operand extents", bool(row and row.get("ops")), str(row))
if row and row.get("ops"):
    t = row["text"]
    for lo, hi, n in row["ops"]:
        print(f"    op{n}: {t[lo:hi]!r}")
    check(
        "the extents index the row's own text",
        all(t[lo:hi].strip() for lo, hi, n in row["ops"]),
        str(row["ops"]),
    )
    # and they agree with what op_format picks for a column inside them
    ok = True
    for lo, hi, n in row["ops"]:
        got = op_format(addr=hex(tea), col=(lo + hi) // 2, mode="show")
        if not got.get("error") and got.get("n") != n:
            ok = False
    check("a column inside an extent selects that same operand", ok)

print("\n=== the cursor on a non-formattable operand is told, not redirected ===")
regop = None
for lo, hi, n in (row or {}).get("ops", []):
    if n not in NS["_idatui_op_candidates"](tea):
        regop = (lo, hi, n)
if regop:
    lo, hi, n = regop
    r = op_format(addr=hex(tea), col=(lo + hi) // 2, mode="cycle")
    print("  ", repr(row["text"][lo:hi]), "->", r.get("error"))
    check(
        "it names the operand and the one that CAN change",
        bool(r.get("error")) and "operand" in r["error"],
        str(r),
    )
else:
    print("  (this instruction has no register-only operand)")

print("\n=== pseudocode: every literal located in one call ===")
pn = NS["pc_nums"](addr="main")
print("  nums:", len(pn["nums"]), "over", pn["lines"], "lines")
check("pc_nums finds literals", len(pn["nums"]) > 5, str(pn)[:200])
multi2 = {}
for rec in pn["nums"]:
    multi2.setdefault(rec["line"], []).append(rec)
two = next((v for v in multi2.values() if len(v) >= 2), None)
if two:
    import ida_hexrays as _hx

    cf2 = _hx.decompile(parse_address("main"))
    disp = NS["_idatui_compact"](
        ida_lines.tag_remove(cf2.get_pseudocode()[two[0]["line"]].line)
    )
    print("  line:", repr(disp.strip()))
    for rec in two:
        print(
            f"    x{rec['x0']}..{rec['x1']} = {disp[rec['x0'] : rec['x1']]!r}  value {rec['value']}"
        )
    check(
        "spans land on the literals in the DISPLAYED text",
        all(disp[r0["x0"] : r0["x1"]].strip() for r0 in two),
        str(two),
    )
    check(
        "distinct literals get distinct spans", two[0]["x0"] != two[1]["x0"], str(two)
    )

print(f"\n{OK} passed, {FAIL} failed")
idapro.close_database(save=False)
sys.exit(1 if FAIL else 0)
