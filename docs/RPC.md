# RPC: puppeteering the TUI

Drive a *live* idatui over a unix socket while it renders normally in its
terminal (what a livestream/viewer sees). The listener runs on the same asyncio
loop as the UI, so handlers touch widgets directly — every injected key has the
identical on-screen effect a real keyboard would.

Layers: `idatui/rpc.py` (server, above `app.py`), `idatui/_sync.py` (the shared
"wait until the UI settled" logic, also used by the tests), `idatui/rpcclient.py`
(stdlib raw JSON client + CLI), and `idatui/drive.py` (the **ergonomic** CLI on
top — terse text, auto-resolves the socket). For agent-driven RE, prefer
`idatui.pane` (spawn/stop panes) + `idatui.drive` (see the `idatui-rpc` skill);
this doc is the underlying protocol reference.

## Running

```
# pane A — the TUI (real render) + a socket listener
./ida-tui /abs/path/to/binary --rpc /tmp/ida.sock

# pane B — drive it. Ergonomic (auto-finds the socket, terse text):
python -m idatui.drive where
python -m idatui.drive pc main strrchr
python -m idatui.drive rename sub_5BE0 stdout_isatty
# ...or the raw JSON transport underneath:
python -m idatui.rpcclient --sock /tmp/ida.sock goto target=main
python -m idatui.rpcclient --sock /tmp/ida.sock screen
```

No auth by design: anyone who can r/w the socket drives the app. The socket is
created mode `0600` (local only).

## Protocol

Newline-delimited JSON, one request/response per line, served one-at-a-time per
connection (the UI is single-user). A mutating call returns **after the UI has
settled**, and its result is a fresh `state()` snapshot — so the driver never
acts on stale state.

**Single-driver:** only one client connection is served at a time; a second
concurrent connection is refused with `error: busy` (no multi-driver support).
Sequential connections (e.g. one `rpcclient` invocation per call) are fine.

```
->  {"id": 1, "method": "goto", "params": {"target": "main"}}
<-  {"id": 1, "result": { ...state... }}
<-  {"id": 1, "error": {"message": "..."}}      # on failure (connection stays up)
```

## Methods

### Session
| method | params | notes |
|--------|--------|-------|
| `ping` | — | `{ok, proto, module, ready, functions, complete}` — also the default when `method` is omitted. Use it to wait for the index to finish loading. |
| `methods` | — | this table, as data. |
| `quit` | — | close the TUI gracefully (releases the database lease). |

### Raw injection (max fidelity)
| method | params | notes |
|--------|--------|-------|
| `keys` | `keys: [str]`, `settle?=true`, `timeout?=20` | inject key names, e.g. `["g","m","a","i","n","enter"]`. Same path the pilot uses; supports `"wait:<ms>"` tokens. |
| `text` | `text: str`, `delay_ms?=0`, `settle?`, `timeout?` | type a literal string into the focused input; `delay_ms` interleaves per-char waits for a typed-out look. |

### Introspection (read-only)
Structured reads for an agent to reason without scraping the screen. The heavy
ones (`pseudocode`/`disassembly`/`xrefs_*`) run off the UI loop so the render never
stalls. `target` is a name, `0xADDR`, or omitted (= current function).

| method | params | returns |
|--------|--------|---------|
| `state` | — | active/pref view, current function `{ea,name}`, cursor `{line,col,word,ea}` (or `{va,byte}` in hex), status text, filter, nav depth, dirty, open `modal`. |
| `view` | `lines?` | visible lines of the active code pane, cursor-marked (disasm/decomp; use `screen` for hex). |
| `screen` | `format?=text\|html\|svg` | `{width,height,format,text}` — a full render of exactly what's on screen (`html`/`svg` are colored, for an out-of-band viewer). |
| `functions` | `filter?`, `limit?=50` | `[{ea,name,size}]`. |
| `pseudocode` | `target?` | `{ea,name,code,failed,error,truncated}` — the **whole** decompiled body. |
| `disassembly` | `target?`, `max?=2000` | `{ea,name,total,lines:[{ea,text}]}`. |
| `xrefs_to` | `target`, `limit?=200` | `[{frm,to,type,fn_addr,fn_name}]` — who references it. |
| `xrefs_from` | `target`, `limit?=200` | what it references. For a **function** (name/entry ea): whole-body callees + string/data refs from the decompiler, `[{to,name,string,is_func,type}]`. For an explicit **0xADDR**: address-scoped `[{frm,to,type,fn_addr,fn_name}]`. |
| `resolve` | `name` | `{ea}` (or `{ea:null}`). |
| `diag` | `n?=10`, `clear?` | `{recent:[{when,what,error,where,thread}], log}` — errors the app swallowed rather than crashing on. The answer to "the verb said success and the pane shows nothing": inside a full-screen TUI a traceback has nowhere to go, so it comes out here. Set `$IDATUI_LOG=/tmp/x.log` when spawning for the same entries plus tracebacks, on disk. |

### Semantic verbs
High-level ops type through the **real prompts** with a per-char delay
(`delay_ms`, default 35ms) so viewers see it typed; each settles on an op-specific
predicate so the returned state is final.

| method | params | effect |
|--------|--------|--------|
| `goto` / `open` | `target`, `delay_ms?`, `timeout?` | `g` prompt → name or `0xADDR` → Enter. |
| `rename` | `name`, `word?`, `delay_ms?` | `n` on the token under the cursor → replace → Enter. `word` first places the cursor on that token (see `cursor_on`). |
| `comment` | `text`, `delay_ms?` | `;` on the current line (a literal `\n` in `text` becomes a real newline → multi-line comment). |
| `retype` | `proto`, `word?`, `delay_ms?` | `y` on the token/function under the cursor (`word` places it first). |
| `follow` | `word?` | Enter: follow the reference under the cursor (`word` places it first); waits for the jump. |
| `back` | — | Escape: pop the nav stack. |
| `toggle_view` | — | Tab: disasm ⇄ pseudocode. |
| `hex` | — | `\`: hex view. |
| `trace` | `seek` \| `goto` \| `step`, `over?` | navigate an execution trace (needs `--trace`). `seek` takes a timestamp, or `"!50"` for a percentage; `step` moves one instruction, `over=true` steps over a call. |
| `binaries` | — | project binaries as `{label, active, resident, indexed}` (project mode only). |
| `switch` | `label` | make another project binary active. |
| `graph` | `action?=show`, `target?`, `blocks?` | the control-flow graph (Space). `show` is a pure read — blocks, typed edges, ranks, box geometry and the cursor, **not** the box-drawing characters; `screen` gives you the drawing. `open`/`close`/`toggle` switch mode, `zoom` cycles full→compact→collapsed, `entry` jumps to the entry block, `succ`/`pred` follow one edge (`J`/`K`), `block target=<id\|0xADDR>` puts the cursor in a block. `blocks=false` omits the per-block list. See `docs/GRAPH_VIEW.md`. |
| `xrefs` | — | `x`: open the xref picker. |
| `symbols` | `query?` | Ctrl+N palette, optionally pre-typed. |
| `structs` | — | Ctrl+T struct editor. |
| `find` | `query`, `mode?=auto\|text\|bytes`, `limit?=500`, `regex?`, `case?` | search the **whole database** and return `{mode, query, truncated, hits:[{addr, head, line, func, seg}]}`. `mode=auto` (the default) guesses from the query. A byte pattern that does not parse is an error naming the bad token, never an empty result. |
| `export` | `path?`, `types?=true` | write the session's findings as **markdown** and return `{path, comments, names, types, functions, bytes}`. Not typed through a prompt: the point of this verb is the file it leaves behind, so a driver gets the path back rather than a screenshot. Defaults to `<binary>.findings.md`. See *Findings export* below. |
| `search` | `term`, `direction?=1` | `/` (or `?`) incremental search in the active code view. |
| `select` | `index?` | in an open modal list (xrefs/symbols) choose the highlighted (or nth) item and activate it. |
| `save` | — | Ctrl+S: persist the `.i64`. |
| `close` | — | Escape (dismiss a modal). |
| `define` | `kind`, `target?`, `delay_ms?` | goto `target` (if given) then press the listing key for `kind` ∈ `code`(c) / `func`(p) / `undef`(u) / `thumb`(t) / `thumbscan`(T) / `data`(d) / `string`(a). Leaves hex/decomp for the listing first (those bindings are listing-only). The IDA-side outcome is in `status` (e.g. *defined 228 instructions (0x4370–0x45e8) — control flow ends here*) and in `define.status`. |
| `rename_many` | `items:[{addr,name}]` **or** `file:<json>`, `allow_overwrite?=true` | bulk-apply a symbol map in ONE worker call, then refresh the caches + function table. Accepts `addr`/`start`/`ea`/`address` and `name`/`label`, or a plain `{addr: name}` object. Returns `rename_many:{requested,skipped,ok,failed,errors[]}`. |
| `opfmt` | `mode?=cycle`, `target?`, `word?`, `line?`, `col?`, `delay_ms?` | how the literal under the cursor is **displayed** (IDA's `o`). `mode` ∈ `cycle`(o) / `back`(O) / `show` / `hex` / `dec` / `oct` / `bin` / `char` / `offset` / `stack` / `default`. `target` gotos first; `word` puts the cursor on that token first (which operand gets reformatted is decided by where the cursor is). Works on the listing and, with the pseudocode focused, on Hex-Rays' own number formats. Result in `status` and `opfmt.status` (e.g. *op1 hex → dec: sub rsp, 24*). |

**`opfmt show` asks without editing** — it reports the current format, the
value, and the stops the cycle would visit (`op1 hex 0x18 [hex, dec, bin,
default]`), which is how a driver finds a literal worth changing without
guessing from rendered text. A line with no literal answers *no literal on this
line to reformat* rather than reformatting something else.

**Which literal** is decided by the cursor column, and the TUI marks that one on
screen. Land inside an operand that has no format of its own (a register) and
the call is refused, naming the operand that does — it will not silently move to
a different one, because the mark would then be lying about what changed. With
the cursor outside every operand (on the mnemonic, say) it falls back to the
first literal on the line.

**Raw images: `define` + `rename_many` are the workflow.** A firmware blob loads
with no functions and no names. Point `define thumb` / `define func` at the entry
points you know (IDA's auto-analysis then cascades through the call graph), and
apply the whole symbol file with `rename_many`. Do **not** loop `rename` over a
symbol file: each one costs a navigation (listing page + decompile) plus two
prompt round-trips, i.e. tens of minutes for a few hundred symbols, where
`rename_many` is one call and a few seconds.

### Database-wide search

`find` is Ctrl+F: two searches over the whole binary, not the current view.

* **text** matches the rendered disassembly line, whitespace-normalised — so
  `call cs:` matches `call    cs:getenv_ptr`. `regex=true` switches to a Python
  regex. Smartcase: an all-lowercase query is case-insensitive.
* **bytes** is IDA's own pattern language via `find_bytes`: hex pairs, `?`
  wildcards (whole byte *or* one nibble, `48 8? ?? 24`), and quoted literals
  (`"Hello", 0`). Commas, no separators at all (`488B05C3`) and mixed spacing
  all normalise to the same pattern.

Mode is guessed unless you say otherwise, and the guess is deliberately biased:
a hex-looking word (`dead`, `add`, `cafe`) is a *text* search, because those are
words. A query whose tokens are all byte-sized but one is malformed (`48 zz c3`)
is treated as bytes and **refused by name** — answering "no match" there would
be indistinguishable from "not present".

`head` is the item to navigate to (a byte match can land mid-instruction);
`addr` is the exact match.

```sh
python -m idatui.drive find 'call cs:'
python -m idatui.drive find '48 8b ?? c3'
python -m idatui.drive raw find query='mov e?x' regex=true limit=20
```

### Findings export

`export` writes what the session **worked out** -- comments, names, prototypes
and the types you declared -- as one markdown document.

The interesting part is provenance. A `.i64` does not record *who* wrote a
comment or a name: IDA's analyzer sets `; switch 73 cases` and `; s1` with the
same `set_cmt` a person uses, the loader sets `elf_gnu_hash_nbuckets` and
`File class: 64-bit` the same way, and the flags, `get_cmt` and even the colour
tag in `generate_disasm_line` are identical for all of them. So idatui keeps its
own **journal** (`idatui/journal.py`) of every edit it makes, in a netnode
inside the database, and the report is built from that -- exact, and still there
next session. Ask it on a database nobody journalled (worked on in the IDA GUI,
or before this existed) and it falls back to filtering by shape and says so in
the document.

```sh
python -m idatui.drive export                    # -> <binary>.findings.md
python -m idatui.drive export /tmp/writeup.md
```

### Movement (fast — bare keypresses, pump-only settle)
| method | params | effect |
|--------|--------|--------|
| `move` | `dir`, `n?=1`, `settle?` | `dir` ∈ down/up/left/right/word/wordback/bol/eol/top/bottom/halfdown/halfup/pagedown/pageup. |
| `cursor` | `line?`, `col?` | set the cursor directly on the active code pane (disasm/decomp), scrolling it into view. |
| `cursor_on` | `word`, `line?`, `occurrence?=1` | place the cursor on the *n*-th token equal to `word` (verified with the app's tokenizer). Decomp searches the whole body; disasm only cached/visible lines. Returns `{found, ...state}`. |

**Both cursor verbs scroll to what they selected, and `cursor_on` searches from
the viewport** (wrapping round to the rows above). A continuous listing is the
whole segment: counting occurrences from row 0 used to land the cursor in an
unrelated function thousands of rows away, off screen, and the next edit then
happened somewhere the operator could not see — with the driver reporting
success. If you mean a specific occurrence far away, pass `line=`.

## Driving pattern for an agent

Compose raw + semantic + introspection: e.g. `goto target=<fn>` → `state`/`view`
to read the pseudocode → `cursor line=.. col=..` onto a token → `rename name=..`
→ `screen` to confirm. For a fully "hand-typed" look, prefer the semantic verbs
(they type with delay); use `move`/`cursor` to reposition quickly between them.

## Notes / gotchas

- **Load options belong to the first open.** `pane spawn --processor/--base/
  --ida-args` (forwarded to `idatui.launch`) only take effect while there is no
  `.i64` yet — IDA bakes them into the database. To change them, delete the
  `.i64` (or use Ctrl+L in the TUI) and spawn again.
- **`--processor arm` is AArch64**, and Hex-Rays will not decompile a 32-bit
  function in a 64-bit database. For 32-bit ARM firmware use
  `--processor arm:ARMv7-A` (see `idatui/formats.py: PROCESSORS`, every name
  there verified against a real IDA).

- Settle is the shared `_sync.settle`: drain the message pump, wait for threaded
  workers, then (for ops with a known outcome) poll a predicate. A verb whose
  predicate can't be derived (e.g. `rename` on an arbitrary token) falls back to
  a generic worker-drain — read `state()` to confirm.
- IDA renders some names without a leading `.` (e.g. `.init_proc` → `init_proc`
  in pseudocode); resolve/goto by the list name, but match tokens by what's shown.
- Drive the surface end-to-end from another process with `idatui.rpcclient` /
  `idatui.drive`; the headless pilot (`tests/test_scenarios.py`) is the UI
  regression lock and shares `_sync.py`'s settle logic with the RPC server.
```
