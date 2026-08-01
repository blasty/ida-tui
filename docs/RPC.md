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
| `xrefs` | — | `x`: open the xref picker. |
| `symbols` | `query?` | Ctrl+N palette, optionally pre-typed. |
| `structs` | — | Ctrl+T struct editor. |
| `search` | `term`, `direction?=1` | `/` (or `?`) incremental search in the active code view. |
| `select` | `index?` | in an open modal list (xrefs/symbols) choose the highlighted (or nth) item and activate it. |
| `save` | — | Ctrl+S: persist the `.i64`. |
| `close` | — | Escape (dismiss a modal). |
| `define` | `kind`, `target?`, `delay_ms?` | goto `target` (if given) then press the listing key for `kind` ∈ `code`(c) / `func`(p) / `undef`(u) / `thumb`(t) / `thumbscan`(T) / `data`(d) / `string`(a). Leaves hex/decomp for the listing first (those bindings are listing-only). The IDA-side outcome is in `status` (e.g. *defined 228 instructions (0x4370–0x45e8) — control flow ends here*) and in `define.status`. |
| `rename_many` | `items:[{addr,name}]` **or** `file:<json>`, `allow_overwrite?=true` | bulk-apply a symbol map in ONE worker call, then refresh the caches + function table. Accepts `addr`/`start`/`ea`/`address` and `name`/`label`, or a plain `{addr: name}` object. Returns `rename_many:{requested,skipped,ok,failed,errors[]}`. |

**Raw images: `define` + `rename_many` are the workflow.** A firmware blob loads
with no functions and no names. Point `define thumb` / `define func` at the entry
points you know (IDA's auto-analysis then cascades through the call graph), and
apply the whole symbol file with `rename_many`. Do **not** loop `rename` over a
symbol file: each one costs a navigation (listing page + decompile) plus two
prompt round-trips, i.e. tens of minutes for a few hundred symbols, where
`rename_many` is one call and a few seconds.

### Movement (fast — bare keypresses, pump-only settle)
| method | params | effect |
|--------|--------|--------|
| `move` | `dir`, `n?=1`, `settle?` | `dir` ∈ down/up/left/right/word/wordback/bol/eol/top/bottom/halfdown/halfup/pagedown/pageup. |
| `cursor` | `line?`, `col?` | set the cursor directly on the active code pane (disasm/decomp). |
| `cursor_on` | `word`, `line?`, `occurrence?=1` | place the cursor on the *n*-th token equal to `word` (verified with the app's tokenizer). Decomp searches the whole body; disasm only cached/visible lines. Returns `{found, ...state}`. |

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
