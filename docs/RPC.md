# RPC: puppeteering the TUI

Drive a *live* idatui over a unix socket while it renders normally in its
terminal (what a livestream/viewer sees). The listener runs on the same asyncio
loop as the UI, so handlers touch widgets directly — every injected key has the
identical on-screen effect a real keyboard would.

Layers: `idatui/rpc.py` (server, above `app.py`), `idatui/_sync.py` (the shared
"wait until the UI settled" logic, also used by the tests), `idatui/rpcclient.py`
(stdlib client + CLI).

## Running

```
# pane A — the TUI (real render) + a socket listener
python -m idatui.tui --db <session> --rpc /tmp/ida.sock

# pane B — drive it
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
| method | params | returns |
|--------|--------|---------|
| `state` | — | active/pref view, current function `{ea,name}`, cursor `{line,col,word,ea}` (or `{va,byte}` in hex), status text, filter, nav depth, dirty, open `modal`. |
| `view` | `lines?` | visible lines of the active code pane, cursor-marked (disasm/decomp; use `screen` for hex). |
| `screen` | — | `{width,height,text}` — a full plain-text render of exactly what's on screen. |
| `functions` | `filter?`, `limit?=50` | `[{ea,name,size}]`. |

### Semantic verbs
High-level ops type through the **real prompts** with a per-char delay
(`delay_ms`, default 35ms) so viewers see it typed; each settles on an op-specific
predicate so the returned state is final.

| method | params | effect |
|--------|--------|--------|
| `goto` / `open` | `target`, `delay_ms?`, `timeout?` | `g` prompt → name or `0xADDR` → Enter. |
| `rename` | `name`, `delay_ms?` | `n` on the token under the cursor → replace → Enter. |
| `comment` | `text`, `delay_ms?` | `;` on the current line. |
| `retype` | `proto`, `delay_ms?` | `y` on the token/function under the cursor. |
| `follow` | — | Enter: follow the reference under the cursor (waits for the jump). |
| `back` | — | Escape: pop the nav stack. |
| `toggle_view` | — | Tab: disasm ⇄ pseudocode. |
| `hex` | — | `\`: hex view. |
| `xrefs` | — | `x`: open the xref picker. |
| `symbols` | `query?` | Ctrl+N palette, optionally pre-typed. |
| `structs` | — | Ctrl+T struct editor. |
| `close` | — | Escape (dismiss a modal). |

### Movement (fast — bare keypresses, pump-only settle)
| method | params | effect |
|--------|--------|--------|
| `move` | `dir`, `n?=1`, `settle?` | `dir` ∈ down/up/left/right/word/wordback/bol/eol/top/bottom/halfdown/halfup/pagedown/pageup. |
| `cursor` | `line?`, `col?` | set the cursor directly on the active code pane (disasm/decomp). |

## Driving pattern for an agent

Compose raw + semantic + introspection: e.g. `goto target=<fn>` → `state`/`view`
to read the pseudocode → `cursor line=.. col=..` onto a token → `rename name=..`
→ `screen` to confirm. For a fully "hand-typed" look, prefer the semantic verbs
(they type with delay); use `move`/`cursor` to reposition quickly between them.

## Notes / gotchas

- Settle is the shared `_sync.settle`: drain the message pump, wait for threaded
  workers, then (for ops with a known outcome) poll a predicate. A verb whose
  predicate can't be derived (e.g. `rename` on an arbitrary token) falls back to
  a generic worker-drain — read `state()` to confirm.
- IDA renders some names without a leading `.` (e.g. `.init_proc` → `init_proc`
  in pseudocode); resolve/goto by the list name, but match tokens by what's shown.
- `tests/rpc_smoke.py` boots the app on a socket in-process and drives the whole
  surface end-to-end — the protocol's regression lock.
```
