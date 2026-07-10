# Blueprint: a generic TUI-driving layer

How to bring the "spawn a pane, drive the real TUI over a socket, read structured
state back" experience (built for **idatui**, see `docs/RPC.md`) to *other* TUI
software — most notably **gdb**, but the pattern generalizes to any terminal app
(vim, k9s, lazygit, htop, a REPL, …).

This is a design reference, not code. It captures the invariants worth keeping,
the parts that are reusable as-is, and the one hard problem you re-solve per
target (knowing when the UI has *settled*).

---

## 1. The reference implementation (what we're generalizing)

idatui is a Textual app we **own**, so we embedded an RPC server directly in its
asyncio event loop. The stack that emerged:

```
 tmux pane A (viewers see this)          tmux pane B (the agent)
 ┌────────────────────────────┐  unix    ┌────────────────────────┐
 │ the TUI, rendering normally │◀socket──▶│ ergonomic client (drive)│
 │ + in-process RPC server     │  JSONL   │  + pane manager         │
 └────────────────────────────┘          └────────────────────────┘
```

Pieces (all reusable ideas): a **unix-socket JSONL server**, **three method
tiers** (raw keys / semantic verbs / structured introspection), a **settle**
primitive (block until the UI is quiescent before returning state), a
**single-driver gate**, a **tmux pane manager** (spawn/stop/list + backend
auto-start + readiness polling), and an **ergonomic client** (auto socket
discovery, terse text, composite gestures).

---

## 2. Invariants worth preserving (why it felt good)

1. **Drive the *real* UI, not a hidden API.** Every action goes through the same
   input path a keyboard would, so the tmux pane shows it happening (livestream /
   debuggability). Bypassing the renderer to mutate state directly is faster but
   defeats the purpose.
2. **Three tiers, always.** `raw` (keystrokes) for fidelity/coverage; `semantic`
   verbs (typed, with an optional per-char delay for the hand-typed look) for
   ergonomics; `introspection` (structured reads) so the agent reasons over data,
   not screen-scraping.
3. **Every mutating call returns *after* the UI settled**, and returns fresh
   state. The driver never acts on a half-rendered frame.
4. **Single-driver by default.** One client at a time; a second concurrent
   connection is refused. No multi-driver coordination to reason about.
5. **Self-documenting surface.** A `methods` call returns the verb table; a
   `state`/`screen` call returns what's happening. The agent can discover the API.
6. **Lifecycle is first-class.** Spawn a pane, wait until *ready*, drive, tear it
   down; never leak panes/processes. Auto-start the backing daemon if it's down.
7. **An ergonomic layer on top.** The raw JSON transport is correct but verbose;
   a thin CLI that auto-resolves the socket and prints terse text is what you
   actually use all day.

---

## 3. Generic architecture

Split into a **reusable core** and a per-target **Adapter**. Only the adapter
changes between targets.

```
        ┌──────────────── reusable core ────────────────┐
client ─┤ transport (unix sock, JSONL, single-driver)   │
 (drive)│ dispatch (method table, tiers, error framing) │
        │ pane manager (tmux spawn/stop/list, readiness) │
        └───────────────────────┬───────────────────────┘
                                 │  Adapter interface
                    ┌────────────┴────────────┐
                    │  Target Adapter          │  ← the only per-target code
                    │  inject / settle /       │
                    │  snapshot / screen /     │
                    │  semantic verbs          │
                    └──────────────────────────┘
```

### The Adapter interface (the contract)

Everything a target must provide. Keep it small:

| method | purpose |
|--------|---------|
| `inject_keys(keys[])` | push keystrokes into the app's real input path |
| `inject_text(str, delay_ms)` | type a literal string (visible typing) |
| `settle(pred?, timeout) -> bool` | block until quiescent, then until `pred` (if given) |
| `snapshot() -> dict` | structured "where am I / what's on screen" state |
| `screen(fmt) -> {w,h,text}` | full render (plain / colored) of the pane |
| `verbs` | target-specific semantic ops (each = compose inject + settle + a predicate) |
| `ready() -> bool` | is the target drivable yet |
| `quit()` | graceful shutdown |

The core turns these into the wire method table and handles transport, framing,
the single-driver gate, and the pane lifecycle.

---

## 4. Target taxonomy — how much the app cooperates

The adapter's implementation depends entirely on how much access you get. Three
levels, best to worst:

### Level 1 — **Embedded** (you own or can patch the app)
Run an RPC server *inside* the app's event loop (idatui). Injection uses the
app's own key API; `settle` uses its message pump + task/worker state; `snapshot`
reads app state directly. **Highest fidelity, cheapest settle** (you have real
signals). Use when you can add ~200 lines to the target.

### Level 2 — **Control-channel** (app has a machine interface)
Many serious TUIs expose a second, structured channel alongside the visual one:
gdb (**GDB/MI** + a **Python API**), tmux (**control mode**, `-CC`), vim
(**channels / `--remote-expr`**), lldb, many REPLs. Strategy: the **visual** pane
is driven with keystrokes for fidelity; **semantic** verbs and **introspection**
go through the control channel, which is request/response (so quiescence is
*given* — a command is done when the channel replies). This is the sweet spot for
gdb (see §8).

### Level 3 — **Black-box PTY** (you can't modify or query it)
The universal fallback: the app is just bytes in / a screen out (vim without
channels, htop, an arbitrary curses app). You inject keystrokes into its PTY and
read state by scraping the rendered screen. **Settle is the hard part** (no
completion signal — you debounce on screen changes). Everything is a keystroke
macro + screen assertion.

> **Most targets are Level 2 or 3.** Design the core so an adapter can *mix*
> levels: e.g. gdb = Level 2 for `break/step/bt/read-mem`, Level 3 (screen
> scrape) for whatever the control channel doesn't expose.

---

## 5. The three hard problems, generically

### 5a. Input injection — "how do keystrokes get in"
- **Embedded:** call the app's key-press API (idatui used Textual's `_press_keys`,
  the same path its own tests use). Supports a `wait:<ms>` token → free typed delay.
- **Control-channel:** structured actions bypass keys entirely (gdb `-exec-*`);
  but *also* keep a keystroke path for TUI navigation.
- **Black-box:** **`tmux send-keys -t <pane> …`** is the universal injector — no
  PTY plumbing. It even names special keys (`Enter`, `C-c`, `Escape`). For a
  literal string, `send-keys -l 'text'`. For the typed aesthetic, send char-by-char
  with a sleep between.

### 5b. Settle / quiescence — "when did the UI finish reacting" *(the crux)*
Pick the strongest signal the target offers. A taxonomy, best → worst:

1. **Completion signal** *(embedded / control-channel).* The app tells you it's
   done: a worker/task queue drains (idatui: message pump + `WorkerManager`), or a
   request/response channel returns (`^done` in GDB/MI). Deterministic; prefer this.
2. **Predicate wait.** Poll a cheap boolean that means "the thing I asked for
   happened" (idatui: `dec.loaded_ea == target`). Always pair a semantic verb with
   its own predicate where one exists.
3. **Prompt / marker detection** *(black-box, structured-ish).* The screen returns
   to a known prompt regex, or the app emits a sentinel you injected (e.g. drive it
   to `echo <nonce>` and wait for `<nonce>` on screen). Robust when a prompt exists.
4. **Output debounce** *(black-box fallback).* Snapshot the screen every ~20 ms;
   consider it settled once it's unchanged for N consecutive samples (e.g. 3× =
   ~60 ms) or a hard timeout. Flakiest; tune N per app; combine with (3).

Factor settle into a shared helper that takes the *yield/poll* strategy and an
optional predicate (idatui's `_sync.settle(app, pred)` is exactly this — reused by
both the live driver and the test suite). That sharing is high-value: your tests
and your driver then agree on "settled."

### 5c. Introspection — "what is on screen / what is the state"
Same best→worst gradient:
1. **Native state** (embedded): read the app's model directly → richest snapshot.
2. **Control-channel queries** (gdb: frames, registers, `-data-read-memory`,
   breakpoints as JSON) → structured, no scraping.
3. **Screen scrape** (black-box): render the pane to a text grid and parse it.
   `tmux capture-pane -p -t <pane>` (add `-e` to keep colors) is the universal
   screen read. For a machine-parseable grid without a real terminal, feed the PTY
   stream through a headless emulator (e.g. **pyte**) and read its buffer.

Always expose a raw `screen()` too (plain + colored). It's the agent's "look with
your eyes" fallback and a great debugging aid (idatui added `format=text|html|svg`;
`html` is nice to pipe to an out-of-band web viewer).

---

## 6. tmux as the universal substrate

For **Level 2/3** targets, don't own the PTY yourself — let **tmux** own it and
drive through tmux. This collapses three problems into three commands and reuses
the pane manager we already built:

| need | tmux primitive |
|------|----------------|
| a visible pane running the target | `tmux split-window -P -F '#{pane_id}' '<cmd>'` |
| inject keystrokes | `tmux send-keys -t <pane> …` (named keys, `-l` literal) |
| read the screen | `tmux capture-pane -p [-e] -t <pane>` |
| is the pane alive | `tmux list-panes -a -F '#{pane_id}'` |
| tear down | `tmux kill-pane -t <pane>` |

A black-box adapter can be built *entirely* on these four. The pane manager
(`spawn/stop/list`, a small registry in `$XDG_RUNTIME_DIR`, backend auto-start,
readiness polling) carries over unchanged — only "what counts as ready" and "what
command to spawn" are per-target.

Caveat: `capture-pane` gives you the *rendered* grid but not semantic structure;
and `send-keys` is fire-and-forget (no completion signal) → you lean on §5b (3)/(4)
for settle. That's the price of black-box.

---

## 7. Reusable vs. per-target

**Reuse verbatim** (target-independent):
- Transport: unix socket, newline-delimited JSON, `{id,method,params}` →
  `{id,result|error}`; single-driver gate; per-request dispatch + error framing.
- Pane manager: `spawn/stop/list`, registry, backend `_ensure_server`, readiness
  poll, graceful `quit` (answer then exit).
- Client + ergonomic CLI: socket auto-resolution (single live pane), terse text
  output, composite verbs, `raw <method> k=v` passthrough, self-documenting
  `methods`.
- The settle *shape* (`wait_for(pred, tick)` + `settle(pred?)`), even though the
  concrete signals differ.

**Write per-target** (the adapter):
- Input injection binding (app key API / control channel / `tmux send-keys`).
- Settle signal (which of §5b applies).
- `snapshot()` and `screen()` sources.
- The semantic verb set (the app's real vocabulary).
- `ready()` and the spawn command.

Rule of thumb: **~80% reuse, ~20% adapter.** Keep the adapter interface narrow so
that stays true.

---

## 8. Worked example: **gdb**

gdb is a *Level 2* target with a great control channel, so aim for a hybrid.

**Layout.** A tmux pane runs gdb in TUI mode (`gdb -q -tui` / `layout src`,
`layout asm`, `layout regs`) — that's what viewers see. Alongside it, a **gdb
Python plugin** (loaded with `-x driver.py`, running inside gdb's own process)
opens the unix socket and *is* the adapter. gdb's Python runs on gdb's thread, so
handlers touch gdb state directly — the embedded pattern, for free, inside a
program you didn't write.

**Injection.**
- *Semantic* verbs call the API directly (visible in the TUI because gdb echoes
  and repaints): `gdb.execute("break main", to_string=True)`, `-exec-run`,
  `-exec-next`, `-exec-continue`, `-exec-finish`. Or GDB/MI via a second channel
  if you prefer strict JSON.
- *Raw* verbs (for TUI-only navigation: `C-x o` to switch windows, PgUp/PgDn in
  the source window, `C-x 2` layouts) go through **`tmux send-keys`** to the pane.

**Settle.** Mostly *given*: `gdb.execute(..., to_string=True)` and MI commands are
synchronous — they return when the command completed, so a semantic verb is
settled the moment the call returns. For *async* execution (`-exec-continue` while
the inferior runs), settle = wait for the next **stop event** (`gdb.events.stop`)
or the MI `*stopped` async record. For raw `send-keys` TUI moves, fall back to
`capture-pane` debounce (§5b-4).

**Introspection** (all structured, no scraping):
- `state()` → `{running|stopped, pc, function, file:line, thread, selected_frame}`
  from `gdb.selected_frame()`, `gdb.selected_thread()`.
- `backtrace()` → walk `gdb.newest_frame()` → `[{level,pc,func,file,line,args}]`.
- `regs()` → `frame.read_register(...)` for the ABI set.
- `mem(addr,len)` → `gdb.selected_inferior().read_memory(...)` (hex/ascii).
- `locals()`, `breakpoints()` (`gdb.breakpoints()` → JSON), `disas(addr?)`.
- `screen()` → `tmux capture-pane -ep` of the TUI pane (the "as a viewer sees it"
  read), *plus* the structured reads above for reasoning.

**Semantic verb set** (the gdb vocabulary): `run/start`, `cont`, `next`, `step`,
`finish`, `until`, `break <loc>`, `tbreak`, `delete <n>`, `watch <expr>`,
`bt [n]`, `frame <n>`, `up/down`, `print <expr>`, `x/<fmt> <addr>`, `set var`,
`layout <src|asm|regs|split>`, `focus <win>`, `raw keys …`.

**Spawn / readiness.** `spawn --bin ./prog [--args …]` → tmux pane runs
`gdb -q -tui -x driver.py --args ./prog …`; **ready** when the plugin's socket is
up *and* gdb reached its prompt (the plugin can signal readiness once loaded).
`stop` = graceful `quit` verb (plugin calls `gdb.execute("quit")`) then kill-pane.

This gives the same feel as idatui: `drive where` → `#3 main at foo.c:42`,
`drive bt`, `drive break foo`, `drive cont`, `drive x/16xb $sp`, `drive screen` —
terse, socket auto-resolved, every action visible in the gdb TUI pane.

---

## 9. Method-surface conventions (keep these consistent across targets)

- **Tiers, named the same everywhere:** `keys`/`text` (raw); `state`/`view`/
  `screen`/`<structured reads>` (introspection); `<semantic verbs>` (per target);
  `ping`/`methods`/`quit` (lifecycle).
- **`ping`** returns `{ok, proto, ready, …}`; **`methods`** returns the verb table
  (self-documentation); **`quit`** answers *then* exits (so the reply flushes).
- Mutating verbs **settle then return fresh `state`**. Read verbs never settle.
- Program-dependent verbs return a clean **`error: not ready`** before init.
- Typed verbs accept **`delay_ms`** (visible typing; `0` = fast). Movement verbs
  are fast (no delay, light settle).
- Errors are data (`{id,error:{message}}`), never drop the connection.

## 10. Client ergonomics (the part you use all day)

- **Auto-resolve the socket**: if exactly one live pane, use it; else `--sock` /
  env; with several, list and ask. Kills the "copy the socket path everywhere"
  tax — the single biggest quality-of-life win.
- **Terse text out**, not raw JSON (`where` → `main @ 0x… [src] L42`); keep a
  `raw <method> k=v` passthrough for the long tail.
- **Composite gestures** for the common multi-step flows (idatui's
  `rename old new` = goto+cursor+type; gdb's `break-and-run`, `stepn N`).
- Fire calls **sequentially** (single-driver); each invocation opens/closes its
  own connection.

## 11. Security & operations

- **Unix socket, mode 0600, local only.** No auth by design (whoever can r/w the
  socket drives it). Add a first-line shared token only if you bind TCP.
- **Single-driver gate** prevents two clients interleaving mutations.
- **Never leak panes/daemons.** Registry + `list --prune`; auto-start shared
  backends idempotently (probe before spawn; a port/socket already-in-use guards
  duplicates); don't kill shared backends on a per-pane `stop`.
- Note the **stale-pane** failure mode: a pane can outlive its backend/session;
  `list` should check liveness, not just tmux presence.

## 12. Onboarding a new target — checklist

1. **Classify** it (§4): can you embed? does it have a control channel? else
   black-box.
2. Pick the **injection** binding (§5a) and the **settle** signal (§5b) — decide
   this first; everything else is easy.
3. Implement the **Adapter** (§3): `inject_keys/text`, `settle`, `snapshot`,
   `screen`, `ready`, `quit`, and the **semantic verbs** (the app's real
   vocabulary — don't invent; mirror what a power user types).
4. Wire the **spawn command** + **readiness** into the pane manager.
5. Reuse transport, client, and ergonomic CLI unchanged.
6. Add a **smoke test** that spawns the target on a socket and drives the whole
   surface end-to-end (idatui's `rpc_smoke.py` is the template — it also locks the
   protocol against regressions).

## 13. Pitfalls & lessons (paid for once already)

- **Settle is where the bugs live.** A verb that "passes" by timing out then
  reading stale state is the classic false-green (idatui hit this: a 25 s hang that
  a check passed *trivially*). Prefer a real signal/predicate; print per-op timing
  so a suddenly-slow verb (a hidden timeout) is visible.
- **Newlines / control bytes** matter when injecting via a line-based reader —
  pick an escaping convention (idatui: literal `\n` → real newline at apply time).
- **Black-box screen scraping is lossy** — no semantic structure, colors optional,
  non-deterministic chrome (a live clock makes frames differ). Crop chrome; prefer
  structured reads when a control channel exists.
- **Match on what's shown, resolve by canonical id.** Names can render differently
  than they're stored (idatui: `.init_proc` shows as `init_proc`).
- **Keep the app visibly driven.** If you ever bypass the UI for speed, gate it
  behind an explicit `fast:true` — the default should always render, because
  "shown as if a user did it" is the whole point.

---

*Reference implementation: `idatui/{rpc,rpcclient,drive,pane,_sync}.py`,
`docs/RPC.md`, `tests/rpc_smoke.py` in this repo.*
