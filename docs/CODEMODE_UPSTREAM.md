# Findings from porting a real client to IDA Code Mode

Notes for the `ida-codemode` maintainers, gathered while porting **ida-tui** (a
Textual TUI frontend for IDA) from a private idalib worker to
`ida_codemode.client.DatabaseHandle`.

Everything below is measured, not inferred. Where we worked around something, the
workaround is named so you can judge whether the library should make it
unnecessary.

**Environment:** ida-codemode 0.3.1, IDA 9.4 (idalib), Linux, single managed
worker backend, quiet box. Target for timings: `targets/echo` unless stated.

**What the client does**, for scale: it renders a continuous disassembly listing,
pseudocode, a CFG graph view and a hex view, paging over the database as the user
scrolls. It is latency-sensitive in a way an agent-driven MCP client is not — a
keypress must repaint. It issues ~1–8 operations per user action.

---

## 1. `timeout_trace` enables line tracing in every frame — 52x on IDA calls

**Highest-impact item by a wide margin.**

`runtime.py` wraps every `execute_python` in `sys.settrace(timeout_trace)` to
enforce the deadline. `timeout_trace` ends with `return timeout_trace`, and
returning a trace function from a `'call'` event asks CPython to trace **every
line of that frame**. So every line of every function the snippet touches pays a
Python-level callback, and the specialising interpreter is disabled throughout.

Measured inside the worker, same process, same database:

| | traced (stock) | untraced | native idalib |
|---|---|---|---|
| `ida_bytes.get_flags(ea)` | 5.49 µs | 0.106 µs | 0.119 µs |
| our 200-row listing page | 20.2 ms | 2.0 ms | — |

Untraced matches a plain idalib process, so the trace hook accounts for
essentially all of it. For us this was the single largest cost in the port —
larger than HTTP, serialisation and IDA itself combined.

Reproduce inside any `execute_python`:

```python
import sys, time, ida_bytes
def bench():
    t = time.perf_counter()
    for _ in range(20000): ida_bytes.get_flags(0x1000)
    return (time.perf_counter() - t) / 20000 * 1e6
traced = bench()
old = sys.gettrace(); sys.settrace(None)
try:    untraced = bench()
finally: sys.settrace(old)
result = {"traced_us": traced, "untraced_us": untraced}
```

**Suggested fixes, cheapest first**

1. `return None` from `timeout_trace` instead of itself. You keep `'call'`-event
   deadline checks — which is enough to interrupt anything that calls a function
   — and drop per-line tracing entirely.
2. On 3.12+, use `sys.monitoring` with only the events you need; it is designed
   for exactly this and is far cheaper than `settrace`.
3. Or drop the trace and rely on the `threading.Timer` →
   `ida_kernwin.set_cancelled()` path you already have, accepting that a
   pure-Python loop with no calls in it cannot be interrupted.

**Our workaround** (we would rather not ship it): the snippet detaches the trace
and restores it in a `finally`. That gives up deadline enforcement for
pure-Python loops inside our own code; your native cancel timer is unaffected and
still fires. Every client that does real work per call will eventually find this
and do the same, which is an argument for fixing it in the runtime.

---

## 2. `to_jsonable` dominates any large result

`execute_python` runs `to_jsonable()` over whatever the snippet returns. Our
answers are already JSON-safe and they are big — a 200-row listing page is
roughly 10k small objects.

| | cost |
|---|---|
| `to_jsonable(page)` | 66.2 ms |
| `json.dumps(page, separators=(",",":"))` — same data | 0.58 ms |
| serialised size | 34.9 KB |

That is 114x, and it was 72% of the page's total cost before we changed it.

**Suggested fixes**

- Fast-path values that are already JSON-safe (a cheap recursive type check that
  bails to the original object beats rebuilding it), or
- let a snippet opt out by returning an already-serialised payload — a documented
  envelope such as `{"__json__": "<...>"}`, or simply passing `str`/`bytes`
  through untouched.

**Our workaround:** snippets `json.dumps` inside the database process and return
one string, which the client parses. `to_jsonable` then walks a single scalar.
Cost went 66.2 ms → ~0.6 ms. It works, but every client with a large result set
has to discover and re-implement it.

---

## 3. The per-operation floor is `execute_sync`, not HTTP

Same worker, same connection, 200 iterations:

| | cost |
|---|---|
| `GET /health` (no `execute_sync`) | **0.165 ms** |
| `execute_python("result = 1")` | **2.025 ms** |

HTTP framing is ~7% of the floor; marshalling the operation onto IDA's main
thread is the other ~93%. The worker runs IDA's own `kernwin.serve()`, so this is
plausibly IDA's dispatch latency rather than anything you control — but it is
worth **documenting**, because it sets a hard 2 ms per-operation budget that
shapes how a client must be designed.

It did not hurt us (our call volume is 1–8 per user action; 4 calls to build a
1060-block graph), but a client that makes one call per row or per symbol will be
20–100x slower than an in-process one and the authors will not know why.

**Suggested fixes:** document the floor; and consider a batch endpoint — accept
`[{op, args}, ...]` and dispatch them within a single `execute_sync` — which
would let chatty clients amortise it without redesigning around it.

---

## 4. Loader switches on an existing database are a FATAL, not an error

Opening a target that already has an `.i64`, while passing spawn-only options,
kills the worker:

```
FATAL ERROR: @0:636[]
Switch '-b400' can be used only when loading a new file
```

The client sees only:

```
IDAConnectionError: idalib worker launcher <pid> exited with status 1
```

This is easy to hit and hard to diagnose: it is the natural second run of
anything that opens a raw blob (`processor=`/`image_base=`/`file_type=` are
recorded in the database the first run produced). Our test suite hit it as a
crash five minutes into a run.

**Suggested fixes**

- In `DatabaseHandle.open()`, when the resolved IDB already exists and
  `new_database` is not set, either ignore the spawn-only options or raise a
  typed error naming them — before handing them to IDA.
- Propagate the worker's fatal text into the client exception. The message
  already exists on the worker's stderr; losing it turns a one-line fix into a
  bisect.

**Our workaround:** the client checks whether the expected IDB exists and drops
`processor`/`image_base`/`file_type` when it does.

---

## 5. Deleting or replacing an IDB under a live lease fails silently

A suite that did "delete the `.i64`, reopen the same path" (safe when it owned a
private worker) now races the previous worker's lease grace. The reopen produced
a handle that never became usable, with no error — just a database with no
listing, and every wait timing out.

**Suggested fixes**

- Detect that the IDB backing a registered instance has been removed or replaced
  and fail loudly (the registry already holds `idb_key`).
- Expose a **public** "wait until this database is released" primitive. We needed
  one and ended up reaching into `registry.REGISTRY_DIR` and `FileLock` to build
  it, which is not an API we should be depending on.
- Document the lease-grace window as part of the lifecycle contract.

---

## 6. No close-without-save, and no rollback

A managed worker saves when its final lease closes. A GUI handle leaves GUI state
as-is. Neither gives a client a way to say "discard what I did".

ida-tui had a "discard & quit" that we could not port; it is now "leave as-is &
quit", and we cannot honestly promise the user their edits are not persisted.

**Suggested fixes:** a close policy on a lease the client created
(`close(save=False)`), or a transaction/rollback API, or a documented
disposable-copy pattern that clients can follow.

---

## 7. No change notification for shared databases

The lease reports liveness, not mutations. If a GUI user or another Code Mode
client renames or retypes while we are attached, our materialised caches (name
generation, decompilation, listing pages) are silently stale. Our own edits
invalidate correctly; someone else's cannot.

**Suggested fix — cheap and sufficient:** a monotonic database revision counter,
bumped on any mutating operation and exposed on `/health` (and ideally on the
lease event stream). Clients can then invalidate by comparing one integer. A full
change feed would be better but is much more work; the counter alone would make
shared editing safe for every caching client.

---

## 8. Package exports and API surface stability

`ida_codemode/__init__.py` exports nothing, so a library consumer must import
from submodules:

```python
from ida_codemode.client   import DatabaseHandle, ClientError, RemoteError, InstanceDisconnectedError
from ida_codemode.registry import REGISTRY_DIR, FileLock, RegistryEntry, canonical_path, idb_key, scan_instances
from ida_codemode.resolver import IdbBusy, expected_idb_path
```

Some of those are clearly internals (`FileLock`, `REGISTRY_DIR`) that we only
touch because no public equivalent exists (see §5).

**Suggested fix:** export `DatabaseHandle` and the public exception types from the
package root, and mark the intended-public registry helpers explicitly. It also
makes "what is API and what is internal" answerable, which right now it is not.

---

## 9. A testing note: `DatabaseHandle.open()`'s 30 keyword-only options

The port we started from called `open(..., loading_address=...)`. The real
parameter is `image_base`. Every `connect()` would have raised `TypeError` on the
first call, and its contract tests passed anyway, because a hand-written fake
handle accepts `**kwargs`.

Not a library bug — but with 30 keyword-only options it is a very easy mistake,
and it is invisible to exactly the offline tests people write.

**Suggested fix:** ship `py.typed` and/or a `Protocol` for the handle, so a fake
can be checked against the real signature and a typo is caught statically. (We
added a test asserting our kwargs are a subset of
`inspect.signature(DatabaseHandle.open).parameters`, which is a poor substitute.)

---

## Priority, from a client author's view

| # | item | impact | fixable by you? |
|---|---|---|---|
| 1 | `timeout_trace` line tracing | 52x on IDA calls, 10x on real operations | yes, one line |
| 2 | `to_jsonable` on large results | 114x on serialisation | yes |
| 7 | no change/revision counter | correctness for shared editing | yes, cheap |
| 4 | loader switches fatal on reopen | crashes, hard to diagnose | yes |
| 5 | replaced/deleted IDB under lease | silent hang | yes |
| 6 | no close-without-save | a feature we had to drop | design question |
| 8 | package exports | forces internal imports | yes, trivial |
| 3 | 2 ms `execute_sync` floor | shapes client design | document; maybe batch |
| 9 | typed handle for fakes | catches a whole bug class | yes |

Items 1 and 2 together were the difference between "the port is 35x slower than
the private worker it replaced" and "the port is within 2x, and faster on several
operations". Both are in the runtime, not in client code — which is why they are
worth fixing centrally rather than leaving each client to rediscover.

Happy to supply the benchmark harness (it is backend-agnostic and runs against
both our old worker and Code Mode), or to test a patch.
