# Findings from porting a real client to IDA Nexus

Notes for the `ida-nexus` maintainers, gathered while porting **ida-tui** (a
Textual TUI frontend for IDA) from a private idalib worker to
`ida_nexus.DatabaseHandle`.

Everything below is measured, not inferred. Where we worked around something, the
workaround is named so you can judge whether the library should make it
unnecessary.

**Environment:** ida-nexus 0.3.1, IDA 9.4 (idalib), Linux, single managed
worker backend, quiet box. Target for timings: `targets/echo` unless stated.

> **Status against the protocol-6 event-stream development tree, based on 0.6.1
> (upstream `439289f`) — every item re-checked.**
>
> | item | verdict |
> |---|---|
> | 1 `timeout_trace` line tracing | ✅ **fixed in 0.3.2** — no `settrace` in the runtime at all |
> | 2 `to_jsonable` on large results | ✅ **fixed in 0.3.2** — `dumps_json` C fast path |
> | 3 2 ms `execute_sync` floor | ✅ **fixed in 0.3.2, 7.0x** — 2.055 ms → 0.294 ms |
> | 4 loader switches fatal on reopen | **partial** — normal reopen fixed in 0.5.x; direct `.i64` paths remain [issue #36](https://github.com/HexRaysSA/ida-nexus/issues/36) |
> | 5 IDB replaced under a live lease | **stale** — out-of-band replacement is outside the supported lifecycle, as it is for the IDA GUI |
> | 6 close without save | **fixed in protocol 6** — the final managed-worker lease can choose `shutdown_database(save=False)` |
> | 7 no change notification | ✅ **fixed in protocol 6** — `DatabaseHandle.subscribe_idb_events()` streams revisioned, operation-attributed IDB changes |
> | 8 package exports | ✅ **fixed in 0.5.x** — a real `__all__` on the package root |
> | 9 no `py.typed` / handle Protocol | ✅ **fixed in 0.5.x** — `ida_nexus/py.typed` ships |
>
> **0.5.x restructured the package**, which is why the old "these files are
> byte-identical" re-check recipe no longer works: `client.py` → `handle.py`,
> `registry.py` → `_registry.py` + `instances.py`, `resolver.py` → `_resolver.py`,
> and the loader options moved into a frozen `DatabaseOpenOptions` dataclass.
> Everything private is now underscore-prefixed, so the cheap re-check after an
> upstream pull is simply: does anything we import still appear in
> `ida_nexus.__all__`?
>
> 0.5.3 → 0.6.1 changed **nothing** we depend on: `__init__.py`, `handle.py`,
> `instances.py`, `options.py`, `errors.py` and `models.py` are byte-identical
> between those two releases. 0.6.1 only collapses the six console scripts into a
> single `ida-nexus` command.
>
> Both client-side workarounds re-measured at **0.99x and 0.97x** on 0.3.2 —
> i.e. nothing — and are deleted. Remote code is now ordinary typed Python,
> installed as content-addressed modules by ida-nexus. Harness:
> `experiments/bench_pack_trace.py`.

**What the client does**, for scale: it renders a continuous disassembly listing,
pseudocode, a CFG graph view and a hex view, paging over the database as the user
scrolls. It is latency-sensitive in a way an agent-driven MCP client is not — a
keypress must repaint. It issues ~1–8 operations per user action.

---

## 1. `timeout_trace` enables line tracing in every frame — 52x on IDA calls

**Highest-impact item by a wide margin.** — ✅ **FIXED in 0.3.2.** The runtime no
longer installs a trace hook at all; cancellation is a C-level thread interrupt.
Our `sys.settrace(None)` workaround is deleted as of `a5137fe`.

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

**FIXED in 0.3.2**, via the first suggested fix below:
`serialization.dumps_json` calls `json.dumps(value, default=to_jsonable)`, so a
JSON-safe result never enters the Python walker. Our packing workaround measured
0.97x and has been deleted.

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

**Retired workaround:** snippets used to `json.dumps` inside the database process
and return one string, which the client parsed. The typed remote API now owns
strict argument/result encoding, and ida-tui contains no generated script
strings or packing envelope.

---

## 3. The per-operation floor is `execute_sync`, not HTTP

✅ **FIXED in 0.3.2 — 7.0x.** Re-measured as a same-box A/B by checking the
installed editable checkout back to `4195f21` and forward again, 200 iterations
each, `targets/echo`:

| | 0.3.1 | 0.3.2 | |
|---|---|---|---|
| `GET /health` | 0.497 ms | 0.318 ms | 1.6x |
| `execute_python("result = 1")` | **2.055 ms** | **0.294 ms** | **7.0x** |

The 0.3.1 column reproduces the original 2.025 ms measurement below almost
exactly, which is what makes the 0.3.2 column believable. `execute_python` now
costs about the same as a bare HTTP GET, so the `execute_sync` marshalling that
was ~93% of the floor is essentially gone. The design advice below — "a client
that makes one call per row will be 20–100x slower than an in-process one" — is
correspondingly much weaker now.

Original 0.3.1 measurement, same worker, same connection, 200 iterations:

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

## 4. Loader switches on an existing database are a FATAL, not an error — one edge remains

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

**Our workaround:** the client checked whether the expected IDB exists and
dropped `processor`/`image_base`/`file_type` when it did.

**FIXED in 0.5.x**, with exactly this fix, in `_resolver._build_worker_command`:

```python
if input_path == expected_idb and input_path != source:
    # Loader/import switches are baked into an existing IDB...
    options = WorkerLaunchOptions()
```

Our workaround is therefore deleted. **One narrow case remains**: the strip needs
`input_path != source`, so passing an `.i64` path *directly* together with load
options (`ida-tui foo.i64 --processor arm`) still forwards the switches and still
fatals. Our old guard keyed on "the target IDB exists" and so covered it. It is a
nonsense invocation and no ida-tui code path generates it — the project layer
always passes `output_database`, and `_needs_load_options` bails when an `.i64`
exists — but the library boundary should still reject or normalize it rather
than launch a known-fatal IDA command. Tracked upstream as
[issue #36](https://github.com/HexRaysSA/ida-nexus/issues/36).

---

## 5. Deleting or replacing an IDB under a live lease — STALE

The original suite deleted an `.i64` while a private worker still had it open,
then immediately reopened the same path. That ownership model no longer applies:
IDA Nexus databases are shared resources, and the IDA GUI itself does not survive
out-of-band replacement of its open database. Detecting arbitrary filesystem
replacement is therefore not part of the supported lifecycle.

The actionable lifecycle gaps that originally forced private-registry access are
fixed. `find_database_owner()` and `wait_database_released()` are public exports;
`DatabaseHandle.close(wait_for_database=True)` can wait for a final managed close;
a draining owner remains registered until the IDB is actually closed; and
`new_database=True` refuses to replace a live owner.

ida-tui now uses the public owner/release API while recreating a database and no
longer reaches into registry locks. Owner loss is attach-only: ida-tui will
rediscover a replacement GUI or worker, but will never turn a
user-closing-the-GUI action into an implicit headless reopen. There is no
remaining upstream request in this section.

---

## 6. Close without save — FIXED in protocol 6

`DatabaseHandle.shutdown_database(save=False)` can discard a managed idalib
worker when the requesting handle is its only active lease and no other operation
is running. The server rejects GUI databases and shared workers.

The coherent ownership model is the **final lease**, not necessarily the lease
that spawned the worker. Releasing a non-final lease makes no whole-database save
decision; responsibility transfers to the leases that remain. The final client
can save or discard the shared session. A client that needs its work to survive
regardless of that later decision must call `save_database()` before releasing
its lease.

This does not claim to provide per-client rollback. Discard applies to all
changes since the last database save, and attempting it while another lease is
active is correctly rejected. That is the same ref-counted lifetime model used
by other shared resources and requires no separate starter capability.

The upstream gap is therefore closed. ida-tui now routes its discard action
through `shutdown_database(save=False)`: a final managed-worker lease discards,
while GUI-backed and still-shared sessions transfer finalization to their owner
or remaining leases.

---

## 7. No change notification for shared databases — FIXED in protocol 6

`DatabaseHandle.subscribe_idb_events()` now returns a closeable iterator over
structured IDB changes. Each event carries a monotonic revision plus
`operation_id`/`operation_label` attribution and an opaque `origin_id`.
`DatabaseHandle.owns_event()` compares that origin with the handle's lease, so a
caching client does not need to generate, retain, or race operation IDs itself.

ida-tui keeps one subscription for its active database, asks the handle to drop
its own events, and batches peer events behind a 200 ms quiet period. One batch
invalidates the function, listing, decompiler, graph, strings, linkage, segment
and byte caches, then reloads the visible view in place. Closing or switching
databases closes the subscription, so the blocking event reader does not leak.

---

## 8. Package exports and API surface stability — FIXED in 0.5.x

`ida_nexus/__init__.py` used to export nothing, so a library consumer had to
import from submodules, including things that were clearly internals (`FileLock`,
`REGISTRY_DIR`, `canonical_path`, `idb_key`, `scan_instances`) that we only
touched because no public equivalent existed.

**Suggested fix was:** export `DatabaseHandle` and the public exception types from
the package root, and mark the intended-public registry helpers explicitly.

**That is what 0.5.x did.** Everything we need is now on the package root, and
the internals moved behind an underscore:

```python
from ida_nexus import DatabaseHandle, DatabaseOpenOptions, DatabaseInstance
from ida_nexus import RemoteError, DatabaseBusyError, DatabaseDisconnectedError
from ida_nexus import discover_databases, find_database_owner, wait_database_released
```

The two lock-poking helpers we had reimplemented client-side
(`_wait_for_entry_release`) are now `wait_database_released()`, and our
registry-scanning ownership check is now `find_database_owner()`. Both are
deleted from our tree. Note `find_database_owner()` *raises*
`AmbiguousDatabaseError` where our scan silently took the first match — a
behaviour improvement, but callers need a handler.

---

## 9. A testing note: `DatabaseHandle.open()`'s 30 keyword-only options — FIXED in 0.5.x

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

**0.5.x ships `ida_nexus/py.typed`**, and the 30 keyword-only options became a
frozen `DatabaseOpenOptions` dataclass — which is strictly better, because an
invented option name is now a `TypeError` at construction rather than something a
`**kwargs` fake swallows. Our subset test survives in two halves
(`_open_kwargs_are_real` for `open()`, `_option_fields_are_real` for the
dataclass fields), because the offline contract suite must keep running with no
`ida_nexus` installed at all and therefore still fakes both.

---

## Priority, from a client author's view

| # | item | impact | fixable by you? |
|---|---|---|---|
| ~~1~~ | ~~`timeout_trace` line tracing~~ | ~~52x on IDA calls~~ | ✅ fixed in 0.3.2 |
| ~~2~~ | ~~`to_jsonable` on large results~~ | ~~114x on serialisation~~ | ✅ fixed in 0.3.2 |
| ~~3~~ | ~~2 ms `execute_sync` floor~~ | ~~shapes client design~~ | ✅ fixed in 0.3.2, 7.0x |
| ~~7~~ | ~~no change/revision counter~~ | ~~correctness for shared editing~~ | ✅ fixed in protocol 6 |
| 4 | direct `.i64` forwards loader-only options | fatal worker startup | [issue #36](https://github.com/HexRaysSA/ida-nexus/issues/36) |
| ~~5~~ | ~~replaced/deleted IDB under lease~~ | ~~out-of-contract filesystem mutation~~ | **stale** |
| ~~6~~ | ~~no close without save~~ | ~~could not discard a managed session~~ | **fixed in protocol 6: final lease decides** |
| ~~8~~ | ~~package exports~~ | ~~forces internal imports~~ | ✅ fixed in 0.5.x |
| ~~9~~ | ~~typed handle for fakes~~ | ~~catches a whole bug class~~ | ✅ fixed in 0.5.x (`py.typed` + options dataclass) |

Items 1 and 2 together were the difference between "the port is 35x slower than
the private worker it replaced" and "the port is within 2x, and faster on several
operations". Both are in the runtime, not in client code — which is why they are
worth fixing centrally rather than leaving each client to rediscover.

**Both landed in 0.3.2**, along with item 3 — all three performance items are now
fixed upstream, and both client-side workarounds could be measured at parity and
retired. That is the outcome this document was written for.

**What is left is entirely non-performance.** Items 6 through 9 are fixed, and
item 5 is stale because out-of-band replacement is not a supported lifecycle for
either IDA Nexus or the IDA GUI. One narrow piece remains: **4**, normalize or
reject loader-only options when the source is itself an existing `.i64`
([issue #36](https://github.com/HexRaysSA/ida-nexus/issues/36)).

Happy to supply the benchmark harness (it is backend-agnostic and runs against
both our old worker and IDA Nexus), or to test a patch.
