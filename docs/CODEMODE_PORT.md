# ida-tui → IDA Code Mode port

This port is an experiment: can ida-tui be implemented as an ordinary client of
`ida_codemode`, sharing GUI databases and managed idalib workers instead of
owning a private worker and depending on ida-pro-mcp tool functions?

## Result

Yes for the database lifecycle and the complete current TUI feature set, with a
small number of operations implemented using IDAPython inside Code Mode's
`execute_python` sandbox because ida-domain does not yet expose the required
behavior.

The old components are gone:

- `idatui/worker.py` (private pickle/socket idalib process)
- `idatui/worker_client.py`
- `server/patch_server.py` (ida-pro-mcp tool injection)

The replacement is `idatui/codemode_client.py`.

## Lifecycle mapping

`CodeModeClient.connect()` calls `ida_codemode.client.DatabaseHandle.open()`.
Resolution is therefore Code Mode's resolution, not ida-tui's:

1. Match a registered GUI by executable path.
2. Otherwise match the owner of the expected IDB.
3. Otherwise serialize creation and start a managed `ida-codemode-worker`.
4. Establish an authenticated SSE lease.
5. Wait through the public autoanalysis route.

The handle's registry entry supplies the backend, PID, executable path, IDB path,
and record ID used by the status/pool layers.

Closing ida-tui closes only its lease. It never closes a GUI or kills an idalib
process. A managed worker saves and exits under Code Mode's own policy after its
last lease disappears. A second agent or TUI can keep using the same instance.

This also changes project pooling semantics. `DatabasePool` is an LRU pool of
leases, not process ownership. Managed-IDB save-on-evict remains; budget eviction
does not implicitly save a GUI. Eviction cannot force a shared worker to exit,
and GUI process memory is only advisory.

## ida-domain coverage

The remote snippets receive Code Mode's preloaded `db` (`ida_domain.Database`).
The following TUI needs map to public ida-domain entities:

| TUI need | ida-domain surface |
|---|---|
| Function paging, lookup, names, sizes | `db.functions` |
| Segments and names | `db.segments` |
| Instructions and plain disassembly | `db.instructions`, `db.functions.get_instructions()` |
| Heads and item classification | `db.heads`, `db.bytes` |
| Bytes and strings | `db.bytes`, `db.strings` |
| Symbol resolution and rename | `db.names`, `db.functions` |
| Comments | `db.comments` |
| Imports and exports | `db.imports`, `db.entries` |
| Xrefs and fine type predicates | `db.xrefs` / `XrefInfo` |
| Named types, members, parse/apply | `db.types` |
| Function prototypes and local variables | `db.pseudocode`, `PseudocodeFunction.local_variables` |
| Decompilation text and object references | `db.pseudocode` |

All values are reduced to JSON primitives inside the database process. No SWIG
or ida-domain object crosses the Code Mode boundary.

## Remaining IDAPython gaps

Code Mode intentionally allows regular Python imports, so these features still
work, but they identify useful additions to ida-domain:

1. **Rich continuous listing**
   - ida-domain enumerates defined heads and renders plain disassembly.
   - ida-tui also needs coalesced undefined runs, IDA colour-tag spans, function
     banners, code-label rows, file-region offsets, and expanded struct members.
   - The `heads` operation uses `ida_bytes`, `ida_lines`, and related modules for
     this presentation model.

2. **Instruction/function carving**
   - Creating an instruction and walking a speculative decode run requires
     `ida_ua.create_insn` and processor flow/return checks.
   - Function creation exists in ida-domain; the explicit-end fallback still
     needs lower-level item boundaries.

3. **ARM/Thumb state**
   - T-register ranges and segment addressing use `ida_segregs`, `ida_idp`, and
     `ida_segment`. There is no equivalent ida-domain operation.

4. **Detailed decompiler diagnostics and line maps**
   - Pseudocode text, ctree objects, and the address map are available through
     ida-domain.
   - Reproducing IDA's per-rendered-line coverage uses
     `cfunc.get_line_item`; obtaining the exact Hex-Rays failure description
     uses `hexrays_failure_t`.

5. **A few type/item primitives**
   - Deleting a named local type and some exact item-undefinition/data-creation
     behavior still use `ida_typeinf`/`ida_bytes` directly.

These uses are isolated in `idatui/codemode_client.py`; the paging and Textual
layers do not import IDAPython.

## API limitations exposed by the port

### No rollback or close-without-save

A Code Mode lease has no rollback operation. Closing a GUI handle leaves the GUI
state as-is. A managed idalib worker currently saves when its final lease closes.
Consequently ida-tui's old “discard & quit” guarantee cannot be implemented.
The UI now labels this choice “leave as-is & quit” and does not explicitly save,
but managed-worker policy may still persist the changes.

A true discard action would need a Code Mode/database API for transaction-like
rollback, a close policy on a newly-owned worker, or a TUI-managed disposable DB
copy.

### Typed loader options only

`DatabaseHandle.open()` supports processor, natural loading address, file type,
output database, and fresh-database selection. It does not support ida-tui's
arbitrary `ida_args` escape hatch. The adapter rejects unsupported switches
rather than silently loading at the wrong architecture/base.

### No database-change notification stream

The lease reports liveness, not mutations. If a GUI user or another Code Mode
client renames/retypes content while ida-tui is open, already-materialized TUI
caches are not invalidated automatically. TUI-originated edits invalidate their
own caches correctly. A database revision counter or change feed would make
shared interactive editing robust.

### Discovery requires a path for ambiguity

`ida-tui` with no path attaches automatically when exactly one database is
registered. With several registrations it lists them and requires an explicit
executable/IDB path. There is not yet a pre-connection database picker in the
Textual UI.

### `DatabaseHandle` import stability

The usable library primitive currently lives at
`ida_codemode.client.DatabaseHandle`; `ida_codemode.__init__` exports nothing.
The port therefore depends on a submodule path. Exporting the handle and public
client exceptions from the package root would make the supported library API
clearer.

## Safety differences

ida-tui no longer removes `.id0/.id1/.id2/.nam/.til` files before opening. That
was only defensible when the TUI exclusively owned a private process; it is
unsafe when a GUI or another client may own the database. Code Mode registry
locks, health probes, and IDA itself now arbitrate ownership.

The old pane “reap private workers” behavior is obsolete. A TUI crash closes its
lease at the socket/kernel boundary; Code Mode decides whether a managed worker
still has clients and when it should stop.

## Verification surfaces

The non-IDA suite verifies project staging, LRU lease behavior, load-option
translation, and adapter response/error normalization. The existing live suites
remain the end-to-end contract:

```sh
uv run python tests/test_codemode_client.py
uv run python tests/test_pool.py
uv run python tests/test_project.py
uv run python tests/test_scenarios.py /path/to/binary
```

For GUI reuse, open the same binary in an IDA with the Code Mode plugin, confirm
it appears in `ida_codemode.registry.discover_instances()`, then launch
`ida-tui /path/to/binary`. The TUI status/`CodeModeClient.backend` should report
`gui`, and closing the TUI must leave IDA open.
