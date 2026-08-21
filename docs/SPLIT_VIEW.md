# Split view — Ghidra-style synced listing ⇄ pseudocode

Goal: show the unified **listing** (left) and the **pseudocode** (right) side by
side, kept in **cursor sync**. Move the cursor in the C view and the covering
instructions light up (and scroll into view) on the asm side; move in the asm and
the owning C line lights up. Both panes track the same function and navigate
together.

## Why this is tractable (existing substrate)

- **Layout is free.** `ListingView`, `DecompView`, `HexView` are already siblings
  in the one `#panes` `Horizontal`. Today `_show_active()` just flips `display` so
  a single code view shows at a time. Split = show listing **and** decomp together
  (each `width: 1fr`).
- **Per-line address already exists.** `DecompView._line_eas[line]` holds each C
  line's `/*0xEA*/` marker (Hex-Rays' primary ea for that line). Crude sync needs
  no new tooling.
- **Reverse jump already exists.** `_decomp_line_for(fn, ea)` maps an instruction
  address → the best pseudocode line (largest marker ≤ ea).
- **Sync hook points exist.** `on_decomp_view_cursor_moved` /
  `on_listing_view_cursor_moved` fire on every cursor move.
- **Highlight overlays are a known pattern.** `render_line` already overlays
  styles (word-under-cursor, search matches); a "linked region" background is one
  more overlay.

## The one hard part: line ↔ instruction mapping

Ghidra highlights **all** instructions a C line owns. We have one ea per line
(the marker), not the set. Getting the set is the only real work, and it's a
known technique:

The old ida-pro-mcp backend derived the per-line marker via
`cfunc.get_line_item(line, col=0, …).get_ea()`. To get the **full set**, sweep
every column of the line (`get_line_item(line, x, …).get_ea()` for `x` in
`0..len`) and collect distinct non-`BADADDR` EAs. The IDA Nexus adapter's
`decomp_map(ea)` operation returns
`[{line, primary_ea, eas:[…]}, …]`; invert for `ea → line`.

## State model

- `self._split: bool` — split mode on/off.
- While split: both panes displayed; `_active` names the **focused** pane
  (`"listing"` or `"decomp"`); the other is the companion.
- `_show_active()` gains a split branch: display listing + decomp, hide hex.
- Entering split loads both panes for the current function; exiting collapses to
  the focused pane.

## Sync model (Phase 2/3)

- **decomp cursor moves** → look up the C line's ea(s) → highlight those rows in
  the listing + scroll the primary ea into view.
- **listing cursor moves** → `_decomp_line_for` (or the inverted rich map) → move
  the decomp cursor to the owning line + highlight it.
- A guard flag (`_syncing`) prevents the two `cursor_moved` handlers from
  ping-ponging each other.
- Highlight: a subtle background style (`_S_LINK`) overlaid on the linked rows;
  the *focused* line keeps the normal block cursor.

## Rendering the highlight

`ListingView.render_line`: if a row's ea ∈ `self._link_eas` (a set the app sets on
sync), overlay `_S_LINK` on that row (below the block cursor / word overlays).
`DecompView`: mark `self._link_line` and tint that row.

## Phased roadmap

**Phase 1 — split layout, no sync.** `_split` mode; show both panes at `1fr` with
a divider; focus one; a toggle (key + palette command "Toggle split view").
Entering split loads listing + decomp for the current function; exiting returns to
the focused pane. `Tab` in split switches the focused pane (single-view `Tab`
still toggles disasm/pseudocode). No new tools. *← this doc's current target.*

**Phase 2 — crude sync (MVP). DONE.** Both `cursor_moved` handlers wired via
`_sync_split`: the focused pane drives; the companion gets a subtle `_S_LINK`
band + scroll-into-view (its cursor never moves, so there's no echo — no guard
needed). listing→decomp uses `DecompView.line_for_ea` (largest marker ≤ ea);
decomp→listing uses `ListingModel.ensure_ea`. Tab re-links from the new driver.
Still single-ea per line (one instruction highlighted); the region comes in
phase 3.

**Phase 3 — rich highlight. DONE.** The IDA Nexus `decomp_map` operation
(`idatui/nexus_client.py`) sweeps `cfunc.get_line_item` across every column of
each pseudocode line and collects the EAs from each item's `dstr()` (`'EA: desc'`
— the same source as the `/*ea*/` marker, so it aligns). `Program.decomp_map(ea)`
returns the per-line ea lists (cached by name-gen); the app loads it async into
`_split_eamap` / `_split_ea2line` and `_sync_split` bands the **whole** instruction
region of a C line (and uses the exact ea→line inverse for the reverse). Falls
back to the single marker until the map lands. Verified on a real IDA Nexus database
(alignment + multi-instruction region band).

**Phase 4 — polish. DONE.**
- Split-aware status: `_split_status()` shows `name @ ea [split · pseudocode line
  N ↔ K insn]` / `[split · listing]` instead of the single-view labels.
- Min-width gate: `action_toggle_split` refuses to enter split below
  `_SPLIT_MIN_WIDTH` (100 cols) — two usable panes need the room.
- Navigation keeps both panes on the same function: verified — a goto/follow in
  split routes through `_open_entry` (listing) → `_show_active` split branch
  (decomp + `_load_split_map`), so both panes reload for the new function and
  split stays on.
- Cross-function follow: the unified listing spans many functions, so when the
  listing cursor leaves the decompiled function's ea span (`_split_range`),
  `_sync_split` re-points the decomp pane to the function under the cursor
  (`_resync_decomp` → `function_of` → re-decompile + reload the map). Over
  data/undefined it just drops the band and keeps the last function.
- Non-issues after review: split is a persistent *mode* orthogonal to nav
  entries, so back/forward simply navigate within split (no per-entry state
  needed); search is already per-focused-pane.

## Open questions

- Entry-point key (proposed: `s` = split, plus the palette command). `Tab` in
  split = switch focused pane.
- Width policy: 50/50 to start; maybe listing-biased later. Min terminal width to
  allow split (à la the logo gate).
- Navigation-in-split: Phase 1 navigates the focused pane only; Phase 4 keeps both
  on the same function.
