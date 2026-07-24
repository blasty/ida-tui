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

ida-pro-mcp derives the per-line marker via
`cfunc.get_line_item(line, col=0, …).get_ea()`. To get the **full set**, sweep
every column of the line (`get_line_item(line, x, …).get_ea()` for `x` in
`0..len`) and collect distinct non-`BADADDR` EAs. Same proven API, swept across
the line. A custom `decomp_map(ea)` tool in `server/patch_server.py` returns
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

**Phase 2 — crude sync (MVP).** Wire both `cursor_moved` handlers using the
existing single-ea map + `_decomp_line_for`. Subtle linked-row highlight
(`_S_LINK`) + scroll-follow. Feels like Ghidra for most lines. No new tools.

**Phase 3 — rich highlight.** `decomp_map` custom tool (line → ea-set) stored on
`Decompilation`; highlight the whole instruction range of a C line; tighten the
reverse map. One custom tool + an idalib spike to confirm the sweep works.

**Phase 4 — polish.** Navigation keeps both panes on the same function; loop/goto
edge cases; decompile-failed fallback; min-width gate + resize; split state in
nav history; per-pane vs shared search.

## Open questions

- Entry-point key (proposed: `s` = split, plus the palette command). `Tab` in
  split = switch focused pane.
- Width policy: 50/50 to start; maybe listing-biased later. Min terminal width to
  allow split (à la the logo gate).
- Navigation-in-split: Phase 1 navigates the focused pane only; Phase 4 keeps both
  on the same function.
