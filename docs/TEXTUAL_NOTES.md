# Textual notes & app patterns

Hard-won Textual behaviour and the patterns this app relies on. Pairs with
`PAGING_FINDINGS.md` (the idalib side).

## Textual pitfalls

- **`BINDINGS` only merge from `DOMNode` subclasses.** A plain mixin's `BINDINGS`
  are silently ignored — each view lists them explicitly (e.g.
  `*SearchMixin.SEARCH_BINDINGS`, `*ColumnCursor.COL_BINDINGS`).
- **`ScrollView` + `render_line`**: `y` is the SCREEN line; we add
  `scroll_offset.y` ourselves. `ScrollView.watch_scroll_y` only repaints when the
  **rounded** scroll value changes.
- **`scroll_to` right after setting `virtual_size` clamps to 0** — `max_scroll_y`
  isn't recomputed until layout. Apply the scroll now AND again via
  `call_after_refresh` with `refresh(layout=True)`; don't zero `virtual_size` on
  load (snaps scroll to 0 → visible flash). See `ColumnCursor._apply_scroll`,
  `ListingView._on_primed`, `DecompView.show`.
- **Scrolling on already-laid-out content (no reload) leaves a stale frame.** A
  plain `scroll_to` moves `scroll_offset` but Textual only repaints on a
  *rounded* scroll change, and with no virtual_size/content change there's no
  layout pass to force a paint — so the pane shows the old frame until the next
  interaction (moving the cursor auto-corrects it). Route these through
  `_apply_scroll` too (immediate scroll + deferred `refresh(layout=True)`). Bit
  us on same-function decompiler jumps (`DecompView.goto`); the reload path
  (`DecompView.show`) hides it because clearing the loading cover repaints.
- **Pilot lays out synchronously**, so programmatic scroll always has a valid
  range in tests — it MASKS the real-terminal clamp/no-repaint bug. Assert the
  **render** (trace `render_line`'s scroll at paint), not just `scroll_offset.y`.
  (`test_tui.py`: "pane is repainted at the restored scroll".) Note even a render
  trace can't catch the `goto` stale-frame case (no layout pass to observe) — it
  only shows in a real terminal.
- **`widget.loading = True`** covers the widget via `_cover_widget` (NOT a normal
  child — `query()` won't find it; check `widget._cover_widget`) and **blurs
  focus** (focus → None), so `Tab` falls back to focus-navigation. Fix: make the
  app `Tab`/`Shift+Tab` binding `priority=True`; restore focus when loading ends.
- **Mouse**: `event.get_content_offset(widget)` → offset past padding/border; add
  `scroll_offset` for the virtual (line, col). `event.chain >= 2` = double-click.
  Subtract any left gutter (`ColumnCursor._col_offset`).
- **Cheap repaints**: `refresh(Region(0, row, w, 1))` for just the changed rows;
  `reactive(x, repaint=False)` to avoid an implicit full refresh on assignment.
- **`Input`** defaults to a 3-row bordered widget. For a 1-row prompt use
  `border: none`, and do NOT `dock: bottom` it next to the `Footer` — they land on
  the same row and the Footer paints over it. Keep prompts in normal flow above
  the Footer (see `#search`/`#rename`/`#status`).
- Textual ships **no C/C++ tree-sitter grammar** — `TextArea(language="cpp")` is a
  silent no-op. We highlight pseudocode with Pygments (`idatui/highlight.py`).
  For the **editable** C in the struct editor, `highlight.CTextArea` overrides
  `TextArea._build_highlight_map()` and fills the widget's own `_highlights`
  map from the same lexer — the hook the tree-sitter path would fill, so the
  line cache, selection and cursor stay stock. Two traps: those spans are
  **byte** offsets into the line (the renderer decodes them with
  `build_byte_to_codepoint_dict`, so character offsets smear on non-ASCII), and
  a `TextAreaTheme` that sets `base_style` overrides the widget's CSS colours —
  ours sets only `syntax_styles` so the editor keeps the app's background.
- **A modal's `Input` messages bubble to the App.** `SymbolPalette` (the Ctrl+N
  fuzzy finder) has its own `Input`; its `Input.Changed`/`Input.Submitted` bubble
  up to the app's handlers (which would run the `#search`/`#func-filter` logic and
  even hide the palette's input). Call `event.stop()` in the modal's handlers.
  A single-line `Input` doesn't bind `up`/`down`, so those bubble to the modal's
  BINDINGS (used to move the result list while the input keeps focus); `enter`
  is consumed by the Input → handle it via `on_input_submitted`.

## App patterns

- **Name-generation invalidation** (`Program._name_gen` / `bump_names`): a rename
  bumps the gen; disasm block caches are cleared (disasm names are live in the
  IDB), and `decompile` is gen-checked and `force_recompile`d lazily on mismatch.
  `force_recompile` needs `items=[{addr}]`, not `addr`.
- **Cursor + scroll history**: `NavEntry` stores `cursor/cursor_x/scroll_y`
  (disasm) and `dec_cursor/dec_cursor_x/dec_scroll_y/dec_scroll_x` (pseudocode).
  `_save_current_pos()` snapshots both views right before a push; restore on
  `_open_entry` / `DecompView.show`.
- **Follow**: name-based (decompiler refs → `resolve`) THEN an **address-based
  fallback** (parse the line's `/*0xEA*/` marker → `xrefs_from` → first code
  target). The address path is immune to a stale token right after a rename.
- Views only ever render a viewport-sized slice; scale lives in the domain
  cache/paging layer, never in a widget.

## Testing gotchas

- `goto` to a non-existent function name is a no-op → "jump back" tests then pass
  trivially. Navigate to a REAL second function.
- Scroll-restore tests with the cursor at the viewport top (`rel = 0`) are
  degenerate (scroll-into-view derives the same scroll). Use a mid-viewport
  cursor (`rel > 0`).
- Cold session ⇒ slow first analysis ⇒ `wait_until` timeouts ⇒ flaky "want 0"
  failures. Re-run on a warm session before trusting a regression.
- Edits mutate the `.i64` — revert renames (via API) for idempotency; use a
  PID-unique temp name to dodge collisions from a prior crashed run.


## A priority app binding fires even under a modal

`Binding("tab,shift+tab", "toggle_view", priority=True)` on the App runs before
the focus chain, so Tab never reached ANY dialog — nothing in a modal could be
tabbed to, in this app, ever. It looked like a bug in one dialog (the load
options address field was unreachable) and was actually app-wide.

The fix is in the action, not the binding: if a modal is up, hand the key back.

```python
def action_toggle_view(self):
    if self.screen is not self.screen_stack[0]:
        self.screen.focus_next()
        return
```

Related: DOM order is rarely the tab order you want. In a dialog with a filter
box, an option list and a second field, `focus_next()` stops at the list — which
is arrow-driven and has nothing to type — so text meant for the second field
lands in the filter. Override `focus_next`/`focus_previous` on the screen to
cycle the fields people actually type into.

## A modal can outgrow the terminal and clip its own controls

`#pal-list { max-height: 24 }` plus a 21-row list pushed the address field and
help line off the bottom of the screen. Nothing errors; the field is simply not
there, which reads to the user as "Tab does nothing". Cap the scrollable part
per-dialog so the controls below it are always visible.
