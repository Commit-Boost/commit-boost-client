# cb-config-tui

Terminal UI for editing Commit Boost TOML configuration files.

## Usage

```bash
cb-config-tui edit <path-to-commit-boost.toml>
```

Launches a full-screen terminal editor with live validation, sidebar navigation, diagnostics, and search.

## Features

### Three-pane layout

| Pane       | Description |
|------------|-------------|
| **Sidebar** (left, 30 cols) | Parsed `[section]`/`[[array]]` headers. Navigate with ↑/↓, Enter jumps editor to that section. |
| **Editor** (center) | Full TOML editor with line numbers, cursor position, dirty marker. |
| **Diagnostics** (bottom) | Sync validation errors with line numbers. Shows ✓ Valid or ✗ N Errors. |

### Live validation

- **Sync validation** runs on every keystroke (200ms debounce). Checks TOML syntax, missing fields, type mismatches.
- **Async validation** runs on Ctrl+S save. Validates RPC chain ID, Docker image names, limits. Saves only if everything passes.
- Errors show source line numbers extracted from the TOML parser's byte span.
- Diagnostics panel highlights selected error; Enter jumps editor to that line.

### Editor

- Full text editing via `tui-textarea`: typing, arrows, backspace, delete, selection, cut/paste.
- **Ctrl+Z** undo, **Ctrl+Y** redo.
- **Ctrl+F** live incremental search:
  - Type search query — matches highlight, cursor jumps to first match.
  - Match counter shows `N matches`.
  - ↑/↓ cycles through matches.
  - **Esc** restores cursor and exits search, **Enter** exits search and stays at match.
- **Ctrl+R** reloads from disk (preserves cursor line).
- **Ctrl+E** opens file in `$EDITOR` (or `vi`), pauses TUI, reloads on editor exit.
- Dirty marker (●) when content differs from disk.

### Save & deploy

| Key | Action |
|-----|--------|
| **Ctrl+S** | Save to disk. Runs async validation first; saves only if valid. |
| **Ctrl+W** | Force-save. Writes to disk even when validation fails. Two-step: first Ctrl+W shows prompt, second confirms, Esc cancels. |

### Focus & navigation

| Key | Action |
|-----|--------|
| **Tab** | Cycle focus: Editor → Sidebar → Diagnostics → Editor |
| **↑/↓** | Navigate items in sidebar or diagnostics (depending on focus) |
| **Enter** | Jump editor to selected sidebar section or diagnostic error |

### Help

**Ctrl+H** shows a popup with all keybindings and validation notes. Esc dismisses.

### Quit

**Ctrl+Q** exits the editor.

## Architecture

```
cb-config-tui
├── app.rs        — App state machine, event handling, search logic
├── main.rs       — Terminal setup, event loop, key routing
├── ui.rs         — Ratatui rendering: layout, status bar, search bar, help
├── validation.rs — Sync TOML validation, span→line:col conversion
├── sidebar.rs    — Section header parsing for sidebar navigation
├── path_mapper.rs — serde error path mapping for flattened configs
└── lib.rs        — Module exports
```

### Key routing

Three-tier event dispatch:

1. **Global hotkeys** (Tab, Ctrl+Q/S/E/R/W/F/H, Esc) — always processed regardless of focus.
2. **Editor focus** — raw `KeyEvent` passed to `tui-textarea::TextArea::input()`. Intercepts Ctrl+Z/Y for undo/redo, Ctrl+F routes to search handler.
3. **Sidebar/Diagnostics focus** — ↑/↓/Enter converted to navigation events.

### Dependencies

- [`ratatui`](https://crates.io/crates/ratatui) — Terminal UI framework
- [`tui-textarea`](https://crates.io/crates/tui-textarea) — Text editor widget with search, undo/redo
- [`crossterm`](https://crates.io/crates/crossterm) — Terminal backend
- [`toml`](https://crates.io/crates/toml) — TOML parsing with span support
- [`serde_path_to_error`](https://crates.io/crates/serde_path_to_error) — Error path tracking
- [`regex`](https://crates.io/crates/regex) — Search pattern matching
- [`clap`](https://crates.io/crates/clap) — CLI argument parsing
- [`cb-common`](../common) — `CommitBoostConfig` types for validation
