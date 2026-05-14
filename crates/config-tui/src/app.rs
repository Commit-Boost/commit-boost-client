use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Style};
use tui_textarea::TextArea;

use crate::{
    sidebar::{self, TomlSection},
    validation::{self, ValidationState},
};

/// Which pane has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Focus {
    Editor,
    Sidebar,
    Diagnostics,
}

/// Simplified keyboard event for global app actions.
/// Editor keys are routed directly to tui-textarea via `input_editor_key`.
#[derive(Debug, Clone, PartialEq)]
pub enum AppEvent {
    Tab,
    CtrlQ,
    CtrlS,
    CtrlF,
    CtrlE,
    CtrlR,
    CtrlW,
    Enter,
    Up,
    Down,
    Esc,
    CtrlH,
}

enum ForceSaveState {
    None,
    Prompt,
    Confirmed,
}

/// Core application state. Pure data — no terminal interaction.
pub struct App {
    /// Path to the config file being edited
    pub file_path: PathBuf,
    /// Text editor widget
    pub editor: TextArea<'static>,
    /// Original content loaded from disk (for dirty tracking)
    pub original: String,
    /// Parsed TOML section headers for sidebar navigation
    pub sections: Vec<TomlSection>,
    /// Which pane has focus
    pub focus: Focus,
    /// Whether content has been modified since last save
    pub dirty: bool,
    /// Signal to exit the event loop
    pub should_quit: bool,
    /// Index of the currently selected section in the sidebar (if any)
    pub selected_section: Option<usize>,
    /// Current sync validation state
    pub validation: ValidationState,
    /// Selected diagnostic index in diagnostics panel (None when no errors)
    pub selected_diagnostic: Option<usize>,
    /// Set to true when the user presses Ctrl+S (triggers async save flow)
    pub save_requested: bool,
    /// True while async save is in progress
    pub save_in_progress: bool,
    /// Error message from last save attempt (None = success)
    pub save_error: Option<String>,
    /// Set to true when the user presses Ctrl+E (external editor)
    pub edit_requested: bool,
    /// Set to true when the user presses Ctrl+R (reload from disk)
    pub reload_requested: bool,
    /// Search mode active (Ctrl+F toggles)
    pub searching: bool,
    /// Current search query text
    pub search_query: String,
    /// Cursor position saved before search started
    pub saved_cursor: (usize, usize),
    /// Current force-save state machine
    force_save_state: ForceSaveState,
    /// Whether the help popup is visible (Ctrl+H toggles)
    pub help_visible: bool,
}

impl App {
    /// Create a new App from a file path and its content.
    pub fn new(file_path: PathBuf, content: String) -> Self {
        let sections = sidebar::parse_sections(&content);
        let lines: Vec<String> = content.lines().map(String::from).collect();
        let mut editor = TextArea::from(lines);
        editor.set_line_number_style(Style::default().fg(Color::DarkGray));
        Self {
            file_path,
            editor,
            original: content,
            sections,
            focus: Focus::Editor,
            dirty: false,
            should_quit: false,
            selected_section: None,
            validation: ValidationState::Pending,
            selected_diagnostic: None,
            save_requested: false,
            save_in_progress: false,
            save_error: None,
            edit_requested: false,
            reload_requested: false,
            searching: false,
            search_query: String::new(),
            saved_cursor: (0, 0),
            force_save_state: ForceSaveState::None,
            help_visible: false,
        }
    }

    /// Get current editor content as a string.
    pub fn current_content(&self) -> String {
        self.editor.lines().join("\n")
    }

    /// Re-run sync validation against current editor content.
    pub fn revalidate(&mut self) {
        let content = self.current_content();
        self.validation = validation::validate_sync(&content);
        self.selected_diagnostic = match &self.validation {
            ValidationState::Invalid(diags) if !diags.is_empty() => Some(0),
            _ => None,
        };
    }

    /// Whether a save can be attempted: sync validation must pass,
    /// and no save may already be in progress.
    pub fn can_save(&self) -> bool {
        self.validation == ValidationState::Valid && !self.save_in_progress
    }

    /// Whether the force-save confirmation prompt is showing.
    pub fn showing_force_save_prompt(&self) -> bool {
        matches!(self.force_save_state, ForceSaveState::Prompt)
    }

    /// Whether the user has confirmed the force-save.
    /// Returns true once, then resets to avoid double-execution.
    pub fn should_execute_force_save(&mut self) -> bool {
        if matches!(self.force_save_state, ForceSaveState::Confirmed) {
            self.force_save_state = ForceSaveState::None;
            true
        } else {
            false
        }
    }

    /// Write current editor content to disk.
    pub fn save_to_disk(&mut self) -> Result<(), String> {
        let content = self.current_content();
        std::fs::write(&self.file_path, &content)
            .map_err(|e| format!("Failed to write {}: {}", self.file_path.display(), e))?;
        self.original = content;
        self.dirty = false;
        self.save_error = None;
        Ok(())
    }

    /// Replace editor content from a string, preserving cursor line position.
    /// Clamps cursor to new content bounds if content shrinks.
    /// Used by reload_from_disk and external editor (Ctrl+E).
    pub fn replace_editor_content(&mut self, content: &str) {
        let cursor_row = self.editor.cursor().0;
        let lines: Vec<String> = content.lines().map(String::from).collect();
        let new_line_count = lines.len();
        self.editor = TextArea::from(lines);
        self.editor.set_line_number_style(Style::default().fg(Color::DarkGray));
        // Restore cursor row, clamped to new content bounds
        if new_line_count > 0 {
            let target_row = cursor_row.min(new_line_count.saturating_sub(1));
            use tui_textarea::CursorMove;
            for _ in 0..target_row {
                self.editor.move_cursor(CursorMove::Down);
            }
        }
        self.original = content.to_string();
        self.dirty = false;
        self.save_error = None;
    }

    /// Reload file content from disk, discarding current edits.
    pub fn reload_from_disk(&mut self) -> Result<(), String> {
        let content = std::fs::read_to_string(&self.file_path)
            .map_err(|e| format!("Failed to read {}: {}", self.file_path.display(), e))?;
        self.replace_editor_content(&content);
        self.revalidate();
        Ok(())
    }

    /// Return temporary file path for $EDITOR escape hatch.
    pub fn temp_edit_path(&self) -> PathBuf {
        let mut p = self.file_path.clone();
        p.set_extension("toml.edit");
        p
    }

    /// Process an application event and update state.
    /// Only handles global events (hotkeys, focus changes).
    /// For editor text input, use `input_editor_key` instead.
    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Tab => {
                self.focus = match self.focus {
                    Focus::Editor => Focus::Sidebar,
                    Focus::Sidebar => Focus::Diagnostics,
                    Focus::Diagnostics => Focus::Editor,
                };
            }
            AppEvent::CtrlQ => {
                self.should_quit = true;
            }
            AppEvent::CtrlS => {
                if self.can_save() {
                    self.save_requested = true;
                }
            }
            AppEvent::CtrlF => {
                if self.focus == Focus::Editor && !self.searching {
                    self.start_search();
                }
            }
            AppEvent::CtrlH => {
                self.help_visible = true;
            }
            AppEvent::CtrlE => {
                self.edit_requested = true;
            }
            AppEvent::CtrlR => {
                self.reload_requested = true;
            }
            AppEvent::CtrlW => {
                self.force_save_state = match self.force_save_state {
                    ForceSaveState::None if !self.dirty => ForceSaveState::None,
                    ForceSaveState::None => ForceSaveState::Prompt,
                    ForceSaveState::Prompt => {
                        // Confirmed — do the force save
                        self.force_save_state = ForceSaveState::Confirmed;
                        ForceSaveState::Confirmed
                    }
                    ForceSaveState::Confirmed => ForceSaveState::Confirmed,
                };
            }
            AppEvent::Esc => {
                if self.help_visible {
                    self.help_visible = false;
                } else {
                    self.force_save_state = ForceSaveState::None;
                }
            }
            AppEvent::Up | AppEvent::Down | AppEvent::Enter => {
                if self.searching {
                    match event {
                        AppEvent::Enter => self.finish_search(),
                        AppEvent::Up => self.search_prev_match(),
                        AppEvent::Down => self.search_next_match(),
                        _ => {}
                    }
                } else {
                    self.handle_diagnostics_nav(&event);
                }
            }
        }
    }

    /// Handle navigation events (Up/Down/Enter) when diagnostics panel has
    /// focus.
    fn handle_diagnostics_nav(&mut self, event: &AppEvent) {
        if self.focus != Focus::Diagnostics {
            return;
        }
        let err_count = match &self.validation {
            ValidationState::Invalid(diags) => diags.len(),
            _ => return,
        };
        if err_count == 0 {
            return;
        }
        match event {
            AppEvent::Up => {
                self.selected_diagnostic = Some(match self.selected_diagnostic {
                    Some(i) if i > 0 => i - 1,
                    _ => 0,
                });
            }
            AppEvent::Down => {
                let max = err_count.saturating_sub(1);
                self.selected_diagnostic = Some(match self.selected_diagnostic {
                    Some(i) if i < max => i + 1,
                    _ => max,
                });
            }
            AppEvent::Enter => {
                if let Some(idx) = self.selected_diagnostic &&
                    let ValidationState::Invalid(ref diags) = self.validation &&
                    let Some(diag) = diags.get(idx) &&
                    let Some(line) = diag.line
                {
                    // Jump editor cursor to the error line
                    let target_row = line.saturating_sub(1);
                    // Move cursor to top, then down to target row
                    use tui_textarea::CursorMove;
                    self.editor.move_cursor(CursorMove::Top);
                    for _ in 0..target_row {
                        self.editor.move_cursor(CursorMove::Down);
                    }
                }
                self.focus = Focus::Editor;
            }
            _ => {}
        }
    }

    /// Pass a raw crossterm key event to the tui-textarea editor.
    /// Returns true if the key was consumed by the editor.
    /// Updates the dirty flag after successful input.
    /// Handles arrow keys, backspace, delete, typing, and all other
    /// editing operations that tui-textarea supports.
    /// Also triggers revalidation when content returns to original (dirty →
    /// clean). Intercepts Ctrl+Z (undo) and Ctrl+Y (redo) before passing to
    /// editor.input().
    pub fn input_editor_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = KeyModifiers::CONTROL;
        // Intercept Ctrl+Z (undo) and Ctrl+Y (redo) — tui-textarea uses emacs bindings
        if key.code == KeyCode::Char('z') && key.modifiers.contains(ctrl) {
            let consumed = self.editor.undo();
            if consumed {
                let was_dirty = self.dirty;
                self.update_dirty();
                if was_dirty && !self.dirty {
                    self.revalidate();
                }
            }
            return consumed;
        }
        if key.code == KeyCode::Char('y') && key.modifiers.contains(ctrl) {
            let consumed = self.editor.redo();
            if consumed {
                self.update_dirty();
            }
            return consumed;
        }

        let consumed = self.editor.input(key);
        if consumed {
            let was_dirty = self.dirty;
            self.update_dirty();
            if was_dirty && !self.dirty {
                // Content returned to original — clear any stale validation state
                self.revalidate();
            }
        }
        consumed
    }

    /// Enter search mode. Saves cursor position and clears search query.
    pub fn start_search(&mut self) {
        self.saved_cursor = self.editor.cursor();
        self.searching = true;
        self.search_query.clear();
    }

    /// Exit search mode. Clears search pattern and restores saved cursor.
    pub fn cancel_search(&mut self) {
        // Clear search pattern (ignore errors — empty string is always valid)
        let _ = self.editor.set_search_pattern("");
        self.editor.move_cursor(tui_textarea::CursorMove::Jump(
            self.saved_cursor.0 as u16,
            self.saved_cursor.1 as u16,
        ));
        self.searching = false;
        self.search_query.clear();
    }

    /// Apply current search query to the editor. Sets regex pattern and jumps
    /// to first match. Returns Ok(match_count) or Err if regex is invalid.
    fn apply_search(&mut self) -> Result<usize, regex::Error> {
        if self.search_query.is_empty() {
            let _ = self.editor.set_search_pattern("");
            // Restore saved cursor when query is empty
            self.editor.move_cursor(tui_textarea::CursorMove::Jump(
                self.saved_cursor.0 as u16,
                self.saved_cursor.1 as u16,
            ));
            return Ok(0);
        }
        self.editor.set_search_pattern(&self.search_query)?;
        // Jump to first match
        // First go to start, then search forward ignoring cursor
        self.editor.move_cursor(tui_textarea::CursorMove::Jump(0, 0));
        self.editor.search_forward(false);
        // Count matches
        let content = self.current_content();
        let re = self.editor.search_pattern().unwrap();
        let count = re.find_iter(&content).count();
        Ok(count)
    }

    /// Append a character to the search query and apply.
    pub fn handle_search_char(&mut self, c: char) -> Result<usize, regex::Error> {
        self.search_query.push(c);
        self.apply_search()
    }

    /// Remove the last character from the search query and apply.
    pub fn handle_search_backspace(&mut self) -> Result<usize, regex::Error> {
        self.search_query.pop();
        self.apply_search()
    }

    /// Move to the next search match.
    pub fn search_next_match(&mut self) {
        if !self.search_query.is_empty() {
            self.editor.search_forward(false);
        }
    }

    /// Move to the previous search match.
    pub fn search_prev_match(&mut self) {
        if !self.search_query.is_empty() {
            self.editor.search_back(false);
        }
    }

    /// Finish search mode (Enter). Clears search bar but keeps cursor at
    /// current position.
    pub fn finish_search(&mut self) {
        let _ = self.editor.set_search_pattern("");
        self.searching = false;
        self.search_query.clear();
    }

    /// Handle a raw key event while in search mode.
    pub fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => {
                let _ = self.handle_search_char(c);
            }
            KeyCode::Backspace => {
                let _ = self.handle_search_backspace();
            }
            KeyCode::Esc => {
                self.cancel_search();
            }
            KeyCode::Enter => {
                self.finish_search();
            }
            KeyCode::Up => {
                self.search_prev_match();
            }
            KeyCode::Down => {
                self.search_next_match();
            }
            _ => {} // ignore other keys in search mode
        }
    }

    /// Clear the force-save prompt (e.g. on Esc or after confirming).
    pub fn clear_force_save_prompt(&mut self) {
        self.force_save_state = ForceSaveState::None;
    }

    /// Execute the confirmed force-save.
    pub fn execute_force_save(&mut self) -> Result<(), String> {
        self.save_to_disk()
    }

    /// Update dirty flag by comparing editor content to original.
    fn update_dirty(&mut self) {
        let current = self.current_content();
        let orig = self.original.trim_end();
        self.dirty = current != orig;
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyModifiers};

    use super::*;

    /// Helper to create a KeyEvent for testing.
    fn test_key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn test_key_code(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn test_content() -> String {
        r#"
chain = "Holesky"

[pbs]
host = "127.0.0.1"

[[relays]]
url = "http://example.com"

[metrics]
enabled = true
"#
        .to_string()
    }

    #[test]
    fn test_app_initializes_with_content_and_sections() {
        let content = test_content();
        let app = App::new(PathBuf::from("test.toml"), content.clone());
        assert_eq!(app.file_path.to_str(), Some("test.toml"));
        assert!(!app.dirty);
        assert!(!app.should_quit);
        assert_eq!(app.focus, Focus::Editor);
        assert_eq!(app.sections.len(), 3);
        assert_eq!(app.validation, ValidationState::Pending);
    }

    #[test]
    fn test_validation_starts_pending() {
        let app = App::new(PathBuf::from("test.toml"), test_content());
        assert_eq!(app.validation, ValidationState::Pending);
    }

    #[test]
    fn test_revalidate_sets_validation_state() {
        let content = "chain = \"Holesky\"\n\n[pbs]\n";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        assert_eq!(app.validation, ValidationState::Pending);
        app.revalidate();
        assert_eq!(app.validation, ValidationState::Valid);
    }

    #[test]
    fn test_ctrl_e_sets_edit_requested() {
        let mut app = App::new(PathBuf::from("test.toml"), test_content());
        assert!(!app.edit_requested);
        app.handle_event(AppEvent::CtrlE);
        assert!(app.edit_requested);
    }

    #[test]
    fn test_revalidates_when_content_returns_to_original_after_error() {
        // Valid content: has chain + [pbs]
        let content = "chain = \"Holesky\"\n\n[pbs]\n";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.revalidate();
        assert_eq!(app.validation, ValidationState::Valid);
        assert!(!app.dirty);

        // Move to end of file, type 'x' to make it dirty + invalid
        // Content: "chain = \"Holesky\"\n\n[pbs]\n" has 4 lines (0-3)
        for _ in 0..3 {
            app.input_editor_key(test_key_code(KeyCode::Down));
        }
        // Now on last (empty) line. Type 'x'
        app.input_editor_key(test_key('x'));
        assert!(app.dirty);
        app.revalidate();
        // Content is now: ...\n[pbs]\nx — invalid TOML (trailing 'x')
        assert!(
            matches!(app.validation, ValidationState::Invalid(_)),
            "should be invalid after adding trailing x"
        );

        // Delete back to original
        app.input_editor_key(test_key_code(KeyCode::Backspace));
        // Content should match original (note: TextArea::lines() strips trailing
        // newline, but update_dirty uses original.trim_end() which also strips
        // it)
        assert!(!app.dirty, "dirty should be false after return to original");
        // After fix: revalidate should have fired, clearing Invalid -> Valid
        assert_eq!(
            app.validation,
            ValidationState::Valid,
            "validation should be Valid after returning to original content"
        );
    }

    #[test]
    fn test_selected_diagnostic_none_when_no_errors() {
        let content = "chain = \"Holesky\"\n\n[pbs]\n";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        assert_eq!(app.selected_diagnostic, None);
        app.revalidate();
        assert_eq!(app.selected_diagnostic, None, "no errors => selected_diagnostic None");
    }

    #[test]
    fn test_selected_diagnostic_some_zero_when_errors_exist() {
        // Missing [pbs] section produces an error
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.revalidate();
        assert_eq!(app.selected_diagnostic, Some(0), "first error should be selected");
    }

    #[test]
    fn test_selected_diagnostic_clears_on_valid_revalidate() {
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.revalidate();
        assert_eq!(app.selected_diagnostic, Some(0));
        // Fix the config
        app.replace_editor_content("chain = \"Holesky\"\n\n[pbs]\n");
        app.revalidate();
        assert_eq!(app.selected_diagnostic, None);
    }

    #[test]
    fn test_diagnostics_up_clamped_at_zero() {
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.revalidate();
        app.selected_diagnostic = Some(0);
        app.focus = Focus::Diagnostics;
        app.handle_event(AppEvent::Up);
        // Up from position 0 should stay at 0 (clamped)
        assert_eq!(app.selected_diagnostic, Some(0));
    }

    #[test]
    fn test_diagnostics_down_capped_at_last() {
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.revalidate();
        let err_count = match &app.validation {
            ValidationState::Invalid(d) => d.len(),
            _ => 0,
        };
        assert!(err_count > 0);
        // Set to last error
        app.selected_diagnostic = Some(err_count - 1);
        app.focus = Focus::Diagnostics;
        app.handle_event(AppEvent::Down);
        // Down from last should stay at last
        assert_eq!(app.selected_diagnostic, Some(err_count - 1));
    }

    #[test]
    fn test_diagnostics_enter_jumps_editor_and_switches_focus() {
        let toml = "x = 1\nchain = \"Holesky\"\n";
        // This will produce an error; we check the span gives us a line > 0
        let mut app = App::new(PathBuf::from("test.toml"), toml.to_string());
        app.revalidate();
        let (diag_line, err_count) = match &app.validation {
            ValidationState::Invalid(d) if !d.is_empty() => (d[0].line, d.len()),
            _ => (Some(1), 1),
        };
        assert!(err_count > 0);
        app.selected_diagnostic = Some(0);
        app.focus = Focus::Diagnostics;

        // Record cursor before enter
        let before_row = app.editor.cursor().0;

        app.handle_event(AppEvent::Enter);

        // Focus should switch to Editor
        assert_eq!(app.focus, Focus::Editor);
        // If diagnostic had a line, cursor should have moved
        if let Some(line) = diag_line {
            // Cursor row is 0-indexed, line is 1-indexed
            let expected_row = line.saturating_sub(1);
            if expected_row != before_row {
                assert_eq!(app.editor.cursor().0, expected_row);
            }
        }
    }

    #[test]
    fn test_diagnostics_nav_ignored_when_focus_is_editor() {
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.revalidate();
        app.selected_diagnostic = Some(0);
        app.focus = Focus::Editor;
        // Up/Down/Enter should not change selected_diagnostic when focus is Editor
        app.handle_event(AppEvent::Up);
        app.handle_event(AppEvent::Down);
        app.handle_event(AppEvent::Enter);
        assert_eq!(app.selected_diagnostic, Some(0));
        assert_eq!(app.focus, Focus::Editor);
    }

    #[test]
    fn test_ctrl_z_undoes_edit() {
        // Note: TextArea::from(lines()) strips trailing newlines.
        // The editor stores "chain = \"Holesky\"\n\n[pbs]" (no trailing \n).
        let content = "chain = \"Holesky\"\n\n[pbs]\n";
        let stored = "chain = \"Holesky\"\n\n[pbs]";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        assert!(!app.dirty);

        // Type 'x' to make an edit
        let consumed = app.input_editor_key(test_key('x'));
        assert!(consumed);
        assert!(app.dirty);
        assert!(app.current_content().starts_with('x'));

        // Ctrl+Z should undo
        let ctrl_z = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL);
        let consumed = app.input_editor_key(ctrl_z);
        assert!(consumed, "Ctrl+Z should be consumed by undo");
        assert_eq!(app.current_content(), stored);
        assert!(!app.dirty, "undo to original should clear dirty");
    }

    #[test]
    fn test_ctrl_y_redoes_undone_edit() {
        let content = "chain = \"Holesky\"\n\n[pbs]\n";
        let stored = "chain = \"Holesky\"\n\n[pbs]";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());

        // Type 'x'
        app.input_editor_key(test_key('x'));
        let after_edit = app.current_content();

        // Undo
        let ctrl_z = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL);
        app.input_editor_key(ctrl_z);
        assert_eq!(app.current_content(), stored);

        // Redo
        let ctrl_y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL);
        let consumed = app.input_editor_key(ctrl_y);
        assert!(consumed, "Ctrl+Y should be consumed by redo");
        assert_eq!(app.current_content(), after_edit);
        assert!(app.dirty);
    }

    #[test]
    fn test_ctrl_z_multiple_undos() {
        let content = "chain = \"Holesky\"\n\n[pbs]\n";
        let stored = "chain = \"Holesky\"\n\n[pbs]";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());

        // Make 3 edits
        app.input_editor_key(test_key('a'));
        app.input_editor_key(test_key('b'));
        app.input_editor_key(test_key('c'));

        let ctrl_z = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL);
        // Undo 'c'
        app.input_editor_key(ctrl_z);
        assert!(!app.current_content().ends_with("abc"));
        // Undo 'b'
        app.input_editor_key(ctrl_z);
        assert!(app.current_content().starts_with('a'));
        assert!(!app.current_content().starts_with("ab"));
        // Undo 'a'
        app.input_editor_key(ctrl_z);
        assert_eq!(app.current_content(), stored);
        assert!(!app.dirty);

        // Ctrl+Z with nothing to undo should be noop
        let consumed = app.input_editor_key(ctrl_z);
        assert!(!consumed, "Ctrl+Z with empty undo history should not consume");
    }

    #[test]
    fn test_ctrl_z_y_noop_when_no_history() {
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());

        // No edits made — Ctrl+Z and Ctrl+Y should be noop (not consumed)
        let ctrl_z = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL);
        let consumed = app.input_editor_key(ctrl_z);
        assert!(!consumed, "Ctrl+Z with no history should not consume");

        let ctrl_y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL);
        let consumed = app.input_editor_key(ctrl_y);
        assert!(!consumed, "Ctrl+Y with no history should not consume");
    }

    #[test]
    fn test_replace_editor_content_preserves_cursor_line() {
        let content = "line1\nline2\nline3\nline4\nline5";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());

        // Move cursor to line 3 (0-indexed: row 2)
        for _ in 0..2 {
            app.input_editor_key(test_key_code(KeyCode::Down));
        }
        assert_eq!(app.editor.cursor().0, 2, "cursor should be on line 3");

        // Reload same content — cursor should stay on line 3
        app.replace_editor_content(content);
        assert_eq!(app.editor.cursor().0, 2, "cursor should stay on line 3 after reload");
    }

    #[test]
    fn test_replace_editor_content_clamps_cursor_when_content_shrinks() {
        let content = "line1\nline2\nline3\nline4\nline5";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());

        // Move cursor to line 5 (0-indexed: row 4)
        for _ in 0..4 {
            app.input_editor_key(test_key_code(KeyCode::Down));
        }
        assert_eq!(app.editor.cursor().0, 4);

        // Replace with shorter content (3 lines)
        let shorter = "line1\nline2\nline3";
        app.replace_editor_content(shorter);
        // Cursor should be clamped to last line (row 2)
        assert_eq!(app.editor.cursor().0, 2, "cursor should clamp to last line");
    }

    #[test]
    fn test_start_search_saves_cursor() {
        let content = "chain = \"Holesky\"\n\n[pbs]\nhost = \"127.0.0.1\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        // Move cursor somewhere
        app.input_editor_key(test_key_code(KeyCode::Down));
        app.input_editor_key(test_key_code(KeyCode::Down));
        let cursor_before = app.editor.cursor();
        assert!(cursor_before.0 > 0, "cursor should be past line 0");

        app.start_search();
        assert!(app.searching);
        assert!(app.search_query.is_empty());
        assert_eq!(app.saved_cursor, cursor_before);
    }

    #[test]
    fn test_cancel_search_restores_cursor() {
        let content = "chain = \"Holesky\"\n\n[pbs]\nhost = \"127.0.0.1\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        // Move cursor to line 2
        app.input_editor_key(test_key_code(KeyCode::Down));
        app.input_editor_key(test_key_code(KeyCode::Down));
        let saved = app.editor.cursor();

        app.start_search();
        // Cursor moved by search... simulate it
        app.editor.move_cursor(tui_textarea::CursorMove::Jump(0, 0));
        app.cancel_search();

        assert!(!app.searching);
        assert_eq!(app.editor.cursor(), saved);
    }

    #[test]
    fn test_handle_search_char_finds_match() {
        let content = "chain = \"Holesky\"\n\n[pbs]\nhost = \"127.0.0.1\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.start_search();

        // Search for "pbs"
        let result = app.handle_search_char('p');
        assert!(result.is_ok());
        let result = app.handle_search_char('b');
        assert!(result.is_ok());
        let result = app.handle_search_char('s');
        assert!(result.is_ok());
        let count = result.unwrap();
        assert_eq!(count, 1, "'pbs' should match once");
        assert_eq!(app.search_query, "pbs");
        // Cursor should be on the [pbs] line
        let (row, _col) = app.editor.cursor();
        assert_eq!(row, 2, "cursor should be on [pbs] line (row 2)");
    }

    #[test]
    fn test_handle_search_backspace_removes_char() {
        let content = "chain = \"Holesky\"\n\n[pbs]\nhost = \"127.0.0.1\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.start_search();
        let _ = app.handle_search_char('c');
        let _ = app.handle_search_char('h');
        assert_eq!(app.search_query, "ch");

        let result = app.handle_search_backspace();
        assert!(result.is_ok());
        assert_eq!(app.search_query, "c");
    }

    #[test]
    fn test_search_next_and_prev_cycle_matches() {
        // Content with multiple instances of "ho"
        let content = "chain = \"Holesky\"\n\n[pbs]\nhost = \"127.0.0.1\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.start_search();

        // Search for "ho" — found in "Holesky" (line 0) and "host" (line 3)
        let _ = app.handle_search_char('h');
        let _ = app.handle_search_char('o');

        // First match should be at line 0 ("Holesky" contains "ho"... no, it's "Ho")
        // "ho" matches "host" on line 3
        let (row, _col) = app.editor.cursor();
        assert_eq!(row, 3, "'ho' should match 'host' on line 3");

        // Move to next match (wraps back)
        app.search_next_match();
        let (row2, _) = app.editor.cursor();
        // Should wrap to the same match (only one)
        assert_eq!(row2, 3);
    }

    #[test]
    fn test_search_pattern_counts_correctly() {
        let content = "aaa bbb aaa ccc aaa";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.start_search();
        let _ = app.handle_search_char('a');
        let _ = app.handle_search_char('a');
        let result = app.handle_search_char('a');
        assert!(result.is_ok());
        let count = result.unwrap();
        assert_eq!(count, 3, "'aaa' should match 3 times");
    }

    #[test]
    fn test_handle_search_key_up_down_cycles_matches() {
        // Content with two instances of "ho"
        let content = "chain = \"Holesky\"\n\n[pbs]\nhost = \"127.0.0.1\"\nholder = true";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.start_search();

        // Type 'h', 'o' — matches "host" and "holder"
        app.handle_search_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        app.handle_search_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));

        // First match: "host" on line 3
        assert_eq!(app.editor.cursor().0, 3);

        // Down → next match: "holder" on line 4
        app.handle_search_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.editor.cursor().0, 4);

        // Down again → wraps back to "host"
        app.handle_search_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.editor.cursor().0, 3);

        // Up → wraps back to "holder"
        app.handle_search_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.editor.cursor().0, 4);
    }

    #[test]
    fn test_invalid_regex_returns_error() {
        let content = "hello world";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        app.start_search();
        let _ = app.handle_search_char('(');
        // Unclosed paren is invalid regex
        let result = app.handle_search_char('h');
        assert!(result.is_err(), "unclosed paren should be invalid regex");
        // Query should still be updated despite error
        assert_eq!(app.search_query, "(h");
    }

    #[test]
    fn test_ctrl_r_sets_reload_requested() {
        let mut app = App::new(PathBuf::from("test.toml"), test_content());
        assert!(!app.reload_requested);
        app.handle_event(AppEvent::CtrlR);
        assert!(app.reload_requested);
    }

    #[test]
    fn test_reload_from_disk_restores_editor() {
        let content = "chain = \"Holesky\"\n\n[pbs]";
        // Use unique temp dir to avoid test pollution
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reload-test.toml");
        std::fs::write(&path, &content).unwrap();

        let mut app = App::new(path.clone(), content.to_string());
        // Modify editor via raw key event
        app.input_editor_key(test_key('x'));
        assert!(app.dirty);

        // Reload from disk
        app.reload_from_disk().unwrap();
        assert!(!app.dirty);
        assert_eq!(app.current_content(), content);
    }

    #[test]
    fn test_ctrl_w_prompts_force_save_when_dirty() {
        let content = "chain = \"Holesky\"".to_string();
        let mut app = App::new(PathBuf::from("test.toml"), content);
        app.input_editor_key(test_key('x')); // make dirty
        assert!(app.dirty);
        assert!(!app.showing_force_save_prompt());
        app.handle_event(AppEvent::CtrlW);
        assert!(app.showing_force_save_prompt());
    }

    #[test]
    fn test_ctrl_w_does_not_prompt_when_not_dirty() {
        let content = "chain = \"Holesky\"".to_string();
        let mut app = App::new(PathBuf::from("test.toml"), content);
        assert!(!app.dirty);
        app.handle_event(AppEvent::CtrlW);
        assert!(!app.showing_force_save_prompt());
    }

    #[test]
    fn test_esc_dismisses_force_save_prompt() {
        let content = "chain = \"Holesky\"".to_string();
        let mut app = App::new(PathBuf::from("test.toml"), content);
        app.input_editor_key(test_key('x'));
        app.handle_event(AppEvent::CtrlW); // show prompt
        assert!(app.showing_force_save_prompt());
        app.handle_event(AppEvent::Esc); // dismiss
        assert!(!app.showing_force_save_prompt());
    }

    #[test]
    fn test_force_save_writes_to_disk() {
        let content = "chain = \"Holesky\"".to_string();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("force-save-test.toml");
        std::fs::write(&path, &content).unwrap();

        let mut app = App::new(path.clone(), content);
        app.input_editor_key(test_key('x')); // make dirty + invalid (missing pbs)
        assert!(app.dirty);

        // Force save
        app.execute_force_save().unwrap();
        assert!(!app.dirty);

        // Verify file content includes our edit
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.starts_with("x"), "force-saved content should have edit");
    }

    #[test]
    fn test_temp_edit_path() {
        let app = App::new(PathBuf::from("config.toml"), test_content());
        let edit_path = app.temp_edit_path();
        assert_eq!(edit_path.extension().unwrap(), "edit");
        assert_eq!(edit_path.file_stem().unwrap(), "config.toml");
    }

    #[test]
    fn test_left_arrow_moves_cursor() {
        let content = "chain = \"Holesky\"\n\n[pbs]";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        // Cursor starts at (0, 0) after TextArea::from(lines)
        // Move right a few chars, then left
        app.input_editor_key(test_key_code(KeyCode::Right));
        app.input_editor_key(test_key_code(KeyCode::Right));
        let (_, col) = app.editor.cursor();
        assert_eq!(col, 2, "cursor should be at column 2 after two right arrows");
        app.input_editor_key(test_key_code(KeyCode::Left));
        let (_, col2) = app.editor.cursor();
        assert_eq!(col2, 1, "cursor should be at column 1 after left arrow");
    }

    #[test]
    fn test_backspace_deletes_char_and_marks_dirty() {
        let content = "chain = \"Holesky\"";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        assert!(!app.dirty);
        // Move to end of content, backspace
        app.input_editor_key(test_key_code(KeyCode::End));
        let consumed = app.input_editor_key(test_key_code(KeyCode::Backspace));
        assert!(consumed, "backspace should be consumed");
        assert!(app.dirty, "backspace should mark dirty");
        let text = app.current_content();
        assert!(!text.ends_with('"'), "backspace should have deleted the closing quote");
    }

    #[test]
    fn test_up_down_arrows_navigate_lines() {
        let content = "line1\nline2\nline3";
        let mut app = App::new(PathBuf::from("test.toml"), content.to_string());
        // Move down
        app.input_editor_key(test_key_code(KeyCode::Down));
        let (row, _) = app.editor.cursor();
        assert_eq!(row, 1, "down arrow should move to row 1");
        // Move down again
        app.input_editor_key(test_key_code(KeyCode::Down));
        let (row2, _) = app.editor.cursor();
        assert_eq!(row2, 2, "down arrow should move to row 2");
        // Move up
        app.input_editor_key(test_key_code(KeyCode::Up));
        let (row3, _) = app.editor.cursor();
        assert_eq!(row3, 1, "up arrow should move back to row 1");
    }

    #[test]
    fn test_editor_has_line_number_style_after_init() {
        let app = App::new(PathBuf::from("test.toml"), test_content());
        assert!(
            app.editor.line_number_style().is_some(),
            "editor should have line number style set"
        );
    }

    #[test]
    fn test_line_number_style_is_dark_gray() {
        let app = App::new(PathBuf::from("test.toml"), test_content());
        let style = app.editor.line_number_style().unwrap();
        assert_eq!(style.fg, Some(Color::DarkGray), "line numbers should be dark gray");
    }

    #[test]
    fn test_line_numbers_survive_reload_from_disk() {
        let content = "chain = \"Holesky\"\n\n[pbs]";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reload-ln-test.toml");
        std::fs::write(&path, &content).unwrap();

        let mut app = App::new(path.clone(), content.to_string());
        assert!(app.editor.line_number_style().is_some(), "should have style after init");

        app.reload_from_disk().unwrap();
        assert!(
            app.editor.line_number_style().is_some(),
            "line number style should survive reload"
        );
    }

    #[test]
    fn test_help_starts_hidden() {
        let app = App::new(PathBuf::from("test.toml"), test_content());
        assert!(!app.help_visible, "help should start hidden");
    }

    #[test]
    fn test_ctrl_h_shows_help() {
        let mut app = App::new(PathBuf::from("test.toml"), test_content());
        assert!(!app.help_visible);
        app.handle_event(AppEvent::CtrlH);
        assert!(app.help_visible, "Ctrl+H should show help");
    }

    #[test]
    fn test_esc_closes_help() {
        let mut app = App::new(PathBuf::from("test.toml"), test_content());
        app.help_visible = true;
        app.handle_event(AppEvent::Esc);
        assert!(!app.help_visible, "Esc should close help");
    }
}
