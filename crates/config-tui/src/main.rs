use std::{io::stdout, path::PathBuf, time::Instant};

use cb_config_tui::app::{App, AppEvent, Focus};
use clap::{Parser, Subcommand};
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use eyre::Result;
use ratatui::{Terminal, backend::CrosstermBackend};

#[derive(Parser)]
#[command(name = "cb-config-tui", about = "Commit Boost Config TUI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Edit a Commit Boost config file
    #[command(name = "edit")]
    Edit {
        /// Path to the commit-boost.toml file
        path: PathBuf,
    },
}

/// Convert a crossterm KeyEvent into a global AppEvent (hotkeys only).
/// Returns None for keys that should be routed to the focused pane.
fn key_to_global_event(key: crossterm::event::KeyEvent) -> Option<AppEvent> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    let ctrl = crossterm::event::KeyModifiers::CONTROL;
    match key.code {
        KeyCode::Tab => Some(AppEvent::Tab),
        KeyCode::Char('q') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlQ),
        KeyCode::Char('s') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlS),
        KeyCode::Char('f') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlF),
        KeyCode::Char('h') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlH),
        KeyCode::Char('e') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlE),
        KeyCode::Char('r') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlR),
        KeyCode::Char('w') if key.modifiers.contains(ctrl) => Some(AppEvent::CtrlW),
        KeyCode::Esc => Some(AppEvent::Esc),
        _ => None,
    }
}

/// Convert a crossterm KeyEvent into navigation events (sidebar/diagnostics).
fn key_to_nav_event(key: crossterm::event::KeyEvent) -> Option<AppEvent> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    match key.code {
        KeyCode::Up => Some(AppEvent::Up),
        KeyCode::Down => Some(AppEvent::Down),
        KeyCode::Enter => Some(AppEvent::Enter),
        _ => None,
    }
}

/// Handle sidebar navigation events.
fn handle_sidebar_navigation(app: &mut App, event: &AppEvent) {
    match event {
        AppEvent::Enter => {
            if let Some(idx) = app.selected_section &&
                idx < app.sections.len()
            {
                let target_line = app.sections[idx].line;
                use tui_textarea::CursorMove;
                app.editor.move_cursor(CursorMove::Top);
                for _ in 0..target_line.saturating_sub(1) {
                    app.editor.move_cursor(CursorMove::Down);
                }
                app.focus = Focus::Editor;
            }
        }
        AppEvent::Up => {
            app.selected_section = Some(match app.selected_section {
                Some(i) if i > 0 => i - 1,
                Some(_) => 0,
                None => 0,
            });
        }
        AppEvent::Down => {
            let max = app.sections.len().saturating_sub(1);
            app.selected_section = Some(match app.selected_section {
                Some(i) if i < max => i + 1,
                Some(_) => max,
                None => 0,
            });
        }
        _ => {}
    }
}

async fn run_edit(path: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| eyre::eyre!("Failed to read {}: {}", path.display(), e))?;

    let mut app = App::new(path, content);

    // Initial validation
    app.revalidate();

    // Set up terminal
    terminal::enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    let mut last_validation = Instant::now();
    let debounce_ms = 200u64;

    terminal.draw(|f| cb_config_tui::ui::render(f, &mut app))?;

    while !app.should_quit {
        if event::poll(std::time::Duration::from_millis(100))? &&
            let Event::Key(key) = event::read()?
        {
            // Help modal: only Esc is processed
            if app.help_visible {
                if let Some(global) = key_to_global_event(key) {
                    app.handle_event(global);
                }
            } else {
                // 1. Global hotkeys — always processed regardless of focus
                if let Some(global) = key_to_global_event(key) {
                    app.handle_event(global);
                } else {
                    // 2. Focus-specific key routing
                    match app.focus {
                        Focus::Editor => {
                            if !app.showing_force_save_prompt() {
                                if app.searching {
                                    app.handle_search_key(key);
                                } else {
                                    app.input_editor_key(key);
                                }
                            }
                        }
                        Focus::Sidebar => {
                            if let Some(nav) = key_to_nav_event(key) {
                                handle_sidebar_navigation(&mut app, &nav);
                            }
                        }
                        Focus::Diagnostics => {
                            if let Some(nav) = key_to_nav_event(key) {
                                app.handle_event(nav);
                            }
                        }
                    }
                }
            }
        }

        // Handle save request (async validate + write)
        if app.save_requested && !app.save_in_progress {
            app.save_requested = false;
            app.save_in_progress = true;

            // Run async CommitBoostConfig::validate()
            let content = app.current_content();
            let save_result = async_save_validate(&content).await;

            match save_result {
                Ok(()) => {
                    // Async validation passed — write to disk
                    match app.save_to_disk() {
                        Ok(()) => {
                            app.save_error = None;
                        }
                        Err(e) => {
                            app.save_error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    app.save_error = Some(e);
                }
            }
            app.save_in_progress = false;
        }

        // Handle external editor (Ctrl+E)
        if app.edit_requested {
            app.edit_requested = false;
            let edit_path = app.temp_edit_path();

            // Save current content to temp file
            let content = app.current_content();
            if let Err(e) = std::fs::write(&edit_path, &content) {
                app.save_error = Some(format!("Failed to create temp file: {}", e));
            } else {
                // Determine editor command
                let editor_cmd = std::env::var("EDITOR")
                    .or_else(|_| std::env::var("VISUAL"))
                    .unwrap_or_else(|_| "vi".to_string());

                // Leave alternate screen
                let _ = terminal::disable_raw_mode();
                let _ = stdout().execute(LeaveAlternateScreen);

                // Spawn editor and wait
                let status = std::process::Command::new(&editor_cmd).arg(&edit_path).status();

                // Re-enter alternate screen
                let _ = terminal::enable_raw_mode();
                let _ = stdout().execute(EnterAlternateScreen);
                let _ = terminal.clear();

                match status {
                    Ok(_) => {
                        // Read the edited content back
                        match std::fs::read_to_string(&edit_path) {
                            Ok(edited_content) => {
                                app.replace_editor_content(&edited_content);
                                app.dirty = true;
                                app.revalidate();
                                app.save_error = None;
                            }
                            Err(e) => {
                                app.save_error = Some(format!("Failed to read edited file: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        app.save_error =
                            Some(format!("Failed to launch editor {}: {}", editor_cmd, e));
                    }
                }

                // Clean up temp file
                let _ = std::fs::remove_file(&edit_path);
            }
        }

        // Handle reload from disk (Ctrl+R)
        if app.reload_requested {
            app.reload_requested = false;
            if let Err(e) = app.reload_from_disk() {
                app.save_error = Some(e);
            } else {
                app.save_error = None;
            }
        }

        // Handle force-save (Ctrl+W)
        if app.showing_force_save_prompt() {
            // Prompt is showing — second Ctrl+W confirms, anything else
            // dismisses
        }
        if app.should_execute_force_save() {
            if let Err(e) = app.execute_force_save() {
                app.save_error = Some(e);
            } else {
                app.save_error = None;
                app.save_error = Some("Force-saved (config still invalid)".to_string());
            }
            app.clear_force_save_prompt();
        }

        // Debounced revalidation
        let elapsed = last_validation.elapsed().as_millis() as u64;
        if app.dirty && !app.save_in_progress && elapsed >= debounce_ms {
            app.revalidate();
            last_validation = Instant::now();
        }

        terminal.draw(|f| cb_config_tui::ui::render(f, &mut app))?;
    }

    terminal::disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}

/// Run async CommitBoostConfig::validate() with the current content.
/// This includes the PbsConfig RPC call if rpc_url is configured.
async fn async_save_validate(content: &str) -> std::result::Result<(), String> {
    let config: cb_common::config::CommitBoostConfig =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {}", e))?;

    config.validate().await.map_err(|e| format!("Validation error: {}", e))
}

fn main() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Edit { path } => run_edit(path).await,
    }
}
