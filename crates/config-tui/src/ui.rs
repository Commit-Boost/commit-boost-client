use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use crate::{
    app::{App, Focus},
    validation::ValidationState,
};

/// Render the full TUI layout.
pub fn render(frame: &mut Frame, app: &mut App) {
    if app.help_visible {
        render_help(frame, frame.area());
        return;
    }

    let has_diagnostics = matches!(app.validation, ValidationState::Invalid(_));

    let constraints: Vec<Constraint> = if has_diagnostics {
        let mut c = vec![
            Constraint::Min(0),    // main area (sidebar + editor)
            Constraint::Length(3), // status bar
            Constraint::Length(8), // diagnostics panel
        ];
        if app.searching {
            c.insert(2, Constraint::Length(1)); // search bar before diagnostics
        }
        c
    } else {
        let mut c = vec![
            Constraint::Min(0),    // main area
            Constraint::Length(3), // status bar
            Constraint::Length(3), // valid indicator
        ];
        if app.searching {
            c.insert(2, Constraint::Length(1)); // search bar after status
        }
        c
    };

    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    let top = areas[0];
    let status_area_idx = if app.searching { 2 } else { 1 };
    let diag_area_idx = if app.searching { 3 } else { 2 };
    let status_area = areas[status_area_idx];
    let diag_area = areas[diag_area_idx];

    if app.searching {
        let search_area = areas[1];
        render_search_bar(frame, app, search_area);
    }

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(30), // sidebar
            Constraint::Min(0),     // editor
        ])
        .split(top);

    render_sidebar(frame, app, main[0]);
    render_editor(frame, app, main[1]);
    render_diagnostics(app, frame, diag_area);
    render_status_bar(frame, app, status_area);
}

fn render_sidebar(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .sections
        .iter()
        .enumerate()
        .map(|(i, section)| {
            let is_selected = app.selected_section == Some(i);
            let style = if is_selected {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(&section.name, style)))
        })
        .collect();

    let block = Block::default()
        .title(" Sections ")
        .borders(Borders::ALL)
        .border_style(border_style(app.focus, Focus::Sidebar));

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    frame.render_widget(list, area);
}

fn render_editor(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = if app.dirty { " Config *" } else { " Config " };

    app.editor.set_block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style(app.focus, Focus::Editor)),
    );
    frame.render_widget(&app.editor, area);
}

fn render_diagnostics(app: &App, frame: &mut Frame, area: Rect) {
    match &app.validation {
        ValidationState::Valid | ValidationState::Pending => {
            let title = match &app.validation {
                ValidationState::Valid => " ✓ Valid ",
                ValidationState::Pending => " ◌ Pending ",
                _ => unreachable!(),
            };
            let block = Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style(app.focus, Focus::Diagnostics));
            let paragraph = Paragraph::new(Line::from(Span::raw(""))).block(block);
            frame.render_widget(paragraph, area);
        }
        ValidationState::Invalid(diags) => {
            let count = diags.len();
            let title = format!(" ✗ {} Error{} ", count, if count == 1 { "" } else { "s" });
            let selected_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
            let normal_style = Style::default();
            let text_width = area.width.saturating_sub(2) as usize; // borders take 2 chars
            let items: Vec<ListItem> = diags
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let path_str = d.path.as_deref().unwrap_or("(root)");
                    let text = format!("{}: {}", path_str, d.message);
                    let is_selected = app.selected_diagnostic == Some(i);
                    let style = if is_selected { selected_style } else { normal_style };
                    let wrapped = wrap_text(&text, text_width);
                    let lines: Vec<Line> = wrapped
                        .into_iter()
                        .map(|chunk| Line::from(Span::styled(chunk, style)))
                        .collect();
                    ListItem::new(lines)
                })
                .collect();

            let block = Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style(app.focus, Focus::Diagnostics));

            let list = List::new(items)
                .block(block)
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
            frame.render_widget(list, area);
        }
    }
}

fn render_search_bar(frame: &mut Frame, app: &App, _area: Rect) {
    let pattern = app.editor.search_pattern();
    let match_count = pattern.map(|re| re.find_iter(&app.current_content()).count()).unwrap_or(0);

    let text = if app.search_query.is_empty() {
        "Search: _".to_string()
    } else if match_count > 0 {
        format!(
            "Search: {}  [{} match{}]",
            app.search_query,
            match_count,
            if match_count == 1 { "" } else { "es" }
        )
    } else {
        format!("Search: {}  [no matches]", app.search_query)
    };

    let block =
        Block::default().borders(Borders::TOP).border_style(Style::default().fg(Color::Cyan));
    let paragraph =
        Paragraph::new(Line::from(Span::styled(text, Style::default().fg(Color::Yellow))))
            .block(block);
    frame.render_widget(paragraph, frame.area());
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let filename = app.file_path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();

    let dirty_mark = if app.dirty { " ●" } else { "" };
    let cursor = app.editor.cursor();
    let cursor_info =
        format!(" Ln {}, Col {}", cursor.0.saturating_add(1), cursor.1.saturating_add(1));

    let focus_indicator = match app.focus {
        Focus::Editor => " EDITOR ",
        Focus::Sidebar => " SIDEBAR ",
        Focus::Diagnostics => " DIAGNOSTICS ",
    };

    let status_right = if app.showing_force_save_prompt() {
        " Force-save invalid config? Ctrl+W confirm, Esc cancel ".to_string()
    } else if app.save_in_progress {
        " Saving... ".to_string()
    } else if let Some(ref err) = app.save_error {
        err.clone()
    } else {
        "Ctrl+Q Quit │ Tab Focus │ Ctrl+S Save │ Ctrl+E Edit │ Ctrl+R Reload │ Ctrl+W Force"
            .to_string()
    };

    let text = Line::from(vec![
        Span::styled(
            format!(" {} ", filename),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            dirty_mark.to_string(),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled(
            focus_indicator.to_string(),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::REVERSED),
        ),
        Span::raw(" │ "),
        Span::styled(cursor_info, Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::styled(
            &status_right,
            if app.showing_force_save_prompt() {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else if app.save_error.is_some() {
                Style::default().fg(Color::Red)
            } else if app.save_in_progress {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            },
        ),
    ]);

    let block = Block::default().borders(Borders::TOP);
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

/// Border style for a pane: Cyan if it has focus, DarkGray otherwise.
fn border_style(current: Focus, target: Focus) -> Style {
    if current == target {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

/// Render a centered help overlay with all keybindings.
fn render_help(frame: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(Span::styled(" Keybindings ", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::raw(" Ctrl+S    Save file")),
        Line::from(Span::raw(" Ctrl+Q    Quit")),
        Line::from(Span::raw(" Ctrl+E    Open in external editor")),
        Line::from(Span::raw(" Ctrl+R    Reload from disk")),
        Line::from(Span::raw(" Ctrl+W    Force-save (invalid)")),
        Line::from(Span::raw(" Ctrl+F    Find in editor")),
        Line::from(Span::raw(" Ctrl+H    This help")),
        Line::from(""),
        Line::from(Span::raw(" Tab       Switch focus")),
        Line::from(Span::raw(" \u{2191}\u{2193}        Navigate sidebar/errors")),
        Line::from(Span::raw(" Enter     Jump to section")),
        Line::from(Span::raw(" Esc       Dismiss prompts/help")),
        Line::from(""),
        Line::from(Span::styled(" Validation ", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::raw(" While you type  \u{2014}  checks TOML syntax")),
        Line::from(Span::raw(" (missing fields, typos, bad types)")),
        Line::from(Span::raw(" Red panel = errors found")),
        Line::from(Span::raw(" Green \u{2713} = config is valid")),
        Line::from(""),
        Line::from(Span::raw(" Ctrl+S  \u{2014}  runs a full check")),
        Line::from(Span::raw(" (RPC chain ID, Docker image, limits)")),
        Line::from(Span::raw(" Saves only if everything passes")),
    ];

    let block = Block::default().title(" Help ").borders(Borders::ALL).style(Style::default());

    let paragraph = Paragraph::new(help_text).block(block);

    // Center the help popup
    let popup_area = centered_rect(44, 28, area);
    frame.render_widget(ratatui::widgets::Clear, popup_area);
    frame.render_widget(paragraph, popup_area);
}

/// Helper to create a centered rectangle.
fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x.saturating_add((r.width.saturating_sub(width)) / 2);
    let y = r.y.saturating_add((r.height.saturating_sub(height)) / 2);
    Rect::new(x, y, width.min(r.width), height.min(r.height))
}

/// Word-wrap text at a given character width. Splits at word boundaries.
/// Returns a vector of line strings, each ≤ width characters.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split(' ') {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_short_text_one_line() {
        let result = wrap_text("hello world", 20);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "hello world");
    }

    #[test]
    fn test_wrap_long_text_multi_line() {
        let result = wrap_text("this is a much longer message that should wrap", 15);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], "this is a much");
        assert_eq!(result[1], "longer message");
        assert_eq!(result[2], "that should");
        assert_eq!(result[3], "wrap");
    }
}
