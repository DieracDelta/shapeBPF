use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    // Draw the process list underneath as context
    super::process_list::draw(f, app);

    if app.action_menu_items.is_empty() {
        return;
    }

    // Dynamic height: items + 2 (border) + 1 (status bar)
    let height = (app.action_menu_items.len() as u16) + 3;
    let area = centered_rect(40, height, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Actions ")
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut constraints: Vec<Constraint> = app
        .action_menu_items
        .iter()
        .map(|_| Constraint::Length(1))
        .collect();
    constraints.push(Constraint::Length(1)); // status bar
    let rows = Layout::vertical(constraints).split(inner);

    for (i, item) in app.action_menu_items.iter().enumerate() {
        let selected = i == app.action_menu_index;
        let marker = if selected { "> " } else { "  " };
        let style = if selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let line = Line::from(Span::styled(format!("{marker}{}", item.label), style));
        f.render_widget(Paragraph::new(line), rows[i]);
    }

    let status = Line::from(vec![
        Span::styled(" j/k", Style::default().fg(Color::Green)),
        Span::raw(" navigate  "),
        Span::styled("Enter/l", Style::default().fg(Color::Green)),
        Span::raw(" select  "),
        Span::styled("Esc/h", Style::default().fg(Color::Green)),
        Span::raw(" cancel"),
    ]);
    f.render_widget(Paragraph::new(status), rows[app.action_menu_items.len()]);
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vert = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(height),
        Constraint::Min(0),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vert[1])[1]
}
