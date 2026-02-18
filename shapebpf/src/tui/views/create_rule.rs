use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let form = match &app.rule_form {
        Some(form) => form,
        None => return,
    };

    // Center the form dialog
    let area = centered_rect(60, 18, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Create Rule ")
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1), // name label + input
        Constraint::Length(1), // spacing
        Constraint::Length(1), // match type
        Constraint::Length(1), // spacing
        Constraint::Length(1), // match value
        Constraint::Length(1), // spacing
        Constraint::Length(1), // egress
        Constraint::Length(1), // spacing
        Constraint::Length(1), // ingress
        Constraint::Length(1), // spacing
        Constraint::Length(1), // priority
        Constraint::Length(1), // spacing
        Constraint::Length(1), // error
        Constraint::Length(1), // status bar
    ])
    .split(inner);

    let title = if form.pending_isolate_pid.is_some() {
        " Isolate & Create Rule "
    } else {
        " Create Rule "
    };
    // Re-draw block with correct title (overwrites the one above)
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().bg(Color::Black));
    f.render_widget(block, area);

    draw_field(f, rows[0], "Name:", &form.name, form.focused_field == 0);
    draw_match_type(f, rows[2], form.match_type.label(), form.focused_field == 1);
    let match_display = if form.pending_isolate_pid.is_some() && form.match_value.is_empty() {
        "(auto-set on save)".to_string()
    } else {
        form.match_value.clone()
    };
    draw_field(f, rows[4], "Match value:", &match_display, form.focused_field == 2);
    draw_field(f, rows[6], "Egress (Mbps):", &form.egress, form.focused_field == 3);
    draw_field(f, rows[8], "Ingress (Mbps):", &form.ingress, form.focused_field == 4);
    draw_field(f, rows[10], "Priority (1-10):", &form.priority, form.focused_field == 5);

    if let Some(err) = &app.last_error {
        let err_line = Line::from(Span::styled(
            format!(" {err}"),
            Style::default().fg(Color::Red),
        ));
        f.render_widget(Paragraph::new(err_line), rows[12]);
    }

    let status = Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Green)),
        Span::raw(" cancel  "),
        Span::styled("Tab/C-n/C-j", Style::default().fg(Color::Green)),
        Span::raw(" next field  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" save  "),
        Span::styled("</>", Style::default().fg(Color::Green)),
        Span::raw(" match type"),
    ]);
    f.render_widget(Paragraph::new(status), rows[13]);
}

fn draw_field(f: &mut Frame, area: Rect, label: &str, value: &str, focused: bool) {
    let chunks = Layout::horizontal([
        Constraint::Length(17),
        Constraint::Min(1),
    ])
    .split(area);

    let label_style = if focused {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };

    let value_style = if focused {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    let display = if focused {
        format!("{value}_")
    } else {
        value.to_string()
    };

    f.render_widget(Paragraph::new(Span::styled(format!(" {label}"), label_style)), chunks[0]);
    f.render_widget(Paragraph::new(Span::styled(display, value_style)), chunks[1]);
}

fn draw_match_type(f: &mut Frame, area: Rect, current: &str, focused: bool) {
    let chunks = Layout::horizontal([
        Constraint::Length(17),
        Constraint::Min(1),
    ])
    .split(area);

    let label_style = if focused {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };

    let value_style = if focused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let arrow_hint = if focused { " < > to change" } else { "" };

    f.render_widget(
        Paragraph::new(Span::styled(" Match type:", label_style)),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(current, value_style),
            Span::styled(arrow_hint, Style::default().fg(Color::DarkGray)),
        ])),
        chunks[1],
    );
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
