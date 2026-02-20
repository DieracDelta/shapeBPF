use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let cgroup = match app.unclassified_grouped.get(app.selected_index) {
        Some(c) => c,
        None => {
            f.render_widget(Paragraph::new("No cgroup selected"), f.area());
            return;
        }
    };

    let has_error = app.last_error.is_some();
    let chunks = Layout::vertical([
        Constraint::Length(3), // title
        Constraint::Min(10),  // pid list
        Constraint::Length(if has_error { 1 } else { 0 }), // error
        Constraint::Length(1), // status
    ])
    .split(f.area());

    let title = Paragraph::new(format!(
        " {} - {} processes",
        cgroup.cgroup_path,
        cgroup.processes.len(),
    ))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let header = Row::new(vec![
        Cell::from("PID"),
        Cell::from("UID"),
        Cell::from("Command"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = cgroup
        .processes
        .iter()
        .enumerate()
        .skip(app.batch_scroll_offset)
        .take(app.visible_rows)
        .map(|(i, p)| {
            let style = if i == app.batch_pid_index {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let comm = if p.comm.is_empty() {
                "(unknown)"
            } else {
                &p.comm
            };
            Row::new(vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.uid.to_string()),
                Cell::from(comm.to_string()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Percentage(70),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Processes in Cgroup "),
    );
    f.render_widget(table, chunks[1]);

    if let Some(err) = &app.last_error {
        let err_line = Line::from(Span::styled(
            format!(" Error: {err}"),
            Style::default().fg(Color::Red),
        ));
        f.render_widget(Paragraph::new(err_line), chunks[2]);
    }

    let status = Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Green)),
        Span::raw(" back  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" isolate to new cgroup"),
    ]);
    f.render_widget(Paragraph::new(status), chunks[3]);
}
