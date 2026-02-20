use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // title
        Constraint::Min(10),  // cgroup list
        Constraint::Length(1), // status
    ])
    .split(f.area());

    let total_procs: usize = app.unclassified_grouped.iter().map(|c| c.processes.len()).sum();
    let title = Paragraph::new(format!(
        " Batch Review - {} cgroups, {} unclassified processes",
        app.unclassified_grouped.len(),
        total_procs,
    ))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let header = Row::new(vec![
        Cell::from("Cgroup Path"),
        Cell::from("# Procs"),
        Cell::from("Commands"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .unclassified_grouped
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(app.visible_rows)
        .map(|(i, cgroup)| {
            let style = if i == app.selected_index {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            // Deduplicated command names
            let comms: Vec<&str> = cgroup
                .processes
                .iter()
                .map(|p| p.comm.as_str())
                .filter(|c| !c.is_empty())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let comms_str = if comms.is_empty() {
                "(unknown)".to_string()
            } else {
                comms.join(", ")
            };

            Row::new(vec![
                Cell::from(cgroup.cgroup_path.clone()),
                Cell::from(cgroup.processes.len().to_string()),
                Cell::from(comms_str),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(50),
            Constraint::Length(8),
            Constraint::Percentage(40),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Unclassified Cgroups "),
    );
    f.render_widget(table, chunks[1]);

    let status = Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Green)),
        Span::raw(" back  "),
        Span::styled("i", Style::default().fg(Color::Green)),
        Span::raw(" info  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" create rule  "),
        Span::styled("p", Style::default().fg(Color::Green)),
        Span::raw(" isolate PID"),
    ]);
    f.render_widget(Paragraph::new(status), chunks[2]);
}
