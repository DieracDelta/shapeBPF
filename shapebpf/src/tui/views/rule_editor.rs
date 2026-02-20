use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use shapebpf_common::ipc::MatchCriteria;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Min(10),  // rules list
        Constraint::Length(1), // status
    ])
    .split(f.area());

    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Match"),
        Cell::from("Egress"),
        Cell::from("Ingress"),
        Cell::from("Priority"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .rules
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(app.visible_rows)
        .map(|(i, r)| {
            let style = if i == app.selected_index {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let match_str = match &r.match_criteria {
                MatchCriteria::User(u) => format!("user={u}"),
                MatchCriteria::ContainerName(c) => format!("container={c}"),
                MatchCriteria::ServiceUnit(s) => format!("service={s}"),
                MatchCriteria::CgroupPath(p) => format!("cgroup={p}"),
                MatchCriteria::ProcessName(n) => format!("proc={n}"),
            };
            let egress = r
                .egress_rate_bps
                .map(|b| format_rate(b))
                .unwrap_or_else(|| "unlimited".to_string());
            let ingress = r
                .ingress_rate_bps
                .map(|b| format_rate(b))
                .unwrap_or_else(|| "unlimited".to_string());

            Row::new(vec![
                Cell::from(r.name.clone()),
                Cell::from(match_str),
                Cell::from(egress),
                Cell::from(ingress),
                Cell::from(r.priority.to_string()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Rules "),
    );
    f.render_widget(table, chunks[0]);

    let status = Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Green)),
        Span::raw(" back  "),
        Span::styled("e/Enter", Style::default().fg(Color::Green)),
        Span::raw(" edit  "),
        Span::styled("a", Style::default().fg(Color::Green)),
        Span::raw(" add  "),
        Span::styled("d", Style::default().fg(Color::Green)),
        Span::raw(" delete"),
    ]);
    f.render_widget(Paragraph::new(status), chunks[1]);
}

fn format_rate(bytes_per_sec: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    if bytes_per_sec >= MB {
        format!("{:.1} MB/s", bytes_per_sec as f64 / MB as f64)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB/s", bytes_per_sec as f64 / KB as f64)
    } else {
        format!("{bytes_per_sec} B/s")
    }
}
