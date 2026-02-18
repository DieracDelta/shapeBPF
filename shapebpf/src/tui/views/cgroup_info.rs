use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let selected = match app.unclassified_grouped.get(app.selected_index) {
        Some(c) => c,
        None => {
            f.render_widget(Paragraph::new("No cgroup selected"), f.area());
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .split(f.area());

    let mut lines = Vec::new();

    // Cgroup path (full, unwrapped)
    lines.push(Line::from(vec![
        Span::styled(" Cgroup:  ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(&selected.cgroup_path),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" Cgroup ID: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(selected.cgroup_id.to_string()),
    ]));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled(
        format!(" Processes in this cgroup ({})", selected.processes.len()),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    // Header
    lines.push(Line::from(vec![
        Span::styled(
            format!(" {:>8}  {:>8}  {}", "PID", "UID", "Command"),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
    ]));

    for p in &selected.processes {
        let comm_display = if p.comm.is_empty() { "(unknown)" } else { &p.comm };
        lines.push(Line::from(format!(" {:>8}  {:>8}  {}", p.pid, p.uid, comm_display)));
    }

    // If we also have traffic stats for this cgroup, show them
    if let Some(s) = app.stats.iter().find(|s| s.cgroup_id == selected.cgroup_id) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Traffic Stats",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!("   TX: {} bytes  ({} packets)", s.stats.tx_bytes, s.stats.tx_packets)));
        lines.push(Line::from(format!("   RX: {} bytes  ({} packets)", s.stats.rx_bytes, s.stats.rx_packets)));
        lines.push(Line::from(format!("   Drops: {}", s.stats.drops)));

        if let Some(ref config) = s.config {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Rate Limit",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!(
                "   Egress:  {} B/s  |  Ingress: {} B/s  |  Priority: {}",
                config.egress_rate_bps, config.ingress_rate_bps, config.priority
            )));
        }
    }

    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Cgroup Info "),
    );
    f.render_widget(detail, chunks[0]);

    let status = Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Green)),
        Span::raw(" back  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" create rule"),
    ]);
    f.render_widget(Paragraph::new(status), chunks[1]);
}
