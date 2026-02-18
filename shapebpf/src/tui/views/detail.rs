use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::tui::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Min(10),  // detail info
        Constraint::Length(1), // status
    ])
    .split(f.area());

    let content = if let Some(s) = app.stats.get(app.selected_index) {
        let mut lines = vec![
            Line::from(format!("Cgroup: {}", s.cgroup_path)),
            Line::from(format!("Cgroup ID: {}", s.cgroup_id)),
            Line::from(""),
            Line::from(format!("TX bytes:   {}", s.stats.tx_bytes)),
            Line::from(format!("RX bytes:   {}", s.stats.rx_bytes)),
            Line::from(format!("TX packets: {}", s.stats.tx_packets)),
            Line::from(format!("RX packets: {}", s.stats.rx_packets)),
            Line::from(format!("Drops:      {}", s.stats.drops)),
            Line::from(""),
        ];

        if let Some(ref config) = s.config {
            lines.push(Line::from(format!(
                "Egress limit:  {} B/s",
                config.egress_rate_bps
            )));
            lines.push(Line::from(format!(
                "Ingress limit: {} B/s",
                config.ingress_rate_bps
            )));
            lines.push(Line::from(format!("Priority: {}", config.priority)));
        } else {
            lines.push(Line::from("No specific rate limit (using default)"));
        }

        lines.push(Line::from(""));
        lines.push(Line::from("Processes:"));
        for p in &s.processes {
            lines.push(Line::from(format!(
                "  PID {} (uid={}) {}",
                p.pid, p.uid, p.comm
            )));
        }
        lines
    } else {
        vec![Line::from("No cgroup selected")]
    };

    let detail = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Cgroup Detail "),
    );
    f.render_widget(detail, chunks[0]);

    let status = Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Green)),
        Span::raw(" back"),
    ]);
    f.render_widget(Paragraph::new(status), chunks[1]);
}
