use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Gauge};
use ratatui::Frame;

/// Draw a bandwidth usage bar showing current rate vs limit.
pub fn draw_bandwidth_bar(
    f: &mut Frame,
    area: Rect,
    current_bps: u64,
    limit_bps: u64,
    label: &str,
) {
    if limit_bps == 0 {
        return;
    }

    let ratio = (current_bps as f64 / limit_bps as f64).min(1.0);
    let color = if ratio > 0.9 {
        Color::Red
    } else if ratio > 0.7 {
        Color::Yellow
    } else {
        Color::Green
    };

    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(color))
        .ratio(ratio)
        .label(format!(
            "{}: {:.0}%",
            label,
            ratio * 100.0
        ));
    f.render_widget(gauge, area);
}
