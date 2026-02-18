use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn draw_notification(f: &mut Frame, area: Rect, unclassified_count: usize) {
    let (text, style) = if unclassified_count > 0 {
        (
            format!(
                " {} unclassified process{} - press 'r' to review",
                unclassified_count,
                if unclassified_count == 1 { "" } else { "es" }
            ),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        (
            " All processes classified".to_string(),
            Style::default().fg(Color::Green),
        )
    };

    let notification = Paragraph::new(text)
        .style(style)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(notification, area);
}
