use std::collections::{BTreeMap, BTreeSet, HashSet};

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use shapebpf_common::ipc::CgroupStats;

use crate::tui::app::App;

// ── Tree data structures ────────────────────────────────────────────

pub enum TreeRowKind {
    CgroupNode,
    Process { pid: u32 },
}

pub struct CgroupTreeRow {
    pub kind: TreeRowKind,
    pub prefix: String,
    pub label: String,
    pub full_path: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub wire_tx_bytes: u64,
    pub wire_rx_bytes: u64,
    pub drops: u64,
    pub priority: String,
    pub limit: String,
    pub processes: String,
    pub has_children: bool,
    pub collapsed: bool,
    /// Index into the stats array, if this row maps to a leaf cgroup
    pub stat_index: Option<usize>,
}

struct TreeNode {
    segment: String,
    full_path: String,
    children: BTreeMap<String, TreeNode>,
    stat_index: Option<usize>,
}

impl TreeNode {
    fn collect_stat_indices(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        if let Some(idx) = self.stat_index {
            indices.push(idx);
        }
        for child in self.children.values() {
            indices.extend(child.collect_stat_indices());
        }
        indices
    }
}

// ── Tree building ───────────────────────────────────────────────────

pub fn build_cgroup_tree(
    stats: &[CgroupStats],
    collapsed: &HashSet<String>,
) -> Vec<CgroupTreeRow> {
    let mut root_children: BTreeMap<String, TreeNode> = BTreeMap::new();

    for (idx, stat) in stats.iter().enumerate() {
        let path = stat.cgroup_path.trim_start_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            continue;
        }

        let mut current = &mut root_children;
        let mut built_path = String::new();

        for (i, &seg) in segments.iter().enumerate() {
            built_path = if built_path.is_empty() {
                format!("/{seg}")
            } else {
                format!("{built_path}/{seg}")
            };

            let node = current
                .entry(seg.to_string())
                .or_insert_with(|| TreeNode {
                    segment: seg.to_string(),
                    full_path: built_path.clone(),
                    children: BTreeMap::new(),
                    stat_index: None,
                });

            if i == segments.len() - 1 {
                node.stat_index = Some(idx);
            }

            current = &mut node.children;
        }
    }

    let mut rows = Vec::new();
    let root_count = root_children.len();
    for (i, node) in root_children.values().enumerate() {
        let is_last = i == root_count - 1;
        flatten_node(
            node,
            0,
            is_last,
            String::new(),
            collapsed,
            stats,
            &mut rows,
        );
    }
    rows
}

fn flatten_node(
    node: &TreeNode,
    depth: usize,
    is_last: bool,
    indent_prefix: String,
    collapsed: &HashSet<String>,
    stats: &[CgroupStats],
    rows: &mut Vec<CgroupTreeRow>,
) {
    let process_count = node.stat_index
        .map(|idx| stats[idx].processes.len())
        .unwrap_or(0);
    let has_children = !node.children.is_empty() || process_count > 0;
    let is_collapsed = collapsed.contains(&node.full_path);

    let connector = if depth == 0 {
        String::new()
    } else if is_last {
        format!("{indent_prefix}\u{2514}\u{2500}") // └─
    } else {
        format!("{indent_prefix}\u{251c}\u{2500}") // ├─
    };

    let indicator = if has_children {
        if is_collapsed {
            "+"
        } else {
            "-"
        }
    } else {
        " "
    };

    let prefix = format!("{connector}{indicator} ");

    let (tx_bytes, rx_bytes, wire_tx_bytes, wire_rx_bytes, drops, priority, limit, processes) =
        if let Some(idx) = node.stat_index {
            let s = &stats[idx];
            let procs: String = s
                .processes
                .iter()
                .map(|p| p.comm.as_str())
                .filter(|c| !c.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            let priority = s
                .config
                .as_ref()
                .map(|c| c.priority.to_string())
                .unwrap_or_else(|| "-".to_string());
            let limit = s
                .config
                .as_ref()
                .map(|c| {
                    format!(
                        "\u{2191}{} \u{2193}{}",
                        format_rate(c.egress_rate_bps),
                        format_rate(c.ingress_rate_bps)
                    )
                })
                .unwrap_or_else(|| "default".to_string());
            (
                s.stats.tx_bytes,
                s.stats.rx_bytes,
                s.wire_stats.tx_bytes,
                s.wire_stats.rx_bytes,
                s.stats.drops,
                priority,
                limit,
                procs,
            )
        } else {
            // Intermediate node: aggregate from all descendants
            let indices = node.collect_stat_indices();
            let mut tx = 0u64;
            let mut rx = 0u64;
            let mut wtx = 0u64;
            let mut wrx = 0u64;
            let mut dr = 0u64;
            for &idx in &indices {
                tx += stats[idx].stats.tx_bytes;
                rx += stats[idx].stats.rx_bytes;
                wtx += stats[idx].wire_stats.tx_bytes;
                wrx += stats[idx].wire_stats.rx_bytes;
                dr += stats[idx].stats.drops;
            }
            (tx, rx, wtx, wrx, dr, "-".to_string(), "-".to_string(), String::new())
        };

    // Clear inline processes when sub-rows will be shown
    let processes = if process_count > 0 && !is_collapsed {
        String::new()
    } else {
        processes
    };

    rows.push(CgroupTreeRow {
        kind: TreeRowKind::CgroupNode,
        prefix,
        label: node.segment.clone(),
        full_path: node.full_path.clone(),
        tx_bytes,
        rx_bytes,
        wire_tx_bytes,
        wire_rx_bytes,
        drops,
        priority,
        limit,
        processes,
        has_children,
        collapsed: is_collapsed,
        stat_index: node.stat_index,
    });

    if is_collapsed {
        return;
    }

    // Emit cgroup tree children
    let child_count = node.children.len();
    let has_proc_subrows = process_count > 0;
    for (i, child) in node.children.values().enumerate() {
        let child_is_last = i == child_count - 1 && !has_proc_subrows;
        let child_indent = if depth == 0 {
            String::new()
        } else if is_last {
            format!("{indent_prefix}  ")
        } else {
            format!("{indent_prefix}\u{2502} ") // │
        };
        flatten_node(
            child,
            depth + 1,
            child_is_last,
            child_indent,
            collapsed,
            stats,
            rows,
        );
    }

    // Emit process sub-rows for cgroups with processes
    if process_count > 0 {
        let idx = node.stat_index.unwrap();
        let procs = &stats[idx].processes;
        let proc_indent = if depth == 0 {
            String::new()
        } else if is_last {
            format!("{indent_prefix}  ")
        } else {
            format!("{indent_prefix}\u{2502} ") // │
        };
        for (pi, proc) in procs.iter().enumerate() {
            let is_last_proc = pi == procs.len() - 1;
            let proc_connector = if is_last_proc {
                format!("{proc_indent}\u{2514}\u{2500}") // └─
            } else {
                format!("{proc_indent}\u{251c}\u{2500}") // ├─
            };
            let proc_prefix = format!("{proc_connector}  ");
            rows.push(CgroupTreeRow {
                kind: TreeRowKind::Process { pid: proc.pid },
                prefix: proc_prefix,
                label: String::new(),
                full_path: node.full_path.clone(),
                tx_bytes: proc.tx_bytes,
                rx_bytes: proc.rx_bytes,
                wire_tx_bytes: proc.wire_tx_bytes,
                wire_rx_bytes: proc.wire_rx_bytes,
                drops: 0,
                priority: String::new(),
                limit: String::new(),
                processes: format!("{} ({})", proc.comm, proc.pid),
                has_children: false,
                collapsed: false,
                stat_index: node.stat_index,
            });
        }
    }
}

/// Collect full_paths of all tree nodes with children at depth >= `min_depth`.
/// Depth 0 = root children (e.g. `system.slice`), depth 1 = their children, etc.
pub fn collect_deep_paths(stats: &[CgroupStats], min_depth: usize) -> HashSet<String> {
    let mut root_children: BTreeMap<String, TreeNode> = BTreeMap::new();

    for (idx, stat) in stats.iter().enumerate() {
        let path = stat.cgroup_path.trim_start_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            continue;
        }
        let mut current = &mut root_children;
        let mut built_path = String::new();
        for (i, &seg) in segments.iter().enumerate() {
            built_path = if built_path.is_empty() {
                format!("/{seg}")
            } else {
                format!("{built_path}/{seg}")
            };
            let node = current
                .entry(seg.to_string())
                .or_insert_with(|| TreeNode {
                    segment: seg.to_string(),
                    full_path: built_path.clone(),
                    children: BTreeMap::new(),
                    stat_index: None,
                });
            if i == segments.len() - 1 {
                node.stat_index = Some(idx);
            }
            current = &mut node.children;
        }
    }

    let mut result = HashSet::new();
    fn walk(children: &BTreeMap<String, TreeNode>, depth: usize, min_depth: usize, out: &mut HashSet<String>) {
        for node in children.values() {
            if depth >= min_depth && !node.children.is_empty() {
                out.insert(node.full_path.clone());
            }
            walk(&node.children, depth + 1, min_depth, out);
        }
    }
    walk(&root_children, 0, min_depth, &mut result);
    result
}

// ── Drawing ─────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Min(10),   // main table
        Constraint::Length(1), // status bar
    ])
    .split(f.area());

    // Main bandwidth table
    let (tx_label, rx_label) = if app.wire_rate_view {
        ("Wire TX/s", "Wire RX/s")
    } else {
        ("TX/s", "RX/s")
    };
    let header = Row::new(vec![
        Cell::from("Cgroup"),
        Cell::from("Processes"),
        Cell::from(tx_label),
        Cell::from(rx_label),
        Cell::from("Drops"),
        Cell::from("Priority"),
        Cell::from("Limit"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = if app.tree_view {
        let tree_rows = build_cgroup_tree(&app.stats, &app.collapsed_cgroups);
        tree_rows
            .iter()
            .enumerate()
            .map(|(i, tr)| {
                let style = if i == app.selected_index {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                let (tx, rx) = if app.wire_rate_view {
                    (tr.wire_tx_bytes, tr.wire_rx_bytes)
                } else {
                    (tr.tx_bytes, tr.rx_bytes)
                };
                match &tr.kind {
                    TreeRowKind::Process { .. } => Row::new(vec![
                        Cell::from(tr.prefix.clone()),
                        Cell::from(tr.processes.clone()),
                        Cell::from(format_rate(tx)),
                        Cell::from(format_rate(rx)),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(""),
                    ])
                    .style(style),
                    TreeRowKind::CgroupNode => Row::new(vec![
                        Cell::from(format!("{}{}", tr.prefix, tr.label)),
                        Cell::from(truncate(&tr.processes, 25)),
                        Cell::from(format_rate(tx)),
                        Cell::from(format_rate(rx)),
                        Cell::from(tr.drops.to_string()),
                        Cell::from(tr.priority.clone()),
                        Cell::from(tr.limit.clone()),
                    ])
                    .style(style),
                }
            })
            .collect()
    } else {
        app.stats
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let style = if i == app.selected_index {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                let procs: String = s
                    .processes
                    .iter()
                    .map(|p| p.comm.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let limit = s
                    .config
                    .as_ref()
                    .map(|c| {
                        format!(
                            "{}/{}",
                            format_rate(c.egress_rate_bps),
                            format_rate(c.ingress_rate_bps)
                        )
                    })
                    .unwrap_or_else(|| "default".to_string());
                let priority = s
                    .config
                    .as_ref()
                    .map(|c| c.priority.to_string())
                    .unwrap_or_else(|| "-".to_string());

                let (tx, rx) = if app.wire_rate_view {
                    (s.wire_stats.tx_bytes, s.wire_stats.rx_bytes)
                } else {
                    (s.stats.tx_bytes, s.stats.rx_bytes)
                };
                Row::new(vec![
                    Cell::from(truncate(&s.cgroup_path, 30)),
                    Cell::from(truncate(&procs, 25)),
                    Cell::from(format_rate(tx)),
                    Cell::from(format_rate(rx)),
                    Cell::from(s.stats.drops.to_string()),
                    Cell::from(priority),
                    Cell::from(limit),
                ])
                .style(style)
            })
            .collect()
    };

    let title = match (app.tree_view, app.wire_rate_view) {
        (true, true) => " shapeBPF - Bandwidth Monitor [Tree] [Wire] ",
        (true, false) => " shapeBPF - Bandwidth Monitor [Tree] ",
        (false, true) => " shapeBPF - Bandwidth Monitor [Wire] ",
        (false, false) => " shapeBPF - Bandwidth Monitor ",
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(18),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
            Constraint::Percentage(9),
            Constraint::Percentage(9),
            Constraint::Percentage(19),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));

    f.render_widget(table, chunks[0]);

    // Status bar
    let mut hints = vec![
        Span::styled(" q", Style::default().fg(Color::Green)),
        Span::raw(" quit  "),
        Span::styled("r", Style::default().fg(Color::Green)),
        Span::raw(" review  "),
        Span::styled("e", Style::default().fg(Color::Green)),
        Span::raw(" rules  "),
        Span::styled("t", Style::default().fg(Color::Green)),
        Span::raw(" tree  "),
        Span::styled("w", Style::default().fg(Color::Green)),
        Span::raw(" wire  "),
        Span::styled("Enter/l", Style::default().fg(Color::Green)),
        Span::raw(" actions  "),
        Span::styled("gg/G", Style::default().fg(Color::Green)),
        Span::raw(" top/bottom  "),
        Span::styled("C-d/u", Style::default().fg(Color::Green)),
        Span::raw(" page"),
    ];
    if app.tree_view {
        hints.push(Span::raw("  "));
        hints.push(Span::styled("h/l", Style::default().fg(Color::Green)));
        hints.push(Span::raw(" fold  "));
        hints.push(Span::styled("zo/zc/za zM/zR", Style::default().fg(Color::Green)));
        hints.push(Span::raw(" folds"));
    }
    let status = Line::from(hints);
    f.render_widget(Paragraph::new(status), chunks[1]);

    // Git hash in bottom-right
    let hash = env!("GIT_HASH");
    if !hash.is_empty() {
        let label = format!("{hash} ");
        let w = label.len() as u16;
        let bar = chunks[1];
        if bar.width > w {
            let version_area = Rect::new(bar.x + bar.width - w, bar.y, w, 1);
            let version = Paragraph::new(label)
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Right);
            f.render_widget(version, version_area);
        }
    }
}

fn format_rate(bytes_per_sec: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes_per_sec == 0 {
        return "---".to_string();
    }
    if bytes_per_sec >= GB {
        format!("{:.1} GB/s", bytes_per_sec as f64 / GB as f64)
    } else if bytes_per_sec >= MB {
        format!("{:.1} MB/s", bytes_per_sec as f64 / MB as f64)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB/s", bytes_per_sec as f64 / KB as f64)
    } else {
        format!("{bytes_per_sec} B/s")
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
