use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::DefaultTerminal;

use shapebpf_common::ipc::{
    CgroupStats, MatchCriteria, ProcessInfo, Request, Response, Rule, UnclassifiedCgroup,
};

use super::ipc_client::IpcClient;
use super::views;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    ProcessList,
    BatchReview,
    BatchReviewPids,
    RuleEditor,
    Detail,
    CreateRule,
    CgroupInfo,
    ActionMenu,
}

#[derive(Debug, Clone)]
pub enum MenuAction {
    ViewDetails,
    EditRule { rule_name: String },
    CreateRule,
    IsolateAndCreateRule { pid: u32, name: String },
    DeleteRuleAndMerge { cgroup_path: String, rule_name: Option<String> },
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub label: String,
    pub action: MenuAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    CgroupPath,
    ProcessName,
    User,
}

impl MatchType {
    pub fn label(&self) -> &'static str {
        match self {
            MatchType::CgroupPath => "cgroup",
            MatchType::ProcessName => "process",
            MatchType::User => "user",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            MatchType::CgroupPath => MatchType::ProcessName,
            MatchType::ProcessName => MatchType::User,
            MatchType::User => MatchType::CgroupPath,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            MatchType::CgroupPath => MatchType::User,
            MatchType::ProcessName => MatchType::CgroupPath,
            MatchType::User => MatchType::ProcessName,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleForm {
    pub name: String,
    pub match_type: MatchType,
    pub match_value: String,
    pub egress: String,
    pub ingress: String,
    pub priority: String,
    pub focused_field: usize,
    /// Pre-computed match values for each type, from the source process
    pub cgroup_value: String,
    pub process_value: String,
    pub user_value: String,
    /// Track whether numeric fields have been edited (first keypress clears default)
    pub field_pristine: [bool; 6],
    /// If set, isolation will happen on form submit using the form's name field
    pub pending_isolate_pid: Option<u32>,
}

impl RuleForm {
    pub fn from_process(proc: &ProcessInfo) -> Self {
        let user_str = proc.uid.to_string();
        Self {
            name: if proc.comm.is_empty() {
                format!("rule-{}", proc.cgroup_path.split('/').last().unwrap_or("unknown"))
            } else {
                proc.comm.clone()
            },
            match_type: if !proc.comm.is_empty() {
                MatchType::ProcessName
            } else {
                MatchType::CgroupPath
            },
            match_value: if !proc.comm.is_empty() {
                proc.comm.clone()
            } else {
                proc.cgroup_path.clone()
            },
            egress: "0".to_string(),
            ingress: "0".to_string(),
            priority: "5".to_string(),
            focused_field: 0,
            cgroup_value: proc.cgroup_path.clone(),
            process_value: proc.comm.clone(),
            user_value: user_str,
            field_pristine: [false, false, false, true, true, true],
            pending_isolate_pid: None,
        }
    }

    pub fn from_rule(rule: &Rule) -> Self {
        let (match_type, match_value) = match &rule.match_criteria {
            MatchCriteria::CgroupPath(v) => (MatchType::CgroupPath, v.clone()),
            MatchCriteria::ProcessName(v) => (MatchType::ProcessName, v.clone()),
            MatchCriteria::User(v) => (MatchType::User, v.clone()),
            MatchCriteria::ContainerName(v) => (MatchType::CgroupPath, v.clone()),
            MatchCriteria::ServiceUnit(v) => (MatchType::CgroupPath, v.clone()),
        };
        let egress = rule
            .egress_rate_bps
            .map(|bps| format!("{:.1}", bps as f64 * 8.0 / 1_000_000.0))
            .unwrap_or_else(|| "0".to_string());
        let ingress = rule
            .ingress_rate_bps
            .map(|bps| format!("{:.1}", bps as f64 * 8.0 / 1_000_000.0))
            .unwrap_or_else(|| "0".to_string());
        Self {
            name: rule.name.clone(),
            match_type,
            match_value: match_value.clone(),
            egress,
            ingress,
            priority: rule.priority.to_string(),
            focused_field: 0,
            cgroup_value: match_value.clone(),
            process_value: match_value.clone(),
            user_value: match_value,
            field_pristine: [false, false, false, false, false, false],
            pending_isolate_pid: None,
        }
    }

    pub fn from_cgroup(cgroup: &UnclassifiedCgroup) -> Self {
        let comms: Vec<&str> = cgroup
            .processes
            .iter()
            .map(|p| p.comm.as_str())
            .filter(|c| !c.is_empty())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let name = comms
            .first()
            .copied()
            .unwrap_or_else(|| {
                cgroup.cgroup_path.split('/').last().unwrap_or("unknown")
            })
            .to_string();
        let uid_str = cgroup
            .processes
            .first()
            .map(|p| p.uid.to_string())
            .unwrap_or_default();
        Self {
            name,
            match_type: MatchType::CgroupPath,
            match_value: cgroup.cgroup_path.clone(),
            egress: "0".to_string(),
            ingress: "0".to_string(),
            priority: "5".to_string(),
            focused_field: 0,
            cgroup_value: cgroup.cgroup_path.clone(),
            process_value: comms.join(","),
            user_value: uid_str,
            field_pristine: [false, false, false, true, true, true],
            pending_isolate_pid: None,
        }
    }

    pub fn field_count() -> usize {
        6 // name, match_type, match_value, egress, ingress, priority
    }

    pub fn active_field_value(&self) -> &str {
        match self.focused_field {
            0 => &self.name,
            2 => &self.match_value,
            3 => &self.egress,
            4 => &self.ingress,
            5 => &self.priority,
            _ => "",
        }
    }

    pub fn active_field_value_mut(&mut self) -> Option<&mut String> {
        match self.focused_field {
            0 => Some(&mut self.name),
            2 => Some(&mut self.match_value),
            3 => Some(&mut self.egress),
            4 => Some(&mut self.ingress),
            5 => Some(&mut self.priority),
            _ => None,
        }
    }

    /// Sync match_value when match_type changes
    pub fn sync_match_value(&mut self) {
        self.match_value = match self.match_type {
            MatchType::CgroupPath => self.cgroup_value.clone(),
            MatchType::ProcessName => self.process_value.clone(),
            MatchType::User => self.user_value.clone(),
        };
    }

    pub fn to_rule(&self) -> Option<Rule> {
        if self.name.is_empty() || self.match_value.is_empty() {
            return None;
        }
        let match_criteria = match self.match_type {
            MatchType::CgroupPath => MatchCriteria::CgroupPath(self.match_value.clone()),
            MatchType::ProcessName => MatchCriteria::ProcessName(self.match_value.clone()),
            MatchType::User => MatchCriteria::User(self.match_value.clone()),
        };
        // Input is Mbps (megabits/sec), convert to bytes/sec for BPF maps
        let egress = self.egress.parse::<f64>().ok()
            .map(|mbps| (mbps * 1_000_000.0 / 8.0) as u64);
        let ingress = self.ingress.parse::<f64>().ok()
            .map(|mbps| (mbps * 1_000_000.0 / 8.0) as u64);
        let priority = self.priority.parse::<u8>().unwrap_or(5).clamp(1, 10);
        Some(Rule {
            name: self.name.clone(),
            match_criteria,
            egress_rate_bps: egress.filter(|&v| v > 0),
            ingress_rate_bps: ingress.filter(|&v| v > 0),
            priority,
        })
    }
}

pub struct App {
    pub mode: AppMode,
    pub client: IpcClient,
    pub stats: Vec<CgroupStats>,
    pub rules: Vec<Rule>,
    pub unclassified: Vec<ProcessInfo>,
    pub unclassified_grouped: Vec<UnclassifiedCgroup>,
    pub selected_index: usize,
    pub batch_pid_index: usize,
    pub should_quit: bool,
    pub last_error: Option<String>,
    pub rule_form: Option<RuleForm>,
    pub tree_view: bool,
    pub wire_rate_view: bool,
    pub collapsed_cgroups: HashSet<String>,
    /// Number of visible rows in tree view (updated during draw)
    pub tree_visible_count: usize,
    /// For two-key vim sequences (gg, zo/zc/za/zM/zR)
    pub pending_key: Option<char>,
    /// Action menu items for the current selection
    pub action_menu_items: Vec<MenuItem>,
    pub action_menu_index: usize,
    /// The CgroupStats that was selected when the action menu was opened
    pub action_target_stats: Option<CgroupStats>,
    /// The specific PID targeted (for process sub-rows in tree view)
    pub action_target_pid: Option<u32>,
    /// Transient status message shown in ProcessList after rule creation
    pub status_message: Option<String>,
}

impl App {
    pub async fn new(client: IpcClient) -> Self {
        Self {
            mode: AppMode::ProcessList,
            client,
            stats: Vec::new(),
            rules: Vec::new(),
            unclassified: Vec::new(),
            unclassified_grouped: Vec::new(),
            selected_index: 0,
            batch_pid_index: 0,
            should_quit: false,
            last_error: None,
            rule_form: None,
            tree_view: true,
            wire_rate_view: false,
            collapsed_cgroups: HashSet::new(),
            tree_visible_count: 0,
            pending_key: None,
            action_menu_items: Vec::new(),
            action_menu_index: 0,
            action_target_stats: None,
            action_target_pid: None,
            status_message: None,
        }
    }

    pub async fn refresh(&mut self) {
        match self.client.request(&Request::GetStats).await {
            Ok(Response::Stats(s)) => self.stats = s,
            Ok(Response::Error(e)) => self.last_error = Some(e),
            Err(e) => self.last_error = Some(format!("{e:#}")),
            _ => {}
        }
        match self.client.request(&Request::GetUnclassifiedGrouped).await {
            Ok(Response::UnclassifiedGrouped(g)) => {
                // Populate flat list from grouped data for backward compat
                self.unclassified = g.iter().flat_map(|c| c.processes.clone()).collect();
                self.unclassified_grouped = g;
            }
            Err(e) => self.last_error = Some(format!("{e:#}")),
            _ => {}
        }
        match self.client.request(&Request::GetRules).await {
            Ok(Response::Rules(r)) => self.rules = r,
            Err(e) => self.last_error = Some(format!("{e:#}")),
            _ => {}
        }
        self.status_message = None;
        self.update_tree_visible_count();
    }

    fn update_tree_visible_count(&mut self) {
        if self.tree_view {
            self.tree_visible_count =
                super::views::process_list::build_cgroup_tree(&self.stats, &self.collapsed_cgroups)
                    .len();
        }
    }

    /// Collapse all tree nodes at depth >= 2 so tree view starts with two levels unfolded.
    fn collapse_deep_nodes(&mut self) {
        let deep = super::views::process_list::collect_deep_paths(&self.stats, 2);
        self.collapsed_cgroups = deep;
        self.update_tree_visible_count();
    }

    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        self.refresh().await;
        self.collapse_deep_nodes();

        loop {
            terminal.draw(|f| {
                match self.mode {
                    AppMode::ProcessList => views::process_list::draw(f, &self),
                    AppMode::BatchReview => views::batch_review::draw(f, &self),
                    AppMode::BatchReviewPids => views::batch_review_pids::draw(f, &self),
                    AppMode::RuleEditor => views::rule_editor::draw(f, &self),
                    AppMode::Detail => views::detail::draw(f, &self),
                    AppMode::CreateRule => views::create_rule::draw(f, &self),
                    AppMode::CgroupInfo => views::cgroup_info::draw(f, &self),
                    AppMode::ActionMenu => views::action_menu::draw(f, &self),
                }
            })?;

            if self.should_quit {
                break;
            }

            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                        break;
                    }
                    self.handle_key(key).await;
                }
            } else {
                if self.mode != AppMode::CreateRule
                    && self.mode != AppMode::CgroupInfo
                    && self.mode != AppMode::BatchReviewPids
                    && self.mode != AppMode::ActionMenu
                {
                    self.refresh().await;
                }
            }
        }

        Ok(())
    }

    /// Number of items in the current list view.
    fn list_len(&self) -> usize {
        match self.mode {
            AppMode::ProcessList if self.tree_view => self.tree_visible_count,
            AppMode::ProcessList => self.stats.len(),
            AppMode::BatchReview => self.unclassified_grouped.len(),
            AppMode::RuleEditor => self.rules.len(),
            AppMode::ActionMenu => self.action_menu_items.len(),
            _ => 0,
        }
    }

    /// Half the visible terminal height, for Ctrl+d/u page jumps.
    fn half_page_size(&self) -> usize {
        crossterm::terminal::size()
            .map(|(_, h)| (h as usize).saturating_sub(6) / 2)
            .unwrap_or(10)
    }

    fn toggle_tree_node(&mut self) {
        let rows = super::views::process_list::build_cgroup_tree(
            &self.stats,
            &self.collapsed_cgroups,
        );
        if let Some(row) = rows.get(self.selected_index) {
            if row.has_children {
                let path = row.full_path.clone();
                if !self.collapsed_cgroups.remove(&path) {
                    self.collapsed_cgroups.insert(path);
                }
            }
        }
        self.update_tree_visible_count();
        if self.selected_index >= self.tree_visible_count && self.tree_visible_count > 0 {
            self.selected_index = self.tree_visible_count - 1;
        }
    }

    fn handle_fold_key(&mut self, c: char) {
        if self.mode != AppMode::ProcessList || !self.tree_view {
            return;
        }
        match c {
            'o' => {
                // zo: expand node at cursor
                let rows = super::views::process_list::build_cgroup_tree(
                    &self.stats,
                    &self.collapsed_cgroups,
                );
                if let Some(row) = rows.get(self.selected_index) {
                    self.collapsed_cgroups.remove(&row.full_path);
                }
            }
            'c' => {
                // zc: collapse node at cursor
                let rows = super::views::process_list::build_cgroup_tree(
                    &self.stats,
                    &self.collapsed_cgroups,
                );
                if let Some(row) = rows.get(self.selected_index) {
                    if row.has_children {
                        self.collapsed_cgroups.insert(row.full_path.clone());
                    }
                }
            }
            'a' => {
                // za: toggle (same as Space)
                self.toggle_tree_node();
                return; // toggle_tree_node already updates count + clamps
            }
            'M' => {
                // zM: collapse all — discover all foldable nodes by building tree with empty collapsed set
                let empty = HashSet::new();
                let rows = super::views::process_list::build_cgroup_tree(&self.stats, &empty);
                for row in &rows {
                    if row.has_children {
                        self.collapsed_cgroups.insert(row.full_path.clone());
                    }
                }
            }
            'R' => {
                // zR: expand all
                self.collapsed_cgroups.clear();
            }
            _ => return,
        }
        self.update_tree_visible_count();
        if self.tree_visible_count > 0 && self.selected_index >= self.tree_visible_count {
            self.selected_index = self.tree_visible_count - 1;
        }
    }

    async fn handle_key(&mut self, key: KeyEvent) {
        let code = key.code;
        let modifiers = key.modifiers;

        if self.mode == AppMode::CreateRule {
            self.handle_form_key(key).await;
            return;
        }

        // Handle pending two-key sequences
        if let Some(pending) = self.pending_key.take() {
            match pending {
                'g' => {
                    if code == KeyCode::Char('g') {
                        // gg: go to first item
                        self.selected_index = 0;
                        return;
                    }
                    // Not 'g' — fall through to normal handling
                }
                'z' => {
                    if let KeyCode::Char(c) = code {
                        self.handle_fold_key(c);
                        return;
                    }
                    // Not a char — fall through
                }
                _ => {}
            }
        }

        // Check if current key starts a pending sequence
        if let KeyCode::Char(c) = code {
            if modifiers.is_empty() || modifiers == KeyModifiers::SHIFT {
                match c {
                    'g' if self.mode != AppMode::CreateRule => {
                        self.pending_key = Some('g');
                        return;
                    }
                    'z' if self.mode == AppMode::ProcessList && self.tree_view => {
                        self.pending_key = Some('z');
                        return;
                    }
                    _ => {}
                }
            }
        }

        // ActionMenu: fully self-contained key handling
        if self.mode == AppMode::ActionMenu {
            let is_ctrl = modifiers.contains(KeyModifiers::CONTROL);
            match code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.action_menu_index = self.action_menu_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.action_menu_index + 1 < self.action_menu_items.len() {
                        self.action_menu_index += 1;
                    }
                }
                KeyCode::Char('n') if is_ctrl => {
                    if self.action_menu_index + 1 < self.action_menu_items.len() {
                        self.action_menu_index += 1;
                    }
                }
                KeyCode::Enter | KeyCode::Char('l') => {
                    self.dispatch_action_menu().await;
                }
                KeyCode::Esc | KeyCode::Char('h') => {
                    self.mode = AppMode::ProcessList;
                }
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            }
            return;
        }

        // Ctrl+d / Ctrl+u (must come before Char('d') for RuleEditor)
        if modifiers.contains(KeyModifiers::CONTROL) {
            match code {
                KeyCode::Char('d') => {
                    let jump = self.half_page_size();
                    let max = self.list_len();
                    self.selected_index = (self.selected_index + jump).min(max.saturating_sub(1));
                    return;
                }
                KeyCode::Char('u') => {
                    let jump = self.half_page_size();
                    self.selected_index = self.selected_index.saturating_sub(jump);
                    return;
                }
                _ => {}
            }
        }

        match code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('r')
                if self.mode != AppMode::CgroupInfo
                    && self.mode != AppMode::BatchReviewPids
                    && self.mode != AppMode::ActionMenu =>
            {
                self.selected_index = 0;
                self.mode = AppMode::BatchReview;
            }
            KeyCode::Char('e')
                if self.mode != AppMode::CgroupInfo
                    && self.mode != AppMode::BatchReviewPids
                    && self.mode != AppMode::ActionMenu =>
            {
                self.selected_index = 0;
                self.mode = AppMode::RuleEditor;
            }
            KeyCode::Esc | KeyCode::Char('h') => match self.mode {
                AppMode::CgroupInfo | AppMode::BatchReviewPids => {
                    self.mode = AppMode::BatchReview;
                }
                AppMode::BatchReview | AppMode::RuleEditor | AppMode::Detail => {
                    self.selected_index = 0;
                    self.mode = AppMode::ProcessList;
                }
                AppMode::ProcessList if code == KeyCode::Char('h') && self.tree_view => {
                    // h in tree view: collapse current node
                    let rows = super::views::process_list::build_cgroup_tree(
                        &self.stats,
                        &self.collapsed_cgroups,
                    );
                    if let Some(row) = rows.get(self.selected_index) {
                        if row.has_children && !row.collapsed {
                            self.collapsed_cgroups.insert(row.full_path.clone());
                            self.update_tree_visible_count();
                        }
                    }
                }
                _ => {
                    self.selected_index = 0;
                    self.mode = AppMode::ProcessList;
                }
            },
            KeyCode::Char('i') if self.mode == AppMode::BatchReview => {
                if !self.unclassified_grouped.is_empty() {
                    self.mode = AppMode::CgroupInfo;
                }
            }
            KeyCode::Char('p') if self.mode == AppMode::BatchReview => {
                if !self.unclassified_grouped.is_empty() {
                    self.batch_pid_index = 0;
                    self.mode = AppMode::BatchReviewPids;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => match self.mode {
                AppMode::BatchReviewPids => {
                    self.batch_pid_index = self.batch_pid_index.saturating_sub(1);
                }
                _ => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
            },
            KeyCode::Down | KeyCode::Char('j') => match self.mode {
                AppMode::BatchReviewPids => {
                    if let Some(cgroup) = self.unclassified_grouped.get(self.selected_index) {
                        if self.batch_pid_index + 1 < cgroup.processes.len() {
                            self.batch_pid_index += 1;
                        }
                    }
                }
                _ => {
                    let max = self.list_len();
                    if self.selected_index + 1 < max {
                        self.selected_index += 1;
                    }
                }
            },
            KeyCode::Char('G') => {
                // G: go to last item
                let max = self.list_len();
                if max > 0 {
                    self.selected_index = max - 1;
                }
            }
            KeyCode::Char('l') => match self.mode {
                AppMode::ProcessList if self.tree_view => {
                    // l in tree view: expand current node
                    let rows = super::views::process_list::build_cgroup_tree(
                        &self.stats,
                        &self.collapsed_cgroups,
                    );
                    if let Some(row) = rows.get(self.selected_index) {
                        if row.has_children && row.collapsed {
                            self.collapsed_cgroups.remove(&row.full_path);
                            self.update_tree_visible_count();
                        }
                    }
                }
                AppMode::ProcessList => {
                    // l in flat view: enter detail (same as Enter)
                    if !self.stats.is_empty() {
                        self.open_action_menu();
                    }
                }
                _ => {}
            },
            KeyCode::Enter => match self.mode {
                AppMode::ProcessList if !self.stats.is_empty() => {
                    self.open_action_menu();
                }
                AppMode::BatchReview => {
                    if let Some(cgroup) = self.unclassified_grouped.get(self.selected_index) {
                        self.rule_form = Some(RuleForm::from_cgroup(cgroup));
                        self.mode = AppMode::CreateRule;
                    }
                }
                AppMode::CgroupInfo => {
                    if let Some(cgroup) = self.unclassified_grouped.get(self.selected_index) {
                        self.rule_form = Some(RuleForm::from_cgroup(cgroup));
                        self.mode = AppMode::CreateRule;
                    }
                }
                AppMode::BatchReviewPids => {
                    if let Some(cgroup) = self.unclassified_grouped.get(self.selected_index) {
                        if let Some(proc) = cgroup.processes.get(self.batch_pid_index) {
                            let form_name = if proc.comm.is_empty() {
                                format!("pid{}", proc.pid)
                            } else {
                                proc.comm.clone()
                            };
                            self.rule_form = Some(RuleForm {
                                name: form_name,
                                match_type: MatchType::CgroupPath,
                                match_value: String::new(),
                                egress: "0".to_string(),
                                ingress: "0".to_string(),
                                priority: "5".to_string(),
                                focused_field: 0,
                                cgroup_value: String::new(),
                                process_value: proc.comm.clone(),
                                user_value: proc.uid.to_string(),
                                field_pristine: [false, false, false, true, true, true],
                                pending_isolate_pid: Some(proc.pid),
                            });
                            self.mode = AppMode::CreateRule;
                        }
                    }
                }
                _ => {}
            },
            KeyCode::Char('d') if self.mode == AppMode::RuleEditor => {
                if let Some(rule) = self.rules.get(self.selected_index) {
                    let name = rule.name.clone();
                    match self.client.request(&Request::DeleteRule { name }).await {
                        Ok(Response::Ok) => {
                            self.refresh().await;
                            if self.selected_index > 0 && self.selected_index >= self.rules.len() {
                                self.selected_index = self.rules.len().saturating_sub(1);
                            }
                        }
                        Ok(Response::Error(e)) => self.last_error = Some(e),
                        Err(e) => self.last_error = Some(format!("{e:#}")),
                        _ => {}
                    }
                }
            }
            KeyCode::Char('a') if self.mode == AppMode::RuleEditor => {
                let blank = ProcessInfo {
                    pid: 0,
                    uid: 0,
                    comm: String::new(),
                    cgroup_id: 0,
                    cgroup_path: String::new(),
                    tx_bytes: 0,
                    rx_bytes: 0,
                    wire_tx_bytes: 0,
                    wire_rx_bytes: 0,
                };
                self.rule_form = Some(RuleForm::from_process(&blank));
                self.mode = AppMode::CreateRule;
            }
            KeyCode::Char('t') if self.mode == AppMode::ProcessList => {
                self.tree_view = !self.tree_view;
                self.selected_index = 0;
                self.update_tree_visible_count();
            }
            KeyCode::Char('w') if self.mode == AppMode::ProcessList => {
                self.wire_rate_view = !self.wire_rate_view;
            }
            KeyCode::Char(' ') if self.mode == AppMode::ProcessList && self.tree_view => {
                self.toggle_tree_node();
            }
            _ => {}
        }
    }

    /// Resolve the currently selected row to a CgroupStats and optional PID.
    fn resolve_selected_stats(&self) -> Option<(CgroupStats, Option<u32>)> {
        if self.tree_view {
            let rows = super::views::process_list::build_cgroup_tree(
                &self.stats,
                &self.collapsed_cgroups,
            );
            let row = rows.get(self.selected_index)?;
            let stat_idx = row.stat_index?;
            let stats = self.stats.get(stat_idx)?.clone();
            let pid = match &row.kind {
                super::views::process_list::TreeRowKind::Process { pid } => Some(*pid),
                _ => None,
            };
            Some((stats, pid))
        } else {
            let stats = self.stats.get(self.selected_index)?.clone();
            Some((stats, None))
        }
    }

    fn open_action_menu(&mut self) {
        let Some((stats, pid)) = self.resolve_selected_stats() else {
            return;
        };

        let mut items = Vec::new();

        // Always offer "View details"
        items.push(MenuItem {
            label: "View details".to_string(),
            action: MenuAction::ViewDetails,
        });

        // "Edit rule" if matched
        if let Some(ref rule_name) = stats.matched_rule_name {
            items.push(MenuItem {
                label: format!("Edit rule '{rule_name}'"),
                action: MenuAction::EditRule {
                    rule_name: rule_name.clone(),
                },
            });
        }

        // "Create rule" or "Isolate & create rule" — only if not created by shapebpf
        if !stats.created_by_shapebpf {
            if let Some(pid) = pid {
                let name = stats
                    .processes
                    .iter()
                    .find(|p| p.pid == pid)
                    .map(|p| p.comm.clone())
                    .unwrap_or_else(|| format!("pid{pid}"));
                items.push(MenuItem {
                    label: format!("Isolate PID {pid} & create rule"),
                    action: MenuAction::IsolateAndCreateRule { pid, name },
                });
            }
            items.push(MenuItem {
                label: "Create rule for this cgroup".to_string(),
                action: MenuAction::CreateRule,
            });
        }

        // "Delete rule & merge back" if created by shapebpf and not externally modified
        if stats.created_by_shapebpf && !stats.externally_modified {
            items.push(MenuItem {
                label: "Delete rule & merge back".to_string(),
                action: MenuAction::DeleteRuleAndMerge {
                    cgroup_path: stats.cgroup_path.clone(),
                    rule_name: stats.matched_rule_name.clone(),
                },
            });
        }

        self.action_target_stats = Some(stats);
        self.action_target_pid = pid;
        self.action_menu_items = items;
        self.action_menu_index = 0;
        self.mode = AppMode::ActionMenu;
    }

    async fn dispatch_action_menu(&mut self) {
        let Some(item) = self.action_menu_items.get(self.action_menu_index).cloned() else {
            return;
        };

        match item.action {
            MenuAction::ViewDetails => {
                // Switch to detail view for the target stats
                if let Some(ref target) = self.action_target_stats {
                    if let Some(idx) = self.stats.iter().position(|s| s.cgroup_id == target.cgroup_id) {
                        self.selected_index = idx;
                    }
                }
                self.mode = AppMode::Detail;
            }
            MenuAction::EditRule { rule_name } => {
                if let Some(rule) = self.rules.iter().find(|r| r.name == rule_name) {
                    self.rule_form = Some(RuleForm::from_rule(rule));
                    self.mode = AppMode::CreateRule;
                } else {
                    self.last_error = Some(format!("Rule '{rule_name}' not found"));
                    self.mode = AppMode::ProcessList;
                }
            }
            MenuAction::CreateRule => {
                if let Some(ref stats) = self.action_target_stats {
                    let procs_str = stats.processes.iter()
                        .map(|p| p.comm.as_str())
                        .filter(|c| !c.is_empty())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(",");
                    let uid_str = stats.processes.first()
                        .map(|p| p.uid.to_string())
                        .unwrap_or_default();
                    self.rule_form = Some(RuleForm {
                        name: stats.cgroup_path.split('/').last()
                            .unwrap_or("unknown").to_string(),
                        match_type: MatchType::CgroupPath,
                        match_value: stats.cgroup_path.clone(),
                        egress: "0".to_string(),
                        ingress: "0".to_string(),
                        priority: "5".to_string(),
                        focused_field: 0,
                        cgroup_value: stats.cgroup_path.clone(),
                        process_value: procs_str,
                        user_value: uid_str,
                        field_pristine: [false, false, false, true, true, true],
                        pending_isolate_pid: None,
                    });
                    self.mode = AppMode::CreateRule;
                }
            }
            MenuAction::IsolateAndCreateRule { pid, name } => {
                // Show form first so the user can edit the name before isolation.
                // Actual isolation happens on form submit.
                let uid_str = self
                    .action_target_stats
                    .as_ref()
                    .and_then(|s| s.processes.iter().find(|p| p.pid == pid))
                    .map(|p| p.uid.to_string())
                    .unwrap_or_default();
                let proc_comm = self
                    .action_target_stats
                    .as_ref()
                    .and_then(|s| s.processes.iter().find(|p| p.pid == pid))
                    .map(|p| p.comm.clone())
                    .unwrap_or_default();
                let form_name = if name.is_empty() {
                    format!("pid{pid}")
                } else {
                    name
                };
                self.rule_form = Some(RuleForm {
                    name: form_name,
                    match_type: MatchType::CgroupPath,
                    match_value: String::new(),
                    egress: "0".to_string(),
                    ingress: "0".to_string(),
                    priority: "5".to_string(),
                    focused_field: 0,
                    cgroup_value: String::new(),
                    process_value: proc_comm,
                    user_value: uid_str,
                    field_pristine: [false, false, false, true, true, true],
                    pending_isolate_pid: Some(pid),
                });
                self.mode = AppMode::CreateRule;
            }
            MenuAction::DeleteRuleAndMerge {
                cgroup_path,
                rule_name,
            } => {
                match self
                    .client
                    .request(&Request::MergeCgroupBack {
                        cgroup_path,
                        rule_name,
                    })
                    .await
                {
                    Ok(Response::Ok) => {
                        self.refresh().await;
                        self.mode = AppMode::ProcessList;
                    }
                    Ok(Response::Error(e)) => {
                        self.last_error = Some(e);
                        self.mode = AppMode::ProcessList;
                    }
                    Err(e) => {
                        self.last_error = Some(format!("{e:#}"));
                        self.mode = AppMode::ProcessList;
                    }
                    _ => {
                        self.mode = AppMode::ProcessList;
                    }
                }
            }
        }
    }

    async fn handle_form_key(&mut self, event: KeyEvent) {
        let code = event.code;
        let is_ctrl = event.modifiers.contains(KeyModifiers::CONTROL);

        let form = match self.rule_form.as_mut() {
            Some(f) => f,
            None => {
                self.mode = AppMode::BatchReview;
                return;
            }
        };

        // Ctrl+n / Ctrl+j act as next-field
        let is_ctrl_next = is_ctrl && matches!(code, KeyCode::Char('n') | KeyCode::Char('j'));

        match code {
            KeyCode::Esc => {
                self.rule_form = None;
                self.mode = AppMode::ProcessList;
                self.selected_index = 0;
            }
            _ if is_ctrl_next => {
                form.focused_field = (form.focused_field + 1) % RuleForm::field_count();
            }
            KeyCode::Tab | KeyCode::Down => {
                form.focused_field = (form.focused_field + 1) % RuleForm::field_count();
            }
            KeyCode::BackTab | KeyCode::Up => {
                if form.focused_field == 0 {
                    form.focused_field = RuleForm::field_count() - 1;
                } else {
                    form.focused_field -= 1;
                }
            }
            KeyCode::Left if form.focused_field == 1 => {
                form.match_type = form.match_type.prev();
                form.sync_match_value();
            }
            KeyCode::Right if form.focused_field == 1 => {
                form.match_type = form.match_type.next();
                form.sync_match_value();
            }
            KeyCode::Char(c) => {
                let idx = form.focused_field;
                let is_numeric_field = idx == 3 || idx == 4; // egress, ingress
                let is_int_field = idx == 5; // priority

                // Validate: numeric fields only accept digits and decimal point
                if is_numeric_field && !c.is_ascii_digit() && c != '.' {
                    // reject non-numeric input
                } else if is_int_field && !c.is_ascii_digit() {
                    // reject non-digit input for priority
                } else if form.field_pristine[idx] {
                    // First keypress on a pristine field: clear default, replace with typed char
                    if let Some(field) = form.active_field_value_mut() {
                        field.clear();
                        field.push(c);
                    }
                    form.field_pristine[idx] = false;
                } else if let Some(field) = form.active_field_value_mut() {
                    field.push(c);
                }
            }
            KeyCode::Backspace => {
                let idx = form.focused_field;
                form.field_pristine[idx] = false;
                if let Some(field) = form.active_field_value_mut() {
                    field.pop();
                }
            }
            KeyCode::Enter => {
                // If pending isolation, perform it first using the form's name
                if let Some(isolate_pid) = form.pending_isolate_pid.take() {
                    let isolate_name = if form.name.is_empty() {
                        format!("pid{isolate_pid}")
                    } else {
                        form.name.clone()
                    };
                    match self
                        .client
                        .request(&Request::IsolatePid {
                            pid: isolate_pid,
                            name: isolate_name,
                        })
                        .await
                    {
                        Ok(Response::Isolated {
                            new_cgroup_id: _,
                            new_cgroup_path,
                        }) => {
                            // Update form with actual cgroup path
                            let form = self.rule_form.as_mut().unwrap();
                            form.match_value = new_cgroup_path.clone();
                            form.cgroup_value = new_cgroup_path;
                        }
                        Ok(Response::Error(e)) => {
                            self.last_error = Some(e);
                            return;
                        }
                        Err(e) => {
                            self.last_error = Some(format!("{e:#}"));
                            return;
                        }
                        _ => return,
                    }
                }

                let form = self.rule_form.as_ref().unwrap();
                let rule_name_for_msg = form.name.clone();
                if let Some(rule) = form.to_rule() {
                    match self.client.request(&Request::UpsertRule { rule }).await {
                        Ok(Response::Ok) => {
                            self.rule_form = None;
                            self.mode = AppMode::ProcessList;
                            self.selected_index = 0;
                            self.refresh().await;
                            self.status_message = Some(format!(
                                "Rule '{}' created \u{2014} applying...",
                                rule_name_for_msg
                            ));
                        }
                        Ok(Response::Error(e)) => self.last_error = Some(e),
                        Err(e) => self.last_error = Some(format!("{e:#}")),
                        _ => {}
                    }
                } else {
                    self.last_error = Some("Name and match value are required".to_string());
                }
            }
            _ => {}
        }
    }
}
