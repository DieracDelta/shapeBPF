use std::collections::HashMap;

use shapebpf_common::ipc::{CgroupStats, ProcessInfo, UnclassifiedCgroup};
use shapebpf_common::{RateConfig, TrafficStats};

/// Collects and caches traffic statistics from BPF maps.
pub struct StatsCollector {
    /// cgroup_id -> latest traffic stats
    traffic: HashMap<u64, TrafficStats>,
    /// pid -> latest per-process traffic stats
    pid_traffic: HashMap<u32, TrafficStats>,
    /// cgroup_id -> rate config (if any)
    configs: HashMap<u64, RateConfig>,
    /// cgroup_id -> cgroup path
    cgroup_paths: HashMap<u64, String>,
    /// cgroup_id -> list of processes
    processes: HashMap<u64, Vec<ProcessInfo>>,
    /// Processes not matching any rule
    unclassified: Vec<ProcessInfo>,
    /// cgroup_id -> matched rule name
    rule_assignments: HashMap<u64, String>,
    /// cgroup_path -> original PID that was isolated into it
    created_cgroups: HashMap<String, u32>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            traffic: HashMap::new(),
            pid_traffic: HashMap::new(),
            configs: HashMap::new(),
            cgroup_paths: HashMap::new(),
            processes: HashMap::new(),
            unclassified: Vec::new(),
            rule_assignments: HashMap::new(),
            created_cgroups: HashMap::new(),
        }
    }

    pub fn update_traffic(&mut self, stats: Vec<(u64, TrafficStats)>) {
        self.traffic.clear();
        for (cgroup_id, s) in stats {
            self.traffic.insert(cgroup_id, s);
        }
    }

    pub fn update_pid_traffic(&mut self, stats: Vec<(u32, TrafficStats)>) {
        self.pid_traffic.clear();
        for (pid, s) in stats {
            self.pid_traffic.insert(pid, s);
        }
    }

    pub fn update_processes(&mut self, procs: Vec<ProcessInfo>) {
        self.processes.clear();
        for p in &procs {
            self.processes
                .entry(p.cgroup_id)
                .or_default()
                .push(p.clone());
        }
    }

    pub fn update_cgroup_path(&mut self, cgroup_id: u64, path: String) {
        self.cgroup_paths.insert(cgroup_id, path);
    }

    pub fn update_config(&mut self, cgroup_id: u64, config: RateConfig) {
        self.configs.insert(cgroup_id, config);
    }

    pub fn set_unclassified(&mut self, procs: Vec<ProcessInfo>) {
        self.unclassified = procs;
    }

    pub fn set_rule_assignment(&mut self, cgroup_id: u64, rule_name: String) {
        self.rule_assignments.insert(cgroup_id, rule_name);
    }

    pub fn track_created_cgroup(&mut self, cgroup_path: String, pid: u32) {
        self.created_cgroups.insert(cgroup_path, pid);
    }

    pub fn untrack_created_cgroup(&mut self, cgroup_path: &str) {
        self.created_cgroups.remove(cgroup_path);
    }

    pub fn get_cgroup_stats(&self) -> Vec<CgroupStats> {
        let mut result = Vec::new();
        let mut seen_cgroup_ids = std::collections::HashSet::new();

        // First: cgroups with traffic stats
        for (&cgroup_id, stats) in &self.traffic {
            seen_cgroup_ids.insert(cgroup_id);
            let cgroup_path = self
                .cgroup_paths
                .get(&cgroup_id)
                .cloned()
                .unwrap_or_default();
            let processes: Vec<ProcessInfo> = self
                .processes
                .get(&cgroup_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|mut p| {
                    if let Some(pid_stats) = self.pid_traffic.get(&p.pid) {
                        p.tx_bytes = pid_stats.tx_bytes;
                        p.rx_bytes = pid_stats.rx_bytes;
                    }
                    p
                })
                .collect();

            let matched_rule_name = self.rule_assignments.get(&cgroup_id).cloned();
            let created_by_shapebpf = self.created_cgroups.contains_key(&cgroup_path);
            let externally_modified = if let Some(&original_pid) = self.created_cgroups.get(&cgroup_path) {
                processes.is_empty()
                    || processes.len() != 1
                    || processes[0].pid != original_pid
            } else {
                false
            };

            result.push(CgroupStats {
                cgroup_id,
                cgroup_path,
                stats: *stats,
                config: self.configs.get(&cgroup_id).copied(),
                processes,
                matched_rule_name,
                created_by_shapebpf,
                externally_modified,
            });
        }

        // Second: cgroups with processes but no traffic stats (e.g. newly isolated)
        for (&cgroup_id, processes) in &self.processes {
            if seen_cgroup_ids.contains(&cgroup_id) || processes.is_empty() {
                continue;
            }
            let cgroup_path = self
                .cgroup_paths
                .get(&cgroup_id)
                .cloned()
                .unwrap_or_default();

            let processes: Vec<ProcessInfo> = processes
                .iter()
                .cloned()
                .map(|mut p| {
                    if let Some(pid_stats) = self.pid_traffic.get(&p.pid) {
                        p.tx_bytes = pid_stats.tx_bytes;
                        p.rx_bytes = pid_stats.rx_bytes;
                    }
                    p
                })
                .collect();

            let matched_rule_name = self.rule_assignments.get(&cgroup_id).cloned();
            let created_by_shapebpf = self.created_cgroups.contains_key(&cgroup_path);
            let externally_modified = if let Some(&original_pid) = self.created_cgroups.get(&cgroup_path) {
                processes.is_empty()
                    || processes.len() != 1
                    || processes[0].pid != original_pid
            } else {
                false
            };

            result.push(CgroupStats {
                cgroup_id,
                cgroup_path,
                stats: TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: 0,
                },
                config: self.configs.get(&cgroup_id).copied(),
                processes,
                matched_rule_name,
                created_by_shapebpf,
                externally_modified,
            });
        }

        result.sort_by(|a, b| b.stats.tx_bytes.cmp(&a.stats.tx_bytes));
        result
    }

    pub fn get_unclassified(&self) -> Vec<ProcessInfo> {
        self.unclassified.clone()
    }

    pub fn get_unclassified_grouped(&self) -> Vec<UnclassifiedCgroup> {
        let mut groups: HashMap<u64, UnclassifiedCgroup> = HashMap::new();
        for p in &self.unclassified {
            groups
                .entry(p.cgroup_id)
                .or_insert_with(|| UnclassifiedCgroup {
                    cgroup_id: p.cgroup_id,
                    cgroup_path: p.cgroup_path.clone(),
                    processes: Vec::new(),
                })
                .processes
                .push(p.clone());
        }
        let mut result: Vec<UnclassifiedCgroup> = groups.into_values().collect();
        result.sort_by(|a, b| b.processes.len().cmp(&a.processes.len()));
        result
    }
}
