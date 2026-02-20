use std::collections::HashMap;

use shapebpf_common::ipc::{CgroupStats, ProcessInfo, UnclassifiedCgroup};
use shapebpf_common::{RateConfig, TrafficStats};

/// Collects and caches traffic statistics from BPF maps.
pub struct StatsCollector {
    /// cgroup_id -> per-second rate (computed from deltas)
    traffic: HashMap<u64, TrafficStats>,
    /// pid -> per-second rate (computed from deltas)
    pid_traffic: HashMap<u32, TrafficStats>,
    /// Previous cumulative counters for delta computation
    prev_traffic: HashMap<u64, TrafficStats>,
    prev_pid_traffic: HashMap<u32, TrafficStats>,
    last_traffic_update: Option<std::time::Instant>,
    last_pid_traffic_update: Option<std::time::Instant>,
    /// Ingress (RX) per-second rates from cgroup_skb/ingress observer
    ingress_traffic: HashMap<u64, TrafficStats>,
    prev_ingress_traffic: HashMap<u64, TrafficStats>,
    last_ingress_traffic_update: Option<std::time::Instant>,
    /// cgroup_id -> per-second wire rate (post-EDT, computed from deltas)
    wire_traffic: HashMap<u64, TrafficStats>,
    /// pid -> per-second wire rate (post-EDT, computed from deltas)
    pid_wire_traffic: HashMap<u32, TrafficStats>,
    prev_wire_traffic: HashMap<u64, TrafficStats>,
    prev_pid_wire_traffic: HashMap<u32, TrafficStats>,
    last_wire_traffic_update: Option<std::time::Instant>,
    last_pid_wire_traffic_update: Option<std::time::Instant>,
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
            prev_traffic: HashMap::new(),
            prev_pid_traffic: HashMap::new(),
            last_traffic_update: None,
            last_pid_traffic_update: None,
            ingress_traffic: HashMap::new(),
            prev_ingress_traffic: HashMap::new(),
            last_ingress_traffic_update: None,
            wire_traffic: HashMap::new(),
            pid_wire_traffic: HashMap::new(),
            prev_wire_traffic: HashMap::new(),
            prev_pid_wire_traffic: HashMap::new(),
            last_wire_traffic_update: None,
            last_pid_wire_traffic_update: None,
            configs: HashMap::new(),
            cgroup_paths: HashMap::new(),
            processes: HashMap::new(),
            unclassified: Vec::new(),
            rule_assignments: HashMap::new(),
            created_cgroups: HashMap::new(),
        }
    }

    pub fn update_traffic(&mut self, stats: Vec<(u64, TrafficStats)>) {
        let now = std::time::Instant::now();
        let elapsed_secs = self
            .last_traffic_update
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001); // avoid division by zero

        self.traffic.clear();
        for &(cgroup_id, ref cumulative) in &stats {
            let rate = if let Some(prev) = self.prev_traffic.get(&cgroup_id) {
                TrafficStats {
                    tx_bytes: (cumulative.tx_bytes.saturating_sub(prev.tx_bytes) as f64
                        / elapsed_secs) as u64,
                    rx_bytes: (cumulative.rx_bytes.saturating_sub(prev.rx_bytes) as f64
                        / elapsed_secs) as u64,
                    tx_packets: (cumulative.tx_packets.saturating_sub(prev.tx_packets) as f64
                        / elapsed_secs) as u64,
                    rx_packets: (cumulative.rx_packets.saturating_sub(prev.rx_packets) as f64
                        / elapsed_secs) as u64,
                    drops: cumulative.drops,
                }
            } else {
                // First sample: no previous data, show zero rate
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: cumulative.drops,
                }
            };
            self.traffic.insert(cgroup_id, rate);
        }

        self.prev_traffic.clear();
        for (cgroup_id, cumulative) in stats {
            self.prev_traffic.insert(cgroup_id, cumulative);
        }
        self.last_traffic_update = Some(now);
    }

    pub fn update_pid_traffic(&mut self, stats: Vec<(u32, TrafficStats)>) {
        let now = std::time::Instant::now();
        let elapsed_secs = self
            .last_pid_traffic_update
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001);

        self.pid_traffic.clear();
        for &(pid, ref cumulative) in &stats {
            let rate = if let Some(prev) = self.prev_pid_traffic.get(&pid) {
                TrafficStats {
                    tx_bytes: (cumulative.tx_bytes.saturating_sub(prev.tx_bytes) as f64
                        / elapsed_secs) as u64,
                    rx_bytes: (cumulative.rx_bytes.saturating_sub(prev.rx_bytes) as f64
                        / elapsed_secs) as u64,
                    tx_packets: (cumulative.tx_packets.saturating_sub(prev.tx_packets) as f64
                        / elapsed_secs) as u64,
                    rx_packets: (cumulative.rx_packets.saturating_sub(prev.rx_packets) as f64
                        / elapsed_secs) as u64,
                    drops: cumulative.drops,
                }
            } else {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: cumulative.drops,
                }
            };
            self.pid_traffic.insert(pid, rate);
        }

        self.prev_pid_traffic.clear();
        for (pid, cumulative) in stats {
            self.prev_pid_traffic.insert(pid, cumulative);
        }
        self.last_pid_traffic_update = Some(now);
    }

    pub fn update_ingress_traffic(&mut self, stats: Vec<(u64, TrafficStats)>) {
        let now = std::time::Instant::now();
        let elapsed_secs = self
            .last_ingress_traffic_update
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001);

        self.ingress_traffic.clear();
        for &(cgroup_id, ref cumulative) in &stats {
            let rate = if let Some(prev) = self.prev_ingress_traffic.get(&cgroup_id) {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: (cumulative.rx_bytes.saturating_sub(prev.rx_bytes) as f64
                        / elapsed_secs) as u64,
                    tx_packets: 0,
                    rx_packets: (cumulative.rx_packets.saturating_sub(prev.rx_packets) as f64
                        / elapsed_secs) as u64,
                    drops: 0,
                }
            } else {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: 0,
                }
            };
            self.ingress_traffic.insert(cgroup_id, rate);
        }

        self.prev_ingress_traffic.clear();
        for (cgroup_id, cumulative) in stats {
            self.prev_ingress_traffic.insert(cgroup_id, cumulative);
        }
        self.last_ingress_traffic_update = Some(now);
    }

    pub fn update_wire_traffic(&mut self, stats: Vec<(u64, TrafficStats)>) {
        let now = std::time::Instant::now();
        let elapsed_secs = self
            .last_wire_traffic_update
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001);

        self.wire_traffic.clear();
        for &(cgroup_id, ref cumulative) in &stats {
            let rate = if let Some(prev) = self.prev_wire_traffic.get(&cgroup_id) {
                TrafficStats {
                    tx_bytes: (cumulative.tx_bytes.saturating_sub(prev.tx_bytes) as f64
                        / elapsed_secs) as u64,
                    rx_bytes: (cumulative.rx_bytes.saturating_sub(prev.rx_bytes) as f64
                        / elapsed_secs) as u64,
                    tx_packets: (cumulative.tx_packets.saturating_sub(prev.tx_packets) as f64
                        / elapsed_secs) as u64,
                    rx_packets: (cumulative.rx_packets.saturating_sub(prev.rx_packets) as f64
                        / elapsed_secs) as u64,
                    drops: cumulative.drops,
                }
            } else {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: cumulative.drops,
                }
            };
            self.wire_traffic.insert(cgroup_id, rate);
        }

        self.prev_wire_traffic.clear();
        for (cgroup_id, cumulative) in stats {
            self.prev_wire_traffic.insert(cgroup_id, cumulative);
        }
        self.last_wire_traffic_update = Some(now);
    }

    pub fn update_pid_wire_traffic(&mut self, stats: Vec<(u32, TrafficStats)>) {
        let now = std::time::Instant::now();
        let elapsed_secs = self
            .last_pid_wire_traffic_update
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001);

        self.pid_wire_traffic.clear();
        for &(pid, ref cumulative) in &stats {
            let rate = if let Some(prev) = self.prev_pid_wire_traffic.get(&pid) {
                TrafficStats {
                    tx_bytes: (cumulative.tx_bytes.saturating_sub(prev.tx_bytes) as f64
                        / elapsed_secs) as u64,
                    rx_bytes: (cumulative.rx_bytes.saturating_sub(prev.rx_bytes) as f64
                        / elapsed_secs) as u64,
                    tx_packets: (cumulative.tx_packets.saturating_sub(prev.tx_packets) as f64
                        / elapsed_secs) as u64,
                    rx_packets: (cumulative.rx_packets.saturating_sub(prev.rx_packets) as f64
                        / elapsed_secs) as u64,
                    drops: cumulative.drops,
                }
            } else {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: cumulative.drops,
                }
            };
            self.pid_wire_traffic.insert(pid, rate);
        }

        self.prev_pid_wire_traffic.clear();
        for (pid, cumulative) in stats {
            self.prev_pid_wire_traffic.insert(pid, cumulative);
        }
        self.last_pid_wire_traffic_update = Some(now);
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

    pub fn all_cgroup_paths(&self) -> Vec<(u64, String)> {
        self.cgroup_paths
            .iter()
            .map(|(&id, path)| (id, path.clone()))
            .collect()
    }

    pub fn traffic_cgroup_ids_without_paths(&self) -> Vec<u64> {
        self.traffic
            .keys()
            .filter(|id| !self.cgroup_paths.contains_key(id))
            .copied()
            .collect()
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
                    if let Some(pid_wire) = self.pid_wire_traffic.get(&p.pid) {
                        p.wire_tx_bytes = pid_wire.tx_bytes;
                        p.wire_rx_bytes = pid_wire.rx_bytes;
                    }
                    p
                })
                .collect();

            // Merge ingress RX data from cgroup_skb/ingress observer
            let ingress = self.ingress_traffic.get(&cgroup_id);

            let wire_stats = self
                .wire_traffic
                .get(&cgroup_id)
                .copied()
                .unwrap_or(TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: 0,
                });

            // Build merged stats: qdisc provides TX, ingress observer provides RX
            let merged_stats = if let Some(ing) = ingress {
                TrafficStats {
                    tx_bytes: stats.tx_bytes,
                    rx_bytes: ing.rx_bytes,
                    tx_packets: stats.tx_packets,
                    rx_packets: ing.rx_packets,
                    drops: stats.drops,
                }
            } else {
                *stats
            };

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
                stats: merged_stats,
                wire_stats,
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
                    if let Some(pid_wire) = self.pid_wire_traffic.get(&p.pid) {
                        p.wire_tx_bytes = pid_wire.tx_bytes;
                        p.wire_rx_bytes = pid_wire.rx_bytes;
                    }
                    p
                })
                .collect();

            let wire_stats = self
                .wire_traffic
                .get(&cgroup_id)
                .copied()
                .unwrap_or(TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: 0,
                });

            let matched_rule_name = self.rule_assignments.get(&cgroup_id).cloned();
            let created_by_shapebpf = self.created_cgroups.contains_key(&cgroup_path);
            let externally_modified = if let Some(&original_pid) = self.created_cgroups.get(&cgroup_path) {
                processes.is_empty()
                    || processes.len() != 1
                    || processes[0].pid != original_pid
            } else {
                false
            };

            // Merge ingress RX data even if no egress traffic
            let ingress_stats = self.ingress_traffic.get(&cgroup_id);
            let merged_stats = if let Some(ing) = ingress_stats {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: ing.rx_bytes,
                    tx_packets: 0,
                    rx_packets: ing.rx_packets,
                    drops: 0,
                }
            } else {
                TrafficStats {
                    tx_bytes: 0,
                    rx_bytes: 0,
                    tx_packets: 0,
                    rx_packets: 0,
                    drops: 0,
                }
            };

            result.push(CgroupStats {
                cgroup_id,
                cgroup_path,
                stats: merged_stats,
                wire_stats,
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
