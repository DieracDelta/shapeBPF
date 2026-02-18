#![cfg_attr(not(feature = "userspace"), no_std)]

// ── Shared #[repr(C)] types for BPF maps ──

/// Per-cgroup rate limit configuration.
/// Stored in RATE_LIMITS (keyed by cgroup_id) and UID_LIMITS (keyed by uid).
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "userspace", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct RateConfig {
    /// Egress rate limit in bytes per second (0 = unlimited)
    pub egress_rate_bps: u64,
    /// Ingress rate limit in bytes per second (0 = unlimited)
    pub ingress_rate_bps: u64,
    /// Priority level (1 = highest, 10 = lowest)
    pub priority: u8,
    pub _pad: [u8; 7],
}

/// Per-cgroup EDT (Earliest Departure Time) pacing state.
/// Stored in EDT_STATE map, keyed by cgroup_id.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "userspace", derive(Debug))]
pub struct EdtState {
    /// Next allowed departure time in nanoseconds (monotonic)
    pub next_departure_ns: u64,
    /// Burst allowance remaining in bytes
    pub burst_remaining: u64,
}

/// Per-cgroup traffic statistics.
/// Stored in TRAFFIC_STATS map, keyed by cgroup_id.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "userspace", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct TrafficStats {
    /// Total bytes sent (egress)
    pub tx_bytes: u64,
    /// Total bytes received (ingress)
    pub rx_bytes: u64,
    /// Total packets sent
    pub tx_packets: u64,
    /// Total packets received
    pub rx_packets: u64,
    /// Packets dropped due to rate limit
    pub drops: u64,
}

/// Process discovery event from sched_process_exec tracepoint.
/// Stored in PID_CGROUP_MAP, keyed by pid.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "userspace", derive(Debug))]
pub struct ProcessEvent {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Cgroup inode ID
    pub cgroup_id: u64,
    /// Process name (comm), null-terminated
    pub comm: [u8; 16],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EdtState {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TrafficStats {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProcessEvent {}

// ── IPC protocol (userspace only) ──

#[cfg(feature = "userspace")]
pub mod ipc {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Request {
        GetStats,
        GetRules,
        SetCgroupLimit {
            cgroup_id: u64,
            config: super::RateConfig,
        },
        SetUidLimit {
            uid: u32,
            config: super::RateConfig,
        },
        SetDefault {
            config: super::RateConfig,
        },
        ClassifyProcess {
            pid: u32,
            rule_name: String,
        },
        UpsertRule {
            rule: Rule,
        },
        DeleteRule {
            name: String,
        },
        GetUnclassified,
        GetUnclassifiedGrouped,
        IsolatePid {
            pid: u32,
            name: String,
        },
        MergeCgroupBack {
            cgroup_path: String,
            rule_name: Option<String>,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Response {
        Stats(Vec<CgroupStats>),
        Rules(Vec<Rule>),
        Unclassified(Vec<ProcessInfo>),
        UnclassifiedGrouped(Vec<UnclassifiedCgroup>),
        Isolated {
            new_cgroup_id: u64,
            new_cgroup_path: String,
        },
        Ok,
        Error(String),
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UnclassifiedCgroup {
        pub cgroup_id: u64,
        pub cgroup_path: String,
        pub processes: Vec<ProcessInfo>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CgroupStats {
        pub cgroup_id: u64,
        pub cgroup_path: String,
        pub stats: super::TrafficStats,
        pub config: Option<super::RateConfig>,
        pub processes: Vec<ProcessInfo>,
        /// Name of the rule that matched this cgroup (if any)
        pub matched_rule_name: Option<String>,
        /// Whether this cgroup was created by shapebpf (via IsolatePid)
        pub created_by_shapebpf: bool,
        /// Whether the cgroup's process list has changed since we created it
        pub externally_modified: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProcessInfo {
        pub pid: u32,
        pub uid: u32,
        pub comm: String,
        pub cgroup_id: u64,
        pub cgroup_path: String,
        pub tx_bytes: u64,
        pub rx_bytes: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Rule {
        pub name: String,
        pub match_criteria: MatchCriteria,
        pub egress_rate_bps: Option<u64>,
        pub ingress_rate_bps: Option<u64>,
        pub priority: u8,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum MatchCriteria {
        User(String),
        ContainerName(String),
        ServiceUnit(String),
        CgroupPath(String),
        ProcessName(String),
    }
}
