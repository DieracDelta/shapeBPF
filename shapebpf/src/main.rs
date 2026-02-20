mod daemon;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;

use daemon::config::Config;
use daemon::discovery::Discovery;
use daemon::ebpf_loader::EbpfLoader;
use daemon::ipc_server::IpcServer;
use daemon::qos::QosManager;
use daemon::rules::RuleEngine;
use daemon::stats::StatsCollector;
use shapebpf_common::ipc::{MatchCriteria, Rule};
use shapebpf_common::RateConfig;

const DEFAULT_CONFIG_PATH: &str = "/etc/shapebpf/config.toml";
const SOCKET_PATH: &str = "/run/shapebpf/shapebpf.sock";
const RULES_PATH: &str = "/var/lib/shapebpf/rules.json";

#[derive(Parser)]
#[command(name = "shapebpf-daemon", about = "Per-process bandwidth shaping daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the daemon
    Run {
        /// Path to config file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Show daemon status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config: config_path } => run_daemon(config_path).await,
        Commands::Status => check_status().await,
    }
}

async fn run_daemon(config_path: PathBuf) -> Result<()> {
    log::info!("loading config from {}", config_path.display());
    let config = Config::load(&config_path)?;

    log::info!("loading eBPF programs");
    let loader = EbpfLoader::load()?;

    // Set default rate limit (non-fatal if qdisc isn't loaded)
    let loader = Arc::new(Mutex::new(loader));
    {
        let mut l = loader.lock().await;
        if l.qdisc_loaded() {
            l.set_default_config(RateConfig {
                egress_rate_bps: config.default_rule.egress_rate_bps,
                ingress_rate_bps: config.default_rule.ingress_rate_bps,
                priority: config.default_rule.priority,
                _pad: [0; 7],
            })?;
        } else {
            log::warn!("qdisc not loaded - rate limiting disabled, running in monitor-only mode");
        }
    }

    // Load rules: try persisted file first, fall back to config
    let rules_path = std::path::Path::new(RULES_PATH);
    let mut rule_engine = RuleEngine::new();
    match RuleEngine::load_rules_from_file(rules_path) {
        Ok(rules) => {
            log::info!("loaded {} rules from {}", rules.len(), RULES_PATH);
            rule_engine.load_rules(rules);
        }
        Err(_) => {
            log::info!("no persisted rules file, seeding from config");
            let rules: Vec<Rule> = config
                .rules
                .iter()
                .map(|r| {
                    let criteria = if let Some(ref user) = r.user {
                        MatchCriteria::User(user.clone())
                    } else if let Some(ref container) = r.container_name {
                        MatchCriteria::ContainerName(container.clone())
                    } else if let Some(ref unit) = r.service_unit {
                        MatchCriteria::ServiceUnit(unit.clone())
                    } else if let Some(ref path) = r.cgroup_path {
                        MatchCriteria::CgroupPath(path.clone())
                    } else if let Some(ref name) = r.process_name {
                        MatchCriteria::ProcessName(name.clone())
                    } else {
                        MatchCriteria::ProcessName(r.name.clone())
                    };
                    Rule {
                        name: r.name.clone(),
                        match_criteria: criteria,
                        egress_rate_bps: r.egress_rate_bps,
                        ingress_rate_bps: r.ingress_rate_bps,
                        priority: r.priority,
                        ephemeral: false,
                    }
                })
                .collect();
            rule_engine.load_rules(rules);
        }
    }
    // Ensure persistence directory exists and configure auto-save
    if let Some(parent) = rules_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log::warn!("failed to create {}: {e:#}", parent.display());
        }
    }
    rule_engine.set_rules_path(rules_path.to_path_buf());
    rule_engine.save_rules();
    let rules = Arc::new(Mutex::new(rule_engine));

    let stats = Arc::new(Mutex::new(StatsCollector::new()));

    // Set up qdisc on the interface
    let mut qos = QosManager::new(config.general.interface.clone());
    if let Err(e) = qos.attach_qdisc() {
        log::warn!("failed to attach qdisc to {}: {e:#}", config.general.interface);
        log::warn!("rate limiting will not be active (monitor-only mode)");
    }

    // Start IPC server
    let ipc = IpcServer::bind(
        std::path::Path::new(SOCKET_PATH),
        Arc::clone(&loader),
        Arc::clone(&rules),
        Arc::clone(&stats),
    )?;

    // Spawn stats collection loop
    let stats_clone = Arc::clone(&stats);
    let loader_clone = Arc::clone(&loader);
    let interval = config.general.stats_interval_ms;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval));
        loop {
            tick.tick().await;
            let loader = loader_clone.lock().await;
            if let Ok(traffic) = loader.read_traffic_stats() {
                let mut s = stats_clone.lock().await;
                s.update_traffic(traffic);
            }
            if let Ok(pid_traffic) = loader.read_pid_traffic_stats() {
                let mut s = stats_clone.lock().await;
                s.update_pid_traffic(pid_traffic);
            }
            if let Ok(wire_traffic) = loader.read_wire_traffic_stats() {
                let mut s = stats_clone.lock().await;
                s.update_wire_traffic(wire_traffic);
            }
            if let Ok(pid_wire) = loader.read_pid_wire_traffic_stats() {
                let mut s = stats_clone.lock().await;
                s.update_pid_wire_traffic(pid_wire);
            }
        }
    });

    // Spawn discovery loop
    let stats_clone2 = Arc::clone(&stats);
    let loader_clone2 = Arc::clone(&loader);
    let rules_clone = Arc::clone(&rules);
    tokio::spawn(async move {
        let mut discovery = Discovery::new();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tick.tick().await;
            // Refresh container names
            if let Err(e) = discovery.refresh_containers().await {
                log::debug!("container discovery: {e:#}");
            }
            // Read process events from BPF
            let mut loader = loader_clone2.lock().await;
            if let Ok(events) = loader.read_process_events() {
                let mut procs = Vec::new();
                let mut unclassified = Vec::new();
                let mut rule_assignments = Vec::new();
                let mut rule_configs: Vec<(u64, RateConfig)> = Vec::new();
                for (_pid, ev) in &events {
                    let comm = core::str::from_utf8(&ev.comm)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                    let cgroup_path = Discovery::pid_cgroup_path(ev.pid)
                        .unwrap_or_default();
                    // Use live cgroup_id from the filesystem (process may have been
                    // moved since the BPF tracepoint captured ev.cgroup_id at exec)
                    let live_cgroup_id = if !cgroup_path.is_empty() {
                        let sys_path = format!("/sys/fs/cgroup{cgroup_path}");
                        std::fs::metadata(&sys_path)
                            .ok()
                            .map(|m| {
                                use std::os::unix::fs::MetadataExt;
                                m.ino()
                            })
                            .unwrap_or(ev.cgroup_id)
                    } else {
                        ev.cgroup_id
                    };
                    let container_id = Discovery::container_id_from_cgroup(&cgroup_path);
                    let container_name = container_id
                        .as_deref()
                        .and_then(|id| discovery.container_name(id));
                    let service_unit = Discovery::service_unit_from_cgroup(&cgroup_path);

                    let pi = shapebpf_common::ipc::ProcessInfo {
                        pid: ev.pid,
                        uid: ev.uid,
                        comm: comm.clone(),
                        cgroup_id: live_cgroup_id,
                        cgroup_path: cgroup_path.clone(),
                        tx_bytes: 0,
                        rx_bytes: 0,
                        wire_tx_bytes: 0,
                        wire_rx_bytes: 0,
                    };

                    let rules = rules_clone.lock().await;
                    match rules.match_process(
                        ev.pid,
                        ev.uid,
                        &comm,
                        &cgroup_path,
                        container_name,
                        service_unit.as_deref(),
                    ) {
                        Some(rule) => {
                            let config = RuleEngine::rule_to_rate_config(rule);
                            rule_assignments.push((live_cgroup_id, rule.name.clone()));
                            rule_configs.push((live_cgroup_id, config));
                        }
                        None => {
                            unclassified.push(pi.clone());
                        }
                    }
                    procs.push(pi);
                }
                // Apply rate limits to BPF maps for matched rules
                for &(cgroup_id, config) in &rule_configs {
                    if let Err(e) = loader.set_cgroup_limit(cgroup_id, config) {
                        log::debug!("set_cgroup_limit for rule match: {e:#}");
                    }
                }
                let mut s = stats_clone2.lock().await;
                // Update configs in stats for TUI display
                for &(cgroup_id, config) in &rule_configs {
                    s.update_config(cgroup_id, config);
                }
                // Populate cgroup paths so the main view can display them
                for p in &procs {
                    if !p.cgroup_path.is_empty() {
                        s.update_cgroup_path(p.cgroup_id, p.cgroup_path.clone());
                    }
                }
                // Track rule assignments
                for (cgroup_id, rule_name) in rule_assignments {
                    s.set_rule_assignment(cgroup_id, rule_name);
                }
                s.update_processes(procs);
                s.set_unclassified(unclassified);
            }
            drop(loader);

            // Resolve cgroup paths for traffic entries without known paths
            {
                let s = stats_clone2.lock().await;
                let unknown_ids: Vec<u64> = s.traffic_cgroup_ids_without_paths();
                drop(s);

                for cgroup_id in unknown_ids {
                    if let Some(path) = Discovery::resolve_cgroup_path(cgroup_id) {
                        let mut s = stats_clone2.lock().await;
                        s.update_cgroup_path(cgroup_id, format!("/{path}"));
                    }
                }
            }

            // Cgroup-level rule matching: apply rules to cgroups by path
            // (catches cgroups whose processes aren't in PID_CGROUP_MAP,
            // e.g. services started before BPF loaded)
            {
                let s = stats_clone2.lock().await;
                let cgroup_paths = s.all_cgroup_paths();
                drop(s);

                let rules = rules_clone.lock().await;
                let mut cgroup_rule_configs = Vec::new();
                let mut cgroup_rule_assignments = Vec::new();

                for (cgroup_id, cgroup_path) in &cgroup_paths {
                    let service_unit = Discovery::service_unit_from_cgroup(cgroup_path);
                    let container_id = Discovery::container_id_from_cgroup(cgroup_path);
                    let container_name = container_id
                        .as_deref()
                        .and_then(|id| discovery.container_name(id));

                    if let Some(rule) = rules.match_cgroup(
                        cgroup_path,
                        container_name,
                        service_unit.as_deref(),
                    ) {
                        let config = RuleEngine::rule_to_rate_config(rule);
                        cgroup_rule_assignments.push((*cgroup_id, rule.name.clone()));
                        cgroup_rule_configs.push((*cgroup_id, config));
                    }
                }
                drop(rules);

                let mut loader = loader_clone2.lock().await;
                for &(cgroup_id, config) in &cgroup_rule_configs {
                    if let Err(e) = loader.set_cgroup_limit(cgroup_id, config) {
                        log::debug!("set_cgroup_limit for cgroup match: {e:#}");
                    }
                }
                drop(loader);

                let mut s = stats_clone2.lock().await;
                for &(cgroup_id, config) in &cgroup_rule_configs {
                    s.update_config(cgroup_id, config);
                }
                for (cgroup_id, rule_name) in cgroup_rule_assignments {
                    s.set_rule_assignment(cgroup_id, rule_name);
                }
            }
        }
    });

    log::info!("shapebpf daemon running");
    ipc.serve().await
}

async fn check_status() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use shapebpf_common::ipc::{Request, Response};

    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .context("connecting to daemon - is it running?")?;

    let req = bincode::serialize(&Request::GetStats)?;
    stream.write_u32(req.len() as u32).await?;
    stream.write_all(&req).await?;

    let len = stream.read_u32().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let resp: Response = bincode::deserialize(&buf)?;

    match resp {
        Response::Stats(stats) => {
            println!("shapebpf daemon is running");
            println!("{} cgroups tracked", stats.len());
            for s in &stats {
                println!(
                    "  cgroup {} ({}): TX {}/s RX {}/s",
                    s.cgroup_id,
                    s.cgroup_path,
                    format_bytes(s.stats.tx_bytes),
                    format_bytes(s.stats.rx_bytes),
                );
            }
        }
        Response::Error(e) => println!("error: {e}"),
        _ => println!("unexpected response"),
    }
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
