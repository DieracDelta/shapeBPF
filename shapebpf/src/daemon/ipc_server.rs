use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use shapebpf_common::ipc::{Request, Response};

use super::ebpf_loader::EbpfLoader;
use super::rules::RuleEngine;
use super::stats::StatsCollector;

const CGROUP_FS_PREFIX: &str = "/sys/fs/cgroup";

fn sysfs_to_relative(path: &str) -> String {
    path.strip_prefix(CGROUP_FS_PREFIX).unwrap_or(path).to_string()
}

fn relative_to_sysfs(path: &str) -> String {
    if path.starts_with(CGROUP_FS_PREFIX) {
        path.to_string()
    } else {
        format!("{CGROUP_FS_PREFIX}{path}")
    }
}

pub struct IpcServer {
    listener: UnixListener,
    loader: Arc<Mutex<EbpfLoader>>,
    rules: Arc<Mutex<RuleEngine>>,
    stats: Arc<Mutex<StatsCollector>>,
}

impl IpcServer {
    pub fn bind(
        socket_path: &Path,
        loader: Arc<Mutex<EbpfLoader>>,
        rules: Arc<Mutex<RuleEngine>>,
        stats: Arc<Mutex<StatsCollector>>,
    ) -> Result<Self> {
        // Remove stale socket file
        let _ = std::fs::remove_file(socket_path);

        // Create parent directory
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        let listener =
            UnixListener::bind(socket_path).context("binding Unix socket")?;

        // Set socket group permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
                .context("setting socket permissions")?;
        }

        Ok(Self {
            listener,
            loader,
            rules,
            stats,
        })
    }

    pub async fn serve(self) -> Result<()> {
        log::info!("IPC server listening");
        loop {
            let (stream, _addr) = self.listener.accept().await.context("accepting connection")?;
            let loader = Arc::clone(&self.loader);
            let rules = Arc::clone(&self.rules);
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, loader, rules, stats).await {
                    log::error!("client error: {e:#}");
                }
            });
        }
    }
}

async fn handle_client(
    mut stream: UnixStream,
    loader: Arc<Mutex<EbpfLoader>>,
    rules: Arc<Mutex<RuleEngine>>,
    stats: Arc<Mutex<StatsCollector>>,
) -> Result<()> {
    loop {
        // Read length-prefixed message
        let len = match stream.read_u32().await {
            Ok(n) => n as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if len > 16 * 1024 * 1024 {
            anyhow::bail!("message too large: {len} bytes");
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.context("reading request body")?;
        let request: Request = bincode::deserialize(&buf).context("deserializing request")?;

        let response = dispatch(request, &loader, &rules, &stats).await;

        let resp_bytes = bincode::serialize(&response).context("serializing response")?;
        stream.write_u32(resp_bytes.len() as u32).await?;
        stream.write_all(&resp_bytes).await?;
    }
}

async fn dispatch(
    request: Request,
    loader: &Arc<Mutex<EbpfLoader>>,
    rules: &Arc<Mutex<RuleEngine>>,
    stats: &Arc<Mutex<StatsCollector>>,
) -> Response {
    match request {
        Request::GetStats => {
            let stats = stats.lock().await;
            Response::Stats(stats.get_cgroup_stats())
        }
        Request::GetRules => {
            let rules = rules.lock().await;
            Response::Rules(rules.get_rules())
        }
        Request::SetCgroupLimit { cgroup_id, config } => {
            let mut loader = loader.lock().await;
            match loader.set_cgroup_limit(cgroup_id, config) {
                Ok(()) => {
                    if let Err(e) = loader.set_ingress_limit(cgroup_id, config) {
                        log::debug!("set_ingress_limit: {e:#}");
                    }
                    Response::Ok
                }
                Err(e) => Response::Error(format!("{e:#}")),
            }
        }
        Request::SetUidLimit { uid, config } => {
            let mut loader = loader.lock().await;
            match loader.set_uid_limit(uid, config) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(format!("{e:#}")),
            }
        }
        Request::SetDefault { config } => {
            let mut loader = loader.lock().await;
            match loader.set_default_config(config) {
                Ok(()) => {
                    if let Err(e) = loader.set_ingress_default_config(config) {
                        log::debug!("set_ingress_default_config: {e:#}");
                    }
                    Response::Ok
                }
                Err(e) => Response::Error(format!("{e:#}")),
            }
        }
        Request::ClassifyProcess { pid, rule_name } => {
            let mut rules = rules.lock().await;
            rules.classify_process(pid, &rule_name);
            Response::Ok
        }
        Request::UpsertRule { rule } => {
            let mut rules = rules.lock().await;
            rules.upsert_rule(rule);
            Response::Ok
        }
        Request::DeleteRule { name } => {
            let mut rules = rules.lock().await;
            rules.delete_rule(&name);
            Response::Ok
        }
        Request::GetUnclassified => {
            let stats = stats.lock().await;
            Response::Unclassified(stats.get_unclassified())
        }
        Request::GetUnclassifiedGrouped => {
            let stats = stats.lock().await;
            Response::UnclassifiedGrouped(stats.get_unclassified_grouped())
        }
        Request::IsolatePid { pid, name } => {
            match isolate_pid_to_cgroup(pid, &name) {
                Ok((new_cgroup_id, sysfs_path)) => {
                    // Convert to relative path for consistent tracking/matching
                    let relative_path = sysfs_to_relative(&sysfs_path);
                    let mut s = stats.lock().await;
                    s.track_created_cgroup(relative_path.clone(), pid);
                    Response::Isolated {
                        new_cgroup_id,
                        new_cgroup_path: relative_path,
                    }
                }
                Err(e) => Response::Error(format!("{e:#}")),
            }
        }
        Request::MergeCgroupBack {
            cgroup_path,
            rule_name,
        } => {
            match merge_cgroup_back(&cgroup_path, rule_name.as_deref(), loader, rules, stats).await
            {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(format!("{e:#}")),
            }
        }
    }
}

async fn merge_cgroup_back(
    cgroup_path: &str,
    rule_name: Option<&str>,
    loader: &Arc<Mutex<EbpfLoader>>,
    rules: &Arc<Mutex<RuleEngine>>,
    stats: &Arc<Mutex<StatsCollector>>,
) -> Result<()> {
    // cgroup_path arrives as a relative path (from discovery/TUI);
    // convert to sysfs for filesystem operations.
    let sysfs_path = relative_to_sysfs(cgroup_path);

    // Read processes from the cgroup
    let procs_content = std::fs::read_to_string(format!("{sysfs_path}/cgroup.procs"))
        .with_context(|| format!("reading {sysfs_path}/cgroup.procs"))?;

    // Determine parent cgroup path
    let parent = std::path::Path::new(&*sysfs_path)
        .parent()
        .context("cgroup has no parent")?
        .to_string_lossy()
        .to_string();

    // Move all PIDs to parent
    for line in procs_content.lines() {
        let pid = line.trim();
        if !pid.is_empty() {
            if let Err(e) = std::fs::write(format!("{parent}/cgroup.procs"), pid) {
                log::warn!("failed to move PID {pid} to parent: {e}");
            }
        }
    }

    // Get cgroup_id before removing the directory
    let cgroup_id = std::fs::metadata(&*sysfs_path)
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.ino()
        })
        .ok();

    // Remove the cgroup directory
    if let Err(e) = std::fs::remove_dir(&*sysfs_path) {
        log::warn!("failed to rmdir {sysfs_path}: {e}");
    }

    // Remove BPF map entries
    if let Some(id) = cgroup_id {
        let mut l = loader.lock().await;
        if let Err(e) = l.remove_cgroup_limit(id) {
            log::debug!("remove_cgroup_limit: {e}");
        }
        if let Err(e) = l.remove_ingress_limit(id) {
            log::debug!("remove_ingress_limit: {e}");
        }
    }

    // Delete the rule if specified
    if let Some(name) = rule_name {
        let mut r = rules.lock().await;
        r.delete_rule(name);
    }

    // Untrack using the original relative path (matches what was tracked)
    {
        let mut s = stats.lock().await;
        s.untrack_created_cgroup(cgroup_path);
    }

    Ok(())
}

/// Read a process's current cgroup path from /proc/{pid}/cgroup.
fn pid_cgroup_path(pid: u32) -> Result<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("reading /proc/{pid}/cgroup"))?;
    // cgroup v2 format: "0::/user.slice/user-0.slice/session-3.scope"
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Ok(format!("/sys/fs/cgroup{path}"));
        }
    }
    anyhow::bail!("could not determine cgroup for PID {pid}")
}

/// Create a child cgroup under the process's current cgroup and move the PID into it.
/// The parent cgroup's limits still apply; the child gets its own cgroup_id for
/// independent rate limiting.
fn isolate_pid_to_cgroup(pid: u32, name: &str) -> Result<(u64, String)> {
    let parent = pid_cgroup_path(pid)?;
    let cgroup_path = format!("{parent}/{name}-pid-{pid}");
    std::fs::create_dir(&cgroup_path)
        .with_context(|| format!("creating cgroup {cgroup_path}"))?;

    std::fs::write(format!("{cgroup_path}/cgroup.procs"), pid.to_string())
        .map_err(|e| {
            if e.raw_os_error() == Some(3) {
                anyhow::anyhow!("PID {pid} no longer exists")
            } else {
                anyhow::anyhow!("writing PID to cgroup.procs: {e:#}")
            }
        })?;

    let meta = std::fs::metadata(&cgroup_path)
        .with_context(|| format!("stat {cgroup_path}"))?;
    let new_cgroup_id = meta.ino();

    Ok((new_cgroup_id, cgroup_path))
}
