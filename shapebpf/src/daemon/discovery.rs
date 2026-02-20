use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use shapebpf_common::ipc::ProcessInfo;

/// Discovers processes and their cgroup associations.
pub struct Discovery {
    /// Container ID -> container name (from Docker/Podman)
    container_names: HashMap<String, String>,
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            container_names: HashMap::new(),
        }
    }

    /// Resolve a cgroup_id to a filesystem path by scanning /sys/fs/cgroup.
    pub fn resolve_cgroup_path(cgroup_id: u64) -> Option<String> {
        // Read /proc/self/cgroup or scan /sys/fs/cgroup for matching inode
        resolve_cgroup_by_inode(cgroup_id)
    }

    /// Check if a PID is a thread group leader (process, not a thread).
    /// Returns false for threads (TID != TGID), true for processes.
    pub fn is_thread_group_leader(pid: u32) -> bool {
        let path = format!("/proc/{pid}/status");
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return true, // dead process, let caller handle
        };
        for line in content.lines() {
            if let Some(tgid_str) = line.strip_prefix("Tgid:\t") {
                return tgid_str.trim().parse::<u32>().ok() == Some(pid);
            }
        }
        true
    }

    /// Get the cgroup path for a given PID.
    pub fn pid_cgroup_path(pid: u32) -> Option<String> {
        let path = format!("/proc/{pid}/cgroup");
        let content = fs::read_to_string(path).ok()?;
        // cgroup v2: single line like "0::/user.slice/..."
        for line in content.lines() {
            if line.starts_with("0::") {
                return Some(line[3..].to_string());
            }
        }
        None
    }

    /// Extract systemd service unit name from a cgroup path.
    pub fn service_unit_from_cgroup(cgroup_path: &str) -> Option<String> {
        // e.g. /system.slice/docker.service -> docker.service
        cgroup_path
            .rsplit('/')
            .find(|segment| segment.ends_with(".service") || segment.ends_with(".scope"))
            .map(|s| s.to_string())
    }

    /// Extract container ID from cgroup path.
    pub fn container_id_from_cgroup(cgroup_path: &str) -> Option<String> {
        // Docker: /system.slice/docker-<id>.scope
        // Podman: /machine.slice/libpod-<id>.scope
        for segment in cgroup_path.split('/') {
            if let Some(id) = segment.strip_prefix("docker-") {
                return id.strip_suffix(".scope").map(|s| s.to_string());
            }
            if let Some(id) = segment.strip_prefix("libpod-") {
                return id.strip_suffix(".scope").map(|s| s.to_string());
            }
        }
        None
    }

    /// Update container name cache from Docker.
    pub async fn refresh_containers(&mut self) -> Result<()> {
        let docker = bollard::Docker::connect_with_local_defaults()
            .context("connecting to Docker")?;
        let containers = docker
            .list_containers(None)
            .await
            .context("listing containers")?;
        self.container_names.clear();
        for c in containers {
            if let (Some(id), Some(names)) = (c.id, c.names) {
                if let Some(name) = names.first() {
                    let name = name.strip_prefix('/').unwrap_or(name);
                    self.container_names.insert(id, name.to_string());
                }
            }
        }
        Ok(())
    }

    /// Look up container name by container ID.
    pub fn container_name(&self, container_id: &str) -> Option<&str> {
        // Docker IDs in cgroup paths are full 64-char hex; container list may have short IDs
        self.container_names
            .iter()
            .find(|(id, _)| container_id.starts_with(id.as_str()) || id.starts_with(container_id))
            .map(|(_, name)| name.as_str())
    }
}

fn resolve_cgroup_by_inode(target_ino: u64) -> Option<String> {
    // Walk /sys/fs/cgroup looking for a directory whose inode matches
    walk_cgroup_tree(&PathBuf::from("/sys/fs/cgroup"), target_ino)
}

fn walk_cgroup_tree(dir: &PathBuf, target_ino: u64) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let meta = fs::metadata(dir).ok()?;
    if meta.ino() == target_ino {
        return Some(
            dir.strip_prefix("/sys/fs/cgroup")
                .ok()?
                .to_string_lossy()
                .to_string(),
        );
    }

    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(result) = walk_cgroup_tree(&path, target_ino) {
                return Some(result);
            }
        }
    }
    None
}
