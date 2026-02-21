use std::ffi::OsStr;

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use aya::Ebpf;
use libbpf_rs::MapCore;
use shapebpf_common::{ProcessEvent, RateConfig, TrafficStats};

/// The compiled aya eBPF object (tracepoints for process discovery).
/// Built by xtask (cargo xtask build-ebpf).
static TRACEPOINT_OBJ: &[u8] = aya::include_bytes_aligned!(
    "../../../shapebpf-ebpf/target/bpfel-unknown-none/release/shapebpf-ebpf"
);

/// The compiled C eBPF object (struct_ops qdisc).
/// Built by xtask (clang compilation of qdisc.bpf.c).
static QDISC_OBJ: &[u8] = include_bytes!(
    "../../../shapebpf-ebpf/target/bpf/qdisc.bpf.o"
);

/// The compiled C eBPF object (cgroup_skb ingress observer).
/// Built by xtask (clang compilation of ingress.bpf.c).
static INGRESS_OBJ: &[u8] = include_bytes!(
    "../../../shapebpf-ebpf/target/bpf/ingress.bpf.o"
);

pub struct EbpfLoader {
    /// aya-managed eBPF for tracepoints + PID_CGROUP_MAP
    bpf: Ebpf,
    /// libbpf-rs-managed eBPF for struct_ops qdisc + rate limit maps
    qdisc_obj: Option<libbpf_rs::Object>,
    /// Keeps struct_ops link alive
    _qdisc_link: Option<libbpf_rs::Link>,
    /// libbpf-rs-managed eBPF for cgroup_skb ingress observer
    ingress_obj: Option<libbpf_rs::Object>,
    /// Keeps cgroup_skb/ingress link alive
    _ingress_link: Option<libbpf_rs::Link>,
}

// SAFETY: libbpf_rs::Object contains NonNull<bpf_object> which is !Send,
// but we only access it behind a tokio::sync::Mutex, ensuring single-threaded
// access. The underlying bpf_object is a heap allocation safe to move between threads.
unsafe impl Send for EbpfLoader {}

impl EbpfLoader {
    /// Load and attach all eBPF programs.
    pub fn load() -> Result<Self> {
        // ── Phase 1: Load tracepoints via aya ──
        let mut bpf = Ebpf::load(TRACEPOINT_OBJ).context("loading tracepoint eBPF object")?;

        use aya::programs::TracePoint;
        let exec_prog: &mut TracePoint = bpf
            .program_mut("sched_process_exec")
            .context("sched_process_exec program not found")?
            .try_into()
            .context("not a TracePoint")?;
        exec_prog.load().context("loading sched_process_exec")?;
        exec_prog
            .attach("sched", "sched_process_exec")
            .context("attaching sched_process_exec")?;

        let fork_prog: &mut TracePoint = bpf
            .program_mut("sched_process_fork")
            .context("sched_process_fork program not found")?
            .try_into()
            .context("not a TracePoint")?;
        fork_prog.load().context("loading sched_process_fork")?;
        fork_prog
            .attach("sched", "sched_process_fork")
            .context("attaching sched_process_fork")?;

        let exit_prog: &mut TracePoint = bpf
            .program_mut("sched_process_exit")
            .context("sched_process_exit program not found")?
            .try_into()
            .context("not a TracePoint")?;
        exit_prog.load().context("loading sched_process_exit")?;
        exit_prog
            .attach("sched", "sched_process_exit")
            .context("attaching sched_process_exit")?;

        // ── Phase 2: Load qdisc struct_ops via libbpf-rs ──
        let (qdisc_obj, qdisc_link) = match Self::load_qdisc() {
            Ok((obj, link)) => {
                log::info!("sch_bpf qdisc loaded successfully");
                (Some(obj), Some(link))
            }
            Err(e) => {
                log::warn!("failed to load sch_bpf qdisc (kernel 6.16+ required): {e:#}");
                log::warn!("running in monitor-only mode (no rate limiting)");
                (None, None)
            }
        };

        // ── Phase 3: Load cgroup_skb ingress observer via libbpf-rs ──
        let (ingress_obj, ingress_link) = match Self::load_ingress() {
            Ok((obj, link)) => {
                log::info!("cgroup_skb/ingress observer loaded successfully");
                (Some(obj), Some(link))
            }
            Err(e) => {
                log::warn!("failed to load cgroup_skb/ingress observer: {e:#}");
                log::warn!("ingress (RX) stats will not be available");
                (None, None)
            }
        };

        Ok(Self {
            bpf,
            qdisc_obj,
            _qdisc_link: qdisc_link,
            ingress_obj,
            _ingress_link: ingress_link,
        })
    }

    fn load_qdisc() -> Result<(libbpf_rs::Object, libbpf_rs::Link)> {
        // Unregister any stale struct_ops from a previous daemon instance
        Self::unregister_stale_struct_ops();

        let mut obj_builder = libbpf_rs::ObjectBuilder::default();
        let open_obj = obj_builder
            .open_memory(QDISC_OBJ)
            .context("opening qdisc BPF object")?;

        let mut obj = open_obj.load().context("loading qdisc BPF object")?;

        // Find and attach the struct_ops map (which registers the Qdisc_ops)
        let link = obj
            .maps_mut()
            .find(|m| m.name() == OsStr::new("shapebpf_qdisc"))
            .context("shapebpf_qdisc struct_ops map not found")?
            .attach_struct_ops()
            .context("attaching shapebpf_qdisc struct_ops")?;

        Ok((obj, link))
    }

    fn load_ingress() -> Result<(libbpf_rs::Object, libbpf_rs::Link)> {
        let mut obj_builder = libbpf_rs::ObjectBuilder::default();
        let open_obj = obj_builder
            .open_memory(INGRESS_OBJ)
            .context("opening ingress BPF object")?;

        let obj = open_obj.load().context("loading ingress BPF object")?;

        // Find the cgroup_skb/ingress program
        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "shapebpf_ingress")
            .context("shapebpf_ingress program not found")?;

        // Attach to root cgroup for system-wide ingress observation
        let cgroup_fd = std::fs::File::open("/sys/fs/cgroup")
            .context("opening root cgroup")?;
        use std::os::unix::io::AsRawFd;
        let link = prog
            .attach_cgroup(cgroup_fd.as_raw_fd())
            .context("attaching cgroup_skb/ingress to root cgroup")?;

        Ok((obj, link))
    }

    /// Unregister any stale shapebpf_qdisc struct_ops left over from a previous
    /// daemon instance that didn't clean up (e.g. crash, SIGKILL, restart).
    fn unregister_stale_struct_ops() {
        let output = std::process::Command::new("bpftool")
            .args(["struct_ops", "unregister", "name", "shapebpf_qdisc"])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                log::info!("unregistered stale shapebpf_qdisc struct_ops");
            }
            _ => {} // Not found or bpftool unavailable — fine, nothing to clean up
        }
    }

    /// Whether the qdisc is loaded (rate limiting active).
    pub fn qdisc_loaded(&self) -> bool {
        self.qdisc_obj.is_some()
    }

    /// Whether the ingress program is loaded.
    pub fn ingress_loaded(&self) -> bool {
        self.ingress_obj.is_some()
    }

    /// Set a per-cgroup rate limit in the qdisc's BPF map.
    pub fn set_cgroup_limit(&mut self, cgroup_id: u64, config: RateConfig) -> Result<()> {
        let obj = self.qdisc_obj.as_mut().context("qdisc not loaded")?;
        let map = find_map_mut(obj, "RATE_LIMITS")?;
        let key = cgroup_id.to_ne_bytes();
        let val = as_bytes(&config);
        map.update(&key, val, libbpf_rs::MapFlags::ANY)
            .context("updating RATE_LIMITS")?;
        Ok(())
    }

    /// Remove a per-cgroup rate limit from the qdisc's BPF map.
    pub fn remove_cgroup_limit(&mut self, cgroup_id: u64) -> Result<()> {
        let obj = self.qdisc_obj.as_mut().context("qdisc not loaded")?;
        let map = find_map_mut(obj, "RATE_LIMITS")?;
        let key = cgroup_id.to_ne_bytes();
        map.delete(&key)
            .context("deleting from RATE_LIMITS")?;
        Ok(())
    }

    /// Set a per-UID rate limit in the qdisc's BPF map.
    pub fn set_uid_limit(&mut self, uid: u32, config: RateConfig) -> Result<()> {
        let obj = self.qdisc_obj.as_mut().context("qdisc not loaded")?;
        let map = find_map_mut(obj, "UID_LIMITS")?;
        let key = uid.to_ne_bytes();
        let val = as_bytes(&config);
        map.update(&key, val, libbpf_rs::MapFlags::ANY)
            .context("updating UID_LIMITS")?;
        Ok(())
    }

    /// Set the default rate limit config.
    pub fn set_default_config(&mut self, config: RateConfig) -> Result<()> {
        let obj = self.qdisc_obj.as_mut().context("qdisc not loaded")?;
        let map = find_map_mut(obj, "DEFAULT_CONFIG")?;
        let key = 0u32.to_ne_bytes();
        let val = as_bytes(&config);
        map.update(&key, val, libbpf_rs::MapFlags::ANY)
            .context("updating DEFAULT_CONFIG")?;
        Ok(())
    }

    /// Set a per-cgroup ingress rate limit in the ingress BPF map.
    pub fn set_ingress_limit(&mut self, cgroup_id: u64, config: RateConfig) -> Result<()> {
        let obj = self.ingress_obj.as_mut().context("ingress not loaded")?;
        let map = find_map_mut(obj, "INGRESS_RATE_LIMITS")?;
        let key = cgroup_id.to_ne_bytes();
        let val = as_bytes(&config);
        map.update(&key, val, libbpf_rs::MapFlags::ANY)
            .context("updating INGRESS_RATE_LIMITS")?;
        Ok(())
    }

    /// Remove a per-cgroup ingress rate limit from the ingress BPF map.
    pub fn remove_ingress_limit(&mut self, cgroup_id: u64) -> Result<()> {
        let obj = self.ingress_obj.as_mut().context("ingress not loaded")?;
        let map = find_map_mut(obj, "INGRESS_RATE_LIMITS")?;
        let key = cgroup_id.to_ne_bytes();
        map.delete(&key)
            .context("deleting from INGRESS_RATE_LIMITS")?;
        Ok(())
    }

    /// Set the default ingress rate limit config.
    pub fn set_ingress_default_config(&mut self, config: RateConfig) -> Result<()> {
        let obj = self.ingress_obj.as_mut().context("ingress not loaded")?;
        let map = find_map_mut(obj, "INGRESS_DEFAULT_CONFIG")?;
        let key = 0u32.to_ne_bytes();
        let val = as_bytes(&config);
        map.update(&key, val, libbpf_rs::MapFlags::ANY)
            .context("updating INGRESS_DEFAULT_CONFIG")?;
        Ok(())
    }

    /// Read all traffic stats from the qdisc's BPF map.
    pub fn read_traffic_stats(&self) -> Result<Vec<(u64, TrafficStats)>> {
        let obj = match self.qdisc_obj.as_ref() {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        let map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("TRAFFIC_STATS"))
            .context("TRAFFIC_STATS map not found")?;
        let mut results = Vec::new();
        for key in map.keys() {
            if key.len() != 8 {
                continue;
            }
            let cgroup_id = u64::from_ne_bytes(key[..8].try_into().unwrap());
            if let Some(val_bytes) = map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if val_bytes.len() >= core::mem::size_of::<TrafficStats>() {
                    let stats: TrafficStats =
                        unsafe { core::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };
                    results.push((cgroup_id, stats));
                }
            }
        }
        Ok(results)
    }

    /// Read per-PID traffic stats from the qdisc's BPF map.
    pub fn read_pid_traffic_stats(&self) -> Result<Vec<(u32, TrafficStats)>> {
        let obj = match self.qdisc_obj.as_ref() {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        let map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("PID_TRAFFIC_STATS"))
            .context("PID_TRAFFIC_STATS map not found")?;
        let mut results = Vec::new();
        for key in map.keys() {
            if key.len() != 4 {
                continue;
            }
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap());
            if let Some(val_bytes) = map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if val_bytes.len() >= core::mem::size_of::<TrafficStats>() {
                    let stats: TrafficStats =
                        unsafe { core::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };
                    results.push((pid, stats));
                }
            }
        }
        Ok(results)
    }

    /// Read all wire-rate traffic stats (post-EDT) from the qdisc's BPF map.
    pub fn read_wire_traffic_stats(&self) -> Result<Vec<(u64, TrafficStats)>> {
        let obj = match self.qdisc_obj.as_ref() {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        let map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("WIRE_TRAFFIC_STATS"))
            .context("WIRE_TRAFFIC_STATS map not found")?;
        let mut results = Vec::new();
        for key in map.keys() {
            if key.len() != 8 {
                continue;
            }
            let cgroup_id = u64::from_ne_bytes(key[..8].try_into().unwrap());
            if let Some(val_bytes) = map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if val_bytes.len() >= core::mem::size_of::<TrafficStats>() {
                    let stats: TrafficStats =
                        unsafe { core::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };
                    results.push((cgroup_id, stats));
                }
            }
        }
        Ok(results)
    }

    /// Read per-PID wire-rate traffic stats (post-EDT) from the qdisc's BPF map.
    pub fn read_pid_wire_traffic_stats(&self) -> Result<Vec<(u32, TrafficStats)>> {
        let obj = match self.qdisc_obj.as_ref() {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        let map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("PID_WIRE_TRAFFIC_STATS"))
            .context("PID_WIRE_TRAFFIC_STATS map not found")?;
        let mut results = Vec::new();
        for key in map.keys() {
            if key.len() != 4 {
                continue;
            }
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap());
            if let Some(val_bytes) = map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if val_bytes.len() >= core::mem::size_of::<TrafficStats>() {
                    let stats: TrafficStats =
                        unsafe { core::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };
                    results.push((pid, stats));
                }
            }
        }
        Ok(results)
    }

    /// Read ingress traffic stats from the cgroup_skb/ingress BPF map.
    pub fn read_ingress_traffic_stats(&self) -> Result<Vec<(u64, TrafficStats)>> {
        let obj = match self.ingress_obj.as_ref() {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        let map = obj
            .maps()
            .find(|m| m.name() == OsStr::new("INGRESS_TRAFFIC_STATS"))
            .context("INGRESS_TRAFFIC_STATS map not found")?;
        let mut results = Vec::new();
        for key in map.keys() {
            if key.len() != 8 {
                continue;
            }
            let cgroup_id = u64::from_ne_bytes(key[..8].try_into().unwrap());
            if let Some(val_bytes) = map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if val_bytes.len() >= core::mem::size_of::<TrafficStats>() {
                    let stats: TrafficStats =
                        unsafe { core::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };
                    results.push((cgroup_id, stats));
                }
            }
        }
        Ok(results)
    }

    /// Seed PID_CGROUP_MAP with processes that existed before the daemon started.
    /// Scans /proc for numeric PIDs, skips threads, and inserts into the BPF map.
    pub fn seed_existing_processes(&mut self) -> Result<usize> {
        use super::discovery::Discovery;

        let map = self
            .bpf
            .map_mut("PID_CGROUP_MAP")
            .context("PID_CGROUP_MAP map not found")?;
        let mut hash = BpfHashMap::<_, u32, ProcessEvent>::try_from(map)
            .context("PID_CGROUP_MAP is not a HashMap")?;

        let mut count = 0usize;
        let proc_dir = std::fs::read_dir("/proc").context("reading /proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Skip threads
            if !Discovery::is_thread_group_leader(pid) {
                continue;
            }

            // Read comm
            let comm_path = format!("/proc/{pid}/comm");
            let comm_str = std::fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim_end()
                .to_string();
            let mut comm = [0u8; 16];
            let bytes = comm_str.as_bytes();
            let len = bytes.len().min(15);
            comm[..len].copy_from_slice(&bytes[..len]);

            // Read UID from /proc/{pid}/status
            let status_path = format!("/proc/{pid}/status");
            let uid = std::fs::read_to_string(&status_path)
                .ok()
                .and_then(|content| {
                    content.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|s| s.parse::<u32>().ok())
                })
                .unwrap_or(0);

            // Get cgroup path and resolve to cgroup_id (inode)
            let cgroup_path = match Discovery::pid_cgroup_path(pid) {
                Some(p) => p,
                None => continue,
            };
            let sys_path = format!("/sys/fs/cgroup{cgroup_path}");
            let cgroup_id = match std::fs::metadata(&sys_path) {
                Ok(meta) => {
                    use std::os::unix::fs::MetadataExt;
                    meta.ino()
                }
                Err(_) => continue,
            };

            let event = ProcessEvent {
                pid,
                uid,
                cgroup_id,
                comm,
            };

            if let Err(e) = hash.insert(pid, event, 0) {
                log::debug!("failed to insert PID {pid} into PID_CGROUP_MAP: {e:#}");
                continue;
            }
            count += 1;
        }

        Ok(count)
    }

    /// Read all process events from the aya BPF map.
    pub fn read_process_events(&self) -> Result<Vec<(u32, ProcessEvent)>> {
        let map = self
            .bpf
            .map("PID_CGROUP_MAP")
            .context("PID_CGROUP_MAP map not found")?;
        let hash = BpfHashMap::<_, u32, ProcessEvent>::try_from(map)
            .context("PID_CGROUP_MAP is not a HashMap")?;
        let mut results = Vec::new();
        for item in hash.iter() {
            let (key, val) = item.context("reading PID_CGROUP_MAP entry")?;
            results.push((key, val));
        }
        Ok(results)
    }
}

fn find_map_mut<'a>(
    obj: &'a mut libbpf_rs::Object,
    name: &str,
) -> Result<libbpf_rs::MapMut<'a>> {
    obj.maps_mut()
        .find(|m| m.name() == OsStr::new(name))
        .with_context(|| format!("{name} map not found"))
}

fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>())
    }
}
