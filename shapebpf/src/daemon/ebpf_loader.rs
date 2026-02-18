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

pub struct EbpfLoader {
    /// aya-managed eBPF for tracepoints + PID_CGROUP_MAP
    bpf: Ebpf,
    /// libbpf-rs-managed eBPF for struct_ops qdisc + rate limit maps
    qdisc_obj: Option<libbpf_rs::Object>,
    /// Keeps struct_ops link alive
    _qdisc_link: Option<libbpf_rs::Link>,
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

        Ok(Self {
            bpf,
            qdisc_obj,
            _qdisc_link: qdisc_link,
        })
    }

    fn load_qdisc() -> Result<(libbpf_rs::Object, libbpf_rs::Link)> {
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

    /// Whether the qdisc is loaded (rate limiting active).
    pub fn qdisc_loaded(&self) -> bool {
        self.qdisc_obj.is_some()
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
