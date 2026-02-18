#![no_std]
#![no_main]

use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm, bpf_probe_read_kernel};

use shapebpf_common::ProcessEvent;

mod offsets;
use offsets::*;

// ── BPF Maps ──

/// Maps PID -> ProcessEvent for process discovery.
/// Written by tracepoints, read by daemon.
#[map]
static PID_CGROUP_MAP: HashMap<u32, ProcessEvent> = HashMap::with_max_entries(32768, 0);

// ── Helpers ──

#[inline(always)]
unsafe fn read_field<T: Copy>(base: *const u8, offset: usize) -> Result<T, i64> {
    bpf_probe_read_kernel(base.add(offset) as *const T)
}

unsafe fn read_cgroup_id(task: *const u8) -> Result<u64, i64> {
    // task->cgroups (css_set pointer)
    let css_set: *const u8 = read_field(task, TASK_CGROUPS)?;
    if css_set.is_null() {
        return Ok(0);
    }

    // css_set->dfl_cgrp (cgroup pointer)
    let cgrp: *const u8 = read_field(css_set, CSS_SET_DFL_CGRP)?;
    if cgrp.is_null() {
        return Ok(0);
    }

    // cgrp->kn (kernfs_node pointer)
    let kn: *const u8 = read_field(cgrp, CGROUP_KN)?;
    if kn.is_null() {
        return Ok(0);
    }

    // kn->id (u64 inode ID)
    let id: u64 = read_field(kn, KN_ID)?;
    Ok(id)
}

// ── Tracepoints ──

/// Captures process exec events: PID, UID, cgroup_id, comm.
#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn sched_process_exec(_ctx: TracePointContext) -> i32 {
    unsafe { try_sched_process_exec().unwrap_or(0) }
}

unsafe fn try_sched_process_exec() -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
    if task.is_null() {
        return Ok(0);
    }

    let comm: [u8; 16] = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let cgroup_id = read_cgroup_id(task).unwrap_or(0);

    let event = ProcessEvent {
        pid,
        uid,
        cgroup_id,
        comm,
    };

    PID_CGROUP_MAP.insert(&pid, &event, 0).map_err(|_| -1i64)?;
    Ok(0)
}

/// Captures fork events so fork-without-exec children (e.g. sshd privilege separation)
/// inherit the parent's cgroup mapping immediately.
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> i32 {
    unsafe { try_sched_process_fork(ctx).unwrap_or(0) }
}

unsafe fn try_sched_process_fork(ctx: TracePointContext) -> Result<i32, i64> {
    // child_pid is at offset 20 in sched_process_fork tracepoint args
    let child_pid: i32 = ctx.read_at(20).map_err(|_| -1i64)?;
    let child_pid = child_pid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
    if task.is_null() {
        return Ok(0);
    }

    let comm: [u8; 16] = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let cgroup_id = read_cgroup_id(task).unwrap_or(0);

    let event = ProcessEvent {
        pid: child_pid,
        uid,
        cgroup_id,
        comm,
    };

    PID_CGROUP_MAP.insert(&child_pid, &event, 0).map_err(|_| -1i64)?;
    Ok(0)
}

/// Cleans up process entry on exit.
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_process_exit(_ctx: TracePointContext) -> i32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    unsafe {
        PID_CGROUP_MAP.remove(&pid);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
