use anyhow::{Context, Result};
use std::ffi::CString;

/// TC_H_ROOT from linux/pkt_sched.h: 0xFFFFFFFF
const TC_H_ROOT: u32 = 0xFFFF_FFFF;

/// Manages qdisc attachment for sch_bpf using libbpf netlink API.
pub struct QosManager {
    interface: String,
    ifindex: i32,
    attached: bool,
}

impl QosManager {
    pub fn new(interface: String) -> Self {
        let ifindex = unsafe { libc::if_nametoindex(CString::new(interface.as_str()).unwrap().as_ptr()) } as i32;
        Self {
            interface,
            ifindex,
            attached: false,
        }
    }

    /// Attach sch_bpf as the root qdisc on the interface.
    /// Uses libbpf's bpf_tc_hook_create with BPF_TC_QDISC.
    /// Requires kernel 6.16+ with CONFIG_NET_SCH_BPF and struct_ops already registered.
    pub fn attach_qdisc(&mut self) -> Result<()> {
        if self.ifindex == 0 {
            anyhow::bail!("interface '{}' not found", self.interface);
        }

        // Remove existing root qdisc first (ignore errors)
        let _ = self.destroy_hook();

        let qdisc_name = CString::new("shapebpf")
            .context("invalid qdisc name")?;

        let mut hook = libbpf_sys::bpf_tc_hook {
            sz: std::mem::size_of::<libbpf_sys::bpf_tc_hook>() as libbpf_sys::size_t,
            ifindex: self.ifindex,
            attach_point: libbpf_sys::BPF_TC_QDISC,
            parent: TC_H_ROOT,
            handle: 0,
            qdisc: qdisc_name.as_ptr(),
        };

        let ret = unsafe { libbpf_sys::bpf_tc_hook_create(&mut hook) };
        if ret < 0 {
            anyhow::bail!(
                "bpf_tc_hook_create failed for '{}' (ifindex {}): errno {}",
                self.interface, self.ifindex, -ret
            );
        }

        log::info!("attached shapebpf qdisc to {} (ifindex {})", self.interface, self.ifindex);
        self.attached = true;
        Ok(())
    }

    fn destroy_hook(&self) -> Result<()> {
        let qdisc_name = CString::new("shapebpf")?;
        let mut hook = libbpf_sys::bpf_tc_hook {
            sz: std::mem::size_of::<libbpf_sys::bpf_tc_hook>() as libbpf_sys::size_t,
            ifindex: self.ifindex,
            attach_point: libbpf_sys::BPF_TC_QDISC,
            parent: TC_H_ROOT,
            handle: 0,
            qdisc: qdisc_name.as_ptr(),
        };

        let ret = unsafe { libbpf_sys::bpf_tc_hook_destroy(&mut hook) };
        if ret < 0 && ret != -2 {
            // -2 is ENOENT (doesn't exist), which is fine
            anyhow::bail!("bpf_tc_hook_destroy failed: errno {}", -ret);
        }
        Ok(())
    }

    /// Remove the sch_bpf qdisc.
    pub fn detach_qdisc(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        self.destroy_hook()?;
        self.attached = false;
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl Drop for QosManager {
    fn drop(&mut self) {
        if self.attached {
            let _ = self.detach_qdisc();
        }
    }
}
