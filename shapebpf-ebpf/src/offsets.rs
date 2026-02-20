// Kernel struct field offsets.
// These are kernel-version specific and must be updated when the kernel changes.
// Extract via: bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A20 "STRUCT 'task_struct'"
// Current: Linux 6.18.9

#[cfg(feature = "arch-x86_64")]
pub const TASK_COMM: usize = 2400;
#[cfg(feature = "arch-x86_64")]
pub const TASK_CGROUPS: usize = 2904;

#[cfg(feature = "arch-aarch64")]
pub const TASK_COMM: usize = 2288;
#[cfg(feature = "arch-aarch64")]
pub const TASK_CGROUPS: usize = 2776;

// css_set->dfl_cgrp offset
// bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A20 "STRUCT 'css_set'"
pub const CSS_SET_DFL_CGRP: usize = 144;

// cgroup->kn offset
// pahole -C cgroup /sys/kernel/btf/vmlinux
pub const CGROUP_KN: usize = 256;

// kernfs_node->id offset
// pahole -C kernfs_node /sys/kernel/btf/vmlinux
pub const KN_ID: usize = 96;
