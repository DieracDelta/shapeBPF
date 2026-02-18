// Kernel struct field offsets.
// These are kernel-version specific and must be updated when the kernel changes.
// Extract via: pahole -C task_struct /sys/kernel/btf/vmlinux
// Current: Linux 6.12 (will need update for 6.16+)

#[cfg(feature = "arch-x86_64")]
pub const TASK_COMM: usize = 2384;
#[cfg(feature = "arch-x86_64")]
pub const TASK_CGROUPS: usize = 2872;

#[cfg(feature = "arch-aarch64")]
pub const TASK_COMM: usize = 2288;
#[cfg(feature = "arch-aarch64")]
pub const TASK_CGROUPS: usize = 2776;

// css_set->dfl_cgrp offset
// pahole -C css_set /sys/kernel/btf/vmlinux
pub const CSS_SET_DFL_CGRP: usize = 136;

// cgroup->kn offset
// pahole -C cgroup /sys/kernel/btf/vmlinux
pub const CGROUP_KN: usize = 256;

// kernfs_node->id offset
// pahole -C kernfs_node /sys/kernel/btf/vmlinux
pub const KN_ID: usize = 96;
