# Why the eBPF program is written in C

Rust **can** produce BPF bytecode — projects like [Aya](https://aya-rs.dev/) compile Rust to
`bpf-unknown-none` and load it into the kernel. [bpftop](https://github.com/Netflix/bpftop) is
one example: its entire eBPF side is Rust using `aya_ebpf` with kprobes, tracepoints, and
HashMaps.

This project uses C because it relies on bleeding-edge BPF features that Aya doesn't support yet:

## What we need that Aya can't do

1. **struct_ops for qdiscs** (`SEC("struct_ops")` implementing `struct Qdisc_ops`) — BPF-based
   qdisc scheduling via `sch_bpf` requires kernel 6.16+ with `CONFIG_NET_SCH_BPF`. Aya has no
   support for arbitrary struct_ops registration, let alone this qdisc-specific variant.

2. **BPF linked lists** (`bpf_list_head`, `bpf_list_node`, `__contains()` annotation) — The
   kernel's typed BPF list infrastructure for managing packet queues. Not exposed by Aya.

3. **BPF kptr / arena allocation** (`__kptr`, `bpf_kptr_xchg`, `bpf_obj_new`, `bpf_obj_drop`) —
   The BPF memory allocation subsystem for owning and transferring kernel pointers. Not available
   in Aya.

4. **Qdisc-specific kfuncs** (`bpf_qdisc_skb_drop`, `bpf_qdisc_watchdog_schedule`,
   `bpf_qdisc_bstats_update`, `bpf_kfree_skb`) — Kernel helper functions for qdisc
   implementations that have no Aya bindings.

## Why not the whole project?

Only the kernel-side eBPF program (`qdisc.bpf.c`) is C. The userspace daemon that loads and
manages it is Rust. If Aya adds support for struct_ops qdiscs and BPF linked lists, this could
be rewritten in Rust.
