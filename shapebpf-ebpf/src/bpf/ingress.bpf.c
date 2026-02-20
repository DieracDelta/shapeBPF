// SPDX-License-Identifier: GPL-2.0
// shapeBPF ingress traffic observer (cgroup_skb/ingress)
// Observes only — always returns 1 (allow all traffic).
// Counts per-cgroup rx_bytes/rx_packets for TUI display.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ── Shared types (must match shapebpf-common) ──

struct traffic_stats {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 rx_packets;
	__u64 drops;
};

// ── BPF Maps ──

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id
	__type(value, struct traffic_stats);
} INGRESS_TRAFFIC_STATS SEC(".maps");

// ── Program ──

SEC("cgroup_skb/ingress")
int shapebpf_ingress(struct __sk_buff *skb)
{
	__u64 cgroup_id = bpf_skb_cgroup_id(skb);
	__u32 len = skb->len;

	struct traffic_stats *stats = bpf_map_lookup_elem(&INGRESS_TRAFFIC_STATS,
							  &cgroup_id);
	if (stats) {
		__sync_fetch_and_add(&stats->rx_bytes, len);
		__sync_fetch_and_add(&stats->rx_packets, 1);
	} else {
		struct traffic_stats new_stats = {};
		new_stats.rx_bytes = len;
		new_stats.rx_packets = 1;
		bpf_map_update_elem(&INGRESS_TRAFFIC_STATS, &cgroup_id,
				    &new_stats, BPF_NOEXIST);
	}

	return 1; // always allow
}

char _license[] SEC("license") = "GPL";
