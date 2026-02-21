// SPDX-License-Identifier: GPL-2.0
// shapeBPF ingress rate limiter (cgroup_skb/ingress)
// Per-cgroup token bucket rate limiting for ingress (download) traffic.
// Counts per-cgroup rx_bytes/rx_packets for TUI display.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ── Shared types (must match shapebpf-common) ──

struct rate_config {
	__u64 egress_rate_bps;
	__u64 ingress_rate_bps;
	__u8 priority;
	__u8 _pad[7];
};

struct traffic_stats {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 rx_packets;
	__u64 drops;
};

// ── Token bucket state ──

struct token_state {
	__u64 tokens;          // available tokens (bytes)
	__u64 last_refill_ns;  // bpf_ktime_get_ns() at last refill
};

// ── BPF Maps ──

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id
	__type(value, struct traffic_stats);
} INGRESS_TRAFFIC_STATS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id
	__type(value, struct rate_config);
} INGRESS_RATE_LIMITS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_config);
} INGRESS_DEFAULT_CONFIG SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id
	__type(value, struct token_state);
} INGRESS_TOKEN_STATE SEC(".maps");

// ── Helpers ──

static __always_inline void update_ingress_stats(__u64 cgroup_id, __u32 len)
{
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
}

static __always_inline void update_ingress_drops(__u64 cgroup_id)
{
	struct traffic_stats *stats = bpf_map_lookup_elem(&INGRESS_TRAFFIC_STATS,
							  &cgroup_id);
	if (stats) {
		__sync_fetch_and_add(&stats->drops, 1);
	}
}

static __always_inline struct rate_config *lookup_ingress_config(__u64 cgroup_id)
{
	struct rate_config *cfg = bpf_map_lookup_elem(&INGRESS_RATE_LIMITS,
						      &cgroup_id);
	if (cfg)
		return cfg;
	__u32 zero = 0;
	return bpf_map_lookup_elem(&INGRESS_DEFAULT_CONFIG, &zero);
}

// ── Program ──

SEC("cgroup_skb/ingress")
int shapebpf_ingress(struct __sk_buff *skb)
{
	__u64 cgroup_id = bpf_skb_cgroup_id(skb);
	__u32 len = skb->len;

	struct rate_config *cfg = lookup_ingress_config(cgroup_id);
	if (cfg && cfg->ingress_rate_bps > 0) {
		__u64 rate = cfg->ingress_rate_bps;
		__u64 now = bpf_ktime_get_ns();

		// Burst size: 100ms worth of tokens, minimum 1 MTU
		__u64 burst = rate / 10;
		if (burst < 1500)
			burst = 1500;

		struct token_state *ts = bpf_map_lookup_elem(&INGRESS_TOKEN_STATE,
							     &cgroup_id);
		if (ts) {
			// Refill tokens based on elapsed time
			__u64 elapsed_ns = now - ts->last_refill_ns;
			__u64 new_tokens = (elapsed_ns * rate) / 1000000000ULL;
			__u64 tokens = ts->tokens + new_tokens;
			if (tokens > burst)
				tokens = burst;

			if (tokens >= len) {
				ts->tokens = tokens - len;
				ts->last_refill_ns = now;
				update_ingress_stats(cgroup_id, len);
				return 1; // allow
			} else {
				// Over limit — try ECN marking first (lossless
				// congestion signal), fall back to drop
				ts->tokens = tokens;
				ts->last_refill_ns = now;

				if (bpf_skb_ecn_set_ce(skb)) {
					// CE set — deliver marked packet
					update_ingress_stats(cgroup_id, len);
					return 1; // allow (ECN-marked)
				}

				// Non-ECN traffic — must drop
				update_ingress_drops(cgroup_id);
				return 0; // drop
			}
		} else {
			// First packet: initialize token bucket with full burst
			struct token_state new_ts = {};
			if (burst >= len) {
				new_ts.tokens = burst - len;
			} else {
				new_ts.tokens = 0;
			}
			new_ts.last_refill_ns = now;
			bpf_map_update_elem(&INGRESS_TOKEN_STATE, &cgroup_id,
					    &new_ts, BPF_NOEXIST);
			update_ingress_stats(cgroup_id, len);
			return 1; // allow first packet
		}
	}

	// No rate limit configured — allow and count
	update_ingress_stats(cgroup_id, len);
	return 1;
}

char _license[] SEC("license") = "GPL";
