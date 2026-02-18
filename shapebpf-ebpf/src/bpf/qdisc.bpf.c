// SPDX-License-Identifier: GPL-2.0
// shapeBPF programmable qdisc via sch_bpf (struct_ops Qdisc_ops)
// Kernel 6.16+ required (CONFIG_NET_SCH_BPF)
//
// Based on kernel selftests/bpf/progs/bpf_qdisc_fifo.c
// Queue management uses BPF linked lists.
// Rate limiting uses EDT (Earliest Departure Time) pacing.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

// ── Shared types (must match shapebpf-common) ──

struct rate_config {
	__u64 egress_rate_bps;
	__u64 ingress_rate_bps;
	__u8 priority;
	__u8 _pad[7];
};

struct edt_state {
	__u64 next_departure_ns;
	__u64 burst_remaining;
};

struct traffic_stats {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 rx_packets;
	__u64 drops;
};

// ── Queue node: wraps an skb in a BPF linked list ──

struct skb_node {
	struct sk_buff __kptr *skb;
	struct bpf_list_node node;
};

// ── Queue state: spin lock + linked list in a map value ──

struct q_state {
	struct bpf_spin_lock lock;
	struct bpf_list_head list __contains(skb_node, node);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct q_state);
} Q_STATE SEC(".maps");

// ── BPF Maps ──

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id
	__type(value, struct rate_config);
} RATE_LIMITS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id or 0 for global
	__type(value, struct edt_state);
} EDT_STATE SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup_id
	__type(value, struct traffic_stats);
} TRAFFIC_STATS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);   // pid
	__type(value, struct traffic_stats);
} PID_TRAFFIC_STATS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);   // uid
	__type(value, struct rate_config);
} UID_LIMITS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_config);
} DEFAULT_CONFIG SEC(".maps");

// ── Helpers ──

static __always_inline struct q_state *get_queue(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&Q_STATE, &key);
}

static __always_inline void update_stats(__u64 cgroup_id, __u32 len)
{
	struct traffic_stats *stats = bpf_map_lookup_elem(&TRAFFIC_STATS,
							  &cgroup_id);
	if (stats) {
		__sync_fetch_and_add(&stats->tx_bytes, len);
		__sync_fetch_and_add(&stats->tx_packets, 1);
	} else {
		struct traffic_stats new_stats = {};
		new_stats.tx_bytes = len;
		new_stats.tx_packets = 1;
		bpf_map_update_elem(&TRAFFIC_STATS, &cgroup_id, &new_stats,
				    BPF_NOEXIST);
	}
}

static __always_inline void update_pid_stats(__u32 len)
{
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (pid == 0)
		return;

	struct traffic_stats *stats = bpf_map_lookup_elem(&PID_TRAFFIC_STATS,
							  &pid);
	if (stats) {
		__sync_fetch_and_add(&stats->tx_bytes, len);
		__sync_fetch_and_add(&stats->tx_packets, 1);
	} else {
		struct traffic_stats new_stats = {};
		new_stats.tx_bytes = len;
		new_stats.tx_packets = 1;
		bpf_map_update_elem(&PID_TRAFFIC_STATS, &pid, &new_stats,
				    BPF_NOEXIST);
	}
}

static __always_inline struct rate_config *lookup_rate_config(__u64 cgroup_id)
{
	// Try per-cgroup limit first
	struct rate_config *cfg = bpf_map_lookup_elem(&RATE_LIMITS,
						      &cgroup_id);
	if (cfg)
		return cfg;
	// Fall back to default
	__u32 zero = 0;
	return bpf_map_lookup_elem(&DEFAULT_CONFIG, &zero);
}

// ── struct_ops: Qdisc_ops callbacks ──

SEC("struct_ops/shapebpf_enqueue")
int BPF_PROG(shapebpf_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct skb_node *skbn;
	struct q_state *q;
	__u32 pkt_len;

	if (sch->q.qlen >= sch->limit)
		goto drop;

	q = get_queue();
	if (!q)
		goto drop;

	pkt_len = qdisc_pkt_len(skb);

	// Get cgroup_id for per-cgroup tracking and rate limiting
	__u64 cgroup_id = bpf_get_current_cgroup_id();

	// Apply EDT pacing (per-cgroup if configured, else default)
	struct rate_config *cfg = lookup_rate_config(cgroup_id);
	if (cfg && cfg->egress_rate_bps > 0) {
		__u64 rate_bps = cfg->egress_rate_bps;
		// delay_ns = (bytes * 8 * 1e9) / rate_bps
		__u64 delay_ns = ((__u64)pkt_len * 8000000000ULL) / rate_bps;
		__u64 now = bpf_ktime_get_ns();

		// Use cgroup_id as EDT key for per-cgroup pacing
		struct edt_state *edt = bpf_map_lookup_elem(&EDT_STATE,
							    &cgroup_id);
		if (edt) {
			__u64 earliest = edt->next_departure_ns;
			if (earliest > now) {
				skb->tstamp = earliest;
				edt->next_departure_ns = earliest + delay_ns;
			} else {
				skb->tstamp = now;
				edt->next_departure_ns = now + delay_ns;
			}
		} else {
			struct edt_state new_edt = {
				.next_departure_ns = now + delay_ns,
				.burst_remaining = 0,
			};
			bpf_map_update_elem(&EDT_STATE, &cgroup_id,
					    &new_edt, BPF_NOEXIST);
			skb->tstamp = now;
		}
	}

	// Allocate queue node and enqueue
	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn)
		goto drop;

	sch->q.qlen++;
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb)
		bpf_qdisc_skb_drop(skb, to_free);

	bpf_spin_lock(&q->lock);
	bpf_list_push_back(&q->list, &skbn->node);
	bpf_spin_unlock(&q->lock);

	sch->qstats.backlog += pkt_len;
	update_stats(cgroup_id, pkt_len);
	update_pid_stats(pkt_len);

	return NET_XMIT_SUCCESS;

drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

SEC("struct_ops/shapebpf_dequeue")
struct sk_buff *BPF_PROG(shapebpf_dequeue, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct sk_buff *skb = NULL;
	struct skb_node *skbn;
	struct q_state *q;

	q = get_queue();
	if (!q)
		return NULL;

	bpf_spin_lock(&q->lock);
	node = bpf_list_pop_front(&q->list);
	bpf_spin_unlock(&q->lock);
	if (!node)
		return NULL;

	skbn = container_of(node, struct skb_node, node);
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	bpf_obj_drop(skbn);
	if (!skb)
		return NULL;

	// Check EDT pacing: is it time to send this packet?
	__u64 now = bpf_ktime_get_ns();
	__u64 tstamp = skb->tstamp;

	if (tstamp > now && tstamp > 0) {
		// Not ready yet - re-enqueue at front and schedule watchdog
		__u32 pkt_len = qdisc_pkt_len(skb);
		struct skb_node *new_skbn = bpf_obj_new(typeof(*new_skbn));

		if (new_skbn) {
			struct sk_buff *old = bpf_kptr_xchg(&new_skbn->skb,
							    skb);
			if (old)
				bpf_kfree_skb(old);

			bpf_spin_lock(&q->lock);
			bpf_list_push_front(&q->list, &new_skbn->node);
			bpf_spin_unlock(&q->lock);
		} else {
			// Allocation failed - must drop
			sch->qstats.backlog -= pkt_len;
			sch->q.qlen--;
			bpf_kfree_skb(skb);
		}

		bpf_qdisc_watchdog_schedule(sch, tstamp, 0);
		return NULL;
	}

	sch->qstats.backlog -= qdisc_pkt_len(skb);
	bpf_qdisc_bstats_update(sch, skb);
	sch->q.qlen--;

	return skb;
}

SEC("struct_ops/shapebpf_init")
int BPF_PROG(shapebpf_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	sch->limit = 10000;
	return 0;
}

SEC("struct_ops/shapebpf_reset")
void BPF_PROG(shapebpf_reset, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct skb_node *skbn;
	struct q_state *q;
	int i;

	q = get_queue();
	if (!q)
		return;

	bpf_for(i, 0, 10000) {
		struct sk_buff *skb = NULL;

		bpf_spin_lock(&q->lock);
		node = bpf_list_pop_front(&q->list);
		bpf_spin_unlock(&q->lock);

		if (!node)
			break;

		skbn = container_of(node, struct skb_node, node);
		skb = bpf_kptr_xchg(&skbn->skb, skb);
		if (skb)
			bpf_kfree_skb(skb);
		bpf_obj_drop(skbn);
	}
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
}

SEC("struct_ops")
void BPF_PROG(shapebpf_destroy, struct Qdisc *sch)
{
}

// ── struct_ops registration ──

SEC(".struct_ops")
struct Qdisc_ops shapebpf_qdisc = {
	.enqueue  = (void *)shapebpf_enqueue,
	.dequeue  = (void *)shapebpf_dequeue,
	.init     = (void *)shapebpf_init,
	.reset    = (void *)shapebpf_reset,
	.destroy  = (void *)shapebpf_destroy,
	.id       = "shapebpf",
};

char _license[] SEC("license") = "GPL";
