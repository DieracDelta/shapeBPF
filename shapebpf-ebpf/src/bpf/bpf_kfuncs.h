/* SPDX-License-Identifier: GPL-2.0 */
/* shapeBPF BPF helper macros and kfunc declarations for qdisc struct_ops.
 *
 * vmlinux.h has __weak __ksym declarations stripped because they produce
 * FUNC entries in .ksyms BTF DATASEC that libbpf transforms into
 * dummy_ksym VARs, which the kernel BTF validator rejects.
 *
 * We provide explicit kfunc declarations here instead, following the
 * pattern used by kernel selftests (bpf_qdisc_common.h).
 */

#ifndef _SHAPEBPF_BPF_KFUNCS_H
#define _SHAPEBPF_BPF_KFUNCS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ── BTF type tags ── */
#ifndef __kptr
#define __kptr __attribute__((btf_type_tag("kptr")))
#endif

#ifndef __contains
#define __contains(name, node) \
	__attribute__((btf_decl_tag("contains:" #name ":" #node)))
#endif

/* ── container_of ── */
#ifndef container_of
#define container_of(ptr, type, member)					\
	({								\
		void *__mptr = (void *)(ptr);				\
		((type *)(__mptr - __builtin_offsetof(type, member)));	\
	})
#endif

/* ── NET_XMIT return codes ── */
#define NET_XMIT_SUCCESS	0x00
#define NET_XMIT_DROP		0x01
#define NET_XMIT_CN		0x02

/* Forward-declare opaque types used by qdisc kfuncs.
 * These may not exist in vmlinux.h if it was generated from a pre-6.16 kernel. */
struct bpf_sk_buff_ptr;

/* ── Qdisc SKB helpers ── */
static __always_inline struct qdisc_skb_cb *
qdisc_skb_cb(const struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

static __always_inline unsigned int qdisc_pkt_len(const struct sk_buff *skb)
{
	return qdisc_skb_cb(skb)->pkt_len;
}

/* ── Kfunc declarations ──
 * These are kernel functions callable from BPF programs.
 * Declared as extern __ksym so libbpf resolves them against kernel BTF.
 */

/* BPF object allocation kfuncs */
extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta__ign) __ksym;
extern void bpf_obj_drop_impl(void *p__alloc, void *meta__ign) __ksym;

/* BPF linked list kfuncs */
extern struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head) __ksym;
extern int bpf_list_push_front_impl(struct bpf_list_head *head,
				    struct bpf_list_node *node,
				    void *meta__ign, __u64 off) __ksym;
extern int bpf_list_push_back_impl(struct bpf_list_head *head,
				   struct bpf_list_node *node,
				   void *meta__ign, __u64 off) __ksym;

/* SKB management kfuncs */
extern void bpf_kfree_skb(struct sk_buff *skb) __ksym;

/* Qdisc-specific kfuncs */
extern void bpf_qdisc_skb_drop(struct sk_buff *skb,
				struct bpf_sk_buff_ptr *to_free) __ksym;
extern void bpf_qdisc_bstats_update(struct Qdisc *sch,
				     const struct sk_buff *skb) __ksym;
extern void bpf_qdisc_watchdog_schedule(struct Qdisc *sch,
					 __u64 expire, __u64 delta_ns) __ksym;

/* ── Wrapper macros for kfuncs ── */
#define bpf_obj_new(type) \
	((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) \
	bpf_obj_drop_impl(kptr, NULL)

#define bpf_list_push_front(head, node) \
	bpf_list_push_front_impl(head, node, NULL, 0)
#define bpf_list_push_back(head, node) \
	bpf_list_push_back_impl(head, node, NULL, 0)

#endif /* _SHAPEBPF_BPF_KFUNCS_H */
