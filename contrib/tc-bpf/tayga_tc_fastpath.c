/*
 *  tayga_tc_fastpath.c -- tc-bpf (cls_bpf) stateless 464XLAT / SIIT fast-path prototype
 *
 *  This prototype is compiled standalone with clang -target bpf and is not
 *  linked into the userspace tayga binary.  Packets that cannot be translated
 *  in the fast path (ICMP, fragments, IPv4 options, IPv6 extension headers,
 *  TTL/HopLimit <= 1, or mapping misses) return TC_ACT_OK to fall back to
 *  userspace TAYGA.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif

/* Minimal BPF helper declarations (avoids requiring libbpf-dev) */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static int (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
				  const void *from, __u32 len, __u64 flags) = (void *)9;
static int (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset,
				  __u64 from, __u64 to, __u64 size) = (void *)10;
static int (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset,
				  __u64 from, __u64 to, __u64 flags) = (void *)11;
static int (*bpf_skb_change_proto)(struct __sk_buff *skb, __be16 proto,
				   __u64 flags) = (void *)31;

#include "tayga_tc_maps.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tayga_bpf_cfg);
} tayga_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, TAYGA_TC_MAX_EAM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct tayga_lpm4_key);
	__type(value, struct tayga_eam_val);
} tayga_eam4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, TAYGA_TC_MAX_EAM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct tayga_lpm6_key);
	__type(value, struct tayga_eam_val);
} tayga_eam6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tayga_bpf_stats);
} tayga_stats_map SEC(".maps");

static __always_inline void bump_stat(int which)
{
	__u32 key = 0;
	struct tayga_bpf_stats *st = bpf_map_lookup_elem(&tayga_stats_map, &key);
	if (!st)
		return;
	if (which == 0)
		st->fast_4to6++;
	else if (which == 1)
		st->fast_6to4++;
	else
		st->slow_fallback++;
}

static __always_inline int translate_4to6(struct __sk_buff *skb,
					  const struct tayga_bpf_cfg *cfg)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip4 = (void *)(eth + 1);

	if ((void *)(ip4 + 1) > data_end)
		return TC_ACT_OK;

	/* Fast-path eligibility: IPv4 without options, unfragmented, TTL > 1, TCP/UDP */
	if (ip4->ihl != 5 || ip4->ttl <= 1 ||
	    (ip4->frag_off & bpf_htons(0x3fff)) != 0 ||
	    (ip4->protocol != IPPROTO_TCP && ip4->protocol != IPPROTO_UDP)) {
		bump_stat(2);
		return TC_ACT_OK;
	}

	struct tayga_lpm4_key skey = { .prefixlen = 32, .addr = ip4->saddr };
	struct tayga_eam_val *src_eam = bpf_map_lookup_elem(&tayga_eam4_map, &skey);
	if (!src_eam) {
		bump_stat(2);
		return TC_ACT_OK;
	}

	__u32 saddr4 = ip4->saddr;
	__u32 daddr4 = ip4->daddr;
	__u8 proto = ip4->protocol;
	__u8 ttl = (__u8)(ip4->ttl - 1);
	__u8 tos = ip4->tos;
	__u16 payload_len = (__u16)(bpf_ntohs(ip4->tot_len) - sizeof(*ip4));

	struct ipv6hdr ip6 = {
		.version = 6,
		.priority = tos >> 4,
		.flow_lbl = { (__u8)((tos & 0x0f) << 4), 0, 0 },
		.payload_len = bpf_htons(payload_len),
		.nexthdr = proto,
		.hop_limit = ttl,
	};
	ip6.saddr.s6_addr32[0] = src_eam->prefix[0];
	ip6.saddr.s6_addr32[1] = src_eam->prefix[1];
	ip6.saddr.s6_addr32[2] = src_eam->prefix[2];
	ip6.saddr.s6_addr32[3] = src_eam->prefix[3];

	/* Destination uses /96 NAT64 prefix */
	ip6.daddr.s6_addr32[0] = cfg->pref64_words[0];
	ip6.daddr.s6_addr32[1] = cfg->pref64_words[1];
	ip6.daddr.s6_addr32[2] = cfg->pref64_words[2];
	ip6.daddr.s6_addr32[3] = daddr4;

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0) {
		bump_stat(2);
		return TC_ACT_OK;
	}

	/* Update Ethernet proto and write IPv6 header */
	__be16 eth_proto = bpf_htons(ETH_P_IPV6);
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
				&eth_proto, sizeof(eth_proto), 0) < 0 ||
	    bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip6, sizeof(ip6), 0) < 0)
		return TC_ACT_SHOT;

	/* Update L4 pseudo-header checksum for 4->6 address change */
	__u32 csum_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		(proto == IPPROTO_TCP ? offsetof(struct tcphdr, check)
				      : offsetof(struct udphdr, check));
	bpf_l4_csum_replace(skb, csum_off, saddr4, ip6.saddr.s6_addr32[0], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, 0, ip6.saddr.s6_addr32[1], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, 0, ip6.saddr.s6_addr32[2], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, 0, ip6.saddr.s6_addr32[3], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, daddr4, ip6.daddr.s6_addr32[0], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, 0, ip6.daddr.s6_addr32[1], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, 0, ip6.daddr.s6_addr32[2], BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, 0, ip6.daddr.s6_addr32[3], BPF_F_PSEUDO_HDR | sizeof(__u32));

	bump_stat(0);
	return TC_ACT_OK;
}

static __always_inline int translate_6to4(struct __sk_buff *skb,
					  const struct tayga_bpf_cfg *cfg)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = (void *)(eth + 1);

	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;

	/* Fast-path eligibility: direct TCP/UDP, HopLimit > 1, source matches /96 */
	if (ip6->hop_limit <= 1 ||
	    (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP) ||
	    ip6->saddr.s6_addr32[0] != cfg->pref64_words[0] ||
	    ip6->saddr.s6_addr32[1] != cfg->pref64_words[1] ||
	    ip6->saddr.s6_addr32[2] != cfg->pref64_words[2]) {
		bump_stat(2);
		return TC_ACT_OK;
	}

	struct tayga_lpm6_key dkey = {
		.prefixlen = 128,
		.addr = {
			ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
			ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3],
		},
	};
	struct tayga_eam_val *dst_eam = bpf_map_lookup_elem(&tayga_eam6_map, &dkey);
	if (!dst_eam) {
		bump_stat(2);
		return TC_ACT_OK;
	}

	__u32 saddr6[4] = {
		ip6->saddr.s6_addr32[0], ip6->saddr.s6_addr32[1],
		ip6->saddr.s6_addr32[2], ip6->saddr.s6_addr32[3],
	};
	__u32 daddr6[4] = {
		ip6->daddr.s6_addr32[0], ip6->daddr.s6_addr32[1],
		ip6->daddr.s6_addr32[2], ip6->daddr.s6_addr32[3],
	};

	struct iphdr ip4 = {
		.version = 4,
		.ihl = 5,
		.tos = (__u8)((ip6->priority << 4) | (ip6->flow_lbl[0] >> 4)),
		.tot_len = bpf_htons((__u16)(bpf_ntohs(ip6->payload_len) + sizeof(struct iphdr))),
		.id = 0,
		.frag_off = bpf_htons(0x4000), /* DF */
		.ttl = (__u8)(ip6->hop_limit - 1),
		.protocol = ip6->nexthdr,
		.check = 0,
		.saddr = saddr6[3],
		.daddr = dst_eam->prefix[0],
	};

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) < 0) {
		bump_stat(2);
		return TC_ACT_OK;
	}

	__be16 eth_proto = bpf_htons(ETH_P_IP);
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
				&eth_proto, sizeof(eth_proto), 0) < 0 ||
	    bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip4, sizeof(ip4), 0) < 0)
		return TC_ACT_SHOT;

	/* Compute IPv4 header checksum via bpf_l3_csum_replace over 16-bit words */
	__u32 csum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) +
		(ip4.protocol == IPPROTO_TCP ? offsetof(struct tcphdr, check)
					     : offsetof(struct udphdr, check));
	bpf_l4_csum_replace(skb, csum_off, saddr6[0], ip4.saddr, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, saddr6[1], 0, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, saddr6[2], 0, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, saddr6[3], 0, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, daddr6[0], ip4.daddr, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, daddr6[1], 0, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, daddr6[2], 0, BPF_F_PSEUDO_HDR | sizeof(__u32));
	bpf_l4_csum_replace(skb, csum_off, daddr6[3], 0, BPF_F_PSEUDO_HDR | sizeof(__u32));

	__u32 ip4_csum_off = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
	__u16 *words = (__u16 *)&ip4;
	for (int i = 0; i < 10; i++)
		bpf_l3_csum_replace(skb, ip4_csum_off, 0, words[i], sizeof(__u16));

	bump_stat(1);
	return TC_ACT_OK;
}

SEC("tc")
int tayga_fastpath(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct tayga_bpf_cfg *cfg = bpf_map_lookup_elem(&tayga_cfg_map, &key);
	if (!cfg || !cfg->enabled)
		return TC_ACT_OK;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return translate_4to6(skb, cfg);
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		return translate_6to4(skb, cfg);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
