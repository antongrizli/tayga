/*
 *  tayga_tc_maps.h -- shared BPF map ABI between tayga_tc_fastpath.c and userspace
 */

#ifndef TAYGA_TC_MAPS_H
#define TAYGA_TC_MAPS_H

#include <linux/types.h>

#define TAYGA_TC_MAX_EAM 4096

struct tayga_bpf_cfg {
	__u32 pref64_words[3]; /* /96 NAT64 prefix in network order */
	__u32 enabled;
};

struct tayga_lpm4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct tayga_lpm6_key {
	__u32 prefixlen;
	__u32 addr[4];
};

struct tayga_eam_val {
	__u32 prefix[4];
	__u8 prefix_len;     /* destination prefix length (0..128 for 4to6, 0..32 for 6to4) */
	__u8 src_prefix_len; /* matched source prefix length (0..32 for 4to6, 0..128 for 6to4) */
	__u8 pad[2];
};

struct tayga_bpf_stats {
	__u64 fast_4to6;
	__u64 fast_6to4;
	__u64 slow_fallback;
};

static __inline __u32 tayga_bpf_bswap32(__u32 v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap32(v);
#else
	return v;
#endif
}

/*
 * Synthesize an IPv6 address for RFC 7757 EAM 4->6 translation.
 * For /32 <-> /128 entries (src_prefix_len == 32) this simply copies prefix.
 * For shorter prefixes, the low (32 - src_prefix_len) bits of saddr4
 * are placed immediately after prefix_len bits of val->prefix.
 */
static __inline void tayga_bpf_eam_4to6(__u32 saddr4,
					const struct tayga_eam_val *val,
					__u32 out6[4])
{
	__u32 l4 = val->src_prefix_len;
	__u32 l6 = val->prefix_len;
	__u32 p0 = val->prefix[0];
	__u32 p1 = val->prefix[1];
	__u32 p2 = val->prefix[2];
	__u32 p3 = val->prefix[3];

	if (l4 >= 32U || l6 >= 128U) {
		out6[0] = p0;
		out6[1] = p1;
		out6[2] = p2;
		out6[3] = p3;
		return;
	}

	__u32 suffix_len = 32U - l4;
	if (suffix_len > 128U - l6) {
		out6[0] = p0;
		out6[1] = p1;
		out6[2] = p2;
		out6[3] = p3;
		return;
	}

	__u32 mask4 = (suffix_len == 32U) ? 0xFFFFFFFFU : ((1U << suffix_len) - 1U);
	__u32 suffix = tayga_bpf_bswap32(saddr4) & mask4;
	__u32 w_idx = l6 >> 5U;
	__u32 bit_off = l6 & 31U;
	__u32 avail = 32U - bit_off;

	__u32 hi_mask = 0;
	__u32 hi_val = 0;
	__u32 lo_mask = 0;
	__u32 lo_val = 0;
	__u32 straddle = 0;

	if (suffix_len <= avail) {
		__u32 shift = avail - suffix_len;
		hi_mask = mask4 << shift;
		hi_val = suffix << shift;
	} else {
		__u32 spill = suffix_len - avail;
		__u32 lo_shift = 32U - spill;
		hi_mask = (1U << avail) - 1U;
		hi_val = suffix >> spill;
		lo_mask = ((1U << spill) - 1U) << lo_shift;
		lo_val = (suffix & ((1U << spill) - 1U)) << lo_shift;
		straddle = 1;
	}

	__u32 h0 = tayga_bpf_bswap32(p0);
	__u32 h1 = tayga_bpf_bswap32(p1);
	__u32 h2 = tayga_bpf_bswap32(p2);
	__u32 h3 = tayga_bpf_bswap32(p3);

	if (w_idx == 0U)
		h0 = (h0 & ~hi_mask) | hi_val;
	if (w_idx == 1U)
		h1 = (h1 & ~hi_mask) | hi_val;
	else if (straddle && w_idx == 0U)
		h1 = (h1 & ~lo_mask) | lo_val;
	if (w_idx == 2U)
		h2 = (h2 & ~hi_mask) | hi_val;
	else if (straddle && w_idx == 1U)
		h2 = (h2 & ~lo_mask) | lo_val;
	if (w_idx == 3U)
		h3 = (h3 & ~hi_mask) | hi_val;
	else if (straddle && w_idx == 2U)
		h3 = (h3 & ~lo_mask) | lo_val;

	out6[0] = tayga_bpf_bswap32(h0);
	out6[1] = tayga_bpf_bswap32(h1);
	out6[2] = tayga_bpf_bswap32(h2);
	out6[3] = tayga_bpf_bswap32(h3);
}

/*
 * Synthesize an IPv4 address for RFC 7757 EAM 6->4 translation.
 * For /128 <-> /32 entries (prefix_len == 32) this simply returns prefix[0].
 * For shorter prefixes, (32 - prefix_len) suffix bits are extracted starting
 * after src_prefix_len bits of addr6 and ORed into val->prefix[0].
 */
static __inline __u32 tayga_bpf_eam_6to4(const __u32 addr6[4],
					 const struct tayga_eam_val *val)
{
	__u32 l4 = val->prefix_len;
	__u32 l6 = val->src_prefix_len;

	if (l4 >= 32U || l6 >= 128U)
		return val->prefix[0];

	__u32 suffix_len = 32U - l4;
	if (suffix_len > 128U - l6)
		return val->prefix[0];

	__u32 w_idx = l6 >> 5U;
	__u32 bit_off = l6 & 31U;
	__u32 avail = 32U - bit_off;

	__u32 a0 = tayga_bpf_bswap32(addr6[0]);
	__u32 a1 = tayga_bpf_bswap32(addr6[1]);
	__u32 a2 = tayga_bpf_bswap32(addr6[2]);
	__u32 a3 = tayga_bpf_bswap32(addr6[3]);
	__u32 w_hi = (w_idx == 0U) ? a0 : (w_idx == 1U) ? a1 : (w_idx == 2U) ? a2 : a3;
	__u32 w_lo = (w_idx == 0U) ? a1 : (w_idx == 1U) ? a2 : a3;

	__u32 mask4 = (suffix_len == 32U) ? 0xFFFFFFFFU : ((1U << suffix_len) - 1U);
	__u32 suffix;
	if (suffix_len <= avail) {
		__u32 shift = avail - suffix_len;
		suffix = (w_hi >> shift) & mask4;
	} else {
		__u32 spill = suffix_len - avail;
		__u32 lo_shift = 32U - spill;
		__u32 spill_mask = (1U << spill) - 1U;
		__u32 hi_part = (w_hi & ((1U << avail) - 1U)) << spill;
		__u32 lo_part = (w_lo >> lo_shift) & spill_mask;
		suffix = hi_part | lo_part;
	}

	__u32 h4 = (tayga_bpf_bswap32(val->prefix[0]) & ~mask4) | suffix;
	return tayga_bpf_bswap32(h4);
}

#endif
