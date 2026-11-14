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
	__u8 prefix_len;
	__u8 pad[3];
};

struct tayga_bpf_stats {
	__u64 fast_4to6;
	__u64 fast_6to4;
	__u64 slow_fallback;
};

#endif
