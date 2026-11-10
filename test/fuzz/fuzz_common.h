/*
 * Shared setup for the libFuzzer packet harnesses.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include "tayga.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* gcfg is defined by conffile.c in libtayga_test.a */
_Atomic time_t now = 1000;

static int fuzz_null_fd = -1;

/* One RFC 6052 default map plus one static host, like a CLAT profile. */
static void fuzz_setup_maps(void)
{
	static struct map_static maps[2];
	memset(&gcfg, 0, sizeof(gcfg));
	INIT_LIST_HEAD(&gcfg.map4_list);
	INIT_LIST_HEAD(&gcfg.map6_list);
	gcfg.maps_immutable = 1;
	gcfg.udp_cksum_mode = UDP_CKSUM_FWD;
	gcfg.mtu = 1500;
	gcfg.icmp_rate_limit = UINT32_MAX;	/* exercise every error path */
	inet_pton(AF_INET, "192.0.0.254", &gcfg.local_addr4);
	inet_pton(AF_INET6, "fd9b:64:1:ff::fe", &gcfg.local_addr6);
	for (int i = 0; i < 2; ++i) {
		maps[i].map4.type = maps[i].map6.type = i ? MAP_TYPE_STATIC : MAP_TYPE_RFC6052;
		maps[i].map4.prefix_len = i ? 32 : 0;
		maps[i].map6.prefix_len = i ? 128 : 96;
		inet_pton(AF_INET, i ? "192.0.0.1" : "0.0.0.0", &maps[i].map4.addr);
		inet_pton(AF_INET6, i ? "fd9b:64:1:ff::10" : "64:ff9b::", &maps[i].map6.addr);
		calc_ip4_mask(&maps[i].map4.mask, NULL, maps[i].map4.prefix_len);
		calc_ip6_mask(&maps[i].map6.mask, NULL, maps[i].map6.prefix_len);
		INIT_LIST_HEAD(&maps[i].map4.list);
		INIT_LIST_HEAD(&maps[i].map6.list);
		if (insert_map4(&maps[i].map4, NULL) || insert_map6(&maps[i].map6, NULL))
			abort();
	}
	fuzz_null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (fuzz_null_fd < 0)
		abort();
}

/*
 * Feed one input to a packet handler.  Byte 0 selects: has_vhdr (bit 0),
 * LOG_OPT_DROP (bit 1) and the offload mode (bits 2-3).  The packet lives in
 * an exact-size heap block (plus the in-place HEADROOM) so ASan flags a
 * one-byte over-read.
 */
static inline void fuzz_packet(const uint8_t *data, size_t size, void (*handler)(struct pkt *))
{
	if (size < 1 || size > 65536)
		return;
	uint8_t flags = data[0];
	data++; size--;

	gcfg.log_opts = (flags & 2) ? LOG_OPT_DROP : 0;
	gcfg.tun_offload_effective = (enum tun_offload_mode)(((flags >> 2) & 3) % 3);

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.tun_fd = fuzz_null_fd;
	if (flags & 1) {
		if (size < sizeof(p.vhdr))
			return;
		memcpy(&p.vhdr, data, sizeof(p.vhdr));
		data += sizeof(p.vhdr); size -= sizeof(p.vhdr);
		p.has_vhdr = 1;
		gcfg.vnet_hdr_sz = (int)sizeof(p.vhdr);
	} else {
		gcfg.vnet_hdr_sz = 0;
	}

	uint8_t *buf = malloc(HEADROOM + size);
	if (!buf)
		abort();
	memset(buf, 0, HEADROOM);
	memcpy(buf + HEADROOM, data, size);
	p.data = buf + HEADROOM;
	p.data_len = (uint32_t)size;
	handler(&p);
	free(buf);
}

#endif
