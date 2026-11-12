/*
 * Translator microbenchmark: userspace cost per packet with the kernel TUN
 * path removed.  Output packets go to /dev/null.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "fuzz_common.h"
#include <errno.h>
#include <stdio.h>
#include <time.h>

#define MAX_TEMPLATE 1500
#define BASELINE_LEN 1428

enum kind { K_BASELINE, K_V4, K_V6 };

struct bench_case {
	const char *name;
	enum kind kind;
	uint8_t proto;		/* IPPROTO_UDP / TCP / ICMP */
	unsigned payload;
	uint8_t tmpl[MAX_TEMPLATE];
	uint32_t len;
};

static uint32_t sum16(const void *data, size_t len, uint32_t sum)
{
	const uint8_t *p = data;
	for (; len > 1; len -= 2, p += 2)
		sum += (uint32_t)(p[0] << 8 | p[1]);
	if (len)
		sum += (uint32_t)(p[0] << 8);
	return sum;
}

static uint16_t fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

/* Build the L4 segment at seg (len bytes) and return its checksum over pseudo. */
static void build_l4(struct bench_case *c, uint8_t *seg, uint32_t pseudo)
{
	unsigned l4len, hdr;
	uint8_t *pl;
	switch (c->proto) {
	case IPPROTO_UDP:
		hdr = 8; l4len = hdr + c->payload;
		put16(seg, 40000); put16(seg + 2, 5001); put16(seg + 4, l4len);
		break;
	case IPPROTO_TCP:
		hdr = 20; l4len = hdr + c->payload;
		put16(seg, 40000); put16(seg + 2, 5001);
		seg[4] = 0x01; seg[5] = 0x02; seg[6] = 0x03; seg[7] = 0x04;	/* seq */
		seg[8] = 0x0a; seg[9] = 0x0b; seg[10] = 0x0c; seg[11] = 0x0d;	/* ack */
		seg[12] = 5 << 4; seg[13] = 0x10;				/* ACK */
		put16(seg + 14, 65535);
		break;
	default:	/* ICMPv4 echo request */
		hdr = 8; l4len = hdr + c->payload;
		seg[0] = 8; seg[1] = 0; put16(seg + 4, 0x1234); put16(seg + 6, 1);
		break;
	}
	pl = seg + hdr;
	for (unsigned i = 0; i < c->payload; ++i)
		pl[i] = (uint8_t)(i * 7 + 1);
	uint32_t sum = sum16(seg, l4len, c->proto == IPPROTO_ICMP ? 0 : pseudo + l4len);
	uint16_t ck = fold(sum);
	if (c->proto == IPPROTO_UDP && !ck)
		ck = 0xffff;
	put16(seg + (c->proto == IPPROTO_UDP ? 6 : c->proto == IPPROTO_TCP ? 16 : 2), ck);
	c->len = l4len;
}

static void build(struct bench_case *c, const char *src, const char *dst)
{
	uint8_t *t = c->tmpl;
	memset(t, 0, sizeof(c->tmpl));
	if (c->kind == K_V4) {
		struct in_addr a, b;
		inet_pton(AF_INET, src, &a);
		inet_pton(AF_INET, dst, &b);
		uint32_t pseudo = sum16(&a, 4, 0) + sum16(&b, 4, 0) + c->proto;
		build_l4(c, t + 20, pseudo);
		uint32_t total = 20 + c->len;
		t[0] = 0x45; put16(t + 2, total); put16(t + 4, 0x4242);
		put16(t + 6, 0x4000);	/* DF */
		t[8] = 64; t[9] = c->proto;
		memcpy(t + 12, &a, 4); memcpy(t + 16, &b, 4);
		put16(t + 10, fold(sum16(t, 20, 0)));
		c->len = total;
	} else {
		struct in6_addr a, b;
		inet_pton(AF_INET6, src, &a);
		inet_pton(AF_INET6, dst, &b);
		/* pseudo-header length is added in build_l4 via pseudo + l4len */
		uint32_t pseudo = sum16(&a, 16, 0) + sum16(&b, 16, 0) + c->proto;
		build_l4(c, t + 40, pseudo);
		t[0] = 0x60; put16(t + 4, c->len);
		t[6] = c->proto; t[7] = 64;
		memcpy(t + 8, &a, 16); memcpy(t + 24, &b, 16);
		c->len += 40;
	}
}

static struct bench_case cases[] = {
	{ "baseline_write_1400", K_BASELINE, 0, 0 },
	{ "udp4to6_64", K_V4, IPPROTO_UDP, 64 },
	{ "udp4to6_1400", K_V4, IPPROTO_UDP, 1400 },
	{ "udp6to4_64", K_V6, IPPROTO_UDP, 64 },
	{ "udp6to4_1400", K_V6, IPPROTO_UDP, 1400 },
	{ "tcp4to6_1400", K_V4, IPPROTO_TCP, 1400 },
	{ "tcp6to4_1400", K_V6, IPPROTO_TCP, 1400 },
	{ "icmp_echo4to6", K_V4, IPPROTO_ICMP, 56 },
};

static uint8_t work[HEADROOM + MAX_TEMPLATE + 64] __attribute__((aligned(16)));

static void run_once(const struct bench_case *c, int fd)
{
	memcpy(work + HEADROOM, c->tmpl, c->len);
	if (c->kind == K_BASELINE) {
		if (write(fd, work + HEADROOM, BASELINE_LEN) < 0)
			abort();
		return;
	}
	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.tun_fd = fd;
	p.data = work + HEADROOM;
	p.data_len = c->len;
	if (c->kind == K_V4)
		handle_ip4(&p);
	else
		handle_ip6(&p);
}

static void self_check(const struct bench_case *c)
{
	int fds[2];
	uint8_t out[2048];
	if (c->kind == K_BASELINE)
		return;
	if (pipe(fds) < 0)
		abort();
	run_once(c, fds[1]);
	close(fds[1]);
	ssize_t n = read(fds[0], out, sizeof(out));
	close(fds[0]);
	int want = c->kind == K_V4 ? 6 : 4;
	if (n <= 0 || (out[0] >> 4) != want) {
		fprintf(stderr, "self-check failed: %s\n", c->name);
		exit(1);
	}
}

static int parse_pos(const char *s, long *out)
{
	char *end;
	errno = 0;
	long v = strtol(s, &end, 10);
	if (errno || *end || end == s || v <= 0)
		return -1;
	*out = v;
	return 0;
}

int main(int argc, char **argv)
{
	long iters = 2000000, runs = 5;
	for (int i = 1; i < argc; ++i) {
		long *dst = !strcmp(argv[i], "--iters") ? &iters :
			    !strcmp(argv[i], "--runs") ? &runs : NULL;
		if (!dst || i + 1 >= argc || parse_pos(argv[i + 1], dst)) {
			fprintf(stderr, "usage: %s [--iters N] [--runs R]  (positive integers)\n", argv[0]);
			return 2;
		}
		++i;
	}

	fuzz_setup_maps();
	gcfg.vnet_hdr_sz = 0;
	gcfg.tun_offload_effective = TUN_OFFLOAD_OFF;

	for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); ++k) {
		struct bench_case *c = &cases[k];
		if (c->kind == K_BASELINE) {
			c->len = BASELINE_LEN;
			for (unsigned i = 0; i < BASELINE_LEN; ++i)
				c->tmpl[i] = (uint8_t)i;
		} else if (c->kind == K_V4) {
			build(c, "192.0.0.1", "198.51.100.1");
		} else {
			build(c, "64:ff9b::c633:6401", "fd9b:64:1:ff::10");
		}
		self_check(c);

		double best = 0;
		for (long r = 0; r < runs; ++r) {
			struct timespec t0, t1;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			for (long i = 0; i < iters; ++i)
				run_once(c, fuzz_null_fd);
			clock_gettime(CLOCK_MONOTONIC, &t1);
			double ns = ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec)) / (double)iters;
			if (r == 0 || ns < best)
				best = ns;
		}
		printf("{\"case\": \"%s\", \"ns_per_pkt\": %.2f, \"iters\": %ld, \"runs\": %ld}\n",
		       c->name, best, iters, runs);
		fflush(stdout);
	}
	return 0;
}
