/* Unit tests for scalar IPv4<->IPv6 and ICMPv4<->ICMPv6 translation in nat64.c. */
#include "tayga.h"
#include "stats.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

_Atomic time_t now = 10000;

static int g_fds[2] = {-1, -1};
static uint8_t g_out[4096];

static uint16_t sum16(const void *data, size_t len, uint32_t sum)
{
	const uint8_t *p = data;
	for (; len > 1; len -= 2, p += 2)
		sum += (uint32_t)(p[0] << 8 | p[1]);
	if (len)
		sum += (uint32_t)(p[0] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)~sum);
}

static uint16_t l4_csum4(const struct in_addr *src, const struct in_addr *dst,
			 uint8_t proto, const void *seg, size_t len)
{
	uint32_t sum = 0;
	const uint8_t *s = (const uint8_t *)src;
	const uint8_t *d = (const uint8_t *)dst;
	sum += (uint32_t)(s[0] << 8 | s[1]) + (uint32_t)(s[2] << 8 | s[3]);
	sum += (uint32_t)(d[0] << 8 | d[1]) + (uint32_t)(d[2] << 8 | d[3]);
	sum += proto + (uint32_t)len;
	return sum16(seg, len, sum);
}

static uint16_t l4_csum6(const struct in6_addr *src, const struct in6_addr *dst,
			 uint8_t proto, const void *seg, size_t len)
{
	uint32_t sum = 0;
	for (int i = 0; i < 16; i += 2) {
		sum += (uint32_t)(src->s6_addr[i] << 8 | src->s6_addr[i + 1]);
		sum += (uint32_t)(dst->s6_addr[i] << 8 | dst->s6_addr[i + 1]);
	}
	sum += proto + (uint32_t)len;
	return sum16(seg, len, sum);
}

static void setup_env(void)
{
	assert(config_init() == 0);
	assert(pthread_mutex_init(&gcfg.map_mutex, NULL) == 0);
	assert(pthread_mutex_init(&gcfg.cache_mutex, NULL) == 0);
	char name[] = "nat64-XXXXXX";
	int fd = mkstemp(name);
	assert(fd >= 0);
	FILE *f = fdopen(fd, "w");
	assert(f);
	fputs("tun-device nat64t\n"
	      "ipv4-addr 192.0.2.254\n"
	      "ipv6-addr fd9b:64:1:ff::fe\n"
	      "prefix 64:ff9b::/96\n"
	      "map 192.0.2.1 fd9b:64:1:ff::10\n"
	      "map 8.8.4.2 fd9b:64:1:ff::20\n", f);
	assert(fclose(f) == 0);
	assert(config_read(name) == 0);
	assert(config_validate() == 0);
	assert(unlink(name) == 0);
	gcfg.mtu = 1500;
	gcfg.icmp_rate_limit = UINT32_MAX;
	gcfg.udp_cksum_mode = UDP_CKSUM_FWD;
	gcfg.log_opts = 0;
	stats_init();
	icmp_rate_limit_reset();
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, g_fds) == 0);
}

static void teardown_env(void)
{
	close(g_fds[0]);
	close(g_fds[1]);
	struct list_head *entry, *next;
	list_for_each_safe(entry, next, &gcfg.map4_list) {
		struct map_static *m = list_entry(entry, struct map_static, map4.list);
		list_del(&m->map4.list);
		list_del(&m->map6.list);
		free(m);
	}
	pthread_mutex_destroy(&gcfg.map_mutex);
	pthread_mutex_destroy(&gcfg.cache_mutex);
}

static void drain_out(void)
{
	while (recv(g_fds[1], g_out, sizeof(g_out), MSG_DONTWAIT) >= 0)
		;
}

static ssize_t recv_out(void)
{
#ifdef __linux__
	return recv(g_fds[1], g_out, sizeof(g_out), MSG_DONTWAIT);
#else
	uint8_t raw[sizeof(g_out) + sizeof(struct tun_pi)];
	ssize_t n = recv(g_fds[1], raw, sizeof(raw), MSG_DONTWAIT);
	if (n < (ssize_t)sizeof(struct tun_pi))
		return -1;
	n -= (ssize_t)sizeof(struct tun_pi);
	memcpy(g_out, raw + sizeof(struct tun_pi), (size_t)n);
	return n;
#endif
}

static void feed_ip4(const uint8_t *pkt, uint32_t len)
{
	uint8_t buf[HEADROOM + 4096];
	assert(len <= 4096);
	memset(buf, 0, HEADROOM);
	memcpy(buf + HEADROOM, pkt, len);
	struct pkt p = {0};
	p.tun_fd = g_fds[0];
	p.data = buf + HEADROOM;
	p.data_len = len;
	drain_out();
	handle_ip4(&p);
}

static void feed_ip6(const uint8_t *pkt, uint32_t len)
{
	uint8_t buf[HEADROOM + 4096];
	assert(len <= 4096);
	memset(buf, 0, HEADROOM);
	memcpy(buf + HEADROOM, pkt, len);
	struct pkt p = {0};
	p.tun_fd = g_fds[0];
	p.data = buf + HEADROOM;
	p.data_len = len;
	drain_out();
	handle_ip6(&p);
}

static uint32_t build_ip4_hdr(uint8_t *b, const char *src, const char *dst,
			      uint8_t proto, uint8_t ttl, uint16_t flags_off,
			      uint32_t l4len)
{
	struct ip4 *ip4 = (struct ip4 *)b;
	memset(ip4, 0, sizeof(*ip4));
	ip4->ver_ihl = 0x45;
	ip4->length = htons((uint16_t)(sizeof(*ip4) + l4len));
	ip4->ident = htons(0x1234);
	ip4->flags_offset = htons(flags_off);
	ip4->ttl = ttl;
	ip4->proto = proto;
	assert(inet_pton(AF_INET, src, &ip4->src) == 1);
	assert(inet_pton(AF_INET, dst, &ip4->dest) == 1);
	ip4->cksum = sum16(ip4, sizeof(*ip4), 0);
	return (uint32_t)(sizeof(*ip4) + l4len);
}

static uint32_t build_ip6_hdr(uint8_t *b, const char *src, const char *dst,
			      uint8_t nexthdr, uint8_t hoplim, uint32_t paylen)
{
	struct ip6 *ip6 = (struct ip6 *)b;
	memset(ip6, 0, sizeof(*ip6));
	ip6->ver_tc_fl = htonl(0x60000000u);
	ip6->payload_length = htons((uint16_t)paylen);
	ip6->next_header = nexthdr;
	ip6->hop_limit = hoplim;
	assert(inet_pton(AF_INET6, src, &ip6->src) == 1);
	assert(inet_pton(AF_INET6, dst, &ip6->dest) == 1);
	return (uint32_t)(sizeof(*ip6) + paylen);
}

static void test_host_icmp4_and_icmp6(void)
{
	uint8_t pkt[128];
	/* IPv4 Echo Request to local_addr4 */
	memset(pkt, 0, sizeof(pkt));
	struct icmp *ic = (struct icmp *)(pkt + 20);
	ic->type = 8; ic->code = 0; ic->word = htonl(0x11220001u);
	memcpy(pkt + 28, "hello", 5);
	ic->cksum = sum16(ic, 13, 0);
	uint32_t len = build_ip4_hdr(pkt, "192.0.2.1", "192.0.2.254", 1, 64, 0x4000, 13);
	feed_ip4(pkt, len);
	ssize_t n = recv_out();
	assert(n == (ssize_t)len);
	assert(((struct ip4 *)g_out)->proto == 1);
	assert(((struct icmp *)(g_out + 20))->type == 0);

	/* IPv4 unknown ICMP type to local_addr4 -> dropped */
	ic->type = 13; ic->cksum = 0; ic->cksum = sum16(ic, 13, 0);
	feed_ip4(pkt, len);
	assert(recv_out() < 0);

	/* IPv4 non-ICMP to local_addr4 -> ICMPv4 Protocol Unreachable (type 3, code 2) */
	len = build_ip4_hdr(pkt, "192.0.2.1", "192.0.2.254", 17, 64, 0x4000, 8);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n > 28);
	assert(((struct icmp *)(g_out + 20))->type == 3);
	assert(((struct icmp *)(g_out + 20))->code == 2);

	/* IPv6 Echo Request to local_addr6 */
	memset(pkt, 0, sizeof(pkt));
	ic = (struct icmp *)(pkt + 40);
	ic->type = 128; ic->code = 0; ic->word = htonl(0x33440001u);
	memcpy(pkt + 48, "world", 5);
	len = build_ip6_hdr(pkt, "fd9b:64:1:ff::10", "fd9b:64:1:ff::fe", 58, 64, 13);
	struct ip6 *ip6 = (struct ip6 *)pkt;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 13);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == (ssize_t)len);
	assert(((struct ip6 *)g_out)->next_header == 58);
	assert(((struct icmp *)(g_out + 40))->type == 129);

	/* IPv6 unknown ICMP type to local_addr6 -> dropped */
	ic->type = 135; ic->cksum = 0;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 13);
	feed_ip6(pkt, len);
	assert(recv_out() < 0);

	/* IPv6 non-ICMP to local_addr6 -> ICMPv6 Parameter Problem (type 4, code 1) */
	len = build_ip6_hdr(pkt, "fd9b:64:1:ff::10", "fd9b:64:1:ff::fe", 17, 64, 8);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n > 48);
	assert(((struct icmp *)(g_out + 40))->type == 4);
	assert(((struct icmp *)(g_out + 40))->code == 1);
	printf("PASS: host_handle_icmp4 and host_handle_icmp6\n");
}

static void test_4to6_data_variants(void)
{
	uint8_t pkt[2048];
	/* TCP 4->6 with flow_label_mode = FLOW_LABEL_COMPUTE */
	gcfg.flow_label_mode = FLOW_LABEL_COMPUTE;
	memset(pkt, 0, 60);
	uint8_t *tcp = pkt + 20;
	tcp[0] = 0x10; tcp[1] = 0x00; tcp[2] = 0x00; tcp[3] = 0x50;
	tcp[12] = 0x50; tcp[13] = 0x10;
	uint32_t len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 6, 64, 0x4000, 28);
	struct ip4 *ip4 = (struct ip4 *)pkt;
	uint16_t c = l4_csum4(&ip4->src, &ip4->dest, 6, tcp, 28);
	memcpy(tcp + 16, &c, 2);
	feed_ip4(pkt, len);
	ssize_t n = recv_out();
	assert(n == 40 + 28);
	struct ip6 *out6 = (struct ip6 *)g_out;
	assert(out6->next_header == 6);
	assert((ntohl(out6->ver_tc_fl) & 0x000fffffu) != 0);
	gcfg.flow_label_mode = FLOW_LABEL_ZERO;

	/* UDP 4->6 with zero checksum: DROP vs CALC */
	memset(pkt, 0, 40);
	uint8_t *udp = pkt + 20;
	udp[0] = 0x11; udp[1] = 0x11; udp[2] = 0x00; udp[3] = 0x35;
	udp[4] = 0x00; udp[5] = 0x10; /* len 16 */
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 17, 64, 0x4000, 16);
	gcfg.udp_cksum_mode = UDP_CKSUM_DROP;
	feed_ip4(pkt, len);
	assert(recv_out() < 0);

	gcfg.udp_cksum_mode = UDP_CKSUM_CALC;
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 16);
	assert(g_out[46] != 0 || g_out[47] != 0);
	gcfg.udp_cksum_mode = UDP_CKSUM_FWD;

	/* Unknown L4 proto (GRE = 47) */
	memset(pkt, 0, 32);
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 47, 64, 0x4000, 12);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 12);
	assert(((struct ip6 *)g_out)->next_header == 47);

	/* DF=0 unfragmented -> translated without Fragment Header */
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 47, 64, 0x0000, 12);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 12);
	assert(((struct ip6 *)g_out)->next_header == 47);

	/* Fragmented IPv4 (MF=1, offset=0) */
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 47, 64, 0x2000, 16);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 8 + 16);
	assert(((struct ip6 *)g_out)->next_header == 44);

	/* IPv4 options stripped (IHL=6, 4 bytes NOP) */
	memset(pkt, 0, 40);
	pkt[0] = 0x46; pkt[2] = 0; pkt[3] = 36;
	pkt[6] = 0x40; pkt[8] = 64; pkt[9] = 47;
	inet_pton(AF_INET, "192.0.2.1", pkt + 12);
	inet_pton(AF_INET, "8.8.8.8", pkt + 16);
	pkt[20] = 1; pkt[21] = 1; pkt[22] = 1; pkt[23] = 0;
	uint16_t c4 = sum16(pkt, 24, 0);
	memcpy(pkt + 10, &c4, 2);
	feed_ip4(pkt, 36);
	n = recv_out();
	assert(n == 40 + 12);

	/* TTL=1 -> ICMPv4 Time Exceeded */
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 47, 1, 0x4000, 12);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n > 28);
	assert(((struct ip4 *)g_out)->proto == 1);
	assert(((struct icmp *)(g_out + 20))->type == 11);

	/* Oversized DF=1 -> ICMPv4 Too Big */
	gcfg.mtu = 1280;
	memset(pkt, 0, sizeof(pkt));
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 47, 64, 0x4000, 1300);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n > 28);
	assert(((struct icmp *)(g_out + 20))->type == 3);
	assert(((struct icmp *)(g_out + 20))->code == 4);
	gcfg.mtu = 1500;

	/* ICMPv4 Echo Request & Reply 4->6 */
	memset(pkt, 0, 40);
	struct icmp *ic = (struct icmp *)(pkt + 20);
	ic->type = 8; ic->word = htonl(0x12340005u);
	ic->cksum = sum16(ic, 12, 0);
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 1, 64, 0x4000, 12);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 12);
	assert(((struct icmp *)(g_out + 40))->type == 128);

	ic->type = 0; ic->cksum = 0; ic->cksum = sum16(ic, 12, 0);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 12);
	assert(((struct icmp *)(g_out + 40))->type == 129);
	printf("PASS: xlate_4to6_data variants\n");
}

static void test_6to4_data_variants(void)
{
	uint8_t pkt[2048];
	/* TCP 6->4 <= 1260 -> DF=0 */
	memset(pkt, 0, 80);
	uint8_t *tcp = pkt + 40;
	tcp[0] = 0x10; tcp[1] = 0x00; tcp[2] = 0x00; tcp[3] = 0x50;
	tcp[12] = 0x50; tcp[13] = 0x10;
	uint32_t len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 6, 64, 28);
	struct ip6 *ip6 = (struct ip6 *)pkt;
	uint16_t c = l4_csum6(&ip6->src, &ip6->dest, 6, tcp, 28);
	memcpy(tcp + 16, &c, 2);
	feed_ip6(pkt, len);
	ssize_t n = recv_out();
	assert(n == 20 + 28);
	assert(((struct ip4 *)g_out)->proto == 6);
	assert((ntohs(((struct ip4 *)g_out)->flags_offset) & 0x4000) == 0);

	/* TCP 6->4 > 1260 -> DF=1 */
	memset(pkt, 0, 1400);
	tcp[12] = 0x50; tcp[13] = 0x10;
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 6, 64, 1300);
	c = l4_csum6(&ip6->src, &ip6->dest, 6, tcp, 1300);
	memcpy(tcp + 16, &c, 2);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 1300);
	assert((ntohs(((struct ip4 *)g_out)->flags_offset) & 0x4000) == 0x4000);

	/* UDP 6->4 */
	memset(pkt, 0, 64);
	uint8_t *udp = pkt + 40;
	udp[0] = 0x11; udp[1] = 0x11; udp[2] = 0x00; udp[3] = 0x35;
	udp[4] = 0x00; udp[5] = 0x10;
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 17, 64, 16);
	c = l4_csum6(&ip6->src, &ip6->dest, 17, udp, 16);
	memcpy(udp + 6, &c, 2);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 16);
	assert(((struct ip4 *)g_out)->proto == 17);

	/* ICMPv6 Echo Request & Reply 6->4 */
	memset(pkt, 0, 64);
	struct icmp *ic = (struct icmp *)(pkt + 40);
	ic->type = 128; ic->word = htonl(0x22220001u);
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 58, 64, 12);
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 12);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 12);
	assert(((struct icmp *)(g_out + 20))->type == 8);

	ic->type = 129; ic->cksum = 0;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 12);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 12);
	assert(((struct icmp *)(g_out + 20))->type == 0);

	/* Hop-by-Hop + Fragment Header (non-atomic, 8-byte aligned payload) */
	memset(pkt, 0, 80);
	pkt[40] = 44; pkt[41] = 0; /* HBH len=0 (8 bytes), next=44 */
	pkt[48] = 47; pkt[50] = 0; pkt[51] = 1; /* Frag: next=47, MF=1 */
	pkt[54] = 0xaa; pkt[55] = 0xbb;
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 0, 64, 32);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 16);
	assert(((struct ip4 *)g_out)->proto == 47);
	assert((ntohs(((struct ip4 *)g_out)->flags_offset) & 0x2000) == 0x2000);

	/* Routing Header with seg_left > 0 -> ICMPv6 Parameter Problem code 0 */
	memset(pkt, 0, 80);
	pkt[40] = 47; pkt[41] = 0; pkt[42] = 0; pkt[43] = 2; /* Routing hdr, seg_left=2 */
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 43, 64, 16);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n > 48);
	assert(((struct icmp *)(g_out + 40))->type == 4);
	assert(((struct icmp *)(g_out + 40))->code == 0);

	/* Hop Limit=1 -> ICMPv6 Time Exceeded */
	memset(pkt, 0, 64);
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 47, 1, 12);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n > 48);
	assert(((struct ip6 *)g_out)->next_header == 58);
	assert(((struct icmp *)(g_out + 40))->type == 3);

	/* Oversized IPv6 -> ICMPv6 Packet Too Big */
	gcfg.mtu = 1280;
	memset(pkt, 0, sizeof(pkt));
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 47, 64, 1300);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n > 48);
	assert(((struct icmp *)(g_out + 40))->type == 2);
	gcfg.mtu = 1500;
	printf("PASS: xlate_6to4_data variants\n");
}

static void test_icmp_errors_both_directions(void)
{
	uint8_t pkt[1600];
	/* ICMPv4 Dest Unreach code 4 (PTB) with embedded IPv4/UDP */
	memset(pkt, 0, 128);
	struct icmp *ic = (struct icmp *)(pkt + 20);
	ic->type = 3; ic->code = 4; ic->word = htonl(1400);
	uint8_t *emb4 = pkt + 28;
	build_ip4_hdr(emb4, "192.0.2.1", "8.8.8.8", 17, 64, 0x4000, 8);
	emb4[20] = 0x12; emb4[21] = 0x34; emb4[22] = 0x00; emb4[23] = 0x50;
	emb4[24] = 0; emb4[25] = 8;
	ic->cksum = sum16(ic, 8 + 28, 0);
	uint32_t len = build_ip4_hdr(pkt, "8.8.4.4", "192.0.2.1", 1, 64, 0x4000, 8 + 28);
	feed_ip4(pkt, len);
	ssize_t n = recv_out();
	assert(n == 40 + 8 + 40 + 8);
	assert(((struct icmp *)(g_out + 40))->type == 2);
	assert(ntohl(((struct icmp *)(g_out + 40))->word) == 1420);

	/* ICMPv4 Time Exceeded + Parameter Problem */
	ic->type = 11; ic->code = 0; ic->word = 0;
	ic->cksum = 0; ic->cksum = sum16(ic, 8 + 28, 0);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 8 + 40 + 8);
	assert(((struct icmp *)(g_out + 40))->type == 3);

	ic->type = 12; ic->code = 0; ic->word = htonl(9u << 24); /* proto ptr */
	ic->cksum = 0; ic->cksum = sum16(ic, 8 + 28, 0);
	feed_ip4(pkt, len);
	n = recv_out();
	assert(n == 40 + 8 + 40 + 8);
	assert(((struct icmp *)(g_out + 40))->type == 4);
	assert(ntohl(((struct icmp *)(g_out + 40))->word) == 6);

	/* ICMPv6 Dest Unreach codes 5 and 6 -> ICMPv4 code 10 */
	memset(pkt, 0, 160);
	ic = (struct icmp *)(pkt + 40);
	ic->type = 1; ic->code = 5; ic->word = 0;
	uint8_t *emb6 = pkt + 48;
	build_ip6_hdr(emb6, "fd9b:64:1:ff::10", "64:ff9b::0808:0808", 17, 64, 8);
	emb6[40] = 0x12; emb6[41] = 0x34; emb6[42] = 0x00; emb6[43] = 0x50;
	emb6[44] = 0; emb6[45] = 8;
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0404", "fd9b:64:1:ff::10", 58, 64, 8 + 48);
	struct ip6 *ip6 = (struct ip6 *)pkt;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 8 + 48);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 8 + 20 + 8);
	assert(((struct icmp *)(g_out + 20))->type == 3);
	assert(((struct icmp *)(g_out + 20))->code == 10);

	/* ICMPv6 PTB -> ICMPv4 type 3 code 4 */
	ic->type = 2; ic->code = 0; ic->word = htonl(1300);
	ic->cksum = 0;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 8 + 48);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 8 + 20 + 8);
	assert(((struct icmp *)(g_out + 20))->type == 3);
	assert(((struct icmp *)(g_out + 20))->code == 4);
	assert((ntohl(((struct icmp *)(g_out + 20))->word) & 0xffffu) == 1280);

	/* ICMPv6 Time Exceeded -> ICMPv4 type 11 */
	ic->type = 3; ic->code = 1; ic->word = 0;
	ic->cksum = 0;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 8 + 48);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 8 + 20 + 8);
	assert(((struct icmp *)(g_out + 20))->type == 11);
	assert(((struct icmp *)(g_out + 20))->code == 1);

	/* ICMPv6 Parameter Problem code 1 -> ICMPv4 type 3 code 2 */
	ic->type = 4; ic->code = 1; ic->word = 0;
	ic->cksum = 0;
	ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 8 + 48);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 8 + 20 + 8);
	assert(((struct icmp *)(g_out + 20))->type == 3);
	assert(((struct icmp *)(g_out + 20))->code == 2);
	printf("PASS: xlate_4to6_icmp_error and xlate_6to4_icmp_error\n");
}

static void feed_ip4_vhdr(const uint8_t *pkt, uint32_t len, struct virtio_net_hdr_raw *vh)
{
	uint8_t buf[HEADROOM + 4096];
	assert(len <= 4096);
	memset(buf, 0, HEADROOM);
	memcpy(buf + HEADROOM, pkt, len);
	struct pkt p = {0};
	p.tun_fd = g_fds[0];
	p.data = buf + HEADROOM;
	p.data_len = len;
	p.has_vhdr = 1;
	p.vhdr = *vh;
	drain_out();
	handle_ip4(&p);
}

static void feed_ip6_vhdr(const uint8_t *pkt, uint32_t len, struct virtio_net_hdr_raw *vh)
{
	uint8_t buf[HEADROOM + 4096];
	assert(len <= 4096);
	memset(buf, 0, HEADROOM);
	memcpy(buf + HEADROOM, pkt, len);
	struct pkt p = {0};
	p.tun_fd = g_fds[0];
	p.data = buf + HEADROOM;
	p.data_len = len;
	p.has_vhdr = 1;
	p.vhdr = *vh;
	drain_out();
	handle_ip6(&p);
}

static void test_offload_csum_and_extra_protos(void)
{
	uint8_t pkt[256];
	struct virtio_net_hdr_raw vh = {0};
	gcfg.log_opts = LOG_OPT_DROP | LOG_OPT_ICMP | LOG_OPT_SELF;

	/* TCP 4->6 with NEEDS_CSUM (vnet_hdr_sz = 0 completes checksum in software) */
	memset(pkt, 0, 64);
	pkt[20] = 0x10; pkt[21] = 0x00; pkt[22] = 0x00; pkt[23] = 0x50;
	pkt[32] = 0x50; pkt[33] = 0x10;
	uint32_t len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 6, 64, 0x4000, 28);
	vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	vh.csum_start = 20;
	vh.csum_offset = 16;
	gcfg.vnet_hdr_sz = 0;
	feed_ip4_vhdr(pkt, len, &vh);
	assert(recv_out() == 40 + 28);

	/* Invalid TCP csum_offset -> dropped */
	vh.csum_offset = 6;
	feed_ip4_vhdr(pkt, len, &vh);
	assert(recv_out() < 0);

	/* TCP 6->4 with NEEDS_CSUM */
	memset(pkt, 0, 80);
	pkt[40] = 0x10; pkt[41] = 0x00; pkt[42] = 0x00; pkt[43] = 0x50;
	pkt[52] = 0x50; pkt[53] = 0x10;
	len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", 6, 64, 28);
	vh.csum_start = 40;
	vh.csum_offset = 16;
	feed_ip6_vhdr(pkt, len, &vh);
	assert(recv_out() == 20 + 28);

	/* DCCP (33), SCTP (132), UDPLite (136) */
	uint8_t protos[] = { 33, 132, 136 };
	for (size_t i = 0; i < 3; i++) {
		memset(pkt, 0, 64);
		if (protos[i] == 136) { pkt[26] = 0x12; pkt[27] = 0x34; }
		len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", protos[i], 64, 0x4000, 16);
		feed_ip4(pkt, len);
		assert(recv_out() == 40 + 16);

		memset(pkt, 0, 80);
		if (protos[i] == 136) { pkt[46] = 0x12; pkt[47] = 0x34; }
		len = build_ip6_hdr(pkt, "64:ff9b::0808:0808", "fd9b:64:1:ff::10", protos[i], 64, 16);
		feed_ip6(pkt, len);
		assert(recv_out() == 20 + 16);
	}
	/* UDPLite zero checksum -> dropped */
	memset(pkt, 0, 64);
	len = build_ip4_hdr(pkt, "192.0.2.1", "8.8.8.8", 136, 64, 0x4000, 16);
	feed_ip4(pkt, len);
	assert(recv_out() < 0);

	/* Unmapped destination -> ICMP error / drop */
	len = build_ip4_hdr(pkt, "192.0.2.2", "8.8.8.8", 47, 64, 0x4000, 12);
	feed_ip4(pkt, len);
	assert(recv_out() > 0); /* Host Unreachable */

	gcfg.log_opts = 0;
	printf("PASS: offload csum, DCCP/SCTP/UDPLite, and drop logging\n");
}

static void test_icmp_error_codes_and_rfc4884(void)
{
	uint8_t pkt[512];
	/* Test multiple ICMPv4 Dest Unreach codes */
	const uint8_t v4_codes[] = { 0, 1, 2, 3, 5, 9, 10, 13 };
	const uint8_t exp_v6_type[] = { 1, 1, 4, 1, 1, 1, 1, 1 };
	for (size_t i = 0; i < sizeof(v4_codes); i++) {
		memset(pkt, 0, 128);
		struct icmp *ic = (struct icmp *)(pkt + 20);
		ic->type = 3; ic->code = v4_codes[i];
		uint8_t *emb4 = pkt + 28;
		build_ip4_hdr(emb4, "192.0.2.1", "8.8.8.8", 17, 64, 0x4000, 8);
		emb4[20] = 0x12; emb4[21] = 0x34; emb4[22] = 0x00; emb4[23] = 0x50;
		emb4[24] = 0; emb4[25] = 8;
		ic->cksum = sum16(ic, 8 + 28, 0);
		uint32_t len = build_ip4_hdr(pkt, "8.8.4.4", "192.0.2.1", 1, 64, 0x4000, 8 + 28);
		feed_ip4(pkt, len);
		ssize_t n = recv_out();
		assert(n > 48);
		assert(((struct icmp *)(g_out + 40))->type == exp_v6_type[i]);
	}

	/* RFC 4884 multi-part ICMPv4 error (padded 128-byte original datagram + 8-byte ext) */
	memset(pkt, 0, 300);
	struct icmp *ic = (struct icmp *)(pkt + 20);
	ic->type = 11; ic->code = 0;
	pkt[25] = 32; /* Length in 32-bit words: 32 * 4 = 128 bytes */
	uint8_t *emb4 = pkt + 28;
	build_ip4_hdr(emb4, "192.0.2.1", "8.8.8.8", 17, 64, 0x4000, 8);
	emb4[20] = 0x12; emb4[21] = 0x34; emb4[22] = 0x00; emb4[23] = 0x50;
	emb4[24] = 0; emb4[25] = 8;
	uint8_t *ext = pkt + 28 + 128;
	ext[0] = 0x20; /* RFC 4884 version 2 */
	ext[4] = 0; ext[5] = 8; ext[6] = 1; ext[7] = 1;
	uint16_t ec = sum16(ext, 8, 0);
	memcpy(ext + 2, &ec, 2);
	ic->cksum = sum16(ic, 8 + 128 + 8, 0);
	uint32_t len = build_ip4_hdr(pkt, "8.8.4.4", "192.0.2.1", 1, 64, 0x4000, 8 + 128 + 8);
	feed_ip4(pkt, len);
	ssize_t n = recv_out();
	assert(n == 40 + 8 + 128 + 8);
	assert(g_out[44] == 16); /* 16 * 8 = 128 bytes */

	/* Test multiple ICMPv6 Dest Unreach codes */
	const uint8_t v6_codes[] = { 0, 1, 2, 3, 4 };
	const uint8_t exp_v4_code[] = { 1, 10, 1, 1, 3 };
	for (size_t i = 0; i < sizeof(v6_codes); i++) {
		memset(pkt, 0, 160);
		ic = (struct icmp *)(pkt + 40);
		ic->type = 1; ic->code = v6_codes[i];
		uint8_t *emb6 = pkt + 48;
		build_ip6_hdr(emb6, "fd9b:64:1:ff::10", "64:ff9b::0808:0808", 17, 64, 8);
		emb6[40] = 0x12; emb6[41] = 0x34; emb6[42] = 0x00; emb6[43] = 0x50;
		emb6[44] = 0; emb6[45] = 8;
		len = build_ip6_hdr(pkt, "64:ff9b::0808:0404", "fd9b:64:1:ff::10", 58, 64, 8 + 48);
		struct ip6 *ip6 = (struct ip6 *)pkt;
		ic->cksum = l4_csum6(&ip6->src, &ip6->dest, 58, ic, 8 + 48);
		feed_ip6(pkt, len);
		n = recv_out();
		assert(n == 20 + 8 + 20 + 8);
		assert(((struct icmp *)(g_out + 20))->type == 3);
		assert(((struct icmp *)(g_out + 20))->code == exp_v4_code[i]);
	}
	printf("PASS: extra ICMP error codes and RFC 4884 extensions\n");
}

static void test_hairpin_and_icmp_v4_pool(void)
{
	uint8_t pkt[1600];

	/* RFC 7757 §4.2 Hairpinning: fd9b:64:1:ff::10 -> 64:ff9b::8.8.4.2
	 * must hairpin back to IPv6 dest fd9b:64:1:ff::20 with hop_limit - 1. */
	memset(pkt, 0, 128);
	uint8_t *udp = pkt + 40;
	udp[0] = 0x12; udp[1] = 0x34; /* src port */
	udp[2] = 0x00; udp[3] = 0x50; /* dst port */
	udp[4] = 0x00; udp[5] = 0x0c; /* len 12 */
	memcpy(udp + 8, "ping", 4);
	uint32_t len = build_ip6_hdr(pkt, "fd9b:64:1:ff::10", "64:ff9b::0808:0402", 17, 64, 12);
	struct ip6 *in6 = (struct ip6 *)pkt;
	uint16_t ucsum = l4_csum6(&in6->src, &in6->dest, 17, udp, 12);
	memcpy(udp + 6, &ucsum, 2);
	feed_ip6(pkt, len);
	ssize_t n = recv_out();
	assert(n == 40 + 12);
	assert((g_out[0] >> 4) == 6);
	struct ip6 *out6 = (struct ip6 *)g_out;
	struct in6_addr exp_src, exp_dst;
	assert(inet_pton(AF_INET6, "fd9b:64:1:ff::10", &exp_src) == 1);
	assert(inet_pton(AF_INET6, "fd9b:64:1:ff::20", &exp_dst) == 1);
	assert(IN6_ARE_ADDR_EQUAL(&out6->src, &exp_src));
	assert(IN6_ARE_ADDR_EQUAL(&out6->dest, &exp_dst));
	assert(out6->hop_limit == 63);
	assert(memcmp(g_out + 40 + 8, "ping", 4) == 0);

	/* RFC 6791: untranslatable IPv6 ICMP error source selects from icmp-v4-pool */
	assert(inet_pton(AF_INET, "198.51.100.128", &gcfg.icmp_v4_pool_addr) == 1);
	gcfg.icmp_v4_pool_mask.s_addr = htonl(0xfffffff0u);
	gcfg.icmp_v4_pool_len = 28;
	memset(pkt, 0, 160);
	struct icmp *ic = (struct icmp *)(pkt + 40);
	ic->type = 3; /* Time Exceeded */
	ic->code = 0;
	uint8_t *emb6 = pkt + 48;
	build_ip6_hdr(emb6, "fd9b:64:1:ff::10", "64:ff9b::0808:0808", 17, 64, 8);
	emb6[40] = 0x12; emb6[41] = 0x34; emb6[42] = 0x00; emb6[43] = 0x50;
	emb6[44] = 0; emb6[45] = 8;
	len = build_ip6_hdr(pkt, "2001:db8:dead::1", "fd9b:64:1:ff::10", 58, 64, 8 + 48);
	in6 = (struct ip6 *)pkt;
	ic->cksum = l4_csum6(&in6->src, &in6->dest, 58, ic, 8 + 48);
	feed_ip6(pkt, len);
	n = recv_out();
	assert(n == 20 + 8 + 20 + 8);
	assert((g_out[0] >> 4) == 4);
	struct ip4 *out4 = (struct ip4 *)g_out;
	uint32_t s4 = ntohl(out4->src.s_addr);
	assert((s4 & 0xfffffff0u) == 0xc6336480u);
	assert((s4 & 0x0fu) >= 1 && (s4 & 0x0fu) <= 14);
	gcfg.icmp_v4_pool_len = 0;

	printf("PASS: RFC 7757 §4.2 hairpinning and RFC 6791 icmp-v4-pool\n");
}

int main(void)
{
	setup_env();
	test_host_icmp4_and_icmp6();
	test_4to6_data_variants();
	test_6to4_data_variants();
	test_icmp_errors_both_directions();
	test_offload_csum_and_extra_protos();
	test_icmp_error_codes_and_rfc4884();
	test_hairpin_and_icmp_v4_pool();
	teardown_env();
	printf("All unit_nat64 tests passed!\n");
	return 0;
}
