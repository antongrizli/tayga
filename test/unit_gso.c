/*
 *  test/unit_gso.c -- Unit tests for TCP GSO/GRO engine
 *  Part of TAYGA CLAT performance optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tayga.h"
#include "gso.h"

struct config gcfg;
time_t now;

static void setup_test_mapping(void)
{
	memset(&gcfg, 0, sizeof(gcfg));
	INIT_LIST_HEAD(&gcfg.map4_list);
	INIT_LIST_HEAD(&gcfg.map6_list);
	gcfg.maps_immutable = 1;
	gcfg.vnet_hdr_sz = 10;
	inet_pton(AF_INET, "192.0.0.254", &gcfg.local_addr4);
	inet_pton(AF_INET6, "fd9b:64:1:ff::254", &gcfg.local_addr6);

	/* Create prefix map: 64:ff9b::/96 */
	static struct map_static pref_map;
	memset(&pref_map, 0, sizeof(pref_map));
	pref_map.map4.type = MAP_TYPE_RFC6052;
	pref_map.map4.prefix_len = 0;
	INIT_LIST_HEAD(&pref_map.map4.list);
	insert_map4(&pref_map.map4, NULL);
	pref_map.map6.type = MAP_TYPE_RFC6052;
	pref_map.map6.prefix_len = 96;
	INIT_LIST_HEAD(&pref_map.map6.list);
	inet_pton(AF_INET6, "64:ff9b::", &pref_map.map6.addr);
	calc_ip6_mask(&pref_map.map6.mask, NULL, 96);
	insert_map6(&pref_map.map6, NULL);

	/* Set static map: 192.0.0.1 <-> fd9b:64:1:ff::10 */
	static struct map_static client_map;
	memset(&client_map, 0, sizeof(client_map));
	client_map.map4.type = MAP_TYPE_STATIC;
	client_map.map4.prefix_len = 32;
	INIT_LIST_HEAD(&client_map.map4.list);
	inet_pton(AF_INET, "192.0.0.1", &client_map.map4.addr);
	calc_ip4_mask(&client_map.map4.mask, NULL, 32);
	insert_map4(&client_map.map4, NULL);
	client_map.map6.type = MAP_TYPE_STATIC;
	client_map.map6.prefix_len = 128;
	INIT_LIST_HEAD(&client_map.map6.list);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &client_map.map6.addr);
	calc_ip6_mask(&client_map.map6.mask, NULL, 128);
	insert_map6(&client_map.map6, NULL);
}

static void test_gso_validate(void)
{
	printf("Testing gso_validate_header()...\n");
	struct pkt p;
	memset(&p, 0, sizeof(p));

	/* Case 1: no vhdr */
	p.has_vhdr = 0;
	assert(gso_validate_header(&p) == 0);

	/* Case 2: GSO_NONE */
	p.has_vhdr = 1;
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
	assert(gso_validate_header(&p) == 0);

	/* Case 3: Unsupported GSO type (e.g. UDP) */
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
	p.vhdr.gso_size = 1400;
	p.vhdr.hdr_len = 54;
	p.data_len = 2000;
	assert(gso_validate_header(&p) == -1);

	/* Case 4: Zero gso_size */
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
	p.vhdr.gso_size = 0;
	assert(gso_validate_header(&p) == -1);

	/* Case 5: hdr_len > data_len */
	p.vhdr.gso_size = 1400;
	p.vhdr.hdr_len = 3000;
	p.data_len = 2000;
	assert(gso_validate_header(&p) == -1);

	/* Case 6: Invalid csum offsets */
	p.vhdr.hdr_len = 54;
	p.data_len = 2000;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.csum_start = 2500;
	assert(gso_validate_header(&p) == -1);

	/* Case 7: Valid TCPv4 GSO */
	p.vhdr.csum_start = 20;
	p.vhdr.csum_offset = 16;
	assert(gso_validate_header(&p) == 1);

	/* Case 8: Valid TCPv6 GSO with ECN */
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6 | VIRTIO_NET_HDR_GSO_ECN;
	p.vhdr.csum_start = 40;
	p.vhdr.csum_offset = 16;
	assert(gso_validate_header(&p) == 1);

	printf("PASS: gso_validate_header()\n");
}

static uint16_t compute_full_tcp_cksum(const void *src, const void *dst, int is_v6,
                                       const struct tcp_hdr *tcp, uint32_t tcp_len,
                                       const uint8_t *payload, uint32_t payload_len)
{
	uint32_t sum = 0;
	if (is_v6) {
		const uint16_t *p6 = (const uint16_t *)src;
		for (int i = 0; i < 8; i++) sum += p6[i];
		p6 = (const uint16_t *)dst;
		for (int i = 0; i < 8; i++) sum += p6[i];
		sum += htons(tcp_len >> 16);
		sum += htons(tcp_len & 0xffff);
		sum += htons(IPPROTO_TCP);
	} else {
		const uint16_t *p4 = (const uint16_t *)src;
		sum += p4[0]; sum += p4[1];
		p4 = (const uint16_t *)dst;
		sum += p4[0]; sum += p4[1];
		sum += htons(IPPROTO_TCP);
		sum += htons((uint16_t)tcp_len);
	}

	uint32_t tcp_hdr_len = (tcp->doff_res >> 4) * 4;
	const uint8_t *tb = (const uint8_t *)tcp;
	for (uint32_t i = 0; i < tcp_hdr_len / 2; i++) {
		if (i == 8) continue; /* skip cksum field */
		uint16_t word;
		memcpy(&word, tb + i * 2, sizeof(word));
		sum += word;
	}

	for (uint32_t i = 0; i < payload_len / 2; i++) {
		uint16_t word;
		memcpy(&word, payload + i * 2, sizeof(word));
		sum += word;
	}
	if (payload_len & 1) {
		sum += htons((uint16_t)payload[payload_len - 1] << 8);
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (uint16_t)~sum;
}

static void test_gso_csum_update(void)
{
	printf("Testing gso_update_csum_6to4() and gso_update_csum_4to6()...\n");

	struct in6_addr src6, dst6;
	inet_pton(AF_INET6, "2001:db8:1::1", &src6);
	inet_pton(AF_INET6, "2001:db8:2::2", &dst6);

	struct in_addr src4, dst4;
	inet_pton(AF_INET, "192.0.2.1", &src4);
	inet_pton(AF_INET, "198.51.100.2", &dst4);

	uint8_t payload[100];
	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i ^ 0x5a);

	struct tcp_hdr tcp;
	memset(&tcp, 0, sizeof(tcp));
	tcp.src_port = htons(12345);
	tcp.dst_port = htons(80);
	tcp.seq = htonl(100000);
	tcp.ack_seq = htonl(50000);
	tcp.doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
	tcp.flags = TCP_FLAG_ACK;
	tcp.window = htons(65535);

	uint32_t tcp_len = sizeof(struct tcp_hdr) + sizeof(payload);

	/* Calculate full IPv6 TCP checksum */
	uint16_t cksum6 = compute_full_tcp_cksum(&src6, &dst6, 1, &tcp, tcp_len, payload, sizeof(payload));
	tcp.cksum = cksum6;

	/* Update to IPv4 */
	gso_update_csum_6to4(&tcp, &src6, &dst6, &src4, &dst4, tcp_len);

	/* Verify matches full IPv4 TCP checksum */
	uint16_t expected_cksum4 = compute_full_tcp_cksum(&src4, &dst4, 0, &tcp, tcp_len, payload, sizeof(payload));
	if (tcp.cksum != expected_cksum4) {
		printf("MISMATCH: got 0x%04x, expected 0x%04x\n", ntohs(tcp.cksum), ntohs(expected_cksum4));
	}
	assert(tcp.cksum == expected_cksum4);

	/* Reverse: update back to IPv6 */
	gso_update_csum_4to6(&tcp, &src4, &dst4, &src6, &dst6, tcp_len);
	assert(tcp.cksum == cksum6);

	printf("PASS: gso_update_csum_6to4() and gso_update_csum_4to6()\n");
}

static void test_gso_csum_seed(void)
{
	printf("Testing gso_calc_tcp_pseudo and gso_update_csum_seed...\n");

	struct in6_addr src6, dst6;
	inet_pton(AF_INET6, "2001:db8:1::1", &src6);
	inet_pton(AF_INET6, "2001:db8:2::2", &dst6);

	struct in_addr src4, dst4;
	inet_pton(AF_INET, "192.0.2.1", &src4);
	inet_pton(AF_INET, "198.51.100.2", &dst4);

	uint32_t tcp_len = 40;
	uint16_t seed4 = gso_calc_tcp_pseudo4(&src4, &dst4, tcp_len);
	uint16_t seed6 = gso_calc_tcp_pseudo6(&src6, &dst6, tcp_len);

	struct tcp_hdr tcp;
	memset(&tcp, 0, sizeof(tcp));
	tcp.cksum = htons(seed6);

	gso_update_csum_seed_6to4(&tcp, &src6, &dst6, &src4, &dst4, tcp_len);
	assert(ntohs(tcp.cksum) == seed4);

	gso_update_csum_seed_4to6(&tcp, &src4, &dst4, &src6, &dst6, tcp_len);
	assert(ntohs(tcp.cksum) == seed6);

	printf("PASS: gso_calc_tcp_pseudo and gso_update_csum_seed\n");
}

static void test_gso_translate_and_split(void)
{
	printf("Testing gso_translate_tcp_6to4() zero-copy, short tail split, and packet inspection...\n");
	setup_test_mapping();

	/* Create socketpair to mock tun_fd */
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

	/* Construct GSO packet: IPv6 + TCP + Payload */
	/* 2 full segments (1400 each) + 1 tail segment (400 bytes) = 3200 bytes payload */
	uint8_t pkt_buf[HEADROOM + 40 + 20 + 3200];
	uint8_t *raw_pkt = pkt_buf + HEADROOM;
	struct ip6 *ip6 = (struct ip6 *)raw_pkt;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));
	uint8_t *payload = raw_pkt + sizeof(struct ip6) + sizeof(struct tcp_hdr);

	memset(pkt_buf, 0, sizeof(pkt_buf));

	/* IPv6 header: src = 64:ff9b::198.51.100.2, dest = fd9b:64:1:ff::10 */
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(sizeof(struct tcp_hdr) + 3200);
	ip6->next_header = IPPROTO_TCP;
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	/* TCP header */
	tcp->src_port = htons(80);
	tcp->dst_port = htons(54321);
	tcp->seq = htonl(1000);
	tcp->ack_seq = htonl(500);
	tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
	tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN;
	tcp->window = htons(65535);

	for (int i = 0; i < 3200; i++) {
		payload[i] = (uint8_t)(i & 0xff);
	}

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.tun_fd = sv[0];
	p.data = raw_pkt;
	p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 3200;
	p.has_vhdr = 1;
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	p.vhdr.gso_size = 1400;
	p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
	p.vhdr.csum_start = sizeof(struct ip6);
	p.vhdr.csum_offset = 16;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

	uint64_t prev_split = atomic_load_explicit(&g_gso_stats.gso_split_tail_pkts, memory_order_relaxed);

	int res = gso_translate_tcp_6to4(&p);
	assert(res == 0);

	uint64_t curr_split = atomic_load_explicit(&g_gso_stats.gso_split_tail_pkts, memory_order_relaxed);
	assert(curr_split == prev_split + 1);

	/* Inspect Datagram 1: Head GSO aggregate */
	uint8_t rx_buf[4096];
	ssize_t n1 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
	assert(n1 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800);

	struct virtio_net_hdr_raw *v1 = (struct virtio_net_hdr_raw *)rx_buf;
	assert(v1->gso_type == VIRTIO_NET_HDR_GSO_TCPV4);
	assert(v1->gso_size == 1400);
	assert(v1->hdr_len == sizeof(struct ip4) + sizeof(struct tcp_hdr));
	assert(v1->csum_start == sizeof(struct ip4));
	assert(v1->csum_offset == 16);
	assert(v1->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);

	struct ip4 *ip4_1 = (struct ip4 *)(rx_buf + 10);
	assert(ip4_1->ver_ihl == 0x45);
	assert(ntohs(ip4_1->length) == sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800);
	assert(ip4_1->flags_offset == htons(IP4_F_DF)); /* DF=1 */
	assert(ip4_1->ident == 0);
	assert(ip4_1->ttl == 63); /* decremented from 64 */
	assert(ip4_1->proto == IPPROTO_TCP);
	assert(ip_checksum(ip4_1, sizeof(struct ip4)) == 0);

	struct tcp_hdr *tcp_1 = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
	assert(tcp_1->seq == htonl(1000));
	assert(tcp_1->flags == TCP_FLAG_ACK); /* FIN and PSH cleared */
	uint16_t exp_seed = gso_calc_tcp_pseudo4(&ip4_1->src, &ip4_1->dest, sizeof(struct tcp_hdr) + 2800);
	assert(ntohs(tcp_1->cksum) == exp_seed);

	uint8_t *payload_1 = rx_buf + 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr);
	for (int i = 0; i < 2800; i++) {
		assert(payload_1[i] == (uint8_t)(i & 0xff));
	}

	/* Inspect Datagram 2: Tail short packet */
	ssize_t n2 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
	assert(n2 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 400);

	struct virtio_net_hdr_raw *v2 = (struct virtio_net_hdr_raw *)rx_buf;
	assert(v2->gso_type == VIRTIO_NET_HDR_GSO_NONE);

	struct ip4 *ip4_2 = (struct ip4 *)(rx_buf + 10);
	assert(ip4_2->ver_ihl == 0x45);
	assert(ntohs(ip4_2->length) == sizeof(struct ip4) + sizeof(struct tcp_hdr) + 400);
	assert(ip4_2->flags_offset == 0); /* DF=0 because total length <= 1260 */
	assert(ip4_2->ident != 0); /* Generated ID */
	assert(ip4_2->ttl == 63);
	assert(ip4_2->proto == IPPROTO_TCP);
	assert(ip_checksum(ip4_2, sizeof(struct ip4)) == 0);

	struct tcp_hdr *tcp_2 = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
	assert(tcp_2->seq == htonl(1000 + 2800)); /* seq advanced by 2800 */
	assert(tcp_2->flags == (TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN)); /* flags preserved */

	uint32_t tail_tcp_total_len = sizeof(struct tcp_hdr) + 400;
	uint16_t tail_cksum = ones_add(ip_checksum(tcp_2, tail_tcp_total_len),
	                               ip4_checksum(ip4_2, tail_tcp_total_len, IPPROTO_TCP));
	assert(tail_cksum == 0); /* Valid full TCP checksum */

	uint8_t *payload_2 = rx_buf + 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr);
	for (int i = 0; i < 400; i++) {
		assert(payload_2[i] == (uint8_t)((2800 + i) & 0xff));
	}

	close(sv[0]);
	close(sv[1]);
	printf("PASS: gso_translate_tcp_6to4() zero-copy, short tail split, and deep inspection\n");
}

static void test_gso_boundary_1260_1261(void)
{
	printf("Testing RFC 7915 §5.1 boundary: total IPv4 length 1260 vs 1261...\n");
	setup_test_mapping();

	/* Case 1: Total IPv4 length = 1260 (20 IP + 20 TCP + 1220 payload) -> DF=0, ID!=0 */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		uint8_t pkt_buf[HEADROOM + 40 + 20 + 1220];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 1220);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 1220;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip6);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		int res = gso_translate_tcp_6to4(&p);
		assert(res == 0);

		uint8_t rx_buf[2048];
		ssize_t n = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n == 10 + 1260);

		struct ip4 *ip4 = (struct ip4 *)(rx_buf + 10);
		assert(ntohs(ip4->length) == 1260);
		assert(ip4->flags_offset == 0); /* DF=0 per RFC 7915 §5.1 */
		assert(ip4->ident != 0); /* Generated IPv4 ID */

		close(sv[0]);
		close(sv[1]);
	}

	/* Case 2: Total IPv4 length = 1261 (20 IP + 20 TCP + 1221 payload) -> DF=1, ID=0 */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		uint8_t pkt_buf[HEADROOM + 40 + 20 + 1221];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 1221);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 1221;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip6);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		int res = gso_translate_tcp_6to4(&p);
		assert(res == 0);

		uint8_t rx_buf[2048];
		ssize_t n = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n == 10 + 1261);

		struct ip4 *ip4 = (struct ip4 *)(rx_buf + 10);
		assert(ntohs(ip4->length) == 1261);
		assert(ip4->flags_offset == htons(IP4_F_DF)); /* DF=1 per RFC 7915 §5.1 */
		assert(ip4->ident == 0); /* ID=0 */

		close(sv[0]);
		close(sv[1]);
	}

	printf("PASS: RFC 7915 §5.1 boundary 1260 vs 1261\n");
}

static void test_gso_tcp_options(void)
{
	printf("Testing TCP options (doff > 5) preservation in head and tail...\n");
	setup_test_mapping();

	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

	/* TCP header with 12 bytes options -> 32 bytes header (doff = 8) */
	uint32_t tcp_hdr_len = 32;
	uint32_t payload_len = 3200; /* 2*1400 + 400 */
	uint8_t pkt_buf[HEADROOM + 40 + 32 + 3200];
	uint8_t *raw_pkt = pkt_buf + HEADROOM;
	struct ip6 *ip6 = (struct ip6 *)raw_pkt;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));
	uint8_t *opts = raw_pkt + sizeof(struct ip6) + sizeof(struct tcp_hdr);
	uint8_t *payload = raw_pkt + sizeof(struct ip6) + tcp_hdr_len;

	memset(pkt_buf, 0, sizeof(pkt_buf));
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(tcp_hdr_len + payload_len);
	ip6->next_header = IPPROTO_TCP;
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	tcp->src_port = htons(80);
	tcp->dst_port = htons(54321);
	tcp->seq = htonl(2000);
	tcp->doff_res = (tcp_hdr_len / 4) << 4;
	tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN;

	/* Mock TCP options: NOP NOP TSval TSecr (12 bytes) */
	opts[0] = 0x01; opts[1] = 0x01; opts[2] = 0x08; opts[3] = 0x0a;
	for (int i = 4; i < 12; i++) opts[i] = (uint8_t)(i ^ 0xaa);

	for (int i = 0; i < (int)payload_len; i++)
		payload[i] = (uint8_t)(i & 0x7f);

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.tun_fd = sv[0];
	p.data = raw_pkt;
	p.data_len = sizeof(struct ip6) + tcp_hdr_len + payload_len;
	p.has_vhdr = 1;
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	p.vhdr.gso_size = 1400;
	p.vhdr.hdr_len = sizeof(struct ip6) + tcp_hdr_len;
	p.vhdr.csum_start = sizeof(struct ip6);
	p.vhdr.csum_offset = 16;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

	int res = gso_translate_tcp_6to4(&p);
	assert(res == 0);

	/* Head datagram */
	uint8_t rx_buf[4096];
	ssize_t n1 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
	assert(n1 == 10 + sizeof(struct ip4) + tcp_hdr_len + 2800);

	struct virtio_net_hdr_raw *v1 = (struct virtio_net_hdr_raw *)rx_buf;
	assert(v1->hdr_len == sizeof(struct ip4) + tcp_hdr_len);
	assert(v1->csum_start == sizeof(struct ip4));

	struct tcp_hdr *tcp_1 = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
	assert((tcp_1->doff_res >> 4) * 4 == tcp_hdr_len);
	uint8_t *opts_1 = (uint8_t *)tcp_1 + sizeof(struct tcp_hdr);
	assert(memcmp(opts_1, opts, 12) == 0);

	/* Tail datagram */
	ssize_t n2 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
	assert(n2 == 10 + sizeof(struct ip4) + tcp_hdr_len + 400);

	struct tcp_hdr *tcp_2 = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
	assert((tcp_2->doff_res >> 4) * 4 == tcp_hdr_len);
	uint8_t *opts_2 = (uint8_t *)tcp_2 + sizeof(struct tcp_hdr);
	assert(memcmp(opts_2, opts, 12) == 0);

	close(sv[0]);
	close(sv[1]);
	printf("PASS: TCP options preservation\n");
}

static void test_gso_ecn_cwr(void)
{
	printf("Testing RFC 3168 ECN / CWR semantics (CWR on head only, cleared on tail/subsequent)...\n");
	setup_test_mapping();

	/* 1. GSO Split-Tail Test: 2 full MSS (1400) + short tail (400) = 3200 bytes */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		uint8_t pkt_buf[HEADROOM + 40 + 20 + 3200];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));
		uint8_t *payload = raw_pkt + sizeof(struct ip6) + sizeof(struct tcp_hdr);

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 3200);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->seq = htonl(1000);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		/* Incoming flags carry ACK, PSH, FIN, ECE (0x40), and CWR (0x80) */
		tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ECE | TCP_FLAG_CWR;

		for (int i = 0; i < 3200; i++)
			payload[i] = (uint8_t)(i & 0xff);

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 3200;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6 | VIRTIO_NET_HDR_GSO_ECN;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip6);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		int res = gso_translate_tcp_6to4(&p);
		assert(res == 0);

		uint8_t rx_buf[4096];
		/* Datagram 1: Head aggregate */
		ssize_t n1 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n1 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800);

		struct virtio_net_hdr_raw *v1 = (struct virtio_net_hdr_raw *)rx_buf;
		assert(v1->gso_type == (VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN));

		struct tcp_hdr *tcp_1 = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
		/* Head MUST retain CWR, ECE, ACK, while FIN/PSH are cleared */
		assert((tcp_1->flags & TCP_FLAG_CWR) != 0);
		assert((tcp_1->flags & TCP_FLAG_ECE) != 0);
		assert((tcp_1->flags & TCP_FLAG_ACK) != 0);
		assert((tcp_1->flags & (TCP_FLAG_FIN | TCP_FLAG_PSH)) == 0);

		/* Datagram 2: Tail short segment */
		ssize_t n2 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n2 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 400);

		struct tcp_hdr *tcp_2 = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
		/* Tail MUST CLEAR CWR per RFC 3168 §6.1.5, while retaining ECE, ACK, FIN, PSH */
		assert((tcp_2->flags & TCP_FLAG_CWR) == 0);
		assert((tcp_2->flags & TCP_FLAG_ECE) != 0);
		assert((tcp_2->flags & TCP_FLAG_ACK) != 0);
		assert((tcp_2->flags & TCP_FLAG_FIN) != 0);
		assert((tcp_2->flags & TCP_FLAG_PSH) != 0);

		close(sv[0]);
		close(sv[1]);
	}

	/* 2. Software Segmentation Test with CWR (6to4) */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		/* 2000 bytes payload with gso_size 1000 -> 2 segments (1000 + 1000) */
		uint8_t pkt_buf[HEADROOM + 40 + 20 + 2000];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 2000);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->seq = htonl(5000);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ECE | TCP_FLAG_CWR;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 2000;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		p.vhdr.gso_size = 1000;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);

		int res = gso_software_segment_and_send_6to4(&p);
		assert(res == 0);

		uint8_t rx_buf[2048];
		/* Segment 1: offset == 0, carries CWR */
		ssize_t n1 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n1 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg1_tcp = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
		assert((seg1_tcp->flags & TCP_FLAG_CWR) != 0);
		assert((seg1_tcp->flags & TCP_FLAG_ECE) != 0);
		assert((seg1_tcp->flags & (TCP_FLAG_FIN | TCP_FLAG_PSH)) == 0);

		/* Segment 2: offset > 0, CWR cleared, FIN/PSH preserved */
		ssize_t n2 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n2 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg2_tcp = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip4));
		assert((seg2_tcp->flags & TCP_FLAG_CWR) == 0);
		assert((seg2_tcp->flags & TCP_FLAG_ECE) != 0);
		assert((seg2_tcp->flags & TCP_FLAG_FIN) != 0);
		assert((seg2_tcp->flags & TCP_FLAG_PSH) != 0);

		close(sv[0]);
		close(sv[1]);
	}

	/* 3. Software Segmentation Test with CWR (4to6) */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		uint8_t pkt_buf[HEADROOM + 20 + 20 + 2000];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip4 *ip4 = (struct ip4 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip4));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip4->ver_ihl = 0x45;
		ip4->length = htons(sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2000);
		ip4->ttl = 64;
		ip4->proto = IPPROTO_TCP;
		inet_pton(AF_INET, "192.0.0.1", &ip4->src);
		inet_pton(AF_INET, "198.51.100.2", &ip4->dest);
		ip4->cksum = ip4_header_checksum(ip4);

		tcp->src_port = htons(54321);
		tcp->dst_port = htons(80);
		tcp->seq = htonl(8000);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ECE | TCP_FLAG_CWR;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2000;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		p.vhdr.gso_size = 1000;
		p.vhdr.hdr_len = sizeof(struct ip4) + sizeof(struct tcp_hdr);

		int res = gso_software_segment_and_send_4to6(&p);
		assert(res == 0);

		uint8_t rx_buf[2048];
		/* Segment 1: offset == 0, carries CWR */
		ssize_t n1 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n1 == 10 + sizeof(struct ip6) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg1_tcp = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip6));
		assert((seg1_tcp->flags & TCP_FLAG_CWR) != 0);
		assert((seg1_tcp->flags & TCP_FLAG_ECE) != 0);
		assert((seg1_tcp->flags & (TCP_FLAG_FIN | TCP_FLAG_PSH)) == 0);

		/* Segment 2: offset > 0, CWR cleared, FIN/PSH preserved */
		ssize_t n2 = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n2 == 10 + sizeof(struct ip6) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg2_tcp = (struct tcp_hdr *)(rx_buf + 10 + sizeof(struct ip6));
		assert((seg2_tcp->flags & TCP_FLAG_CWR) == 0);
		assert((seg2_tcp->flags & TCP_FLAG_ECE) != 0);
		assert((seg2_tcp->flags & TCP_FLAG_FIN) != 0);
		assert((seg2_tcp->flags & TCP_FLAG_PSH) != 0);

		close(sv[0]);
		close(sv[1]);
	}

	printf("PASS: RFC 3168 ECN / CWR semantics\n");
}

static void test_gso_ttl_hop_limit(void)
{
	printf("Testing RFC 7915 TTL / Hop Limit expiration and forwarding (0, 1, 2)...\n");
	setup_test_mapping();

	/* 1. IPv6 -> IPv4: hop_limit = 0, 1 (ICMP Time Exceeded sent, return 0), hop_limit = 2 (forwarded, TTL=1) */
	for (uint8_t hl = 0; hl <= 2; hl++) {
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		uint8_t pkt_buf[HEADROOM + 40 + 20 + 2800];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 2800);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = hl;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 2800;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip6);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		int res = gso_translate_tcp_6to4(&p);
		assert(res == 0);

		uint8_t rx_buf[4096];
		ssize_t n = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n > 0);

#ifdef __linux__
#define ICMP_PI_LEN 0
#else
#define ICMP_PI_LEN sizeof(struct tun_pi)
#endif

		if (hl <= 1) {
			/* Expect ICMPv6 Time Exceeded (Type 3, Code 0) */
			struct ip6 *rx_ip6 = (struct ip6 *)(rx_buf + 10 + ICMP_PI_LEN);
			assert(rx_ip6->next_header == 58); /* ICMPv6 */
			struct icmp *rx_icmp = (struct icmp *)(rx_buf + 10 + ICMP_PI_LEN + sizeof(struct ip6));
			assert(rx_icmp->type == 3); /* Time Exceeded */
			assert(rx_icmp->code == 0); /* Hop limit exceeded in transit */
		} else {
			/* hl == 2: Forwarded IPv4 packet with TTL = 1 */
			struct ip4 *rx_ip4 = (struct ip4 *)(rx_buf + 10);
			assert(rx_ip4->proto == IPPROTO_TCP);
			assert(rx_ip4->ttl == 1);
		}

		close(sv[0]);
		close(sv[1]);
	}

	/* 2. IPv4 -> IPv6: ttl = 0, 1 (ICMP Time Exceeded sent, return 0), ttl = 2 (forwarded, hop_limit=1) */
	for (uint8_t ttl_in = 0; ttl_in <= 2; ttl_in++) {
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		uint8_t pkt_buf[HEADROOM + 20 + 20 + 2800];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip4 *ip4 = (struct ip4 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip4));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip4->ver_ihl = 0x45;
		ip4->length = htons(sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800);
		ip4->ttl = ttl_in;
		ip4->proto = IPPROTO_TCP;
		inet_pton(AF_INET, "192.0.0.1", &ip4->src);
		inet_pton(AF_INET, "198.51.100.2", &ip4->dest);
		ip4->cksum = ip4_header_checksum(ip4);

		tcp->src_port = htons(54321);
		tcp->dst_port = htons(80);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip4) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip4);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		int res = gso_translate_tcp_4to6(&p);
		assert(res == 0);

		uint8_t rx_buf[4096];
		ssize_t n = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(n > 0);

		if (ttl_in <= 1) {
			/* Expect ICMPv4 Time Exceeded (Type 11, Code 0) */
			struct ip4 *rx_ip4 = (struct ip4 *)(rx_buf + 10 + ICMP_PI_LEN);
			assert(rx_ip4->proto == 1); /* ICMPv4 */
			struct icmp *rx_icmp = (struct icmp *)(rx_buf + 10 + ICMP_PI_LEN + sizeof(struct ip4));
			assert(rx_icmp->type == 11); /* Time Exceeded */
			assert(rx_icmp->code == 0); /* TTL expired in transit */
		} else {
			/* ttl_in == 2: Forwarded IPv6 packet with Hop Limit = 1 */
			struct ip6 *rx_ip6 = (struct ip6 *)(rx_buf + 10);
			assert(rx_ip6->next_header == IPPROTO_TCP);
			assert(rx_ip6->hop_limit == 1);
		}

		close(sv[0]);
		close(sv[1]);
	}

	printf("PASS: RFC 7915 TTL / Hop Limit expiration (0, 1) and forwarding (2)\n");
}

static void test_gso_mock_write_error(void)
{
	printf("Testing mock write failure error handling and double-parse prevention...\n");
	signal(SIGPIPE, SIG_IGN);
	setup_test_mapping();

	/* Test 1: IPv6 -> IPv4 write failure */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		close(sv[1]); /* Close read end to cause write failure */

		uint8_t pkt_buf[HEADROOM + 40 + 20 + 2800];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 2800);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 2800;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip6);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		uint64_t prev_err = atomic_load_explicit(&g_gso_stats.gso_tun_write_errors, memory_order_relaxed);

		int res = gso_translate_tcp_6to4(&p);
		/* Must return 0 so caller doesn't re-parse corrupted buffer */
		assert(res == 0);

		uint64_t curr_err = atomic_load_explicit(&g_gso_stats.gso_tun_write_errors, memory_order_relaxed);
		assert(curr_err > prev_err);

		close(sv[0]);
	}

	/* Test 2: IPv4 -> IPv6 write failure */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		close(sv[1]);

		uint8_t pkt_buf[HEADROOM + 20 + 20 + 2800];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip4 *ip4 = (struct ip4 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip4));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip4->ver_ihl = 0x45;
		ip4->length = htons(sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800);
		ip4->ttl = 64;
		ip4->proto = IPPROTO_TCP;
		inet_pton(AF_INET, "192.0.0.1", &ip4->src);
		inet_pton(AF_INET, "198.51.100.2", &ip4->dest);
		ip4->cksum = ip4_header_checksum(ip4);

		tcp->src_port = htons(54321);
		tcp->dst_port = htons(80);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip4) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip4);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		uint64_t prev_err = atomic_load_explicit(&g_gso_stats.gso_tun_write_errors, memory_order_relaxed);

		int res = gso_translate_tcp_4to6(&p);
		assert(res == 0);

		uint64_t curr_err = atomic_load_explicit(&g_gso_stats.gso_tun_write_errors, memory_order_relaxed);
		assert(curr_err > prev_err);

		close(sv[0]);
	}

	/* Test 3: Head aggregate successfully sent, tail segment write fails */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
		assert(set_nonblock(sv[0]) == 0);

		const size_t head_dgram_sz = 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800;

		/* Fill stream buffer until send returns EAGAIN / EWOULDBLOCK */
		uint8_t dummy[1024];
		memset(dummy, 0xaa, sizeof(dummy));
		size_t total_filled = 0;
		while (1) {
			ssize_t n = send(sv[0], dummy, sizeof(dummy), 0);
			if (n > 0) {
				total_filled += n;
			} else {
				break;
			}
		}
		assert(total_filled > head_dgram_sz);

		/* Drain exactly head_dgram_sz bytes so sv[0] has capacity for exactly the Head datagram */
		uint8_t drain[4096];
		size_t drained = 0;
		while (drained < head_dgram_sz) {
			size_t to_read = head_dgram_sz - drained;
			if (to_read > sizeof(drain))
				to_read = sizeof(drain);
			ssize_t nd = recv(sv[1], drain, to_read, 0);
			assert(nd > 0);
			drained += nd;
		}

		/* Construct split-tail GSO packet: 2 full segments (1400 each) + 1 tail segment (400 bytes) */
		uint8_t pkt_buf[HEADROOM + 40 + 20 + 3200];
		uint8_t *raw_pkt = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)raw_pkt;
		struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

		memset(pkt_buf, 0, sizeof(pkt_buf));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct tcp_hdr) + 3200);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

		tcp->src_port = htons(80);
		tcp->dst_port = htons(54321);
		tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
		tcp->flags = TCP_FLAG_ACK;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.tun_fd = sv[0];
		p.data = raw_pkt;
		p.data_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + 3200;
		p.has_vhdr = 1;
		p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		p.vhdr.gso_size = 1400;
		p.vhdr.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr);
		p.vhdr.csum_start = sizeof(struct ip6);
		p.vhdr.csum_offset = 16;
		p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

		uint64_t prev_err = atomic_load_explicit(&g_gso_stats.gso_tun_write_errors, memory_order_relaxed);
		uint64_t prev_tx = atomic_load_explicit(&g_gso_stats.gso_pkts_tx, memory_order_relaxed);

		int res = gso_translate_tcp_6to4(&p);
		/* Must return 0: packet was consumed and head was sent, no re-parsing */
		assert(res == 0);

		/* Verify: 1 packet (head) was transmitted, and tail produced 1 write error */
		uint64_t curr_err = atomic_load_explicit(&g_gso_stats.gso_tun_write_errors, memory_order_relaxed);
		uint64_t curr_tx = atomic_load_explicit(&g_gso_stats.gso_pkts_tx, memory_order_relaxed);
		assert(curr_err == prev_err + 1);
		assert(curr_tx == prev_tx + 1);

		/* Drain remaining dummy bytes from sv[1] */
		size_t rem_dummy = total_filled - head_dgram_sz;
		while (rem_dummy > 0) {
			size_t to_read = rem_dummy > sizeof(drain) ? sizeof(drain) : rem_dummy;
			ssize_t nr = recv(sv[1], drain, to_read, 0);
			assert(nr > 0);
			rem_dummy -= nr;
		}

		/* Now the next bytes in stream MUST be the Head GSO aggregate */
		uint8_t rx_buf[4096];
		size_t head_rcvd = 0;
		while (head_rcvd < head_dgram_sz) {
			size_t to_read = head_dgram_sz - head_rcvd;
			ssize_t nr = recv(sv[1], rx_buf + head_rcvd, to_read, 0);
			assert(nr > 0);
			head_rcvd += nr;
		}
		assert(head_rcvd == head_dgram_sz);
		struct virtio_net_hdr_raw *vh = (struct virtio_net_hdr_raw *)rx_buf;
		assert(vh->gso_type == VIRTIO_NET_HDR_GSO_TCPV4);

		/* And no tail packet exists in the stream */
		assert(set_nonblock(sv[1]) == 0);
		ssize_t nt = recv(sv[1], rx_buf, sizeof(rx_buf), 0);
		assert(nt < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

		close(sv[0]);
		close(sv[1]);
	}

	printf("PASS: mock write failure error handling and double-parse prevention\n");
}

int main(void)
{
	printf("=== Running unit_gso test suite ===\n");
	test_gso_validate();
	test_gso_csum_update();
	test_gso_csum_seed();
	test_gso_translate_and_split();
	test_gso_boundary_1260_1261();
	test_gso_tcp_options();
	test_gso_ecn_cwr();
	test_gso_ttl_hop_limit();
	test_gso_mock_write_error();
	gso_dump_stats();
	printf("All unit_gso tests passed successfully!\n");
	return 0;
}
