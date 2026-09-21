/*
 *  test/unit_gso.c -- Unit tests for TCP GSO/GRO engine
 *  Part of TAYGA CLAT performance optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tayga.h"
#include "gso.h"

struct config gcfg;
time_t now;

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
	printf("Testing gso_translate_tcp_6to4() zero-copy and short tail split...\n");

	/* Initialize lists and mappings in gcfg */
	memset(&gcfg, 0, sizeof(gcfg));
	INIT_LIST_HEAD(&gcfg.map4_list);
	INIT_LIST_HEAD(&gcfg.map6_list);
	gcfg.maps_immutable = 1;

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
	ip6->dest = client_map.map6.addr;

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

	/* Verify split tail stat incremented */
	uint64_t curr_split = atomic_load_explicit(&g_gso_stats.gso_split_tail_pkts, memory_order_relaxed);
	assert(curr_split == prev_split + 1);

	close(sv[0]);
	close(sv[1]);

	printf("PASS: gso_translate_tcp_6to4() zero-copy and short tail split\n");
}

int main(void)
{
	printf("=== Running unit_gso test suite ===\n");
	test_gso_validate();
	test_gso_csum_update();
	test_gso_csum_seed();
	test_gso_translate_and_split();
	gso_dump_stats();
	printf("All unit_gso tests passed successfully!\n");
	return 0;
}
