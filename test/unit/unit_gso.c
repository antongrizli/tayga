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
#include "stats.h"

/* Offset the 10-byte virtio header by two bytes so IP/TCP headers are
 * four-byte aligned, including packets with a four-byte BSD TUN header.
 * Keep the receive capacity an array so sizeof still gives the buffer size. */
#define RX_BUFFER(name, size) \
    struct { alignas(4) uint8_t padding[2]; uint8_t data[size]; } name

static inline void get_gso_snapshot(struct tayga_stats *s) {
	stats_flush_worker();
	stats_get_snapshot(s);
}

struct config gcfg;
_Atomic time_t now;

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

	/* Case 3: Unsupported GSO type */
	p.vhdr.gso_type = 0x7f;
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

	/* UFO is IP fragmentation, not UDP_L4 datagram segmentation. */
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
	assert(gso_validate_header(&p) == -1);
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4 | VIRTIO_NET_HDR_GSO_ECN;
	assert(gso_validate_header(&p) == -1); /* ECN GSO flag is TCP-only */

	/* Case 8: Valid TCPv6 GSO with ECN */
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6 | VIRTIO_NET_HDR_GSO_ECN;
	p.vhdr.csum_start = 40;
	p.vhdr.csum_offset = 16;
	assert(gso_validate_header(&p) == 1);

	/* Case 9: Valid UDP USO GSO */
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
	p.vhdr.hdr_len = 48;
	p.vhdr.csum_start = 40;
	p.vhdr.csum_offset = 6;
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

static void test_gso_translate_and_split(int framing, unsigned tcp_header_len, unsigned full_segments)
{
	printf("Testing TCP split: framing=%d TCP header=%u full segments=%u...\n",
	       framing, tcp_header_len, full_segments);
	setup_test_mapping();
	gcfg.vnet_hdr_sz = framing;
	unsigned head_payload_len = full_segments * 1400;
	unsigned payload_len = head_payload_len + 400;

	/* Create socketpair to mock tun_fd */
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

	/* Construct GSO packet: IPv6 + TCP + Payload */
	/* One/two full MSS segments and a 400-byte tail; reserve maximum storage. */
	alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 60 + 3200];
	uint8_t *raw_pkt = pkt_buf + HEADROOM;
	struct ip6 *ip6 = (struct ip6 *)raw_pkt;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));
	uint8_t *payload = raw_pkt + sizeof(struct ip6) + tcp_header_len;

	memset(pkt_buf, 0, sizeof(pkt_buf));

	/* IPv6 header: src = 64:ff9b::198.51.100.2, dest = fd9b:64:1:ff::10 */
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(tcp_header_len + payload_len);
	ip6->next_header = IPPROTO_TCP;
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	/* TCP header */
	tcp->src_port = htons(80);
	tcp->dst_port = htons(54321);
	tcp->seq = htonl(1000);
	tcp->ack_seq = htonl(500);
	tcp->doff_res = (tcp_header_len / 4) << 4;
	tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN;
	tcp->window = htons(65535);

	for (int i = 0; i < (int)payload_len; i++) {
		payload[i] = (uint8_t)(i & 0xff);
	}

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.tun_fd = sv[0];
	p.data = raw_pkt;
	p.data_len = sizeof(struct ip6) + tcp_header_len + payload_len;
	p.has_vhdr = 1;
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	p.vhdr.gso_size = 1400;
	/* Linux hdr_len may cover the entire original linear aggregate. The short
	 * tail split must clamp the outgoing head hint to the shorter head packet. */
	p.vhdr.hdr_len = p.data_len;
	p.vhdr.csum_start = sizeof(struct ip6);
	p.vhdr.csum_offset = 16;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

	struct tayga_stats s_prev, s_curr;
	get_gso_snapshot(&s_prev);

	int res = gso_translate_tcp_6to4(&p);
	assert(res == 0);

	get_gso_snapshot(&s_curr);
	assert(s_curr.gso_split_tail_pkts == s_prev.gso_split_tail_pkts + 1);

	/* Inspect Datagram 1: Ordinary head packet or multi-segment aggregate. */
	alignas(4) uint8_t rx_storage[4100];
	uint8_t *received = rx_storage + (4 - framing % 4) % 4;
	ssize_t n1 = recv(sv[1], received, 4096, 0);
	assert(n1 == framing + sizeof(struct ip4) + tcp_header_len + head_payload_len);

	struct virtio_net_hdr_raw *v1 = (struct virtio_net_hdr_raw *)received;
	if (framing) {
	assert(v1->gso_type == (full_segments == 1 ? VIRTIO_NET_HDR_GSO_NONE : VIRTIO_NET_HDR_GSO_TCPV4));
	assert(v1->gso_size == (full_segments == 1 ? 0 : 1400));
	assert(v1->hdr_len == sizeof(struct ip4) + tcp_header_len + head_payload_len);
	assert(v1->hdr_len <= n1 - framing);
	assert(v1->csum_start == sizeof(struct ip4));
	assert(v1->csum_offset == 16);
	assert(v1->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);

	}

	struct ip4 *ip4_1 = (struct ip4 *)(received + framing);
	assert(ip4_1->ver_ihl == 0x45);
	assert(ntohs(ip4_1->length) == sizeof(struct ip4) + tcp_header_len + head_payload_len);
	assert(ip4_1->flags_offset == htons(IP4_F_DF)); /* DF=1 */
	assert(ip4_1->ident == 0);
	assert(ip4_1->ttl == 63); /* decremented from 64 */
	assert(ip4_1->proto == IPPROTO_TCP);
	assert(ip_checksum(ip4_1, sizeof(struct ip4)) == 0);

	struct tcp_hdr *tcp_1 = (struct tcp_hdr *)(received + framing + sizeof(struct ip4));
	assert(tcp_1->seq == htonl(1000));
	assert(tcp_1->flags == TCP_FLAG_ACK); /* FIN and PSH cleared */
	uint16_t exp_seed = gso_calc_tcp_pseudo4(&ip4_1->src, &ip4_1->dest, tcp_header_len + head_payload_len);
	assert(ntohs(tcp_1->cksum) == exp_seed);

	uint8_t *payload_1 = received + framing + sizeof(struct ip4) + tcp_header_len;
	for (int i = 0; i < (int)head_payload_len; i++) {
		assert(payload_1[i] == (uint8_t)(i & 0xff));
	}

	/* Inspect Datagram 2: Tail short packet */
	ssize_t n2 = recv(sv[1], received, 4096, 0);
	assert(n2 == framing + sizeof(struct ip4) + tcp_header_len + 400);

	struct virtio_net_hdr_raw *v2 = (struct virtio_net_hdr_raw *)received;
	if (framing) {
		assert(v2->gso_type == VIRTIO_NET_HDR_GSO_NONE);
		assert(v2->flags == VIRTIO_NET_HDR_F_NEEDS_CSUM);
		assert(v2->gso_size == 0 && v2->csum_start == sizeof(struct ip4));
		assert(v2->csum_offset == 16 && v2->hdr_len == sizeof(struct ip4) + tcp_header_len);
	}

	struct ip4 *ip4_2 = (struct ip4 *)(received + framing);
	assert(ip4_2->ver_ihl == 0x45);
	assert(ntohs(ip4_2->length) == sizeof(struct ip4) + tcp_header_len + 400);
	assert(ip4_2->flags_offset == 0); /* DF=0 because total length <= 1260 */
	assert(ip4_2->ident != 0); /* Generated ID */
	assert(ip4_2->ttl == 63);
	assert(ip4_2->proto == IPPROTO_TCP);
	assert(ip_checksum(ip4_2, sizeof(struct ip4)) == 0);

	struct tcp_hdr *tcp_2 = (struct tcp_hdr *)(received + framing + sizeof(struct ip4));
	assert(tcp_2->seq == htonl(1000 + head_payload_len));
	assert(tcp_2->flags == (TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN)); /* flags preserved */

	uint32_t tail_tcp_total_len = tcp_header_len + 400;
	uint16_t tail_cksum = ones_add(ip_checksum(tcp_2, tail_tcp_total_len),
	                               ip4_checksum(ip4_2, tail_tcp_total_len, IPPROTO_TCP));
	if (framing)
		assert(tcp_2->cksum == htons(gso_calc_tcp_pseudo4(&ip4_2->src, &ip4_2->dest, tail_tcp_total_len)));
	else
		assert(tail_cksum == 0); /* Valid full software TCP checksum */

	uint8_t *payload_2 = received + framing + sizeof(struct ip4) + tcp_header_len;
	for (int i = 0; i < 400; i++) {
		assert(payload_2[i] == (uint8_t)((head_payload_len + i) & 0xff));
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

		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 1220];
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

		RX_BUFFER(rx_buf, 2048);
		ssize_t n = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n == 10 + 1260);

		struct ip4 *ip4 = (struct ip4 *)(rx_buf.data + 10);
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

		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 1221];
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

		RX_BUFFER(rx_buf, 2048);
		ssize_t n = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n == 10 + 1261);

		struct ip4 *ip4 = (struct ip4 *)(rx_buf.data + 10);
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
	alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 32 + 3200];
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
	RX_BUFFER(rx_buf, 4096);
	ssize_t n1 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
	assert(n1 == (ssize_t)(10 + sizeof(struct ip4) + tcp_hdr_len + 2800));

	struct virtio_net_hdr_raw *v1 = (struct virtio_net_hdr_raw *)rx_buf.data;
	assert(v1->hdr_len == sizeof(struct ip4) + tcp_hdr_len);
	assert(v1->csum_start == sizeof(struct ip4));

	struct tcp_hdr *tcp_1 = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip4));
	assert((tcp_1->doff_res >> 4) * 4 == tcp_hdr_len);
	uint8_t *opts_1 = (uint8_t *)tcp_1 + sizeof(struct tcp_hdr);
	assert(memcmp(opts_1, opts, 12) == 0);

	/* Tail datagram */
	ssize_t n2 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
	assert(n2 == (ssize_t)(10 + sizeof(struct ip4) + tcp_hdr_len + 400));

	struct tcp_hdr *tcp_2 = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip4));
	assert((tcp_2->doff_res >> 4) * 4 == tcp_hdr_len);
	uint8_t *opts_2 = (uint8_t *)tcp_2 + sizeof(struct tcp_hdr);
	assert(memcmp(opts_2, opts, 12) == 0);

	close(sv[0]);
	close(sv[1]);
	printf("PASS: TCP options preservation\n");
}

static void test_gso_ipv4_options(void)
{
	printf("Testing IPv4 options are stripped before TCP GSO translation...\n");
	setup_test_mapping();
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(4) uint8_t pkt_buf[HEADROOM + 24 + sizeof(struct tcp_hdr) + 64] = {0};
	uint8_t *raw = pkt_buf + HEADROOM;
	struct ip4 *ip4 = (struct ip4 *)raw;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(raw + 24);
	ip4->ver_ihl = 0x46;
	ip4->length = htons(24 + sizeof(*tcp) + 64);
	ip4->ttl = 64;
	ip4->proto = IPPROTO_TCP;
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);
	inet_pton(AF_INET, "198.51.100.2", &ip4->dest);
	memset(raw + 20, 1, 4); /* Four NOP options; RFC 7915 ignores them. */
	tcp->src_port = htons(12345);
	tcp->dst_port = htons(443);
	tcp->seq = htonl(1234);
	tcp->doff_res = 5 << 4;
	tcp->flags = TCP_FLAG_ACK;
	memset((uint8_t *)tcp + sizeof(*tcp), 0x5a, 64);
	uint8_t expected_payload[64];
	memcpy(expected_payload, (uint8_t *)tcp + sizeof(*tcp), sizeof(expected_payload));
	ip4->cksum = ip_checksum(ip4, 24);
	struct pkt p = {.tun_fd = sv[0], .data = raw,
		.data_len = 24 + sizeof(*tcp) + 64, .has_vhdr = 1};
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
	p.vhdr.gso_size = 1000;
	p.vhdr.hdr_len = 24 + sizeof(*tcp) + 16;
	p.vhdr.csum_start = 24;
	p.vhdr.csum_offset = 16;
	assert(gso_translate_tcp_4to6(&p) == 0);
	RX_BUFFER(rx, 256);
	ssize_t n = recv(sv[1], rx.data, sizeof(rx.data), 0);
	assert(n == 10 + sizeof(struct ip6) + sizeof(*tcp) + 64);
	struct virtio_net_hdr_raw *vh = (void *)rx.data;
	assert(vh->hdr_len == sizeof(struct ip6) + sizeof(*tcp) + 16);
	assert(vh->csum_start == sizeof(struct ip6));
	struct ip6 *ip6 = (void *)(rx.data + 10);
	assert(ip6->next_header == IPPROTO_TCP);
	struct tcp_hdr *out_tcp = (void *)((uint8_t *)ip6 + sizeof(*ip6));
	assert(out_tcp->src_port == htons(12345));
	assert(out_tcp->dst_port == htons(443));
	assert(ntohs(out_tcp->cksum) == gso_calc_tcp_pseudo6(
		&ip6->src, &ip6->dest, sizeof(*tcp) + 64));
	assert(memcmp((uint8_t *)out_tcp + sizeof(*tcp), expected_payload, sizeof(expected_payload)) == 0);

	/* An unexpired LSRR option must not be translated. */
	alignas(4) uint8_t source_route_buf[HEADROOM + 28 + sizeof(*tcp) + 8] = {0};
	raw = source_route_buf + HEADROOM;
	ip4 = (struct ip4 *)raw;
	tcp = (struct tcp_hdr *)(raw + 28);
	ip4->ver_ihl = 0x47;
	ip4->length = htons(28 + sizeof(*tcp) + 8);
	ip4->ttl = 64;
	ip4->proto = IPPROTO_TCP;
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);
	inet_pton(AF_INET, "198.51.100.2", &ip4->dest);
	raw[20] = 131; raw[21] = 7; raw[22] = 4;
	ip4->cksum = ip_checksum(ip4, 28);
	p = (struct pkt){.tun_fd = sv[0], .data = raw,
		.data_len = 28 + sizeof(*tcp) + 8, .has_vhdr = 1};
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
	p.vhdr.gso_size = 1000;
	p.vhdr.hdr_len = 28 + sizeof(*tcp);
	p.vhdr.csum_start = 28;
	p.vhdr.csum_offset = 16;
	assert(gso_translate_tcp_4to6(&p) < 0);
	assert(recv(sv[1], rx.data, sizeof(rx.data), MSG_DONTWAIT) < 0);
	/* Reject an IHL larger than the packet before reading its checksum. */
	ip4->ver_ihl = 0x4f;
	p.data_len = sizeof(struct ip4) + sizeof(*tcp);
	ip4->length = htons((uint16_t)p.data_len);
	assert(gso_translate_tcp_4to6(&p) < 0);
	close(sv[0]);
	close(sv[1]);
	printf("PASS: IPv4 option compaction and source-route rejection\n");
}

static void test_gso_ecn_cwr(void)
{
	printf("Testing RFC 3168 ECN / CWR semantics (CWR on head only, cleared on tail/subsequent)...\n");
	setup_test_mapping();

	/* 1. GSO Split-Tail Test: 2 full MSS (1400) + short tail (400) = 3200 bytes */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 3200];
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

		RX_BUFFER(rx_buf, 4096);
		/* Datagram 1: Head aggregate */
		ssize_t n1 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n1 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 2800);

		struct virtio_net_hdr_raw *v1 = (struct virtio_net_hdr_raw *)rx_buf.data;
		assert(v1->gso_type == (VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN));

		struct tcp_hdr *tcp_1 = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip4));
		/* Head MUST retain CWR, ECE, ACK, while FIN/PSH are cleared */
		assert((tcp_1->flags & TCP_FLAG_CWR) != 0);
		assert((tcp_1->flags & TCP_FLAG_ECE) != 0);
		assert((tcp_1->flags & TCP_FLAG_ACK) != 0);
		assert((tcp_1->flags & (TCP_FLAG_FIN | TCP_FLAG_PSH)) == 0);

		/* Datagram 2: Tail short segment */
		ssize_t n2 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n2 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 400);

		struct tcp_hdr *tcp_2 = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip4));
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
		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 2000];
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

		RX_BUFFER(rx_buf, 2048);
		/* Segment 1: offset == 0, carries CWR */
		ssize_t n1 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n1 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg1_tcp = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip4));
		assert((seg1_tcp->flags & TCP_FLAG_CWR) != 0);
		assert((seg1_tcp->flags & TCP_FLAG_ECE) != 0);
		assert((seg1_tcp->flags & (TCP_FLAG_FIN | TCP_FLAG_PSH)) == 0);

		/* Segment 2: offset > 0, CWR cleared, FIN/PSH preserved */
		ssize_t n2 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n2 == 10 + sizeof(struct ip4) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg2_tcp = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip4));
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

		alignas(4) uint8_t pkt_buf[HEADROOM + 20 + 20 + 2000];
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

		RX_BUFFER(rx_buf, 2048);
		/* Segment 1: offset == 0, carries CWR */
		ssize_t n1 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n1 == 10 + sizeof(struct ip6) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg1_tcp = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip6));
		assert((seg1_tcp->flags & TCP_FLAG_CWR) != 0);
		assert((seg1_tcp->flags & TCP_FLAG_ECE) != 0);
		assert((seg1_tcp->flags & (TCP_FLAG_FIN | TCP_FLAG_PSH)) == 0);

		/* Segment 2: offset > 0, CWR cleared, FIN/PSH preserved */
		ssize_t n2 = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n2 == 10 + sizeof(struct ip6) + sizeof(struct tcp_hdr) + 1000);
		struct tcp_hdr *seg2_tcp = (struct tcp_hdr *)(rx_buf.data + 10 + sizeof(struct ip6));
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

		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 2800];
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

		RX_BUFFER(rx_buf, 4096);
		ssize_t n = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n > 0);

#ifdef __linux__
#define ICMP_PI_LEN 0
#else
#define ICMP_PI_LEN sizeof(struct tun_pi)
#endif

		if (hl <= 1) {
			/* Expect ICMPv6 Time Exceeded (Type 3, Code 0) */
			struct ip6 *rx_ip6 = (struct ip6 *)(rx_buf.data + 10 + ICMP_PI_LEN);
			assert(rx_ip6->next_header == 58); /* ICMPv6 */
			struct icmp *rx_icmp = (struct icmp *)(rx_buf.data + 10 + ICMP_PI_LEN + sizeof(struct ip6));
			assert(rx_icmp->type == 3); /* Time Exceeded */
			assert(rx_icmp->code == 0); /* Hop limit exceeded in transit */
		} else {
			/* hl == 2: Forwarded IPv4 packet with TTL = 1 */
			struct ip4 *rx_ip4 = (struct ip4 *)(rx_buf.data + 10);
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

		alignas(4) uint8_t pkt_buf[HEADROOM + 20 + 20 + 2800];
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

		RX_BUFFER(rx_buf, 4096);
		ssize_t n = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(n > 0);

		if (ttl_in <= 1) {
			/* Expect ICMPv4 Time Exceeded (Type 11, Code 0) */
			struct ip4 *rx_ip4 = (struct ip4 *)(rx_buf.data + 10 + ICMP_PI_LEN);
			assert(rx_ip4->proto == 1); /* ICMPv4 */
			struct icmp *rx_icmp = (struct icmp *)(rx_buf.data + 10 + ICMP_PI_LEN + sizeof(struct ip4));
			assert(rx_icmp->type == 11); /* Time Exceeded */
			assert(rx_icmp->code == 0); /* TTL expired in transit */
		} else {
			/* ttl_in == 2: Forwarded IPv6 packet with Hop Limit = 1 */
			struct ip6 *rx_ip6 = (struct ip6 *)(rx_buf.data + 10);
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

		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 2800];
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

		struct tayga_stats s_prev, s_curr;
		get_gso_snapshot(&s_prev);

		int res = gso_translate_tcp_6to4(&p);
		/* Must return 0 so caller doesn't re-parse corrupted buffer */
		assert(res == 0);

		get_gso_snapshot(&s_curr);
		assert(s_curr.gso_tun_write_errors > s_prev.gso_tun_write_errors);

		close(sv[0]);
	}

	/* Test 2: IPv4 -> IPv6 write failure */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		close(sv[1]);

		alignas(4) uint8_t pkt_buf[HEADROOM + 20 + 20 + 2800];
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

		struct tayga_stats s_prev, s_curr;
		get_gso_snapshot(&s_prev);

		int res = gso_translate_tcp_4to6(&p);
		assert(res == 0);

		get_gso_snapshot(&s_curr);
		assert(s_curr.gso_tun_write_errors > s_prev.gso_tun_write_errors);

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
			ssize_t nw = send(sv[0], dummy, sizeof(dummy), 0);
			if (nw < 0) {
				assert(errno == EAGAIN || errno == EWOULDBLOCK);
				break;
			}
			total_filled += nw;
		}

		/* Drain exactly head_dgram_sz bytes from stream so head aggregate will fit but tail will fail */
		assert(set_nonblock(sv[1]) == 0);
		uint8_t drain[1024];
		size_t drained = 0;
		while (drained < head_dgram_sz) {
			size_t to_read = head_dgram_sz - drained;
			if (to_read > sizeof(drain)) to_read = sizeof(drain);
			ssize_t nr = recv(sv[1], drain, to_read, 0);
			assert(nr > 0);
			drained += nr;
		}

		/* Setup GSO packet with head + short tail */
		alignas(4) uint8_t pkt_buf[HEADROOM + 40 + 20 + 3200];
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
		tcp->seq = htonl(1000);
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

		struct tayga_stats s_prev, s_curr;
		get_gso_snapshot(&s_prev);

		int res = gso_translate_tcp_6to4(&p);
		/* Must return 0: packet was consumed and head was sent, no re-parsing */
		assert(res == 0);

		/* Verify: 1 packet (head) was transmitted, and tail produced 1 write error */
		get_gso_snapshot(&s_curr);
		assert(s_curr.gso_tun_write_errors == s_prev.gso_tun_write_errors + 1);
		assert(s_curr.gso_tx_pkts == s_prev.gso_tx_pkts + 1);

		/* Drain remaining dummy bytes from sv[1] */
		size_t rem_dummy = total_filled - head_dgram_sz;
		while (rem_dummy > 0) {
			size_t to_read = rem_dummy > sizeof(drain) ? sizeof(drain) : rem_dummy;
			ssize_t nr = recv(sv[1], drain, to_read, 0);
			assert(nr > 0);
			rem_dummy -= nr;
		}

		/* Now the next bytes in stream MUST be the Head GSO aggregate */
		RX_BUFFER(rx_buf, 4096);
		size_t head_rcvd = 0;
		while (head_rcvd < head_dgram_sz) {
			size_t to_read = head_dgram_sz - head_rcvd;
			ssize_t nr = recv(sv[1], rx_buf.data + head_rcvd, to_read, 0);
			assert(nr > 0);
			head_rcvd += nr;
		}
		assert(head_rcvd == head_dgram_sz);
		struct virtio_net_hdr_raw *vh = (struct virtio_net_hdr_raw *)rx_buf.data;
		assert(vh->gso_type == VIRTIO_NET_HDR_GSO_TCPV4);

		/* And no tail packet exists in the stream */
		assert(set_nonblock(sv[1]) == 0);
		ssize_t nt = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(nt < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

		close(sv[0]);
		close(sv[1]);
	}

	printf("PASS: mock write failure error handling and double-parse prevention\n");
}

static void test_gso_udp_uso(void)
{
	printf("Testing UDP Generic Segmentation Offload (USO) and fallback...\n");
	setup_test_mapping();

	/* 1. Fast-path 6to4 USO translation, including DF=0 range reservation. */
	for (int small = 0; small < 2; small++) {
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		gcfg.tun_has_uso = 1;

		alignas(4) uint8_t pkt_buf[HEADROOM + 8192];
		uint8_t *pkt_data = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)pkt_data;
		struct udp_hdr *udp = (struct udp_hdr *)(pkt_data + sizeof(struct ip6));
		uint8_t *payload = pkt_data + sizeof(struct ip6) + sizeof(struct udp_hdr);
		uint32_t payload_len = small ? 3600 : 4400;
		uint16_t segment_size = small ? 1200 : 2200;
		set_ip4_ident_counter(65534);

		memset(ip6, 0, sizeof(*ip6));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct udp_hdr) + payload_len);
		ip6->next_header = IPPROTO_UDP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->src);
		inet_pton(AF_INET6, "64:ff9b::192.0.2.1", &ip6->dest);

		udp->src_port = htons(12345);
		udp->dst_port = htons(8080);
		udp->length = htons(sizeof(struct udp_hdr) + payload_len);
		udp->cksum = 0;
		for (uint32_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)(i & 0xff);

		struct pkt p = {
			.tun_fd = sv[0],
			.data = pkt_data,
			.data_len = sizeof(struct ip6) + sizeof(struct udp_hdr) + payload_len,
			.header_len = 0,
			.has_vhdr = 1,
			.vhdr = {
				.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
				.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
				.hdr_len = sizeof(struct ip6) + sizeof(struct udp_hdr),
				.gso_size = segment_size,
				.csum_start = sizeof(struct ip6),
				.csum_offset = 6,
			},
		};

		assert(gso_translate_udp_6to4(&p) == 0);

		RX_BUFFER(rx_buf, HEADROOM + 8192);
		ssize_t nr = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(nr == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip4) + sizeof(struct udp_hdr) + payload_len));

		struct virtio_net_hdr_raw *vh = (struct virtio_net_hdr_raw *)rx_buf.data;
		assert(vh->gso_type == VIRTIO_NET_HDR_GSO_UDP_L4);
		assert(vh->gso_size == segment_size);
		assert(vh->csum_start == sizeof(struct ip4));
		assert(vh->csum_offset == 6);

		struct ip4 *rx_ip4 = (struct ip4 *)(rx_buf.data + gcfg.vnet_hdr_sz);
		assert(rx_ip4->proto == IPPROTO_UDP);
		assert(rx_ip4->ttl == 63);
		assert(ntohs(rx_ip4->length) == sizeof(struct ip4) + sizeof(struct udp_hdr) + payload_len);
		assert(ntohs(rx_ip4->flags_offset) == (small ? 0 : IP4_F_DF));
		assert(ntohs(rx_ip4->ident) == (small ? 65534 : 0));
		assert(next_ip4_ident() == (small ? 1 : 65534));

		struct udp_hdr *rx_udp = (struct udp_hdr *)(rx_buf.data + gcfg.vnet_hdr_sz + sizeof(struct ip4));
		assert(rx_udp->src_port == htons(12345));
		assert(rx_udp->dst_port == htons(8080));

		close(sv[0]);
		close(sv[1]);
	}

	/* 2. Fast-path 4to6 USO translation */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		gcfg.tun_has_uso = 1;

		alignas(4) uint8_t pkt_buf[HEADROOM + 8192];
		uint8_t *pkt_data = pkt_buf + HEADROOM;
		struct ip4 *ip4 = (struct ip4 *)pkt_data;
		struct udp_hdr *udp = (struct udp_hdr *)(pkt_data + sizeof(struct ip4));
		uint8_t *payload = pkt_data + sizeof(struct ip4) + sizeof(struct udp_hdr);
		uint32_t payload_len = 2400;

		memset(ip4, 0, sizeof(*ip4));
		ip4->ver_ihl = 0x45;
		ip4->length = htons(sizeof(struct ip4) + sizeof(struct udp_hdr) + payload_len);
		ip4->ttl = 64;
		ip4->proto = IPPROTO_UDP;
		inet_pton(AF_INET, "192.0.0.1", &ip4->src);
		inet_pton(AF_INET, "192.0.2.1", &ip4->dest);
		ip4->cksum = ip4_header_checksum(ip4);

		udp->src_port = htons(12345);
		udp->dst_port = htons(8080);
		udp->length = htons(sizeof(struct udp_hdr) + payload_len);
		udp->cksum = 0;
		for (uint32_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)(i & 0xff);

		struct pkt p = {
			.tun_fd = sv[0],
			.data = pkt_data,
			.data_len = sizeof(struct ip4) + sizeof(struct udp_hdr) + payload_len,
			.header_len = 0,
			.has_vhdr = 1,
			.vhdr = {
				.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
				.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
				.hdr_len = sizeof(struct ip4) + sizeof(struct udp_hdr),
				.gso_size = 1200,
				.csum_start = sizeof(struct ip4),
				.csum_offset = 6,
			},
		};

		assert(gso_translate_udp_4to6(&p) == 0);

		RX_BUFFER(rx_buf, HEADROOM + 8192);
		ssize_t nr = recv(sv[1], rx_buf.data, sizeof(rx_buf.data), 0);
		assert(nr == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip6) + sizeof(struct udp_hdr) + payload_len));

		struct virtio_net_hdr_raw *vh = (struct virtio_net_hdr_raw *)rx_buf.data;
		assert(vh->gso_type == VIRTIO_NET_HDR_GSO_UDP_L4);
		assert(vh->gso_size == 1200);
		assert(vh->csum_start == sizeof(struct ip6));
		assert(vh->csum_offset == 6);

		struct ip6 *rx_ip6 = (struct ip6 *)(rx_buf.data + gcfg.vnet_hdr_sz);
		assert(rx_ip6->next_header == IPPROTO_UDP);
		assert(rx_ip6->hop_limit == 63);

		struct udp_hdr *rx_udp = (struct udp_hdr *)(rx_buf.data + gcfg.vnet_hdr_sz + sizeof(struct ip6));
		assert(rx_udp->src_port == htons(12345));
		assert(rx_udp->dst_port == htons(8080));

		close(sv[0]);
		close(sv[1]);
	}

	/* 3. Fallback software segmentation 6to4 (tun_has_uso = 0) */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		gcfg.tun_has_uso = 0;

		alignas(4) uint8_t pkt_buf[HEADROOM + 8192];
		uint8_t *pkt_data = pkt_buf + HEADROOM;
		struct ip6 *ip6 = (struct ip6 *)pkt_data;
		struct udp_hdr *udp = (struct udp_hdr *)(pkt_data + sizeof(struct ip6));
		uint8_t *payload = pkt_data + sizeof(struct ip6) + sizeof(struct udp_hdr);
		uint32_t payload_len = 6100; // exercise segments larger than the former 2048-byte buffer

		memset(ip6, 0, sizeof(*ip6));
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(sizeof(struct udp_hdr) + payload_len);
		ip6->next_header = IPPROTO_UDP;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->src);
		inet_pton(AF_INET6, "64:ff9b::192.0.2.1", &ip6->dest);

		udp->src_port = htons(12345);
		udp->dst_port = htons(8080);
		udp->length = htons(sizeof(struct udp_hdr) + payload_len);
		udp->cksum = 0;
		for (uint32_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)(i & 0xff);

		struct pkt p = {
			.tun_fd = sv[0],
			.data = pkt_data,
			.data_len = sizeof(struct ip6) + sizeof(struct udp_hdr) + payload_len,
			.header_len = 0,
			.has_vhdr = 1,
			.vhdr = {
				.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
				.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
				.hdr_len = sizeof(struct ip6) + sizeof(struct udp_hdr),
				.gso_size = 3000,
				.csum_start = sizeof(struct ip6),
				.csum_offset = 6,
			},
		};

		assert(gso_translate_udp_6to4(&p) == 0);

		/* Segment 1: 3000 payload */
		RX_BUFFER(rx1, 4096);
		ssize_t n1 = recv(sv[1], rx1.data, sizeof(rx1.data), 0);
		assert(n1 == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip4) + sizeof(struct udp_hdr) + 3000));
		uint8_t *seg1 = rx1.data + gcfg.vnet_hdr_sz;
		struct ip4 *ip4_1 = (struct ip4 *)seg1;
		struct udp_hdr *udp_1 = (struct udp_hdr *)(seg1 + sizeof(struct ip4));
		assert(ntohs(udp_1->length) == sizeof(struct udp_hdr) + 3000);
		assert(ones_add(ip_checksum(udp_1, ntohs(udp_1->length)),
		                ip4_checksum(ip4_1, ntohs(udp_1->length), IPPROTO_UDP)) == 0);

		/* Segment 2: 3000 payload */
		RX_BUFFER(rx2, 4096);
		ssize_t n2 = recv(sv[1], rx2.data, sizeof(rx2.data), 0);
		assert(n2 == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip4) + sizeof(struct udp_hdr) + 3000));
		uint8_t *seg2 = rx2.data + gcfg.vnet_hdr_sz;
		struct ip4 *ip4_2 = (struct ip4 *)seg2;
		struct udp_hdr *udp_2 = (struct udp_hdr *)(seg2 + sizeof(struct ip4));
		assert(ntohs(udp_2->length) == sizeof(struct udp_hdr) + 3000);
		assert(ones_add(ip_checksum(udp_2, ntohs(udp_2->length)),
		                ip4_checksum(ip4_2, ntohs(udp_2->length), IPPROTO_UDP)) == 0);

		/* Segment 3: 100 payload */
		RX_BUFFER(rx3, 4096);
		ssize_t n3 = recv(sv[1], rx3.data, sizeof(rx3.data), 0);
		assert(n3 == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip4) + sizeof(struct udp_hdr) + 100));
		uint8_t *seg3 = rx3.data + gcfg.vnet_hdr_sz;
		struct ip4 *ip4_3 = (struct ip4 *)seg3;
		struct udp_hdr *udp_3 = (struct udp_hdr *)(seg3 + sizeof(struct ip4));
		assert(ntohs(udp_3->length) == sizeof(struct udp_hdr) + 100);
		assert(ones_add(ip_checksum(udp_3, ntohs(udp_3->length)),
		                ip4_checksum(ip4_3, ntohs(udp_3->length), IPPROTO_UDP)) == 0);

		close(sv[0]);
		close(sv[1]);
	}

	/* 4. Fallback software segmentation 4to6 with segments larger than 2048 */
	{
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		gcfg.tun_has_uso = 0;

		alignas(4) uint8_t pkt_buf[HEADROOM + 8192];
		uint8_t *pkt_data = pkt_buf + HEADROOM;
		struct ip4 *ip4 = (struct ip4 *)pkt_data;
		struct udp_hdr *udp = (struct udp_hdr *)(pkt_data + sizeof(struct ip4));
		uint8_t *payload = (uint8_t *)udp + sizeof(struct udp_hdr);
		uint32_t payload_len = 6100;

		memset(ip4, 0, sizeof(*ip4));
		ip4->ver_ihl = 0x45;
		ip4->length = htons(sizeof(struct ip4) + sizeof(struct udp_hdr) + payload_len);
		ip4->ttl = 64;
		ip4->proto = IPPROTO_UDP;
		inet_pton(AF_INET, "192.0.0.1", &ip4->src);
		inet_pton(AF_INET, "192.0.2.1", &ip4->dest);
		ip4->cksum = ip4_header_checksum(ip4);
		udp->src_port = htons(12345);
		udp->dst_port = htons(8080);
		udp->length = htons(sizeof(struct udp_hdr) + payload_len);
		for (uint32_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)(i & 0xff);

		struct pkt p = {
			.tun_fd = sv[0], .data = pkt_data,
			.data_len = sizeof(struct ip4) + sizeof(struct udp_hdr) + payload_len,
			.has_vhdr = 1,
			.vhdr = {
				.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
				.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
				.hdr_len = sizeof(struct ip4) + sizeof(struct udp_hdr),
				.gso_size = 3000,
				.csum_start = sizeof(struct ip4), .csum_offset = 6,
			},
		};
		assert(gso_translate_udp_4to6(&p) == 0);

		const uint32_t segment_sizes[] = {3000, 3000, 100};
		for (size_t i = 0; i < sizeof(segment_sizes) / sizeof(segment_sizes[0]); i++) {
			RX_BUFFER(rx, 4096);
			ssize_t nr = recv(sv[1], rx.data, sizeof(rx.data), 0);
			uint32_t udp_segment_len = sizeof(struct udp_hdr) + segment_sizes[i];
			assert(nr == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip6) + udp_segment_len));
			struct ip6 *ip6 = (struct ip6 *)(rx.data + gcfg.vnet_hdr_sz);
			struct udp_hdr *rx_udp = (struct udp_hdr *)((uint8_t *)ip6 + sizeof(struct ip6));
			assert(ip6->next_header == IPPROTO_UDP);
			assert(ntohs(ip6->payload_length) == udp_segment_len);
			assert(ntohs(rx_udp->length) == udp_segment_len);
			assert(ones_add(ip_checksum(rx_udp, udp_segment_len),
			                ip6_checksum(ip6, udp_segment_len, IPPROTO_UDP)) == 0);
		}
		close(sv[0]);
		close(sv[1]);
	}

	printf("PASS: UDP Generic Segmentation Offload (USO) and fallback\n");
}

/* Exercise the real packet handler, including partial checksum completion
 * before IPv6 fragmentation. Reassemble the fragments and check the checksum. */
static void test_partial_udp_fragmentation(void)
{
	setup_test_mapping();
	gcfg.tun_offload = TUN_OFFLOAD_AUTO;
    gcfg.tun_offload_effective = TUN_OFFLOAD_TCP;
	gcfg.mtu = 1280;
	gcfg.ipv6_offlink_mtu = 1280;
	/* The real packet handler emits a BSD TUN family header before IPv6. */
	size_t ip_offset = gcfg.vnet_hdr_sz;
#ifndef __linux__
	ip_offset += sizeof(struct tun_pi);
#endif
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(4) uint8_t buf[HEADROOM + 20 + 1508] = {0};
	struct ip4 *ip4 = (struct ip4 *)(buf + HEADROOM);
	ip4->ver_ihl = 0x45;
	ip4->length = htons(20 + 1508);
	ip4->ttl = 64;
	ip4->proto = IPPROTO_UDP;
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);
	inet_pton(AF_INET, "11.0.0.2", &ip4->dest);
	ip4->cksum = ip_checksum(ip4, 20);
	struct udp_hdr *udp = (struct udp_hdr *)(ip4 + 1);
	udp->src_port = htons(1234);
	udp->dst_port = htons(5678);
	udp->length = htons(1508);
	memset(udp + 1, 0xa5, 1500);
	udp->cksum = htons(gso_calc_udp_pseudo4(&ip4->src, &ip4->dest, 1508));
	struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip4,
		.data_len = 1528, .has_vhdr = 1};
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.csum_start = 20;
	p.vhdr.csum_offset = 6;
	handle_ip4(&p);
	alignas(4) uint8_t assembled[1508];
	RX_BUFFER(rx, 2048);
	struct ip6 translated;
	size_t total = 0;
	for (int i = 0; i < 2; i++) {
		ssize_t n = recv(sv[1], rx.data, sizeof(rx.data), MSG_DONTWAIT);
		assert(n > (ssize_t)(ip_offset + 48));
		struct virtio_net_hdr_raw *vh = (void *)rx.data;
		assert(!(vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM));
		struct ip6 *ip6 = (void *)(rx.data + ip_offset);
		translated = *ip6;
		assert(ip6->next_header == 44);
		struct ip6_frag *frag = (void *)(ip6 + 1);
		size_t off = ntohs(frag->offset_flags) & IP6_F_MASK;
		size_t len = ntohs(ip6->payload_length) - sizeof(*frag);
		assert(off == total && off + len <= sizeof(assembled));
		memcpy(assembled + off, frag + 1, len);
		total += len;
	}
	assert(total == sizeof(assembled));
	assert(ones_add(ip_checksum(assembled, total),
		ip6_checksum(&translated, total, IPPROTO_UDP)) == 0);
	/* Invalid segmentation metadata must not fall through to plain translation. */
	p = (struct pkt){.tun_fd = sv[0], .data = (uint8_t *)ip4,
		.data_len = 1528, .has_vhdr = 1};
	p.vhdr.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
	p.vhdr.gso_size = 0;
	handle_ip4(&p);
	assert(recv(sv[1], rx.data, sizeof(rx.data), MSG_DONTWAIT) < 0);
	/* More than 128 logical datagrams in one aggregate is rejected before any
	 * output, bounding software work and matching the UDP_SEGMENT API limit. */
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.gso_size = 10;
	p.vhdr.hdr_len = sizeof(struct ip4) + sizeof(struct udp_hdr);
	p.vhdr.csum_start = sizeof(struct ip4);
	p.vhdr.csum_offset = 6;
	handle_ip4(&p);
	assert(recv(sv[1], rx.data, sizeof(rx.data), MSG_DONTWAIT) < 0);
	close(sv[0]);
	close(sv[1]);
	printf("PASS: Partial UDP fragmentation checksum and invalid GSO rejection\n");
}

static void test_gso_sw_seg_4to6_jumbo_mss(void)
{
	printf("Testing gso_software_segment_and_send_4to6() with jumbo MSS (gso_size=4000)...\n");
	setup_test_mapping();
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

	alignas(4) uint8_t pkt_buf[HEADROOM + 16384];
	memset(pkt_buf, 0, sizeof(pkt_buf));
	uint8_t *base = pkt_buf + HEADROOM;

	uint32_t payload_len = 8000;
	uint32_t tcp_len = sizeof(struct tcp_hdr) + payload_len;
	uint32_t ip4_len = sizeof(struct ip4) + tcp_len;

	struct ip4 *ip4 = (struct ip4 *)base;
	ip4->ver_ihl = 0x45;
	ip4->length = htons((uint16_t)ip4_len);
	ip4->flags_offset = htons(IP4_F_DF);
	ip4->ttl = 64;
	ip4->proto = IPPROTO_TCP;
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);
	inet_pton(AF_INET, "8.8.8.8", &ip4->dest);
	ip4->cksum = ip4_header_checksum(ip4);

	struct tcp_hdr *tcp = (struct tcp_hdr *)(base + sizeof(struct ip4));
	tcp->src_port = htons(40000);
	tcp->dst_port = htons(443);
	tcp->seq = htonl(1);
	tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
	tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
	tcp->window = htons(1024);
	tcp->cksum = htons(gso_calc_tcp_pseudo4(&ip4->src, &ip4->dest, tcp_len));

	struct pkt p = {
		.tun_fd = sv[0],
		.data = base,
		.data_len = ip4_len,
		.has_vhdr = 1,
		.vhdr = {
			.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
			.gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
			.hdr_len = sizeof(struct ip4) + sizeof(struct tcp_hdr),
			.gso_size = 4000,
			.csum_start = sizeof(struct ip4),
			.csum_offset = 16,
		}
	};

	for (uint32_t i = 0; i < payload_len; ++i)
		((uint8_t *)(tcp + 1))[i] = (uint8_t)(i * 31);
	int ret = gso_software_segment_and_send_4to6(&p);
	assert(ret == 0);
	for (unsigned segment = 0; segment < 2; ++segment) {
		RX_BUFFER(received, 8192);
		ssize_t length = recv(sv[1], received.data, sizeof(received.data), 0);
		assert(length == (ssize_t)(gcfg.vnet_hdr_sz + sizeof(struct ip6) + sizeof(struct tcp_hdr) + 4000));
		struct ip6 *out = (struct ip6 *)(received.data + gcfg.vnet_hdr_sz);
		struct tcp_hdr *out_tcp = (struct tcp_hdr *)(out + 1);
		assert(ntohs(out->payload_length) == sizeof(struct tcp_hdr) + 4000);
		assert(ntohl(out_tcp->seq) == 1 + segment * 4000);
		assert(!memcmp(out_tcp + 1, (uint8_t *)(tcp + 1) + segment * 4000, 4000));
		assert(ones_add(ip_checksum(out_tcp, ntohs(out->payload_length)),
		                ip6_checksum(out, ntohs(out->payload_length), IPPROTO_TCP)) == 0);
	}
	uint8_t extra;
	assert(recv(sv[1], &extra, 1, MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	close(sv[0]);
	close(sv[1]);
	printf("PASS: gso_software_segment_and_send_4to6() jumbo MSS\n");
}

static void test_gso_error_parity(void)
{
    for (int family = 4; family <= 6; family += 2) {
        for (int udp = 0; udp < 2; ++udp) {
            for (int kind = 0; kind < 4; ++kind) {
                setup_test_mapping(); gcfg.vnet_hdr_sz = 0; gcfg.mtu = 1280;
                gcfg.tun_has_uso = 1; gcfg.wkpf_strict = 1;
                int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
                alignas(4) uint8_t storage[HEADROOM + 8192] = {0}, response[8192];
                uint8_t *data = storage + HEADROOM;
                unsigned l3 = family == 4 ? 20 : 40, l4 = udp ? 8 : 20;
                unsigned mss = kind ? 100 : 2000, length = l3 + l4 + 2 * mss;
                if (family == 4) {
                    struct ip4 *ip = (struct ip4 *)data;
                    ip->ver_ihl = 0x45; ip->length = htons(length); ip->flags_offset = htons(IP4_F_DF);
                    ip->ttl = 64; ip->proto = udp ? IPPROTO_UDP : IPPROTO_TCP;
                    inet_pton(AF_INET, kind == 3 ? "10.0.0.1" : "192.0.0.1", &ip->src);
                    inet_pton(AF_INET, kind == 1 ? "192.0.0.254" : kind == 2 ? "10.0.0.2" : "8.8.8.8", &ip->dest);
                    ip->cksum = ip4_header_checksum(ip);
                } else {
                    struct ip6 *ip = (struct ip6 *)data;
                    ip->ver_tc_fl = htonl(0x60000000); ip->payload_length = htons(length - 40);
                    ip->hop_limit = 64; ip->next_header = udp ? IPPROTO_UDP : IPPROTO_TCP;
                    inet_pton(AF_INET6, kind == 3 ? "fdab::1" : "fd9b:64:1:ff::10", &ip->src);
                    inet_pton(AF_INET6, kind == 1 ? "fd9b:64:1:ff::254" : kind == 2 ? "fdab::2" : "64:ff9b::808:808", &ip->dest);
                }
                if (udp) ((struct udp_hdr *)(data + l3))->length = htons(length - l3);
                else ((struct tcp_hdr *)(data + l3))->doff_res = 5 << 4;
                struct pkt p = {.tun_fd = sv[0], .data = data, .data_len = length, .has_vhdr = 1,
                    .vhdr = {.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
                        .gso_type = udp ? VIRTIO_NET_HDR_GSO_UDP_L4 : family == 4 ? VIRTIO_NET_HDR_GSO_TCPV4 : VIRTIO_NET_HDR_GSO_TCPV6,
                        .hdr_len = l3 + l4, .gso_size = mss, .csum_start = l3, .csum_offset = udp ? 6 : 16}};
                int result = udp ? (family == 4 ? gso_translate_udp_4to6(&p) : gso_translate_udp_6to4(&p)) :
                                   (family == 4 ? gso_translate_tcp_4to6(&p) : gso_translate_tcp_6to4(&p));
                assert(result == 0);
                ssize_t count = recv(sv[1], response, sizeof(response), MSG_DONTWAIT);
#ifdef __linux__
                unsigned offset = 0;
#else
                unsigned offset = sizeof(struct tun_pi);
#endif
                assert(count > (ssize_t)(offset + l3 + sizeof(struct icmp)));
                struct icmp *error = (struct icmp *)(response + offset + l3);
                if (family == 4) {
                    const unsigned codes[] = {4, 2, 1, 10};
                    assert(error->type == 3 && error->code == codes[kind]);
                    assert(((struct ip4 *)(response + offset))->proto == IPPROTO_ICMP);
                    assert(ip_checksum(error, count - offset - l3) == 0);
                } else {
                    const unsigned types[] = {2, 4, 1, 1}, codes[] = {0, 1, 0, 5};
                    assert(error->type == types[kind] && error->code == codes[kind]);
                    struct ip6 *ip = (struct ip6 *)(response + offset);
                    assert(ip->next_header == IPPROTO_ICMPV6);
                    assert(ones_add(ip_checksum(error, count - offset - l3), ip6_checksum(ip, count - offset - l3, IPPROTO_ICMPV6)) == 0);
                }
                close(sv[0]); close(sv[1]);
            }
        }
    }
    puts("PASS: TCP/UDP GSO MTU, self, destination and source rejection ICMP in both directions");
}

static void test_gso_uint16_overflow_6to4(void)
{
	printf("Testing 16-bit IPv4 length overflow fallback in gso_translate_tcp_6to4()...\n");
	setup_test_mapping();
	gcfg.vnet_hdr_sz = 10;
	gcfg.mtu = 65535;

	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	int sock_buf_size = 256 * 1024;
	setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));
	setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));

	/* Payload of 65500 + 20 (TCP) = 65520 <= 65535 in IPv6, but + 20 (IPv4) = 65540 > 65535 */
	uint32_t payload_len = 65500;
	uint32_t ip6_len = sizeof(struct ip6) + sizeof(struct tcp_hdr) + payload_len;
	uint8_t *storage = calloc(1, HEADROOM + ip6_len);
	assert(storage);
	uint8_t *raw_pkt = storage + HEADROOM;
	struct ip6 *ip6 = (struct ip6 *)raw_pkt;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(raw_pkt + sizeof(struct ip6));

	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons((uint16_t)(sizeof(struct tcp_hdr) + payload_len));
	ip6->next_header = IPPROTO_TCP;
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	tcp->src_port = htons(80);
	tcp->dst_port = htons(54321);
	tcp->seq = htonl(1000);
	tcp->doff_res = 5 << 4;
	tcp->flags = TCP_FLAG_ACK | TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_ECE | TCP_FLAG_CWR;
	for (uint32_t n = 0; n < payload_len; ++n)
		((uint8_t *)(tcp + 1))[n] = (uint8_t)(n % 251);
	set_ip4_ident_counter(100);

	struct pkt p = {
		.tun_fd = sv[0],
		.data = raw_pkt,
		.data_len = ip6_len,
		.has_vhdr = 1,
		.vhdr = {
			.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
			.gso_type = VIRTIO_NET_HDR_GSO_TCPV6,
			.hdr_len = sizeof(struct ip6) + sizeof(struct tcp_hdr),
			.gso_size = 1440,
			.csum_start = sizeof(struct ip6),
			.csum_offset = 16,
		}
	};

	int res = gso_translate_tcp_6to4(&p);
	assert(res == 0);

	/* Check that individual segments were received and none have wrapped ip4->length */
	uint32_t segments_received = 0, offset = 0;
	while (1) {
		RX_BUFFER(received, 4096);
		ssize_t n = recv(sv[1], received.data, sizeof(received.data), MSG_DONTWAIT);
		if (n <= 0) break;
		segments_received++;
		struct ip4 *out = (struct ip4 *)(received.data + gcfg.vnet_hdr_sz);
		uint16_t out_len = ntohs(out->length);
		assert(out_len <= 1440 + sizeof(struct ip4) + sizeof(struct tcp_hdr));
		assert(out_len > sizeof(struct ip4) + sizeof(struct tcp_hdr));
		assert(ip_checksum(out, sizeof(*out)) == 0);
		struct tcp_hdr *segment = (void *)(out + 1);
		uint32_t chunk = out_len - sizeof(*out) - sizeof(*segment);
		assert(ntohl(segment->seq) == 1000 + offset);
		assert(!memcmp(segment + 1, (uint8_t *)(tcp + 1) + offset, chunk));
		assert(ones_add(ip_checksum(segment, sizeof(*segment) + chunk),
		                ip4_checksum(out, sizeof(*segment) + chunk, IPPROTO_TCP)) == 0);
		int last = offset + chunk == payload_len;
		assert(!!(segment->flags & TCP_FLAG_FIN) == last);
		assert(!!(segment->flags & TCP_FLAG_PSH) == last);
		assert(!!(segment->flags & TCP_FLAG_CWR) == (offset == 0));
		assert(segment->flags & TCP_FLAG_ECE);
		if (out_len <= 1260) assert(out->flags_offset == 0 && ntohs(out->ident) == 100);
		else assert(out->flags_offset == htons(IP4_F_DF) && out->ident == 0);
		offset += chunk;
	}
	assert(segments_received == (payload_len + 1440 - 1) / 1440);
	assert(offset == payload_len && next_ip4_ident() == 101);

	close(sv[0]);
	close(sv[1]);
	free(storage);
	printf("PASS: gso_translate_tcp_6to4() overflow fallback to software segmentation\n");
}


/* Exercise the emitter, not just the shared allocator: short/empty segments
 * must reserve IDs even when the advertised MSS would produce DF=1. */
static void test_software_segment_ids(void)
{
    const struct { unsigned payload, mss; } cases[] = {
        {0, 1400}, {1, 1400}, {300, 1400}, {2400, 1200},
        {2800, 1400}, {3101, 1400}, {1220, 1400}, {1232, 1400},
    };
    for (int udp = 0; udp < 2; ++udp) {
        for (unsigned c = 0; c < sizeof(cases)/sizeof(cases[0]); ++c) {
            setup_test_mapping(); gcfg.mtu = 65535;
            int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
            unsigned transport = udp ? sizeof(struct udp_hdr) : sizeof(struct tcp_hdr);
            unsigned bytes = cases[c].payload;
            uint8_t *storage = calloc(1, HEADROOM + 40 + transport + bytes); assert(storage);
            struct ip6 *ip6 = (void *)(storage + HEADROOM);
            ip6->ver_tc_fl = htonl(0x60000000);
            ip6->payload_length = htons(transport + bytes);
            ip6->next_header = udp ? IPPROTO_UDP : IPPROTO_TCP; ip6->hop_limit = 64;
            inet_pton(AF_INET6, "64:ff9b::198.51.100.2", &ip6->src);
            inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);
            if (udp) { struct udp_hdr *u = (void *)(ip6 + 1); u->length = htons(transport + bytes); }
            else { struct tcp_hdr *t = (void *)(ip6 + 1); t->doff_res = 5 << 4; t->flags = TCP_FLAG_ACK; }
            uint8_t *payload = (uint8_t *)(ip6 + 1) + transport;
            for (unsigned n = 0; n < bytes; ++n) payload[n] = (uint8_t)(n % 251);
            struct pkt packet = {.tun_fd = sv[0], .data = (void *)ip6,
                .data_len = 40 + transport + bytes, .has_vhdr = 1,
                .vhdr = {.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    .gso_type = udp ? VIRTIO_NET_HDR_GSO_UDP_L4 : VIRTIO_NET_HDR_GSO_TCPV6,
                    .hdr_len = 40 + transport, .gso_size = cases[c].mss,
                    .csum_start = 40, .csum_offset = udp ? 6 : 16}};
            set_ip4_ident_counter(65534);
            assert(next_ip4_ident() == 65534); /* Mix scalar and batched IDs. */
            assert((udp ? gso_software_segment_and_send_udp_6to4(&packet) :
                          gso_software_segment_and_send_6to4(&packet)) == 0);
            unsigned offset = 0, segments = 0; uint16_t next_id = 65535;
            do {
                RX_BUFFER(rx, 4096);
                ssize_t length = recv(sv[1], rx.data, sizeof(rx.data), MSG_DONTWAIT);
                assert(length > 10);
                struct ip4 *out = (void *)(rx.data + 10);
                unsigned chunk = bytes - offset;
                if (chunk > cases[c].mss) chunk = cases[c].mss;
                assert(length == (ssize_t)(10 + sizeof(struct ip4) + transport + chunk));
                assert(ntohs(out->length) == sizeof(struct ip4) + transport + chunk);
                assert(ip_checksum(out, sizeof(*out)) == 0);
                if (sizeof(struct ip4) + transport + chunk <= 1260) {
                    assert(out->flags_offset == 0);
                    assert(ntohs(out->ident) == next_id++);
                } else {
                    assert(out->flags_offset == htons(IP4_F_DF) && out->ident == 0);
                }
                uint8_t *l4 = (uint8_t *)(out + 1);
                assert(ones_add(ip_checksum(l4, transport + chunk),
                    ip4_checksum(out, transport + chunk, udp ? IPPROTO_UDP : IPPROTO_TCP)) == 0);
                assert(memcmp(l4 + transport, payload + offset, chunk) == 0);
                if (!udp) assert(ntohl(((struct tcp_hdr *)l4)->seq) == offset);
                offset += chunk; ++segments;
            } while (offset < bytes);
            assert(segments == (bytes ? (bytes + cases[c].mss - 1) / cases[c].mss : 1));
            assert(next_ip4_ident() == next_id);
            uint8_t extra; assert(recv(sv[1], &extra, 1, MSG_DONTWAIT) < 0);
            free(storage); close(sv[0]); close(sv[1]);
        }
    }
    puts("PASS: software TCP/UDP emitted IDs, checksums, payload, empty segments and wrap");
}


static void test_software_input_contract(void)
{
    int (*emit[2][2])(struct pkt *) = {
        {gso_software_segment_and_send_4to6, gso_software_segment_and_send_udp_4to6},
        {gso_software_segment_and_send_6to4, gso_software_segment_and_send_udp_6to4}};
    for (int v6=0;v6<2;v6++) for (int udp=0;udp<2;udp++) {
        for (int bad=0;bad<13;bad++) {
            setup_test_mapping();gcfg.mtu=1500;
            int sv[2];assert(socketpair(AF_UNIX,SOCK_DGRAM,0,sv)==0);
            alignas(4) uint8_t storage[HEADROOM+256]={0};
            uint8_t *raw=storage+HEADROOM;
            unsigned l3=v6?40:20,l4=udp?8:20,total=l3+l4+100;
            if (v6) {
                struct ip6 *ip=(void *)raw;ip->ver_tc_fl=htonl(0x60000000);
                ip->payload_length=htons(l4+100);ip->next_header=udp?17:6;ip->hop_limit=64;
                inet_pton(AF_INET6,"64:ff9b::c633:6402",&ip->src);
                inet_pton(AF_INET6,"fd9b:64:1:ff::10",&ip->dest);
            } else {
                struct ip4 *ip=(void *)raw;ip->ver_ihl=0x45;ip->length=htons(total);ip->ttl=64;
                ip->proto=udp?17:6;inet_pton(AF_INET,"192.0.0.1",&ip->src);
                inet_pton(AF_INET,"198.51.100.2",&ip->dest);ip->cksum=ip4_header_checksum(ip);
            }
            if(udp) ((struct udp_hdr *)(raw+l3))->length=htons(l4+100);
            else ((struct tcp_hdr *)(raw+l3))->doff_res=5<<4;
            struct pkt p={.tun_fd=sv[0],.data=raw,.data_len=total,.has_vhdr=1,
                .vhdr={.flags=VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    .gso_type=udp?VIRTIO_NET_HDR_GSO_UDP_L4:v6?VIRTIO_NET_HDR_GSO_TCPV6:VIRTIO_NET_HDR_GSO_TCPV4,
                    .hdr_len=l3+l4,.gso_size=100,.csum_start=l3,.csum_offset=udp?6:16}};
            switch(bad) {
                case 0:p.has_vhdr=0;break;
                case 1:p.vhdr.gso_size=0;break;
                case 2:p.vhdr.gso_type=udp?VIRTIO_NET_HDR_GSO_TCPV6:VIRTIO_NET_HDR_GSO_UDP_L4;break;
                case 3:p.vhdr.hdr_len=l3;break;
                case 4:p.vhdr.csum_offset=5;break;
                case 5:if(v6)((struct ip6 *)raw)->next_header=1;else((struct ip4 *)raw)->proto=1;break;
                case 6:if(v6)((struct ip6 *)raw)->payload_length=htons(1);else((struct ip4 *)raw)->length=htons(1);break;
                case 7:if(udp)((struct udp_hdr *)(raw+l3))->length=htons(1);else((struct tcp_hdr *)(raw+l3))->doff_res=1<<4;break;
                case 8:p.data_len=l3+l4-1;break;
                case 9:p.vhdr.csum_start=l3+1;break;
                case 10:if(v6)((struct ip6 *)raw)->next_header=44;else((struct ip4 *)raw)->flags_offset=htons(IP4_F_MF);break;
                case 11:if(v6)((struct ip6 *)raw)->ver_tc_fl=htonl(0x50000000);else((struct ip4 *)raw)->ver_ihl=0x44;break;
                case 12:if(v6)inet_pton(AF_INET6,"ff02::1",&((struct ip6 *)raw)->src);else inet_pton(AF_INET,"224.0.0.1",&((struct ip4 *)raw)->src);break;
            }
            if (!v6) {struct ip4 *ip=(void *)raw;ip->cksum=0;ip->cksum=ip4_header_checksum(ip);}
            assert(emit[v6][udp](&p)<0);
            uint8_t byte;assert(recv(sv[1],&byte,1,MSG_DONTWAIT)<0);
            close(sv[0]);close(sv[1]);
        }
    }
    puts("PASS: all public software emitters reject mismatched/truncated GSO metadata without output");
}

static void test_single_tcp_gso_metadata(void)
{
    const unsigned payloads[] = {0, 1, 999, 1000, 1001};
    for (unsigned family = 4; family <= 6; family += 2) {
        for (unsigned n = 0; n < sizeof(payloads)/sizeof(payloads[0]); n++) {
            setup_test_mapping(); gcfg.mtu = 1500;
            int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
            unsigned payload_len = payloads[n], l3 = family == 4 ? 20 : 40;
            alignas(4) uint8_t storage[HEADROOM+40+32+1001] = {0};
            uint8_t *raw = storage+HEADROOM;
            struct tcp_hdr *tcp = (void *)(raw+l3);
            tcp->src_port = htons(6000); tcp->dst_port = htons(7000);
            tcp->doff_res = 8<<4; tcp->flags = TCP_FLAG_ACK|TCP_FLAG_CWR|TCP_FLAG_ECE;
            uint8_t *options = (uint8_t *)tcp+20;
            options[0] = options[1] = 1; options[2] = 8; options[3] = 10;
            for (unsigned i = 0; i < payload_len; i++) raw[l3+32+i] = (uint8_t)i;
            if (family == 4) {
                struct ip4 *ip = (void *)raw;
                ip->ver_ihl = 0x45; ip->length = htons(l3+32+payload_len);
                ip->ttl = 64; ip->proto = IPPROTO_TCP;
                inet_pton(AF_INET,"192.0.0.1",&ip->src);
                inet_pton(AF_INET,"198.51.100.2",&ip->dest);
                ip->cksum = ip4_header_checksum(ip);
                tcp->cksum = htons(gso_calc_tcp_pseudo4(&ip->src,&ip->dest,32+payload_len));
            } else {
                struct ip6 *ip = (void *)raw;
                ip->ver_tc_fl = htonl(0x60000000); ip->payload_length = htons(32+payload_len);
                ip->hop_limit = 64; ip->next_header = IPPROTO_TCP;
                inet_pton(AF_INET6,"64:ff9b::c633:6402",&ip->src);
                inet_pton(AF_INET6,"fd9b:64:1:ff::10",&ip->dest);
                tcp->cksum = htons(gso_calc_tcp_pseudo6(&ip->src,&ip->dest,32+payload_len));
            }
            struct pkt p = {.tun_fd=sv[0],.data=raw,.data_len=l3+32+payload_len,.has_vhdr=1,
                .vhdr={.flags=VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    .gso_type=(family==4?VIRTIO_NET_HDR_GSO_TCPV4:VIRTIO_NET_HDR_GSO_TCPV6)|VIRTIO_NET_HDR_GSO_ECN,
                    .hdr_len=l3+32,.gso_size=1000,.csum_start=l3,.csum_offset=16}};
            assert((family==4?gso_translate_tcp_4to6(&p):gso_translate_tcp_6to4(&p)) == 0);
            RX_BUFFER(received, 2048);
            unsigned out_l3 = family == 4 ? 40 : 20;
            assert(recv(sv[1],received.data,sizeof(received.data),0) == (ssize_t)(10+out_l3+32+payload_len));
            struct virtio_net_hdr_raw *v = (void *)received.data;
            assert(v->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
            assert(v->csum_start == out_l3 && v->csum_offset == 16);
            assert(v->gso_size == (payload_len <= 1000 ? 0 : 1000));
            assert(v->gso_type == (payload_len <= 1000 ? VIRTIO_NET_HDR_GSO_NONE :
                ((family==4?VIRTIO_NET_HDR_GSO_TCPV6:VIRTIO_NET_HDR_GSO_TCPV4)|VIRTIO_NET_HDR_GSO_ECN)));
            struct tcp_hdr *out_tcp = (void *)(received.data+10+out_l3);
            assert(out_tcp->doff_res == 8<<4 && out_tcp->flags == (TCP_FLAG_ACK|TCP_FLAG_CWR|TCP_FLAG_ECE));
            assert(!memcmp((uint8_t *)out_tcp+32,raw+l3+32,payload_len));
            uint16_t seed;
            if (family == 4) {
                struct ip6 *ip = (void *)(received.data+10);
                seed = gso_calc_tcp_pseudo6(&ip->src,&ip->dest,32+payload_len);
            } else {
                struct ip4 *ip = (void *)(received.data+10);
                seed = gso_calc_tcp_pseudo4(&ip->src,&ip->dest,32+payload_len);
            }
            assert(out_tcp->cksum == htons(seed));
            uint8_t extra; assert(recv(sv[1],&extra,1,MSG_DONTWAIT) < 0);
            close(sv[0]); close(sv[1]);
        }
    }
    puts("PASS: single TCP output clears GSO, retains checksum offload and preserves multi-segment aggregates");
}

int main(void)
{
	printf("=== Running unit_gso test suite ===\n");
	stats_init();
	test_software_input_contract();
	test_software_segment_ids();
	test_gso_error_parity();
	test_gso_validate();
	test_single_tcp_gso_metadata();
	test_gso_csum_update();
	test_gso_csum_seed();
	const unsigned headers[] = {20, 32, 60};
	for (int frame = 0; frame < 3; ++frame)
		for (unsigned h = 0; h < 3; ++h)
			for (unsigned full = 1; full <= 2; ++full)
				test_gso_translate_and_split(frame == 0 ? 0 : frame == 1 ? 10 : 12, headers[h], full);
	test_gso_boundary_1260_1261();
	test_gso_tcp_options();
	test_gso_ipv4_options();
	test_gso_ecn_cwr();
	test_gso_ttl_hop_limit();
	test_gso_mock_write_error();
	test_gso_udp_uso();
	test_partial_udp_fragmentation();
	test_gso_sw_seg_4to6_jumbo_mss();
	test_gso_uint16_overflow_6to4();
	gso_dump_stats();
	printf("All unit_gso tests passed successfully!\n");
	return 0;
}
