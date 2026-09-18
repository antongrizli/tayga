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
	const uint16_t *tw = (const uint16_t *)tcp;
	for (uint32_t i = 0; i < tcp_hdr_len / 2; i++) {
		if (i == 8) continue; /* skip cksum field */
		sum += tw[i];
	}

	const uint16_t *pw = (const uint16_t *)payload;
	for (uint32_t i = 0; i < payload_len / 2; i++) {
		sum += pw[i];
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

int main(void)
{
	printf("=== Running unit_gso test suite ===\n");
	test_gso_validate();
	test_gso_csum_update();
	test_gso_csum_seed();
	printf("All unit_gso tests passed successfully!\n");
	return 0;
}
