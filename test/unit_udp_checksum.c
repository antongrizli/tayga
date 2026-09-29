#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include "tayga.h"
#include "gso.h"

/* Reference full checksum calculation over IPv4/IPv6 pseudoheader + UDP payload */
static uint16_t calc_full_udp_cksum4(const struct in_addr *src, const struct in_addr *dst,
                                     const void *payload, uint16_t len)
{
	uint32_t sum = 0;
	const uint16_t *s = (const uint16_t *)src;
	const uint16_t *d = (const uint16_t *)dst;
	sum += ntohs(s[0]) + ntohs(s[1]);
	sum += ntohs(d[0]) + ntohs(d[1]);
	sum += IPPROTO_UDP;
	sum += len;

	const uint8_t *p = (const uint8_t *)payload;
	int c = len;
	while (c > 1) {
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		c -= 2;
	}
	if (c > 0)
		sum += (uint32_t)p[0] << 8;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	uint16_t res = (uint16_t)~sum;
	if (res == 0)
		res = 0xffff;
	return res;
}

static uint16_t calc_full_udp_cksum6(const struct in6_addr *src, const struct in6_addr *dst,
                                     const void *payload, uint16_t len)
{
	uint32_t sum = 0;
	const uint16_t *s = (const uint16_t *)src;
	const uint16_t *d = (const uint16_t *)dst;
	for (int i = 0; i < 8; i++) sum += ntohs(s[i]);
	for (int i = 0; i < 8; i++) sum += ntohs(d[i]);
	sum += len;
	sum += IPPROTO_UDP;

	const uint8_t *p = (const uint8_t *)payload;
	int c = len;
	while (c > 1) {
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		c -= 2;
	}
	if (c > 0)
		sum += (uint32_t)p[0] << 8;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	uint16_t res = (uint16_t)~sum;
	if (res == 0)
		res = 0xffff;
	return res;
}

/* Config and globals for unit test */
struct config gcfg;
time_t now;

static void test_metadata_bounds(void)
{
	printf("Testing UDP checksum metadata bounds validation...\n");
	uint8_t buf[256];
	memset(buf, 0, sizeof(buf));

	struct ip4 *ip4 = (struct ip4 *)buf;
	ip4->ver_ihl = 0x45;
	ip4->length = htons(28); /* 20 IP + 8 UDP */
	ip4->proto = IPPROTO_UDP;
	inet_pton(AF_INET, "192.168.88.2", &ip4->src);
	inet_pton(AF_INET, "11.0.0.2", &ip4->dest);

	uint8_t *udp = buf + 20;
	*(uint16_t *)(udp + 0) = htons(1234);
	*(uint16_t *)(udp + 2) = htons(5678);
	*(uint16_t *)(udp + 4) = htons(8); /* udp len */
	*(uint16_t *)(udp + 6) = 0;

	struct ip6 ip6;
	memset(&ip6, 0, sizeof(ip6));
	inet_pton(AF_INET6, "2001:db8:1::2", &ip6.src);
	inet_pton(AF_INET6, "64:ff9b::b00:2", &ip6.dest);

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.ip4 = ip4;
	p.header_len = 20;
	p.data = udp;
	p.data_len = 8;
	p.data_proto = IPPROTO_UDP;
	p.has_vhdr = 1;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.csum_start = 20;
	p.vhdr.csum_offset = 6;

	gcfg.vnet_hdr_sz = 10;

	/* 1. Valid metadata passes */
	int ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_NONE);

	/* 2. Invalid csum_start (e.g. 19 != header_len) is rejected */
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.csum_start = 19;
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);
	p.vhdr.csum_start = 20;

	/* 3. Invalid csum_offset (e.g. 16 instead of 6 for UDP) is rejected */
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.csum_offset = 16;
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);
	p.vhdr.csum_offset = 6;

	/* 4. csum bounds beyond packet length is rejected */
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	ip4->length = htons(26); /* says 26 bytes total, but csum is at 20+6+2 = 28 */
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);
	ip4->length = htons(28);

	/* 5. Invalid UDP header length (> data_len or < 8) is rejected */
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	*(uint16_t *)(udp + 4) = htons(10); /* header says 10, but only 8 provided */
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	*(uint16_t *)(udp + 4) = htons(4); /* header says 4 < 8 */
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);
	*(uint16_t *)(udp + 4) = htons(8);

	/* First fragment with NEEDS_CSUM is rejected before it can be forwarded. */
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	ip4->flags_offset = htons(IP4_F_MF);
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);
	ip4->flags_offset = 0;

	/* A completed checksum on the first fragment still needs address adjustment. */
	*(uint16_t *)(udp + 6) = htons(0x1234);
	ip4->flags_offset = htons(IP4_F_MF);
	p.vhdr.flags = 0;
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_NONE);
	assert(*(uint16_t *)(udp + 6) != htons(0x1234));
	ip4->flags_offset = 0;

	/* IPv6 first fragments follow the same partial and completed checksum rules. */
	struct ip6_frag frag;
	memset(&frag, 0, sizeof(frag));
	frag.offset_flags = htons(IP6_F_MF);
	ip6.payload_length = htons(16); /* fragment header plus UDP header */
	p.ip4 = NULL;
	p.ip6 = &ip6;
	p.ip6_frag = &frag;
	p.header_len = sizeof(frag);
	p.vhdr.csum_start = sizeof(struct ip6) + sizeof(frag);
	p.vhdr.csum_offset = 6;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	ret = xlate_payload_6to4(&p, ip4, 0);
	assert(ret == ERROR_DROP);
	*(uint16_t *)(udp + 6) = htons(0x1234);
	p.vhdr.flags = 0;
	ret = xlate_payload_6to4(&p, ip4, 0);
	assert(ret == ERROR_NONE);
	assert(*(uint16_t *)(udp + 6) != htons(0x1234));

	printf("PASS: Metadata bounds validation\n");
}

static void test_complete_checksum_translation(void)
{
	printf("Testing complete UDP checksum translation (4to6 & 6to4) across payload sizes...\n");
	const int sizes[] = {0, 1, 3, 7, 64, 65, 256, 512, 1200, 1240};
	const int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

	struct in_addr src4, dst4;
	struct in6_addr src6, dst6;
	inet_pton(AF_INET, "192.168.88.2", &src4);
	inet_pton(AF_INET, "11.0.0.2", &dst4);
	inet_pton(AF_INET6, "2001:db8:1::192.168.88.2", &src6);
	inet_pton(AF_INET6, "64:ff9b::b00:2", &dst6);

	for (int s = 0; s < num_sizes; s++) {
		int payload_len = sizes[s];
		uint16_t udp_len = 8 + payload_len;
		uint8_t *pkt_buf = malloc(64 + 40 + udp_len);
		assert(pkt_buf);

		uint8_t *data = pkt_buf + 64;
		/* Fill deterministic pseudo-random payload */
		for (int i = 0; i < udp_len; i++) {
			data[i] = (uint8_t)((i * 37 + payload_len * 13 + 5) & 0xff);
		}
		*(uint16_t *)(data + 0) = htons(12345);
		*(uint16_t *)(data + 2) = htons(80);
		*(uint16_t *)(data + 4) = htons(udp_len);
		*(uint16_t *)(data + 6) = 0;

		/* Compute original IPv4 UDP checksum */
		uint16_t orig_cksum4 = calc_full_udp_cksum4(&src4, &dst4, data, udp_len);
		*(uint16_t *)(data + 6) = htons(orig_cksum4);

		struct ip4 ip4;
		memset(&ip4, 0, sizeof(ip4));
		ip4.ver_ihl = 0x45;
		ip4.length = htons(20 + udp_len);
		ip4.proto = IPPROTO_UDP;
		ip4.src = src4;
		ip4.dest = dst4;

		struct ip6 ip6;
		memset(&ip6, 0, sizeof(ip6));
		ip6.src = src6;
		ip6.dest = dst6;
		ip6.payload_length = htons(udp_len);
		ip6.next_header = IPPROTO_UDP;

		struct pkt p;
		memset(&p, 0, sizeof(p));
		p.ip4 = &ip4;
		p.header_len = 20;
		p.data = data;
		p.data_len = udp_len;
		p.data_proto = IPPROTO_UDP;
		p.has_vhdr = 0;

		/* Translate 4 to 6 */
		int ret = xlate_payload_4to6(&p, &ip6, 0);
		assert(ret == ERROR_NONE);

		uint16_t actual_cksum6 = ntohs(*(uint16_t *)(data + 6));
		*(uint16_t *)(data + 6) = 0;
		uint16_t expected_cksum6 = calc_full_udp_cksum6(&src6, &dst6, data, udp_len);
		assert(actual_cksum6 != 0);
		if (actual_cksum6 != expected_cksum6) {
			fprintf(stderr, "FAIL 4to6 size %d: actual=0x%04x expected=0x%04x\n",
			        payload_len, actual_cksum6, expected_cksum6);
			assert(actual_cksum6 == expected_cksum6);
		}
		*(uint16_t *)(data + 6) = htons(actual_cksum6);

		/* Translate 6 to 4 back */
		p.ip4 = NULL;
		p.ip6 = &ip6;
		p.header_len = 0;
		ret = xlate_payload_6to4(&p, &ip4, 0);
		assert(ret == ERROR_NONE);

		uint16_t actual_cksum4 = ntohs(*(uint16_t *)(data + 6));
		assert(actual_cksum4 != 0);
		if (actual_cksum4 != orig_cksum4) {
			fprintf(stderr, "FAIL 6to4 size %d: actual=0x%04x expected=0x%04x\n",
			        payload_len, actual_cksum4, orig_cksum4);
			assert(actual_cksum4 == orig_cksum4);
		}

		free(pkt_buf);
	}
	printf("PASS: Complete UDP checksum translation across all payload sizes\n");
}

static void test_zero_checksum_boundary(void)
{
	printf("Testing RFC 768 / RFC 1624 zero checksum boundary condition...\n");
	/* Deliberately craft addresses and payload such that sum folds to 0xffff,
	 * resulting in ~sum == 0x0000. In UDP, this must be sent as 0xffff. */
	struct in_addr src4, dst4;
	struct in6_addr src6, dst6;
	inet_pton(AF_INET, "10.0.0.1", &src4);
	inet_pton(AF_INET, "10.0.0.2", &dst4);
	inet_pton(AF_INET6, "2001:db8::1", &src6);
	inet_pton(AF_INET6, "64:ff9b::a00:2", &dst6);

	uint8_t data[8];
	memset(data, 0, sizeof(data));
	*(uint16_t *)(data + 0) = htons(1000);
	*(uint16_t *)(data + 2) = htons(2000);
	*(uint16_t *)(data + 4) = htons(8);

	/* Find a checksum value that updates to 0x0000 */
	struct ip4 ip4;
	memset(&ip4, 0, sizeof(ip4));
	ip4.ver_ihl = 0x45;
	ip4.length = htons(28);
	ip4.proto = IPPROTO_UDP;
	ip4.src = src4;
	ip4.dest = dst4;

	struct ip6 ip6;
	memset(&ip6, 0, sizeof(ip6));
	ip6.src = src6;
	ip6.dest = dst6;
	ip6.payload_length = htons(8);
	ip6.next_header = IPPROTO_UDP;

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.ip4 = &ip4;
	p.header_len = 20;
	p.data = data;
	p.data_len = 8;
	p.data_proto = IPPROTO_UDP;
	p.has_vhdr = 0;

	/* Loop through all 65536 possible initial checksums and verify NONE ever outputs 0x0000 */
	for (uint32_t val = 1; val <= 0xffff; val++) {
		*(uint16_t *)(data + 6) = htons((uint16_t)val);
		int ret = xlate_payload_4to6(&p, &ip6, 0);
		assert(ret == ERROR_NONE);
		uint16_t out = ntohs(*(uint16_t *)(data + 6));
		assert(out != 0x0000); /* Must NEVER be 0 */
	}

	printf("PASS: Zero checksum boundary encoding (0x0000 -> 0xffff verified across all 65,535 non-zero inputs)\n");
}

static void test_partial_checksum_offload(void)
{
	printf("Testing partial checksum (NEEDS_CSUM) seed generation and kernel completion...\n");
	struct in_addr src4, dst4;
	struct in6_addr src6, dst6;
	inet_pton(AF_INET, "192.168.88.2", &src4);
	inet_pton(AF_INET, "11.0.0.2", &dst4);
	inet_pton(AF_INET6, "2001:db8:1::192.168.88.2", &src6);
	inet_pton(AF_INET6, "64:ff9b::b00:2", &dst6);

	uint8_t data[32];
	memset(data, 0xab, sizeof(data));
	*(uint16_t *)(data + 0) = htons(5000);
	*(uint16_t *)(data + 2) = htons(6000);
	*(uint16_t *)(data + 4) = htons(sizeof(data));
	*(uint16_t *)(data + 6) = 0; /* Seed could be 0 or anything */
	uint8_t original_data[sizeof(data)];
	memcpy(original_data, data, sizeof(data));

	struct ip4 ip4;
	memset(&ip4, 0, sizeof(ip4));
	ip4.ver_ihl = 0x45;
	ip4.length = htons(20 + sizeof(data));
	ip4.proto = IPPROTO_UDP;
	ip4.src = src4;
	ip4.dest = dst4;

	struct ip6 ip6;
	memset(&ip6, 0, sizeof(ip6));
	ip6.src = src6;
	ip6.dest = dst6;
	ip6.payload_length = htons(sizeof(data));
	ip6.next_header = IPPROTO_UDP;

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.ip4 = &ip4;
	p.header_len = 20;
	p.data = data;
	p.data_len = sizeof(data);
	p.data_proto = IPPROTO_UDP;
	p.has_vhdr = 1;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	p.vhdr.csum_start = 20;
	p.vhdr.csum_offset = 6;

	gcfg.vnet_hdr_sz = 10;
	int ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_NONE);

	/* Check that seed is gso_calc_udp_pseudo6 */
	uint16_t expected_seed = gso_calc_udp_pseudo6(&src6, &dst6, sizeof(data));
	uint16_t actual_seed = ntohs(*(uint16_t *)(data + 6));
	assert(actual_seed == expected_seed);

	/* Simulate kernel checksum completion using this seed */
	uint32_t csum = actual_seed;
	*(uint16_t *)(data + 6) = 0;
	const uint8_t *ptr = data;
	int c = sizeof(data);
	while (c > 1) {
		csum += ((uint32_t)ptr[0] << 8) | ptr[1];
		ptr += 2;
		c -= 2;
	}
	while (csum >> 16)
		csum = (csum & 0xffff) + (csum >> 16);
	uint16_t completed = (uint16_t)~csum;
	if (completed == 0) completed = 0xffff;

	uint16_t full_expected = calc_full_udp_cksum6(&src6, &dst6, data, sizeof(data));
	assert(completed == full_expected);

	/* Now test software fallback when gcfg.vnet_hdr_sz == 0 */
	memcpy(data, original_data, sizeof(data));
	/* A partial checksum field can carry a nonzero source pseudoheader seed. */
	*(uint16_t *)(data + 6) = htons(gso_calc_udp_pseudo4(&src4, &dst4, sizeof(data)));
	gcfg.vnet_hdr_sz = 0;
	p.vhdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_NONE);
	assert(!(p.vhdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)); /* NEEDS_CSUM was cleared */
	assert(ntohs(*(uint16_t *)(data + 6)) == full_expected); /* Checksum completed in SW */

	gcfg.vnet_hdr_sz = 10;
	printf("PASS: Partial checksum (NEEDS_CSUM) seed & completion\n");
}

static void test_absent_checksum_policy(void)
{
	printf("Testing IPv4 absent checksum policies (DROP, FWD, CALC)...\n");
	struct in_addr src4, dst4;
	struct in6_addr src6, dst6;
	inet_pton(AF_INET, "192.168.88.2", &src4);
	inet_pton(AF_INET, "11.0.0.2", &dst4);
	inet_pton(AF_INET6, "2001:db8:1::192.168.88.2", &src6);
	inet_pton(AF_INET6, "64:ff9b::b00:2", &dst6);

	uint8_t data[16];
	memset(data, 0x12, sizeof(data));
	*(uint16_t *)(data + 0) = htons(5000);
	*(uint16_t *)(data + 2) = htons(6000);
	*(uint16_t *)(data + 4) = htons(sizeof(data));
	*(uint16_t *)(data + 6) = 0; /* Absent checksum */

	struct ip4 ip4;
	memset(&ip4, 0, sizeof(ip4));
	ip4.ver_ihl = 0x45;
	ip4.length = htons(20 + sizeof(data));
	ip4.proto = IPPROTO_UDP;
	ip4.src = src4;
	ip4.dest = dst4;

	struct ip6 ip6;
	memset(&ip6, 0, sizeof(ip6));
	ip6.src = src6;
	ip6.dest = dst6;
	ip6.payload_length = htons(sizeof(data));
	ip6.next_header = IPPROTO_UDP;

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.ip4 = &ip4;
	p.header_len = 20;
	p.data = data;
	p.data_len = sizeof(data);
	p.data_proto = IPPROTO_UDP;
	p.has_vhdr = 0;

	/* 1. UDP_CKSUM_DROP */
	gcfg.udp_cksum_mode = UDP_CKSUM_DROP;
	*(uint16_t *)(data + 6) = 0;
	assert(xlate_payload_4to6(&p, &ip6, 0) == ERROR_DROP);

	/* 2. UDP_CKSUM_FWD */
	gcfg.udp_cksum_mode = UDP_CKSUM_FWD;
	*(uint16_t *)(data + 6) = 0;
	assert(xlate_payload_4to6(&p, &ip6, 0) == ERROR_NONE);
	assert(*(uint16_t *)(data + 6) == 0);

	/* 3. UDP_CKSUM_CALC */
	gcfg.udp_cksum_mode = UDP_CKSUM_CALC;
	*(uint16_t *)(data + 6) = 0;
	assert(xlate_payload_4to6(&p, &ip6, 0) == ERROR_NONE);
	uint16_t calc = ntohs(*(uint16_t *)(data + 6));
	assert(calc != 0);
	*(uint16_t *)(data + 6) = 0;
	assert(calc == calc_full_udp_cksum6(&src6, &dst6, data, sizeof(data)));

	printf("PASS: Absent checksum policy (DROP, FWD, CALC)\n");
}

static void test_icmp_embedded_truncated(void)
{
	printf("Testing ICMP embedded packet UDP handling (truncated headers)...\n");
	struct ip4 ip4;
	memset(&ip4, 0, sizeof(ip4));
	ip4.ver_ihl = 0x45;
	ip4.length = htons(24);
	ip4.proto = IPPROTO_UDP;

	struct ip6 ip6;
	memset(&ip6, 0, sizeof(ip6));

	uint8_t data[8];
	memset(data, 0, sizeof(data));

	struct pkt p;
	memset(&p, 0, sizeof(p));
	p.ip4 = &ip4;
	p.header_len = 20;
	p.data = data;
	p.data_len = 4; /* Truncated UDP header: only 4 bytes */
	p.data_proto = IPPROTO_UDP;
	p.has_vhdr = 0;

	/* Truncated embedded payload with em=1 must NOT crash or drop */
	int ret = xlate_payload_4to6(&p, &ip6, 1);
	assert(ret == ERROR_NONE);

	/* Truncated non-embedded payload (em=0) must drop */
	ret = xlate_payload_4to6(&p, &ip6, 0);
	assert(ret == ERROR_DROP);

	printf("PASS: ICMP embedded truncated UDP header handling\n");
}

int main(void)
{
	printf("=== Running unit_udp_checksum test suite ===\n");
	test_metadata_bounds();
	test_complete_checksum_translation();
	test_zero_checksum_boundary();
	test_partial_checksum_offload();
	test_absent_checksum_policy();
	test_icmp_embedded_truncated();
	printf("=== All unit_udp_checksum tests passed successfully! ===\n");
	return 0;
}
