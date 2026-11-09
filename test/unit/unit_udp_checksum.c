#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
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
_Atomic time_t now;

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

static void test_icmp6_param_problem_negative_ptr(void)
{
	printf("Testing ICMPv6 Parameter Problem negative pointer bounds ([SEC-01])...\n");
	INIT_LIST_HEAD(&gcfg.map4_list);
	INIT_LIST_HEAD(&gcfg.map6_list);
	pthread_mutex_init(&gcfg.map_mutex, NULL);
	pthread_mutex_init(&gcfg.cache_mutex, NULL);
	uint8_t buf[HEADROOM + 256];
	memset(buf, 0, sizeof(buf));
	uint8_t *pkt_start = buf + HEADROOM;

	/* Outer IPv6 header */
	struct ip6 *ip6 = (struct ip6 *)pkt_start;
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(sizeof(struct icmp) + sizeof(struct ip6) + 8);
	ip6->next_header = 58; /* ICMPv6 */
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	/* Outer ICMPv6 Parameter Problem (Type 4, Code 0) with pointer = 0x80000000 */
	struct icmp *icmp6 = (struct icmp *)(ip6 + 1);
	icmp6->type = 4;
	icmp6->code = 0;
	icmp6->word = htonl(0x80000000U); /* Negative when cast to int32_t */

	/* Inner offending IPv6 header + 8B UDP */
	struct ip6 *ip6_em = (struct ip6 *)(icmp6 + 1);
	ip6_em->ver_tc_fl = htonl(0x60000000);
	ip6_em->payload_length = htons(8);
	ip6_em->next_header = IPPROTO_UDP;
	ip6_em->hop_limit = 64;
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6_em->src);
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6_em->dest);

	icmp6->cksum = 0;
	icmp6->cksum = ones_add(ip_checksum(icmp6, ntohs(ip6->payload_length)),
	                        ip6_checksum(ip6, ntohs(ip6->payload_length), 58));

	struct pkt p = {
		.tun_fd = -1,
		.data = pkt_start,
		.data_len = sizeof(struct ip6) + ntohs(ip6->payload_length),
	};

	/* Must drop cleanly without crashing on out-of-bounds new_ptr_tbl[old_ptr] */
	handle_ip6(&p);
	printf("PASS: ICMPv6 Parameter Problem negative pointer safely dropped\n");
}

static void setup_quote_maps(void)
{
    memset(&gcfg, 0, sizeof(gcfg));
    INIT_LIST_HEAD(&gcfg.map4_list); INIT_LIST_HEAD(&gcfg.map6_list);
    gcfg.maps_immutable = 1; gcfg.udp_cksum_mode = UDP_CKSUM_FWD;
    inet_pton(AF_INET, "192.0.0.254", &gcfg.local_addr4);
    inet_pton(AF_INET6, "fd9b:64:1:ff::fe", &gcfg.local_addr6);
    static struct map_static maps[2]; memset(maps, 0, sizeof(maps));
    for (int i = 0; i < 2; ++i) {
        maps[i].map4.type = maps[i].map6.type = i ? MAP_TYPE_STATIC : MAP_TYPE_RFC6052;
        maps[i].map4.prefix_len = i ? 32 : 0;
        maps[i].map6.prefix_len = i ? 128 : 96;
        inet_pton(AF_INET, i ? "192.0.0.1" : "0.0.0.0", &maps[i].map4.addr);
        inet_pton(AF_INET6, i ? "fd9b:64:1:ff::10" : "64:ff9b::", &maps[i].map6.addr);
        calc_ip4_mask(&maps[i].map4.mask, NULL, maps[i].map4.prefix_len);
        calc_ip6_mask(&maps[i].map6.mask, NULL, maps[i].map6.prefix_len);
        INIT_LIST_HEAD(&maps[i].map4.list); INIT_LIST_HEAD(&maps[i].map6.list);
        assert(insert_map4(&maps[i].map4, NULL) == 0); assert(insert_map6(&maps[i].map6, NULL) == 0);
    }
}

/* RFC-002/003: no ICMP errors for non-first fragments or multicast, and
 * originated errors are rate limited with a separate PMTU budget. */
static int drain_count(int fd)
{
	uint8_t b[2048];
	int n = 0;
	while (recv(fd, b, sizeof(b), MSG_DONTWAIT) > 0)
		n++;
	return n;
}

static void test_icmp_error_suppression_and_rate_limit(void)
{
	setup_quote_maps();
	gcfg.mtu = 1500;
	icmp_rate_limit_reset();
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	int sz = 1 << 20;
	setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));

	alignas(8) uint8_t b4[HEADROOM + 64] = {0};
	struct ip4 *ip4 = (struct ip4 *)(b4 + HEADROOM);
	ip4->ver_ihl = 0x45; ip4->ttl = 1; ip4->proto = IPPROTO_UDP;
	ip4->length = htons(28);
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);
	inet_pton(AF_INET, "8.8.8.8", &ip4->dest);
	struct pkt p4 = {.tun_fd = sv[0], .ip4 = ip4, .data = (uint8_t *)ip4 + 20,
	                 .data_len = 8, .header_len = 20, .data_proto = IPPROTO_UDP};

	ip4->flags_offset = htons(100); /* non-first fragment */
	host_send_icmp4_error(11, 0, 0, &p4);
	assert(drain_count(sv[1]) == 0);
	ip4->flags_offset = 0;
	inet_pton(AF_INET, "224.0.0.1", &ip4->src); /* multicast source */
	host_send_icmp4_error(11, 0, 0, &p4);
	assert(drain_count(sv[1]) == 0);
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);

	gcfg.icmp_rate_limit = 10;	/* burst 10, +10/s */
	int sent = 0;
	for (int i = 0; i < 1000; i++) {
		host_send_icmp4_error(11, 0, 0, &p4);
		sent += drain_count(sv[1]);	/* unix dgram queues are short */
	}
	assert(sent >= 200 && sent <= 260);	/* initial burst, ~+10/s */
	/* Exhausted TTL budget must not starve Fragmentation Needed. */
	gcfg.icmp_rate_limit = 0;
	host_send_icmp4_error(3, 4, 1480, &p4);
	assert(drain_count(sv[1]) == 1);

	icmp_rate_limit_reset();
	gcfg.icmp_rate_limit = UINT32_MAX;
	sent = 0;
	for (int i = 0; i < 500; i++) {
		host_send_icmp4_error(11, 0, 0, &p4);
		sent += drain_count(sv[1]);
	}
	assert(sent == 500);
	gcfg.icmp_rate_limit = 0;
	icmp_rate_limit_reset();

	alignas(8) uint8_t b6[HEADROOM + 64] = {0};
	struct ip6 *ip6 = (struct ip6 *)(b6 + HEADROOM);
	ip6->ver_tc_fl = htonl(0x60000000); ip6->next_header = IPPROTO_UDP;
	ip6->payload_length = htons(8); ip6->hop_limit = 1;
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->src);
	inet_pton(AF_INET6, "ff02::1", &ip6->dest);
	struct pkt p6 = {.tun_fd = sv[0], .ip6 = ip6, .data = (uint8_t *)ip6 + 40,
	                 .data_len = 8, .header_len = 0, .data_proto = IPPROTO_UDP};
	host_send_icmp6_error(3, 0, 0, &p6); /* multicast dest: suppressed */
	assert(drain_count(sv[1]) == 0);
	host_send_icmp6_error(2, 0, 1280, &p6); /* PTB exception */
	assert(drain_count(sv[1]) == 1);
	memset(&ip6->src, 0, sizeof(ip6->src)); /* unspecified src */
	host_send_icmp6_error(2, 0, 1280, &p6);
	assert(drain_count(sv[1]) == 0);
	close(sv[0]); close(sv[1]);
	puts("PASS: ICMP error suppression and rate limiting");
}

/* xlate_6to4_icmp_error clamps the quoted datagram's IPv4 total length: a lying
 * inner payload_length must neither overflow 16 bits nor underflow when the
 * inner header carries extension headers. Observable as the inner Total Length. */
static unsigned quoted_total_len(unsigned inner_plen, int with_hbh)
{
	setup_quote_maps();
	gcfg.mtu = 1500;
	gcfg.icmp_rate_limit = UINT32_MAX;
	icmp_rate_limit_reset();
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(8) uint8_t buf[HEADROOM + 256] = {0};
	struct ip6 *o = (struct ip6 *)(buf + HEADROOM);
	unsigned inner_len = sizeof(struct ip6) + (with_hbh ? 8 : 0) + 8;
	o->ver_tc_fl = htonl(0x60000000);
	o->payload_length = htons(sizeof(struct icmp) + inner_len);
	o->next_header = 58; o->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::808:808", &o->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &o->dest);
	struct icmp *ic = (struct icmp *)(o + 1);
	ic->type = 3; ic->code = 0;
	struct ip6 *in = (struct ip6 *)(ic + 1);
	in->ver_tc_fl = htonl(0x60000000);
	in->payload_length = htons((uint16_t)inner_plen);
	in->next_header = with_hbh ? 0 : IPPROTO_UDP; in->hop_limit = 5;
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &in->src);
	inet_pton(AF_INET6, "64:ff9b::808:808", &in->dest);
	uint8_t *l4 = (uint8_t *)(in + 1);
	if (with_hbh) { l4[0] = IPPROTO_UDP; l4[1] = 0; l4[2] = 1; l4[3] = 4; l4 += 8; }
	l4[0] = 0x10; l4[1] = 0x00; l4[2] = 0x20; l4[3] = 0x00; l4[4] = 0; l4[5] = 8; /* UDP, truncated */
	ic->cksum = 0;
	ic->cksum = ones_add(ip_checksum(ic, ntohs(o->payload_length)),
			ip6_checksum(o, ntohs(o->payload_length), 58));
	struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)o, .data_len = sizeof(struct ip6) + sizeof(struct icmp) + inner_len};
	handle_ip6(&p);
	uint8_t out[1024];
	ssize_t n = recv(sv[1], out, sizeof(out), MSG_DONTWAIT);
	close(sv[0]); close(sv[1]);
	if (n <= 0) return 0;
	size_t base = gcfg.vnet_hdr_sz ? (size_t)gcfg.vnet_hdr_sz : 0;
#ifndef __linux__
	base += sizeof(struct tun_pi);
#endif
	struct ip4 *oip = (struct ip4 *)(out + base);
	assert(oip->proto == 1);
	struct ip4 *qip = (struct ip4 *)((uint8_t *)(oip + 1) + sizeof(struct icmp));
	return ntohs(qip->length);
}

static void test_icmp6to4_quoted_length_clamp(void)
{
	/* Honest large datagram quoted truncated: 20 + payload_length. */
	assert(quoted_total_len(1000, 0) == 1020);
	/* A lying maximum payload_length is clamped to the 16-bit IPv4 limit. */
	assert(quoted_total_len(65535, 0) == 65535);
	/* payload_length smaller than the inner extension headers falls back to
	 * the quoted length instead of underflowing. */
	unsigned q = quoted_total_len(4, 1);
	assert(q == 0 || (q >= 20 && q <= 20 + 16));	/* dropped, or a bounded length */
	printf("PASS: ICMPv6->ICMPv4 quoted total length clamp (1020, 65535, no underflow)\n");
}

/* RFC-005c: "Unrecognized Next Header" points at the Next Header field that
 * named the unknown protocol, not at a constant 6 (RFC 4443 section 3.4). */
static void test_icmp6_unknown_next_header_pointer(void)
{
	setup_quote_maps();
	gcfg.mtu = 1500;
	gcfg.icmp_rate_limit = UINT32_MAX;
	icmp_rate_limit_reset();
	const unsigned pi = 
#ifdef __linux__
		0;
#else
		sizeof(struct tun_pi);
#endif
	for (int ext = 0; ext < 2; ++ext) {
		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
		alignas(8) uint8_t buf[HEADROOM + 96] = {0};
		struct ip6 *ip6 = (struct ip6 *)(buf + HEADROOM);
		unsigned payload = ext ? 8 + 8 : 8;
		ip6->ver_tc_fl = htonl(0x60000000);
		ip6->payload_length = htons(payload);
		ip6->next_header = ext ? 0 /* Hop-by-Hop */ : 99;
		ip6->hop_limit = 64;
		inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->src);
		ip6->dest = gcfg.local_addr6;
		uint8_t *l4 = (uint8_t *)(ip6 + 1);
		if (ext) { l4[0] = 99; l4[1] = 0; l4[2] = 1; l4[3] = 4; } /* HBH: next=99, 6 bytes PadN */
		struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip6,
			.data_len = sizeof(struct ip6) + payload};
		handle_ip6(&p);
		uint8_t out[512];
		ssize_t n = recv(sv[1], out, sizeof(out), MSG_DONTWAIT);
		assert(n > (ssize_t)(pi + sizeof(struct ip6) + 8));
		/* Skip the optional vnet header prefix (10 bytes when negotiated). */
		size_t base = gcfg.vnet_hdr_sz ? (size_t)gcfg.vnet_hdr_sz : 0;
		struct ip6 *rep = (struct ip6 *)(out + base + pi);
		assert(rep->next_header == 58);
		struct icmp *ic = (struct icmp *)(rep + 1);
		assert(ic->type == 4 && ic->code == 1);
		assert(ntohl(ic->word) == (ext ? 40u : 6u));
		close(sv[0]); close(sv[1]);
	}
	icmp_rate_limit_reset();
	puts("PASS: Unrecognized Next Header pointer follows the extension chain");
}

/* RFC-001: an ICMPv4 Time Exceeded carrying an RFC 4884 extension keeps it
 * (padded to 128 octets, Length in 8-octet units) with a valid checksum. */
static void test_rfc4884_ext_4to6(void)
{
	setup_quote_maps(); gcfg.mtu = 1500;
	icmp_rate_limit_reset();
	int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(8) uint8_t buf[HEADROOM + 256] = {0};
	uint8_t resp[512];
	struct ip4 *ip = (struct ip4 *)(buf + HEADROOM);
	uint8_t *icmp = (uint8_t *)(ip + 1);
	uint8_t *inner = icmp + 8;
	enum { ORIG = 128, EXT = 8 };
	ip->ver_ihl = 0x45; ip->ttl = 64; ip->proto = IPPROTO_ICMP;
	ip->length = htons(20 + 8 + ORIG + EXT);
	inet_pton(AF_INET, "8.8.4.4", &ip->src);
	inet_pton(AF_INET, "192.0.0.1", &ip->dest);
	ip->cksum = ip_checksum(ip, 20);
	icmp[0] = 11; icmp[1] = 0; icmp[5] = ORIG / 4;
	struct ip4 *in = (struct ip4 *)inner;
	in->ver_ihl = 0x45; in->ttl = 1; in->proto = IPPROTO_UDP;
	in->length = htons(28);
	inet_pton(AF_INET, "192.0.0.1", &in->src);
	inet_pton(AF_INET, "8.8.8.8", &in->dest);
	in->cksum = ip_checksum(in, 20);
	uint8_t *ext = inner + ORIG;
	const uint8_t extdata[EXT] = {0x20, 0, 0, 0, 0, 8, 1, 1};
	memcpy(ext, extdata, EXT);
	uint16_t c = ip_checksum(icmp, 8 + ORIG + EXT);
	memcpy(icmp + 2, &c, 2);
	struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip, .data_len = 20 + 8 + ORIG + EXT};
	handle_ip4(&p);
	ssize_t n = recv(sv[1], resp, sizeof(resp), MSG_DONTWAIT);
	unsigned off = 0;
#ifndef __linux__
	off = sizeof(struct tun_pi);
#endif
	assert(n == (ssize_t)(off + 40 + 8 + 128 + EXT));
	struct ip6 *o6 = (struct ip6 *)(resp + off);
	uint8_t *oi = (uint8_t *)(o6 + 1);
	assert(o6->next_header == IPPROTO_ICMPV6 && oi[0] == 3);
	assert(oi[4] == 128 / 8);		/* RFC 4884 Length attribute */
	assert(memcmp(oi + 8 + 128, extdata, EXT) == 0);
	assert(ones_add(ip_checksum(oi, ntohs(o6->payload_length)),
	                ip6_checksum(o6, ntohs(o6->payload_length), 58)) == 0);
	close(sv[0]); close(sv[1]);
	puts("PASS: RFC 4884 extension preserved in ICMPv4->ICMPv6 error");
}

static void test_rfc4884_ext_6to4(void)
{
	setup_quote_maps(); gcfg.mtu = 1500;
	icmp_rate_limit_reset();
	int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(8) uint8_t buf[HEADROOM + 400] = {0};
	uint8_t resp[512];
	enum { ORIG = 128, EXT = 8 };
	struct ip6 *ip = (struct ip6 *)(buf + HEADROOM);
	struct icmp *ic = (struct icmp *)(ip + 1);
	struct ip6 *in = (struct ip6 *)(ic + 1);
	uint8_t *ext = (uint8_t *)in + ORIG;
	const uint8_t extdata[EXT] = {0x20, 0, 0, 0, 0, 8, 1, 1};
	ip->ver_tc_fl = htonl(0x60000000); ip->hop_limit = 64;
	ip->next_header = IPPROTO_ICMPV6;
	ip->payload_length = htons(8 + ORIG + EXT);
	inet_pton(AF_INET6, "64:ff9b::808:404", &ip->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip->dest);
	ic->type = 3; ic->code = 0; ic->word = htonl((ORIG / 8) << 24);
	in->ver_tc_fl = htonl(0x60000000); in->hop_limit = 1;
	in->next_header = IPPROTO_UDP; in->payload_length = htons(8);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &in->src);
	inet_pton(AF_INET6, "64:ff9b::808:808", &in->dest);
	memcpy(ext, extdata, EXT);
	ic->cksum = 0;
	ic->cksum = ones_add(ip_checksum(ic, 8 + ORIG + EXT),
	                     ip6_checksum(ip, 8 + ORIG + EXT, 58));
	struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip,
	                .data_len = 40 + 8 + ORIG + EXT};
	handle_ip6(&p);
	ssize_t n = recv(sv[1], resp, sizeof(resp), MSG_DONTWAIT);
	unsigned off = 0;
#ifndef __linux__
	off = sizeof(struct tun_pi);
#endif
	assert(n == (ssize_t)(off + 20 + 8 + 128 + EXT));
	struct ip4 *o4 = (struct ip4 *)(resp + off);
	uint8_t *oi = (uint8_t *)(o4 + 1);
	assert(o4->proto == IPPROTO_ICMP && oi[0] == 11);
	assert(oi[5] == 128 / 4);		/* RFC 4884 Length attribute */
	assert(memcmp(oi + 8 + 128, extdata, EXT) == 0);
	assert(ip_checksum(oi, 8 + 128 + EXT) == 0);
	close(sv[0]); close(sv[1]);
	puts("PASS: RFC 4884 extension preserved in ICMPv6->ICMPv4 error");
}

/* RFC 6946: an IPv6 "atomic fragment" (fragment header, offset 0, M=0) is
 * translated on its own (RFC 7915 5.1): DF cleared, ID from the header. */
static void test_ipv6_atomic_fragment(void)
{
	setup_quote_maps(); gcfg.mtu = 1500;
	int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(4) uint8_t buffer[HEADROOM + 128] = {0}, response[128];
	struct ip6 *ip = (struct ip6 *)(buffer + HEADROOM);
	ip->ver_tc_fl = htonl(0x60000000); ip->hop_limit = 64;
	ip->next_header = 44; ip->payload_length = htons(16);
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip->dest);
	uint8_t *fh = (uint8_t *)(ip + 1);
	fh[0] = IPPROTO_UDP;			/* offset 0, MF 0 */
	uint32_t ident = htonl(0x12345678);
	memcpy(fh + 4, &ident, 4);
	uint8_t *udp = fh + 8;
	uint16_t words[4] = {htons(1234), htons(4321), htons(8), 0};
	memcpy(udp, words, sizeof(words));
	uint16_t checksum = htons(calc_full_udp_cksum6(&ip->src, &ip->dest, udp, 8));
	memcpy(udp + 6, &checksum, sizeof(checksum));
	struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip, .data_len = 40 + 16};
	handle_ip6(&p);
	ssize_t length = recv(sv[1], response, sizeof(response), MSG_DONTWAIT);
	unsigned offset = 0;
#ifndef __linux__
	offset = sizeof(struct tun_pi);
#endif
	assert(length == (ssize_t)(offset + 28));
	struct ip4 *out = (struct ip4 *)(response + offset);
	assert(out->proto == IPPROTO_UDP && out->ttl == 63);
	assert((ntohs(out->flags_offset) & (IP4_F_DF | IP4_F_MF | IP4_F_MASK)) == 0);
	assert(ntohs(out->ident) == 0x5678);
	assert(ip_checksum(out, 20) == 0);
	close(sv[0]); close(sv[1]);
	puts("PASS: IPv6 atomic fragment translated as an unfragmented packet");
}

/* STAB-001: truncated frames must be dropped without reading past data_len.
 * Exact-size heap buffers make ASan flag any OOB header/log read. */
static void test_truncated_ip_headers(void)
{
	setup_quote_maps();
	gcfg.log_opts = LOG_OPT_DROP;
	for (unsigned v = 4; v <= 6; v += 2) {
		unsigned max = v == 4 ? 20 : 40;
		for (unsigned len = 0; len < max; len++) {
			uint8_t *buf = malloc(len ? len : 1);
			assert(buf);
			memset(buf, 0, len ? len : 1);
			if (len)
				buf[0] = (uint8_t)(v << 4 | (v == 4 ? 5 : 0));
			if (len > 8 && v == 6)
				buf[8] = 0xff;
			struct pkt p = {.tun_fd = -1, .data = buf, .data_len = len};
			if (v == 4)
				handle_ip4(&p);
			else
				handle_ip6(&p);
			free(buf);
		}
	}
	gcfg.log_opts = 0;
	puts("PASS: truncated IPv4/IPv6 frames dropped without OOB reads");
}

/* Exercise the complete data output path, including BSD's TUN family header. */
static void test_ipv6_udp_output_family(void)
{
    setup_quote_maps(); gcfg.mtu = 1500;
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    alignas(4) uint8_t buffer[HEADROOM + 128] = {0}, response[128];
    struct ip6 *ip = (struct ip6 *)(buffer + HEADROOM);
    ip->ver_tc_fl = htonl(0x60000000); ip->hop_limit = 64;
    ip->next_header = IPPROTO_UDP; ip->payload_length = htons(8);
    inet_pton(AF_INET6, "64:ff9b::808:808", &ip->src);
    inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip->dest);
    uint8_t *udp = (uint8_t *)(ip + 1);
    uint16_t words[4] = {htons(1234), htons(4321), htons(8), 0};
    memcpy(udp, words, sizeof(words));
    uint16_t checksum = htons(calc_full_udp_cksum6(&ip->src, &ip->dest, udp, 8));
    memcpy(udp + 6, &checksum, sizeof(checksum));
    struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip, .data_len = 48};
    handle_ip6(&p);
    ssize_t length = recv(sv[1], response, sizeof(response), MSG_DONTWAIT);
    unsigned offset = 0;
#ifndef __linux__
    offset = sizeof(struct tun_pi);
    uint32_t family; memcpy(&family, response, sizeof(family));
    assert(ntohl(family) == AF_INET);
#endif
    assert(length == (ssize_t)(offset + 28));
    struct ip4 *out = (struct ip4 *)(response + offset);
    assert(out->proto == IPPROTO_UDP && out->ttl == 63);
    assert(ip_checksum(out, 20) == 0);
    assert(ones_add(ip_checksum(out + 1, 8), ip4_checksum(out, 8, IPPROTO_UDP)) == 0);
    close(sv[0]); close(sv[1]);
    puts("PASS: IPv6 UDP data output has a valid IPv4 packet and TUN family");
}

static void test_icmp_echo_checksum_translation(void)
{
    struct ip4 ip4 = {0}; struct ip6 ip6 = {0};
    inet_pton(AF_INET, "192.0.0.1", &ip4.src); inet_pton(AF_INET, "8.8.8.8", &ip4.dest);
    inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6.src); inet_pton(AF_INET6, "64:ff9b::808:808", &ip6.dest);
    ip4.length = htons(32);
    alignas(4) uint8_t bytes[12] = {8, 0, 0, 0, 0x12, 0x34, 0, 1, 1, 2, 3, 4};
    struct icmp *echo = (struct icmp *)bytes;
    echo->cksum = ip_checksum(bytes, sizeof(bytes));
    struct pkt p = {.ip4 = &ip4, .ip6 = &ip6, .icmp = echo, .data = bytes,
                    .data_len = sizeof(bytes), .header_len = 20, .data_proto = IPPROTO_ICMP};
    assert(xlate_payload_4to6(&p, &ip6, 0) == 0);
    assert(echo->type == 128);
    assert(ones_add(ip_checksum(bytes, sizeof(bytes)), ip6_checksum(&ip6, sizeof(bytes), IPPROTO_ICMPV6)) == 0);
    p.data_proto = IPPROTO_ICMPV6; p.header_len = 0;
    ip6.payload_length = htons(sizeof(bytes));
    assert(xlate_payload_6to4(&p, &ip4, 0) == 0);
    assert(echo->type == 8 && ip_checksum(bytes, sizeof(bytes)) == 0);
    puts("PASS: ICMP echo checksum is valid in both translation directions");
}

static void test_tcp_zero_checksum_preserved(void)
{
    struct ip4 ip4 = {0}; struct ip6 ip6 = {0};
    inet_pton(AF_INET, "192.0.0.1", &ip4.src); inet_pton(AF_INET, "8.8.8.8", &ip4.dest);
    inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6.src); inet_pton(AF_INET6, "64:ff9b::808:808", &ip6.dest);
    uint8_t storage[32] = {0};
    struct pkt p = {.ip4 = &ip4, .ip6 = &ip6, .data = storage + 1, .data_len = 20, .data_proto = IPPROTO_TCP};
    for (int direction = 0; direction < 2; ++direction) {
        int found = 0;
        for (unsigned value = 0; value <= UINT16_MAX; ++value) {
            uint16_t checksum = htons(value); memcpy(p.data + 16, &checksum, 2);
            assert((direction ? xlate_payload_6to4(&p, &ip4, 0) : xlate_payload_4to6(&p, &ip6, 0)) == 0);
            memcpy(&checksum, p.data + 16, 2);
            if (!checksum) { found = 1; break; }
        }
        assert(found);
    }
    puts("PASS: TCP zero checksum preserved in both directions at odd transport offsets");
}

static void test_icmp6_error_truncated_fragment_quote(void)
{
	printf("Testing ICMPv6 error with truncated inner fragment ([RFC-02])...\n");
	/* Construct an ICMPv6 Time Exceeded (Type 3, Code 0) containing an inner IPv6
	 * header + Fragment Header (MF=1, offset=0) + 12 bytes of truncated payload
	 * (12 is not divisible by 8). Verify parse_ip6(&p_em, 1) accepts it. */
	setup_quote_maps();
	int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	alignas(4) uint8_t buf[HEADROOM + 256];
	memset(buf, 0, sizeof(buf));
	uint8_t *pkt_start = buf + HEADROOM;

	struct ip6 *ip6 = (struct ip6 *)pkt_start;
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(sizeof(struct icmp) + sizeof(struct ip6) + sizeof(struct ip6_frag) + 12);
	ip6->next_header = 58;
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	struct icmp *icmp6 = (struct icmp *)(ip6 + 1);
	icmp6->type = 3; /* Time Exceeded */
	icmp6->code = 0;
	icmp6->word = 0;

	struct ip6 *ip6_em = (struct ip6 *)(icmp6 + 1);
	ip6_em->ver_tc_fl = htonl(0x60000000);
	ip6_em->payload_length = htons(1408); /* Original un-truncated length */
	ip6_em->next_header = 44; /* Fragment Header */
	ip6_em->hop_limit = 1;
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6_em->src);
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6_em->dest);

	struct ip6_frag *frag_em = (struct ip6_frag *)(ip6_em + 1);
	frag_em->next_header = IPPROTO_UDP;
	frag_em->offset_flags = htons(IP6_F_MF); /* MF=1, offset=0 */
	frag_em->ident = htonl(0x12345678);

	icmp6->cksum = 0;
	icmp6->cksum = ones_add(ip_checksum(icmp6, ntohs(ip6->payload_length)),
	                        ip6_checksum(ip6, ntohs(ip6->payload_length), 58));

	struct pkt p = {
		.tun_fd = sv[0],
		.data = pkt_start,
		.data_len = sizeof(struct ip6) + ntohs(ip6->payload_length),
	};
	handle_ip6(&p);
	alignas(4) uint8_t captured[256];
	ssize_t length = recv(sv[1], captured, sizeof(captured), MSG_DONTWAIT);
#ifdef __linux__
	unsigned offset = 0;
#else
	unsigned offset = sizeof(struct tun_pi);
#endif
	assert(length == (ssize_t)(offset + 20 + 8 + 20 + 12));
	struct ip4 *out = (struct ip4 *)(captured + offset);
	struct icmp *error = (struct icmp *)(out + 1);
	struct ip4 *quote = (struct ip4 *)(error + 1);
	assert(out->proto == IPPROTO_ICMP && error->type == 11);
	assert(ntohs(quote->flags_offset) & IP4_F_MF);
	assert(ntohs(quote->ident) == 0x5678 && ntohs(quote->length) == 1420);
	assert(ip_checksum(out, 20) == 0 && ip_checksum(error, 40) == 0);
	close(sv[0]); close(sv[1]);
	printf("PASS: ICMPv6 error with truncated inner fragment handled\n");
}

static void test_icmp4_error_fragment_quote(void)
{
    setup_quote_maps(); gcfg.mtu = 1500;
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    alignas(4) uint8_t buffer[HEADROOM + 256] = {0}, captured[256];
    struct ip4 *ip = (struct ip4 *)(buffer + HEADROOM);
    struct icmp *error = (struct icmp *)(ip + 1);
    struct ip4 *quote = (struct ip4 *)(error + 1);
    ip->ver_ihl = quote->ver_ihl = 0x45; ip->ttl = quote->ttl = 64;
    ip->proto = IPPROTO_ICMP; ip->length = htons(60);
    inet_pton(AF_INET, "8.8.8.8", &ip->src); inet_pton(AF_INET, "192.0.0.1", &ip->dest);
    quote->src = ip->dest; quote->dest = ip->src;
    quote->length = htons(1420); quote->flags_offset = htons(IP4_F_MF);
    quote->ident = htons(0x1234); quote->proto = IPPROTO_UDP;
    quote->cksum = ip4_header_checksum(quote);
    error->type = 11; error->cksum = ip_checksum(error, 40);
    ip->cksum = ip4_header_checksum(ip);
    struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip, .data_len = 60};
    handle_ip4(&p);
#ifdef __linux__
    unsigned offset = 0;
#else
    unsigned offset = sizeof(struct tun_pi);
#endif
    assert(recv(sv[1], captured, sizeof(captured), MSG_DONTWAIT) == (ssize_t)(offset + 108));
    struct ip6 *out = (struct ip6 *)(captured + offset);
    struct icmp *out_error = (struct icmp *)(out + 1);
    struct ip6 *inner = (struct ip6 *)(out_error + 1);
    struct ip6_frag *frag = (struct ip6_frag *)(inner + 1);
    assert(out_error->type == 3 && inner->next_header == 44 && ntohs(inner->payload_length) == 1408);
    assert((ntohs(frag->offset_flags) & IP6_F_MF) && ntohl(frag->ident) == 0x1234);
    assert(ones_add(ip_checksum(out_error, 68), ip6_checksum(out, 68, IPPROTO_ICMPV6)) == 0);
    close(sv[0]); close(sv[1]);
    puts("PASS: ICMPv4 truncated fragment quote gains a verified IPv6 Fragment Header");
}

static void test_embedded_routing_and_extension_limit(void)
{
    setup_quote_maps(); gcfg.mtu = 1500;
    int sv[2], inner_fd[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, inner_fd) == 0);
    alignas(4) uint8_t buffer[HEADROOM + 256] = {0}, response[256];
    struct ip6 *ip = (struct ip6 *)(buffer + HEADROOM);
    struct icmp *error = (struct icmp *)(ip + 1);
    struct ip6 *inner = (struct ip6 *)(error + 1);
    ip->ver_tc_fl = inner->ver_tc_fl = htonl(0x60000000);
    ip->hop_limit = inner->hop_limit = 64;
    ip->next_header = IPPROTO_ICMPV6; inner->next_header = 43;
    ip->payload_length = htons(64); inner->payload_length = htons(16);
    inet_pton(AF_INET6, "64:ff9b::808:808", &ip->src);
    inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip->dest);
    inner->src = ip->dest; inner->dest = ip->src;
    uint8_t *routing = (uint8_t *)(inner + 1); routing[0] = IPPROTO_UDP; routing[3] = 1;
    error->type = 3;
    error->cksum = ones_add(ip_checksum(error, 64), ip6_checksum(ip, 64, IPPROTO_ICMPV6));
    int saved_stdin = dup(STDIN_FILENO); assert(saved_stdin >= 0);
    assert(dup2(inner_fd[0], STDIN_FILENO) == STDIN_FILENO);
    struct pkt p = {.tun_fd = sv[0], .data = (uint8_t *)ip, .data_len = 104};
    handle_ip6(&p);
    assert(dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO); close(saved_stdin);
    assert(recv(inner_fd[1], response, sizeof(response), MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    assert(recv(sv[1], response, sizeof(response), MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    close(inner_fd[0]); close(inner_fd[1]);
    for (unsigned count = 8; count <= 9; ++count) {
        memset(buffer, 0, sizeof(buffer)); ip = (struct ip6 *)(buffer + HEADROOM);
        ip->ver_tc_fl = htonl(0x60000000); ip->hop_limit = 64;
        ip->next_header = 60; ip->payload_length = htons(count * 8 + 8);
        inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip->src);
        inet_pton(AF_INET6, "64:ff9b::808:808", &ip->dest);
        uint8_t *extension = (uint8_t *)(ip + 1);
        for (unsigned n = 0; n < count; ++n) extension[n * 8] = n + 1 == count ? IPPROTO_UDP : 60;
        p = (struct pkt){.tun_fd = sv[0], .data = (uint8_t *)ip, .data_len = 40 + count * 8 + 8};
        handle_ip6(&p);
        ssize_t received = recv(sv[1], response, sizeof(response), MSG_DONTWAIT);
        if (count == 8) assert(received > 0);
        else assert(received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    }
    close(sv[0]); close(sv[1]);
    puts("PASS: embedded routing errors produce no output, extension-header cap accepts 8 and rejects 9");
}

int main(void)
{
	printf("=== Running unit_udp_checksum test suite ===\n");
	test_ipv6_udp_output_family();
	test_truncated_ip_headers();
	test_ipv6_atomic_fragment();
	test_rfc4884_ext_4to6();
	test_rfc4884_ext_6to4();
	test_icmp_error_suppression_and_rate_limit();
	test_icmp6_unknown_next_header_pointer();
	test_icmp6to4_quoted_length_clamp();
	test_icmp_echo_checksum_translation();
	test_tcp_zero_checksum_preserved();
	test_metadata_bounds();
	test_complete_checksum_translation();
	test_zero_checksum_boundary();
	test_partial_checksum_offload();
	test_absent_checksum_policy();
	test_icmp_embedded_truncated();
	test_icmp6_param_problem_negative_ptr();
	test_icmp6_error_truncated_fragment_quote();
	test_icmp4_error_fragment_quote();
	test_embedded_routing_and_extension_limit();
	printf("=== All unit_udp_checksum tests passed successfully! ===\n");
	return 0;
}
