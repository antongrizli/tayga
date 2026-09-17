#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include "tayga.h"

/* Reference TAYGA ip_checksum */
static uint16_t ref_ip_checksum(const void *d, int c)
{
	const uint8_t *data = d;
	uint32_t sum = 0;
	while (c > 1) {
		sum += ((uint32_t)data[0] << 8) | data[1];
		data += 2;
		c -= 2;
	}
	if (c > 0)
		sum += (uint32_t)data[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~htons(sum);
}

int main(void)
{
	struct ip4 h;
	printf("Running unit_checksum tests...\n");

	/* Test 1: All zeros */
	memset(&h, 0, sizeof(h));
	uint16_t ref = ref_ip_checksum(&h, 20);
	uint16_t fast = ip4_header_checksum(&h);
	assert(ref == fast);
	assert(fast == 0xffff);

	/* Test 2: Standard realistic IPv4 header */
	memset(&h, 0, sizeof(h));
	h.ver_ihl = 0x45;
	h.tos = 0x00;
	h.length = htons(1500);
	h.ident = htons(0x1234);
	h.flags_offset = htons(0x4000);
	h.ttl = 64;
	h.proto = 6;
	h.cksum = 0;
	h.src.s_addr = htonl(0xc0a85802); /* 192.168.88.2 */
	h.dest.s_addr = htonl(0x0b000002); /* 11.0.0.2 */
	ref = ref_ip_checksum(&h, 20);
	fast = ip4_header_checksum(&h);
	assert(ref == fast);

	/* Test 3: Corner cases with all 0xff except cksum */
	memset(&h, 0xff, sizeof(h));
	h.cksum = 0;
	ref = ref_ip_checksum(&h, 20);
	fast = ip4_header_checksum(&h);
	assert(ref == fast);

	/* Test 4: 1,000,000 pseudo-random headers with carry wrap-arounds */
	uint32_t seed = 0x12345678;
	for (int i = 0; i < 1000000; i++) {
		uint32_t words[5];
		for (int j = 0; j < 5; j++) {
			seed = seed * 1664525u + 1013904223u;
			words[j] = seed;
		}
		memcpy(&h, words, sizeof(h));
		h.cksum = 0;
		ref = ref_ip_checksum(&h, 20);
		fast = ip4_header_checksum(&h);
		if (ref != fast) {
			fprintf(stderr, "FAIL: Checksum mismatch at iteration %d: ref=0x%04x fast=0x%04x\n",
				i, ref, fast);
			return 1;
		}
	}

	printf("PASS: unit_checksum passed all 1,000,000 iterations and edge cases.\n");
	return 0;
}
