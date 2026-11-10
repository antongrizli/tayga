/* libFuzzer harness: untrusted DNS answers and Router Advertisements. */
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int parse_dns_response(const uint8_t *resp, size_t rlen, uint16_t expected_id,
                       const char *expected_domain, struct in6_addr *out, int *prefix_len);
int parse_ra_pref64_option(const uint8_t *ra, size_t ra_len, struct in6_addr *out_prefix,
                           int *out_plen, uint32_t *out_lifetime_sec);
int extract_pref64(const struct in6_addr *in, struct in6_addr *out, int *prefix_len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct in6_addr out;
	int plen = 0;
	uint32_t life = 0;
	/* Exact-size copy so ASan sees any over-read. */
	uint8_t *copy = size ? malloc(size) : NULL;
	if (size && !copy)
		return 0;
	if (size)
		memcpy(copy, data, size);
	(void)parse_dns_response(copy, size, size >= 2 ? (uint16_t)((data[0] << 8) | data[1]) : 0,
	                         "ipv4only.arpa", &out, &plen);
	(void)parse_ra_pref64_option(copy, size, &out, &plen, &life);
	if (size >= 16) {
		struct in6_addr in;
		memcpy(&in, copy, 16);
		(void)extract_pref64(&in, &out, &plen);
	}
	free(copy);
	return 0;
}
