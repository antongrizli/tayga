/* libFuzzer harness: flow_parse() ingress classifier (header-only, no state). */
#include "flow_dispatch.h"
#include <assert.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct flow_packet a, b;
	int ra = flow_parse(data, size, &a);
	int rb = flow_parse(data, size, &b);
	/* Parsing is deterministic and never reports a half-built key as success. */
	assert(ra == rb);
	if (ra == 0)
		assert(a.flow_hash == b.flow_hash && a.fragment_hash == b.fragment_hash &&
		       a.transport == b.transport && a.fragmented == b.fragmented && a.first == b.first);
	/* A truncated copy must never read past its end (ASan checks the copy). */
	if (size > 1) {
		size_t n = size - 1 - (data[0] % size);
		if (n) {
			uint8_t *copy = malloc(n);
			if (!copy)
				return 0;
			memcpy(copy, data, n);
			struct flow_packet t;
			(void)flow_parse(copy, n, &t);
			free(copy);
		}
	}
	return 0;
}
