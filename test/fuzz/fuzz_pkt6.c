/* libFuzzer harness: arbitrary IPv6 frames through handle_ip6(). */
#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_setup_maps();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_packet(data, size, handle_ip6);
	return 0;
}
