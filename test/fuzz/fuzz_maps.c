/* libFuzzer harness: map-file parser and atomic reload (addrmap_reload), then
 * lookups through the resulting tables and the flat prefix index. */
#include "tayga.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

_Atomic time_t now = 1000;

static char map_path[] = "/tmp/fuzz-maps-XXXXXX";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	int fd = mkstemp(map_path);
	if (fd < 0)
		abort();
	close(fd);
	if (config_init() != 0)
		abort();
	pthread_mutex_init(&gcfg.map_mutex, NULL);
	pthread_mutex_init(&gcfg.cache_mutex, NULL);
	gcfg.cache_size = 64;
	gcfg.hash_bits = 4;
	gcfg.rand[0] = 1;
	INIT_LIST_HEAD(&gcfg.map4_list);
	INIT_LIST_HEAD(&gcfg.map6_list);
	if (create_cache() != 0)
		abort();
	snprintf(gcfg.map_file, sizeof(gcfg.map_file), "%s", map_path);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 65536)
		return 0;
	FILE *f = fopen(map_path, "w");
	if (!f)
		return 0;
	if (size)
		(void)fwrite(data, 1, size, f);
	fclose(f);
	atomic_fetch_add(&now, 1);
	(void)addrmap_reload();		/* may reject; previous maps are then kept */
	/* Exercise lookups and the index over whatever is currently loaded. */
	(void)addrmap_build_index();
	for (uint32_t i = 0; i < 8; i++) {
		struct in_addr a4 = { .s_addr = htonl(0xc0000200u + i * 0x01010101u) };
		struct in6_addr a6, b6;
		memset(&a6, 0, sizeof(a6));
		a6.s6_addr[0] = 0x20; a6.s6_addr[1] = 0x01; a6.s6_addr[15] = (uint8_t)i;
		(void)map_ip4_to_ip6(&b6, &a4);
		(void)map_ip6_to_ip4(&a4, &a6, 0);
		(void)find_map4(&a4);
		(void)find_map6(&a6);
	}
	addrmap_free_index();
	return 0;
}
