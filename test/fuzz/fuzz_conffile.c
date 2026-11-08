/* libFuzzer harness: tayga.conf parser and validator. */
#include "tayga.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* gcfg is defined by conffile.c in libtayga_test.a */
_Atomic time_t now = 1000;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 65536)
		return 0;
	char name[] = "/tmp/fuzz-conf-XXXXXX";
	int fd = mkstemp(name);
	if (fd < 0)
		return 0;
	if (size && write(fd, data, size) != (ssize_t)size) {
		close(fd);
		unlink(name);
		return 0;
	}
	close(fd);
	if (config_init() == 0) {
		if (config_read(name) == 0)
			(void)config_validate();
		config_free();
	}
	unlink(name);
	return 0;
}
