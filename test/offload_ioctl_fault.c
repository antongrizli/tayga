/* Integration-test fault injection only; never linked into TAYGA. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

static int tun_fds[128];
static int tun_fd_count;

static int is_test_tun_fd(int fd)
{
	for (int i = 0; i < tun_fd_count; i++)
		if (tun_fds[i] == fd)
			return 1;
	return 0;
}

int ioctl(int fd, unsigned long request, ...)
{
	static int (*real_ioctl)(int, unsigned long, ...);
	static unsigned int enables;
	va_list ap;
	va_start(ap, request);
	unsigned long arg = va_arg(ap, unsigned long);
	va_end(ap);
	if (!real_ioctl)
		real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	const char *fault = getenv("TAYGA_TEST_OFFLOAD_FAIL");
	if (fault && request == TUNSETIFF && !strcmp(fault, "vnet") &&
	    (((struct ifreq *)arg)->ifr_flags & IFF_VNET_HDR)) {
		errno = EINVAL;
		return -1;
	}
	if (fault && request == TUNSETOFFLOAD && arg) {
		enables++;
		if (!strcmp(fault, "primary") ||
		    (!strcmp(fault, "worker") && enables == 2)) {
			errno = EINVAL;
			return -1;
		}
	}
	int ret = real_ioctl(fd, request, arg);
	if (ret == 0 && request == TUNSETIFF && tun_fd_count < 128)
		tun_fds[tun_fd_count++] = fd;
	return ret;
}

ssize_t read(int fd, void *buffer, size_t size)
{
	static ssize_t (*real_read)(int, void *, size_t);
	if (!real_read)
		real_read = dlsym(RTLD_NEXT, "read");
	if (getenv("TAYGA_TEST_TUN_READ_FAIL") && is_test_tun_fd(fd)) {
		errno = EIO;
		return -1;
	}
	return real_read(fd, buffer, size);
}

int poll(struct pollfd *fds, nfds_t count, int timeout)
{
	static int (*real_poll)(struct pollfd *, nfds_t, int);
	if (!real_poll)
		real_poll = dlsym(RTLD_NEXT, "poll");
	if (getenv("TAYGA_TEST_TUN_READ_FAIL")) {
		for (nfds_t i = 0; i < count; i++) {
			if (is_test_tun_fd(fds[i].fd)) {
				fds[i].revents = POLLIN;
				return 1;
			}
		}
	}
	return real_poll(fds, count, timeout);
}
