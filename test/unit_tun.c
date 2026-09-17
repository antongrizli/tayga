#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "tayga.h"

struct config gcfg;

void handle_ip4(struct pkt *p) { (void)p; }
void handle_ip6(struct pkt *p) { (void)p; }

/* Real glibc functions wrapped via -Wl,--wrap */
extern ssize_t __real_write(int fd, const void *buf, size_t count);
extern ssize_t __real_writev(int fd, const struct iovec *iov, int iovcnt);

/* Mock control flags */
enum mock_mode {
	MOCK_PASSTHROUGH = 0,
	MOCK_EINTR_ONCE,
	MOCK_EINTR_ALWAYS,
	MOCK_SHORT_WRITE
};

static enum mock_mode current_mock_mode = MOCK_PASSTHROUGH;
static int write_call_count = 0;

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
	write_call_count++;

	switch (current_mock_mode) {
	case MOCK_EINTR_ONCE:
		if (write_call_count == 1) {
			errno = EINTR;
			return -1;
		}
		return __real_write(fd, buf, count);

	case MOCK_EINTR_ALWAYS:
		errno = EINTR;
		return -1;

	case MOCK_SHORT_WRITE:
		/* Return 10 bytes instead of full count */
		if (count > 10)
			return 10;
		return count;

	case MOCK_PASSTHROUGH:
	default:
		return __real_write(fd, buf, count);
	}
}

ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
	write_call_count++;

	switch (current_mock_mode) {
	case MOCK_EINTR_ONCE:
		if (write_call_count == 1) {
			errno = EINTR;
			return -1;
		}
		return __real_writev(fd, iov, iovcnt);

	case MOCK_EINTR_ALWAYS:
		errno = EINTR;
		return -1;

	case MOCK_SHORT_WRITE:
		/* Return short write */
		return 10;

	case MOCK_PASSTHROUGH:
	default:
		return __real_writev(fd, iov, iovcnt);
	}
}

int main(void)
{
	printf("Running unit_tun tests...\n");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		perror("socketpair");
		return 1;
	}

	char test_data[128];
	memset(test_data, 0x5a, sizeof(test_data));

	/* Test 1: Successful contiguous tun_write */
	current_mock_mode = MOCK_PASSTHROUGH;
	write_call_count = 0;
	ssize_t ret = tun_write(sv[0], test_data, sizeof(test_data));
	assert(ret == sizeof(test_data));

	char recv_buf[256];
	ssize_t rret = read(sv[1], recv_buf, sizeof(recv_buf));
	assert(rret == sizeof(test_data));
	assert(memcmp(test_data, recv_buf, sizeof(test_data)) == 0);
	printf("PASS: Successful contiguous tun_write\n");

	/* Test 2: Successful vectored tun_writev */
	struct iovec iov[2];
	char hdr[20];
	char payload[40];
	memset(hdr, 0x11, sizeof(hdr));
	memset(payload, 0x22, sizeof(payload));

	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = payload;
	iov[1].iov_len = sizeof(payload);

	current_mock_mode = MOCK_PASSTHROUGH;
	write_call_count = 0;
	ret = tun_writev(sv[0], iov, 2);
	assert(ret == (ssize_t)(sizeof(hdr) + sizeof(payload)));

	rret = read(sv[1], recv_buf, sizeof(recv_buf));
	assert(rret == (ssize_t)(sizeof(hdr) + sizeof(payload)));
	assert(memcmp(recv_buf, hdr, sizeof(hdr)) == 0);
	assert(memcmp(recv_buf + sizeof(hdr), payload, sizeof(payload)) == 0);
	printf("PASS: Successful vectored tun_writev\n");

	/* Test 3: EINTR, then success on retry */
	current_mock_mode = MOCK_EINTR_ONCE;
	write_call_count = 0;
	ret = tun_write(sv[0], test_data, sizeof(test_data));
	assert(ret == sizeof(test_data));
	assert(write_call_count == 2); /* 1st failed with EINTR, 2nd succeeded */
	rret = read(sv[1], recv_buf, sizeof(recv_buf));
	assert(rret == sizeof(test_data));
	printf("PASS: tun_write recovers after single EINTR (retries = 2)\n");

	current_mock_mode = MOCK_EINTR_ONCE;
	write_call_count = 0;
	ret = tun_writev(sv[0], iov, 2);
	assert(ret == (ssize_t)(sizeof(hdr) + sizeof(payload)));
	assert(write_call_count == 2);
	rret = read(sv[1], recv_buf, sizeof(recv_buf));
	assert(rret == (ssize_t)(sizeof(hdr) + sizeof(payload)));
	printf("PASS: tun_writev recovers after single EINTR (retries = 2)\n");

	/* Test 4: Exactly 5 consecutive EINTRs fail with -1 and errno preserved as EINTR */
	current_mock_mode = MOCK_EINTR_ALWAYS;
	write_call_count = 0;
	errno = 0;
	ret = tun_write(sv[0], test_data, sizeof(test_data));
	assert(ret == -1);
	assert(write_call_count == 5); /* Exactly 5 attempts made */
	assert(errno == EINTR);        /* Preserved across slog */
	printf("PASS: tun_write exits after strictly 5 EINTR attempts with errno == EINTR\n");

	current_mock_mode = MOCK_EINTR_ALWAYS;
	write_call_count = 0;
	errno = 0;
	ret = tun_writev(sv[0], iov, 2);
	assert(ret == -1);
	assert(write_call_count == 5);
	assert(errno == EINTR);
	printf("PASS: tun_writev exits after strictly 5 EINTR attempts with errno == EINTR\n");

	/* Test 5: Short write returns -1, sets errno = EIO, and does not retry */
	current_mock_mode = MOCK_SHORT_WRITE;
	write_call_count = 0;
	errno = 0;
	ret = tun_write(sv[0], test_data, sizeof(test_data));
	assert(ret == -1);
	assert(write_call_count == 1); /* No retry attempted on short write */
	assert(errno == EIO);
	printf("PASS: tun_write short write returns -1, sets errno == EIO, 0 retries\n");

	current_mock_mode = MOCK_SHORT_WRITE;
	write_call_count = 0;
	errno = 0;
	ret = tun_writev(sv[0], iov, 2);
	assert(ret == -1);
	assert(write_call_count == 1);
	assert(errno == EIO);
	printf("PASS: tun_writev short write returns -1, sets errno == EIO, 0 retries\n");

	/* Test 6: Invalid fd returns -1 and sets errno == EBADF (preserved across slog) */
	current_mock_mode = MOCK_PASSTHROUGH;
	errno = 0;
	ret = tun_write(-1, test_data, sizeof(test_data));
	assert(ret < 0);
	assert(errno == EBADF);

	errno = 0;
	ret = tun_writev(-1, iov, 2);
	assert(ret < 0);
	assert(errno == EBADF);
	printf("PASS: Error returns -1 with errno == EBADF preserved across slog\n");

	close(sv[0]);
	close(sv[1]);

	printf("PASS: All unit_tun tests passed.\n");
	return 0;
}
