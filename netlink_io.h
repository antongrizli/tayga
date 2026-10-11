/* Bounded rtnetlink exchanges. The caller retains descriptor ownership. */
#ifndef TAYGA_NETLINK_IO_H
#define TAYGA_NETLINK_IO_H
#ifdef __linux__
#include <linux/netlink.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <limits.h>

static inline int64_t rtnl_milliseconds(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static inline ssize_t rtnl_receive(int fd, void *buffer, size_t capacity,
		uint32_t seq, int64_t deadline)
{
	for (;;) {
		int64_t remaining = deadline - rtnl_milliseconds();
		if (remaining <= 0) { errno = ETIMEDOUT; return -1; }
		struct pollfd p = {.fd = fd, .events = POLLIN};
		int ret = poll(&p, 1, (int)remaining);
		if (ret < 0 && errno == EINTR) continue;
		if (ret <= 0) { if (!ret) errno = ETIMEDOUT; return -1; }
		struct sockaddr_nl peer = {0};
		struct iovec iov = {buffer, capacity};
		struct msghdr msg = {.msg_name = &peer, .msg_namelen = sizeof(peer),
			.msg_iov = &iov, .msg_iovlen = 1};
		ssize_t len = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (len < 0 && (errno == EINTR || errno == EAGAIN)) continue;
		if (len <= 0) { if (!len) errno = EPROTO; return -1; }
		if (msg.msg_flags & MSG_TRUNC) { errno = EMSGSIZE; return -1; }
		if (msg.msg_namelen != sizeof(peer) || peer.nl_family != AF_NETLINK || peer.nl_pid) {
			errno = EPROTO; return -1;
		}
		int bytes = (int)len;
		for (struct nlmsghdr *n = buffer; NLMSG_OK(n, bytes); n = NLMSG_NEXT(n, bytes)) {
			if (n->nlmsg_seq != seq || (n->nlmsg_flags & NLM_F_DUMP_INTR)) {
				errno = EPROTO; return -1;
			}
		}
		if (bytes) { errno = EPROTO; return -1; }
		return len;
	}
}

static inline int rtnl_ack(const void *buffer, size_t length, uint32_t seq)
{
	if (length > INT_MAX) { errno = EMSGSIZE; return -1; }
	int bytes = (int)length;
	for (const struct nlmsghdr *n = buffer; NLMSG_OK(n, bytes); n = NLMSG_NEXT(n, bytes)) {
		if (n->nlmsg_seq != seq || n->nlmsg_type != NLMSG_ERROR ||
			n->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
			errno = EPROTO; return -1;
		}
		if ((size_t)NLMSG_ALIGN(n->nlmsg_len) != length) { errno = EPROTO; return -1; }
		int error = ((const struct nlmsgerr *)NLMSG_DATA(n))->error;
		if (error > 0 || error < -4095) { errno = EPROTO; return -1; }
		if (error) { errno = -error; return -1; }
		return 0;
	}
	errno = EPROTO;
	return -1;
}

static inline int rtnl_send(int fd, const struct nlmsghdr *request, int64_t deadline)
{
	struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
	for (;;) {
		if (rtnl_milliseconds() >= deadline) { errno = ETIMEDOUT; return -1; }
		ssize_t len = sendto(fd, request, request->nlmsg_len, MSG_DONTWAIT,
			(struct sockaddr *)&kernel, sizeof(kernel));
		if (len < 0 && errno == EINTR) continue;
		if (len < 0) return -1;
		if (len != request->nlmsg_len) { errno = EIO; return -1; }
		return 0;
	}
}

static inline int rtnl_request(int fd, const struct nlmsghdr *request)
{
	int64_t deadline = rtnl_milliseconds() + 2000;
	if (rtnl_send(fd, request, deadline)) return -1;
	_Alignas(struct nlmsghdr) char buffer[4096];
	ssize_t len = rtnl_receive(fd, buffer, sizeof(buffer), request->nlmsg_seq, deadline);
	return len < 0 ? -1 : rtnl_ack(buffer, (size_t)len, request->nlmsg_seq);
}
#endif
#endif
