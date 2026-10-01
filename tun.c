/*
 *  tun.c -- tunnel interface routines
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 *  Copyright (C) 2010  Nathan Lutchansky <lutchann@litech.org>
 *  Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */
#include "tayga.h"
#include "stats.h"
#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/file.h>
#include <sys/stat.h>
static int tun_owner_lock = -1;
/* Build-only research candidate; normal builds keep existing TUN semantics.
 * IFF_NAPI must be identical on initial, fallback and worker attachments.
 * Unsupported kernels fail initialization; this is never silently enabled. */
#ifdef TAYGA_EXPERIMENTAL_NAPI
#define TAYGA_TUN_BASE_FLAGS (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_NAPI)
static int tun_verify_napi(int fd, int queue)
{
	struct ifreq actual;
	memset(&actual, 0, sizeof(actual));
	if (ioctl(fd, TUNGETIFF, &actual) < 0 || !(actual.ifr_flags & IFF_NAPI)) {
		slog(LOG_CRIT, "Experimental TUN NAPI queue %d could not be verified\n", queue);
		return -1;
	}
	slog(LOG_INFO, "Experimental TUN NAPI verified on queue %d\n", queue);
	return 0;
}
#else
#define TAYGA_TUN_BASE_FLAGS (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE)
#endif
#define TCP_OFFLOAD_FLAGS (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6)
#define UDP_OFFLOAD_FLAGS (TCP_OFFLOAD_FLAGS | TUN_F_USO4 | TUN_F_USO6)

/* Workers are not running during negotiation. A candidate is committed only
 * after every attached descriptor accepts the same device-wide feature mask. */
static int tun_negotiate(int primary, int *queues, int count,
						 enum tun_offload_mode requested, int has_vnet)
{
	unsigned int masks[3];
	int candidates = 0;
	gcfg.tun_offload_complete = 0;
	gcfg.tun_has_uso = 0;
	gcfg.tun_offload_flags = 0;
	gcfg.tun_offload_effective = TUN_OFFLOAD_OFF;
	gcfg.tun_offload_reason = !has_vnet && requested == TUN_OFFLOAD_AUTO ? "vnet_unavailable" : "none";
	if (has_vnet || requested != TUN_OFFLOAD_AUTO) gcfg.tun_offload_errno = 0;
	gcfg.tun_offload_queue = -1;
	if (has_vnet && (requested == TUN_OFFLOAD_AUTO || requested == TUN_OFFLOAD_UDP))
		masks[candidates++] = UDP_OFFLOAD_FLAGS;
	if (has_vnet && (requested == TUN_OFFLOAD_AUTO || requested == TUN_OFFLOAD_TCP))
		masks[candidates++] = TCP_OFFLOAD_FLAGS;
	if (requested == TUN_OFFLOAD_AUTO || requested == TUN_OFFLOAD_OFF)
		masks[candidates++] = 0;
	for (int c = 0; c < candidates; c++) {
		int failed = 0;
		for (int q = -1; q < count; q++) {
			int ret, attempts = 0;
			do {
				ret = ioctl(q < 0 ? primary : queues[q], TUNSETOFFLOAD, masks[c]);
			} while (ret < 0 && errno == EINTR && ++attempts < 3);
			if (ret < 0) {
				gcfg.tun_offload_errno = errno;
				gcfg.tun_offload_queue = q;
				gcfg.tun_offload_reason = masks[c] == UDP_OFFLOAD_FLAGS ?
					"udp_unavailable" : "offload_unavailable";
				slog(LOG_WARNING, "TUNSETOFFLOAD failed: flags=0x%x queue=%d: %s\n",
					 masks[c], q, strerror(errno));
				if (!masks[c] || gcfg.tun_offload_errno == EBADF || gcfg.tun_offload_errno == ENODEV)
					return ERROR_REJECT;
				failed = 1;
				break;
			}
		}
		if (failed)
			continue;
		gcfg.tun_offload_flags = masks[c];
		gcfg.tun_has_uso = masks[c] == UDP_OFFLOAD_FLAGS;
		gcfg.tun_offload_effective = gcfg.tun_has_uso ? TUN_OFFLOAD_UDP :
			masks[c] ? TUN_OFFLOAD_TCP : TUN_OFFLOAD_OFF;
		gcfg.tun_offload_complete = 1;
		return 0;
	}
	return ERROR_REJECT;
}
#endif



int set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		slog(LOG_CRIT, "fcntl F_GETFL returned %s\n", strerror(errno));
		return ERROR_REJECT;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		slog(LOG_CRIT, "fcntl F_SETFL returned %s\n", strerror(errno));
		return ERROR_REJECT;
	}
	return 0;
}

int tun_check_offload_support(void)
{
#ifdef __linux__
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		printf("OFFLOAD_CHECK: FAIL (cannot open /dev/net/tun: %s)\n", strerror(errno));
		return 1;
	}
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
	snprintf(ifr.ifr_name, IFNAMSIZ, "tun_chk%%d");
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		printf("OFFLOAD_CHECK: FAIL (IFF_VNET_HDR ioctl failed: %s)\n", strerror(errno));
		close(fd);
		return 1;
	}
	int sz = 0;
	if (ioctl(fd, TUNGETVNETHDRSZ, &sz) < 0 || (sz != 10 && sz != 12)) {
		printf("OFFLOAD_CHECK: FAIL (cannot verify vnet header size)\n");
		close(fd);
		return 1;
	}
	int ret = tun_negotiate(fd, NULL, 0, TUN_OFFLOAD_AUTO, 1);
	close(fd);
	if (ret < 0 || gcfg.tun_offload_effective == TUN_OFFLOAD_OFF) {
		printf("OFFLOAD_CHECK: FAIL (TCP/UDP offload unavailable)\n");
		return 1;
	}
	printf("OFFLOAD_CHECK: OK (vnet_hdr_sz=%d, effective=%s, udp_available=%s)\n",
		   sz, tun_offload_name(gcfg.tun_offload_effective), gcfg.tun_has_uso ? "yes" : "no");
	return 0;
#else
	printf("OFFLOAD_CHECK: NOT_SUPPORTED (Linux TUN only)\n");
	return 1;
#endif
}

#ifdef __linux__
int netlink_wait_for_ack(int fd)
{
	char buf[4096];
	ssize_t len;
	struct nlmsghdr *nh;
	/* Receive ACK */
	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) {
		slog(LOG_CRIT,"NETLINK Receive Failed\n");
		return ERROR_REJECT;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);

			//Found our ack
			if (err->error == 0) {
				close(fd);
				return 0;
			}
			close(fd);
			slog(LOG_CRIT,"NETLINK Returned Error %d\n",err->error);
			return ERROR_REJECT;
		}
	}

	close(fd);
	slog(LOG_CRIT,"NETLINK Response Not Received\n");
	return ERROR_REJECT;
}


/**
 * @brief Set interface flags via Netlink
 *
 * This function connects to the Netlink socket and sends a request to set
 * the specified flags on the given network interface.
 *
 * @param ifidx The index of the network interface (e.g., 0).
 * @param flags The flags to set on the interface (e.g., IFF_UP).
 * @param change The flags that are changing (e.g., IFF_UP).
 * @return 0 on success, ERROR_REJECT on failure.
 */
int netlink_set_if_flags(int ifidx,
						 unsigned int flags,
						 unsigned int change)
{
	int fd;
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
	} req;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		slog(LOG_CRIT,"NETLINK Socket Failed\n");
		return ERROR_REJECT;
	}

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_type  = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq   = 1;
	req.nh.nlmsg_pid   = getpid();

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index  = ifidx;
	req.ifi.ifi_flags  = flags;
	req.ifi.ifi_change = change;

	if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
		close(fd);
		slog(LOG_CRIT,"NETLINK Send Failed\n");
		return ERROR_REJECT;
	}

	/* Receive ACK */
	return netlink_wait_for_ack(fd);
}

/**
 * @brief Modyfy interface address via Netlink
 * 
 * This function connects to the Netlink socket and sends a request to add or
 * delete an IP address on the specified network interface.
 * 
 * @param ifidx The index of the network interface
 * @param af_family The address family (e.g., AF_INET or AF_INET6
 * @param addr The IP address in in_addr or in6_addr format
 * @param prefixlen The prefix length of the IP address
 * @param add 1 to add or 0 to delete the address
 */
int netlink_addr_modify(int ifidx,
						int af_family,
						const void *addr,
						int prefixlen,
						int add)
{
	int fd;
	char buf[256];
	struct nlmsghdr *nh;
	struct ifaddrmsg *ifa;
	struct rtattr *rta;
	size_t addrlen;


	if (af_family == AF_INET) addrlen = sizeof(struct in_addr);
	else addrlen = sizeof(struct in6_addr);

	/* Open socket */
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		slog(LOG_CRIT,"NETLINK Socket Failed\n");
		return ERROR_REJECT;
	}

	memset(buf, 0, sizeof(buf));

	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifa));
	nh->nlmsg_type  = add ? RTM_NEWADDR : RTM_DELADDR;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
					  (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	nh->nlmsg_seq   = 1;
	nh->nlmsg_pid   = getpid();

	ifa = NLMSG_DATA(nh);
	ifa->ifa_family    = af_family;
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = ifidx;

	/* IFA_ADDRESS */
	rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
	rta->rta_type = IFA_ADDRESS;
	rta->rta_len  = RTA_LENGTH(addrlen);
	memcpy(RTA_DATA(rta), addr, addrlen);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;

	/* IFA_LOCAL only meaningful for IPv4 */
	if (af_family == AF_INET) {
		rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
		rta->rta_type = IFA_LOCAL;
		rta->rta_len  = RTA_LENGTH(addrlen);
		memcpy(RTA_DATA(rta), addr, addrlen);
		nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;
	}

	if (send(fd, nh, nh->nlmsg_len, 0) < 0) {
		close(fd);
		slog(LOG_CRIT,"NETLINK Send Failed\n");
		return ERROR_REJECT;
	}

	/* Receive ACK */
	return netlink_wait_for_ack(fd);
}

/**
 * @brief Modyfy interface routes via Netlink
 * 
 * This function connects to the Netlink socket and sends a request to add or
 * delete a route to the specified network interface.
 * 
 * @param ifidx The index of the network interface
 * @param af_family The address family (e.g., AF_INET or AF_INET6
 * @param dst The route destination in in_addr or in6_addr format
 * @param prefixlen The prefix length of the route
 * @param add 1 to add or 0 to delete the route
 */
int netlink_route_dev_modify(int ifidx,
							 int af_family,
							 const void *dst,
							 int prefixlen,
							 int add)
{
	int fd;
	char buf[256];
	struct nlmsghdr *nh;
	struct rtmsg *rtm;
	struct rtattr *rta;
	size_t addrlen;

	if (af_family == AF_INET) addrlen = sizeof(struct in_addr);
	else addrlen = sizeof(struct in6_addr);

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		slog(LOG_CRIT,"NETLINK Socket Failed\n");
		return ERROR_REJECT;
	}

	memset(buf, 0, sizeof(buf));

	/* Netlink header */
	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*rtm));
	nh->nlmsg_type  = add ? RTM_NEWROUTE : RTM_DELROUTE;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
					  (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	nh->nlmsg_seq   = 1;
	nh->nlmsg_pid   = getpid();

	/* Route message */
	rtm = NLMSG_DATA(nh);
	rtm->rtm_family   = af_family;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope    = RT_SCOPE_LINK;
	rtm->rtm_type     = RTN_UNICAST;
	rtm->rtm_dst_len  = prefixlen;

	/* Destination */
	rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
	rta->rta_type = RTA_DST;
	rta->rta_len  = RTA_LENGTH(addrlen);
	memcpy(RTA_DATA(rta), dst, addrlen);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;

	/* Output interface */
	rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
	rta->rta_type = RTA_OIF;
	rta->rta_len  = RTA_LENGTH(sizeof(ifidx));
	memcpy(RTA_DATA(rta), &ifidx, sizeof(ifidx));
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;

	/* Send */
	if (send(fd, nh, nh->nlmsg_len, 0) < 0) {
		close(fd);
		slog(LOG_CRIT,"NETLINK Send Failed\n");
		return ERROR_REJECT;
	}

	/* Receive ACK */
	return netlink_wait_for_ack(fd);
}

/* Administrative DOWN removes routes (and may remove IPv6 addresses).
 * Preserve only this owned interface's configuration before quiescing it. */
struct tun_saved_config {
	struct tun_saved_config *next;
	struct nlmsghdr message;
};

static void tun_free_saved_config(struct tun_saved_config *saved)
{
	while (saved) {
		struct tun_saved_config *next = saved->next;
		free(saved);
		saved = next;
	}
}

static int tun_config_socket(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) return -1;
	struct timeval timeout = { .tv_sec = 2 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int tun_save_config(int ifidx, int type, struct tun_saved_config **saved)
{
	int fd = tun_config_socket();
	if (fd < 0) return ERROR_REJECT;
	struct { struct nlmsghdr header; struct rtmsg data; } request = {
		.header = { .nlmsg_len = NLMSG_LENGTH(type == RTM_GETADDR ?
					sizeof(struct ifaddrmsg) : sizeof(struct rtmsg)),
					.nlmsg_type = type, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
					.nlmsg_seq = 1 },
		.data = { .rtm_family = AF_UNSPEC },
	};
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	if (sendto(fd, &request, request.header.nlmsg_len, 0,
			   (struct sockaddr *)&kernel, sizeof(kernel)) < 0) goto fail;
	for (int batches = 0; batches < 256; batches++) {
		_Alignas(struct nlmsghdr) char buffer[65536];
		struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
		ssize_t len = recvmsg(fd, &msg, 0);
		if (len <= 0 || (msg.msg_flags & MSG_TRUNC)) goto fail;
		for (struct nlmsghdr *n = (struct nlmsghdr *)buffer;
			 NLMSG_OK(n, len); n = NLMSG_NEXT(n, len)) {
			if (n->nlmsg_flags & NLM_F_DUMP_INTR) goto fail;
			if (n->nlmsg_type == NLMSG_DONE) { close(fd); return 0; }
			if (n->nlmsg_type == NLMSG_ERROR) goto fail;
			int belongs = 0;
			if (type == RTM_GETADDR && n->nlmsg_type == RTM_NEWADDR &&
				n->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg))) {
				struct ifaddrmsg *a = NLMSG_DATA(n);
				belongs = a->ifa_index == (unsigned int)ifidx;
			} else if (type == RTM_GETROUTE && n->nlmsg_type == RTM_NEWROUTE &&
					   n->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg))) {
				struct rtmsg *r = NLMSG_DATA(n);
				int remaining = RTM_PAYLOAD(n);
				for (struct rtattr *a = RTM_RTA(r); RTA_OK(a, remaining);
					 a = RTA_NEXT(a, remaining)) {
					if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= sizeof(int)) {
						int index;
						memcpy(&index, RTA_DATA(a), sizeof(index));
						belongs |= index == ifidx;
					} else if (a->rta_type == RTA_MULTIPATH) {
						int bytes = RTA_PAYLOAD(a);
						for (struct rtnexthop *nh = RTA_DATA(a); RTNH_OK(nh, bytes); nh = RTNH_NEXT(nh)) {
							belongs |= nh->rtnh_ifindex == ifidx;
							bytes -= RTNH_ALIGN(nh->rtnh_len);
						}
					}
				}
			}
			if (belongs) {
				struct tun_saved_config *item = malloc(offsetof(struct tun_saved_config, message) + n->nlmsg_len);
				if (!item) goto fail;
				memcpy(&item->message, n, n->nlmsg_len);
				item->next = *saved;
				*saved = item;
			}
		}
	}
fail:
	close(fd);
	slog(LOG_CRIT, "Cannot snapshot TUN configuration before initialization\n");
	return ERROR_REJECT;
}

static int tun_restore_config(struct tun_saved_config *saved)
{
	/* Addresses first, then routes including externally configured tables. */
	for (int type = RTM_NEWADDR; type <= RTM_NEWROUTE; type += RTM_NEWROUTE - RTM_NEWADDR) {
		for (struct tun_saved_config *item = saved; item; item = item->next) {
			struct nlmsghdr *n = &item->message;
			if (n->nlmsg_type != type) continue;
			/* Kernel-generated connected/local routes are recreated from the
			 * restored addresses; replaying their dump-only flags is invalid. */
			if (type == RTM_NEWROUTE) {
				struct rtmsg *route = NLMSG_DATA(n);
				if (route->rtm_protocol == RTPROT_KERNEL || (route->rtm_flags & RTM_F_CLONED))
					continue;
				/* LINKDOWN in a dump is observed state, not NEWROUTE input. */
				route->rtm_flags &= ~(0xffU & ~(RTNH_F_ONLINK | RTNH_F_PERVASIVE));
				int bytes = RTM_PAYLOAD(n);
				for (struct rtattr *attr = RTM_RTA(route); RTA_OK(attr, bytes); attr = RTA_NEXT(attr, bytes)) {
					if (attr->rta_type != RTA_MULTIPATH) continue;
					int remaining = RTA_PAYLOAD(attr);
					for (struct rtnexthop *nh = RTA_DATA(attr); RTNH_OK(nh, remaining); nh = RTNH_NEXT(nh)) {
						nh->rtnh_flags &= RTNH_F_ONLINK | RTNH_F_PERVASIVE;
						remaining -= RTNH_ALIGN(nh->rtnh_len);
					}
				}
			}
			int fd = tun_config_socket();
			if (fd < 0) return ERROR_REJECT;
			n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
			n->nlmsg_seq = 1;
			n->nlmsg_pid = 0;
			struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
			int ret = ERROR_REJECT;
			if (sendto(fd, n, n->nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) >= 0) {
				_Alignas(struct nlmsghdr) char buffer[4096];
				ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
				for (struct nlmsghdr *ack = (struct nlmsghdr *)buffer;
					 NLMSG_OK(ack, len); ack = NLMSG_NEXT(ack, len)) {
					if (ack->nlmsg_type == NLMSG_ERROR &&
						ack->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
						int error = ((struct nlmsgerr *)NLMSG_DATA(ack))->error;
						if (!error || error == -EEXIST) ret = 0;
						else slog(LOG_CRIT, "TUN configuration restore type=%d family=%d error=%d: %s\n",
								  type, *(unsigned char *)NLMSG_DATA(n), -error, strerror(-error));
					}
				}
			}
			close(fd);
			if (ret < 0) {
				slog(LOG_CRIT, "Cannot restore TUN address/route after initialization\n");
				return ret;
			}
		}
	}
	return 0;
}

int tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd = -1;
	int ifidx = 0;
	int restore_up = 0;
	struct tun_saved_config *saved = NULL;
	int attached_queues = 0;
	int created_persistent = 0;
	int want_vnet = !do_rmtun && gcfg.tun_offload != TUN_OFFLOAD_OFF;

	gcfg.tun_fd = -1;
	/* Namespace identity prevents independent containers with equal device
	 * names from contending. Keep the lock across daemonization and chroot. */
	struct stat ns;
	char lock_path[256];
	if (stat("/proc/self/ns/net", &ns) < 0)
		goto setup_fail;
	snprintf(lock_path, sizeof(lock_path), "/run/tayga-tun-%llu-%s.lock",
			 (unsigned long long)ns.st_ino, gcfg.tundev);
	tun_owner_lock = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (tun_owner_lock < 0 || flock(tun_owner_lock, LOCK_EX | LOCK_NB) < 0) {
		slog(LOG_CRIT, "Cannot obtain exclusive TUN ownership: %s\n", strerror(errno));
		if (tun_owner_lock >= 0) close(tun_owner_lock);
		tun_owner_lock = -1;
		goto setup_fail;
	}
	gcfg.tun_fd = open("/dev/net/tun", O_RDWR);
	if (gcfg.tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
				strerror(errno));
		goto setup_fail;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TAYGA_TUN_BASE_FLAGS;
	if (want_vnet) {
		ifr.ifr_flags |= IFF_VNET_HDR;
	}
	strcpy(ifr.ifr_name, gcfg.tundev);
	if (ioctl(gcfg.tun_fd, TUNSETIFF, &ifr) < 0) {
		if (want_vnet && gcfg.tun_offload == TUN_OFFLOAD_AUTO &&
			(errno == EINVAL || errno == EOPNOTSUPP)) {
			gcfg.tun_offload_errno = errno;
			slog(LOG_WARNING, "Unable to attach tun with IFF_VNET_HDR (%s), fallback to offload=off\n",
				strerror(errno));
			want_vnet = 0;
			gcfg.vnet_hdr_sz = 0;
			ifr.ifr_flags = TAYGA_TUN_BASE_FLAGS;
			if (ioctl(gcfg.tun_fd, TUNSETIFF, &ifr) < 0) {
				slog(LOG_CRIT, "Unable to attach tun device %s, aborting: %s\n",
					gcfg.tundev, strerror(errno));
				goto setup_fail;
			}
		} else {
			slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
					"%s\n", gcfg.tundev, strerror(errno));
			goto setup_fail;
		}
	}

	ifidx = if_nametoindex(gcfg.tundev);
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (!ifidx || fd < 0)
		goto setup_fail;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg.tundev);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		goto setup_fail;
	restore_up = !!(ifr.ifr_flags & IFF_UP);
	if (!do_rmtun && restore_up) {
		if (tun_save_config(ifidx, RTM_GETADDR, &saved) < 0 ||
			tun_save_config(ifidx, RTM_GETROUTE, &saved) < 0 ||
			netlink_set_if_flags(ifidx, 0, IFF_UP)) goto setup_fail;
	}
	close(fd);
	fd = -1;
	memset(&ifr, 0, sizeof(ifr));
	if (ioctl(gcfg.tun_fd, TUNGETIFF, &ifr) < 0) goto setup_fail;
	#ifdef TAYGA_EXPERIMENTAL_NAPI
	if (!do_rmtun && tun_verify_napi(gcfg.tun_fd, -1) < 0) goto setup_fail;
#endif
	want_vnet = !!(ifr.ifr_flags & IFF_VNET_HDR);
	gcfg.vnet_hdr_sz = 0;
	if (want_vnet && !do_rmtun) {
		int sz = 0;
		if (ioctl(gcfg.tun_fd, TUNGETVNETHDRSZ, &sz) < 0) {
			slog(LOG_CRIT, "Cannot verify TUN vnet header size: %s\n", strerror(errno));
			goto setup_fail;
		}
		if (sz != 10 && sz != 12) {
			slog(LOG_CRIT, "Unsupported TUN vnet header size %d (expected 10 or 12)\n", sz);
			goto setup_fail;
		}
		gcfg.vnet_hdr_sz = sz;
	}
	/* Removing a persistent interface does not require offload capability. */
	if (do_mktun && tun_negotiate(gcfg.tun_fd, NULL, 0, gcfg.tun_offload, want_vnet) < 0) {
		goto setup_fail;
	}

	if (do_mktun) {
		int was_persistent = !!(ifr.ifr_flags & IFF_PERSIST);
		if (ioctl(gcfg.tun_fd, TUNSETPERSIST, 1) < 0) {
			slog(LOG_CRIT, "Unable to set persist flag on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			goto setup_fail;
		}
		created_persistent = !was_persistent;
		if (ioctl(gcfg.tun_fd, TUNSETOWNER, 0) < 0) {
			slog(LOG_CRIT, "Unable to set owner on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			goto setup_fail;
		}
		if (ioctl(gcfg.tun_fd, TUNSETGROUP, 0) < 0) {
			slog(LOG_CRIT, "Unable to set group on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			goto setup_fail;
		}
		slog(LOG_NOTICE, "Created persistent tun device %s\n",
				gcfg.tundev);
		if (restore_up && (netlink_set_if_flags(ifidx, IFF_UP, IFF_UP) ||
						   tun_restore_config(saved))) goto setup_fail;
		tun_free_saved_config(saved); saved = NULL;
		close(gcfg.tun_fd); gcfg.tun_fd = -1;
		close(tun_owner_lock); tun_owner_lock = -1;
		return 0;
	} else if (do_rmtun) {
		if (ioctl(gcfg.tun_fd, TUNSETPERSIST, 0) < 0) {
			slog(LOG_CRIT, "Unable to clear persist flag on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			goto setup_fail;
		}
		slog(LOG_NOTICE, "Removed persistent tun device %s\n",
				gcfg.tundev);
		tun_free_saved_config(saved); saved = NULL;
		close(gcfg.tun_fd); gcfg.tun_fd = -1;
		close(tun_owner_lock); tun_owner_lock = -1;
		return 0;
	}

	if(set_nonblock(gcfg.tun_fd)) goto setup_fail;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		goto setup_fail;
	}

	/* Query MTU from tun adapter */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg.tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		goto setup_fail;
	}
	close(fd);
	fd = -1;

	/* MTU is less than 1280, not allowed */
	gcfg.mtu = ifr.ifr_mtu;
	if(gcfg.mtu < MTU_MIN) {
		slog(LOG_CRIT, "MTU of %d is too small, must be at least %d\n",
				gcfg.mtu, MTU_MIN);
		goto setup_fail;
	}

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg.tundev,
			gcfg.mtu);

	/* Get our own device ID for the tun setup operations */
	ifidx = if_nametoindex(gcfg.tundev);

	if (ifidx == 0) {
		slog(LOG_INFO, "Failed to get if idx from tun device %s\n",gcfg.tundev);
		goto setup_fail;
	}
	/* Setup multiqueue additional queues */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TAYGA_TUN_BASE_FLAGS;
	if (gcfg.vnet_hdr_sz > 0)
		ifr.ifr_flags |= IFF_VNET_HDR;
	strcpy(ifr.ifr_name, gcfg.tundev);
	for(int i = 0; i < gcfg.workers; i++) {
		gcfg.tun_fd_addl[i] = open("/dev/net/tun", O_RDWR);
		if (gcfg.tun_fd_addl[i] < 0) {
			slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
					strerror(errno));
			goto setup_fail;
		}
		attached_queues++;
		if (ioctl(gcfg.tun_fd_addl[i], TUNSETIFF, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
					"%s\n", gcfg.tundev, strerror(errno));
			goto setup_fail;
		}
#ifdef TAYGA_EXPERIMENTAL_NAPI
		if (tun_verify_napi(gcfg.tun_fd_addl[i], i) < 0) goto setup_fail;
#endif
		if (gcfg.vnet_hdr_sz) {
			int size = 0;
			if (ioctl(gcfg.tun_fd_addl[i], TUNGETVNETHDRSZ, &size) < 0 || size != gcfg.vnet_hdr_sz) {
				slog(LOG_CRIT, "Worker TUN queue %d has unverified header framing\n", i);
				goto setup_fail;
			}
		}
		if (set_nonblock(gcfg.tun_fd_addl[i]) < 0) {
			slog(LOG_CRIT, "Unable to make worker TUN queue %d nonblocking\n", i);
			goto setup_fail;
		}
	}

	unsigned char *pending = malloc(RECV_BUF_SIZE);
	if (!pending) goto setup_fail;
	int drained;
	for (drained = 0; drained < 1024; drained++) {
		ssize_t n = read(gcfg.tun_fd, pending, RECV_BUF_SIZE);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) { free(pending); goto setup_fail; }
	}
	free(pending);
	if (drained > 0) slog(LOG_WARNING, "Discarded %d queued packets while initializing TUN\n", drained);
	if (drained == 1024) {
		slog(LOG_CRIT, "TUN input did not quiesce during initialization\n");
		goto setup_fail;
	}
	if (tun_negotiate(gcfg.tun_fd, gcfg.tun_fd_addl, attached_queues,
					  gcfg.tun_offload, want_vnet) < 0)
		goto setup_fail;
	if (gcfg.tun_offload_effective == TUN_OFFLOAD_OFF && gcfg.tun_offload == TUN_OFFLOAD_AUTO) {
		slog(LOG_WARNING, "TUN fallback to offload=off (retaining negotiated framing)\n");
	}
	/* Bring tun device up */
	if(gcfg.tun_up || restore_up) {
		if(netlink_set_if_flags(ifidx,IFF_UP,IFF_UP)) goto setup_fail;
		slog(LOG_INFO, "Tun device %s is UP\n",gcfg.tundev);
	}

	if (restore_up && tun_restore_config(saved)) goto setup_fail;
	tun_free_saved_config(saved); saved = NULL;

	/* Add IPs to the tun dev */
	char addrbuf[INET6_ADDRSTRLEN];
	struct list_head *entry;
	list_for_each(entry, &gcfg.tun_ip4_list) {
		struct tun_ip4 *ip4;
		ip4 = list_entry(entry, struct tun_ip4, list);
		if(netlink_addr_modify(ifidx,AF_INET,&ip4->addr,
				ip4->prefix_len,1)) goto setup_fail;
		slog(LOG_INFO, "Added IPv4 address %s/%d to tun device %s\n",
			inet_ntop(AF_INET,&ip4->addr,addrbuf,INET6_ADDRSTRLEN),
			ip4->prefix_len,gcfg.tundev);
	}
	list_for_each(entry, &gcfg.tun_ip6_list) {
		struct tun_ip6 *ip6;
		ip6 = list_entry(entry, struct tun_ip6, list);
		if(netlink_addr_modify(ifidx,AF_INET6,&ip6->addr,
				ip6->prefix_len,1)) goto setup_fail;
		slog(LOG_INFO, "Added IPv6 address %s/%d to tun device %s\n",
			inet_ntop(AF_INET6,&ip6->addr,addrbuf,INET6_ADDRSTRLEN),
			ip6->prefix_len,gcfg.tundev);
	}

	/* Add routes to the tun dev */
	list_for_each(entry, &gcfg.tun_rt4_list) {
		struct tun_ip4 *ip4;
		ip4 = list_entry(entry, struct tun_ip4, list);
		if(netlink_route_dev_modify(ifidx,AF_INET,&ip4->addr,
				ip4->prefix_len,1)) goto setup_fail;
		slog(LOG_INFO, "Added IPv4 route %s/%d to tun device %s\n",
			inet_ntop(AF_INET,&ip4->addr,addrbuf,INET6_ADDRSTRLEN),
			ip4->prefix_len,gcfg.tundev);
	}
	list_for_each(entry, &gcfg.tun_rt6_list) {
		struct tun_ip6 *ip6;
		ip6 = list_entry(entry, struct tun_ip6, list);
		if(netlink_route_dev_modify(ifidx,AF_INET6,&ip6->addr,
				ip6->prefix_len,1)) goto setup_fail;
		slog(LOG_INFO, "Added IPv6 route %s/%d to tun device %s\n",
			inet_ntop(AF_INET6,&ip6->addr,addrbuf,INET6_ADDRSTRLEN),
			ip6->prefix_len,gcfg.tundev);
	}


	/* Disable queue of main tun if we have >0 workers */
	if(gcfg.workers > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_DETACH_QUEUE;
		if (ioctl(gcfg.tun_fd, TUNSETQUEUE, (void *)&ifr) < 0) {
			slog(LOG_CRIT, "Unable to detach main TUN queue: %s\n", strerror(errno));
			goto setup_fail;
		}
	}

	if (gcfg.tun_offload_flags) {
		if (gcfg.tun_has_uso)
			slog(LOG_INFO, "TUN offload active: vnet_hdr_sz=%d, TSO4|TSO6|CSUM|USO4|USO6 (experimental UDP USO)\n", gcfg.vnet_hdr_sz);
		else
			slog(LOG_INFO, "TUN offload active: vnet_hdr_sz=%d, TSO4|TSO6|CSUM (UDP USO disabled)\n", gcfg.vnet_hdr_sz);
	}
	slog(LOG_INFO, "TUN offload negotiated: requested=%s effective=%s vnet_hdr_sz=%d flags=0x%x reason=%s\n",
		 tun_offload_name(gcfg.tun_offload), tun_offload_name(gcfg.tun_offload_effective),
		 gcfg.vnet_hdr_sz, gcfg.tun_offload_flags, gcfg.tun_offload_reason);
	return 0;
setup_fail:
	if (created_persistent && gcfg.tun_fd >= 0) ioctl(gcfg.tun_fd, TUNSETPERSIST, 0);
	if (fd >= 0) close(fd);
	if (restore_up && ifidx && !do_rmtun) {
		if (!netlink_set_if_flags(ifidx, IFF_UP, IFF_UP)) tun_restore_config(saved);
	}
	tun_free_saved_config(saved);
	for (int i = 0; i < attached_queues; i++) {
		close(gcfg.tun_fd_addl[i]);
		gcfg.tun_fd_addl[i] = -1;
	}
	if (gcfg.tun_fd >= 0) close(gcfg.tun_fd);
	gcfg.tun_fd = -1;
	gcfg.tun_offload_complete = 0;
	if (tun_owner_lock >= 0) close(tun_owner_lock);
	tun_owner_lock = -1;
	return ERROR_REJECT;
}
#endif /* ifdef __linux__ */

#ifdef __FreeBSD__
int tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd, do_rename = 0, multi_af;
	char devname[64];

	if (gcfg.tun_offload == TUN_OFFLOAD_TCP || gcfg.tun_offload == TUN_OFFLOAD_UDP) {
		slog(LOG_CRIT, "TCP/UDP TUN offload requires Linux\n");
		return ERROR_REJECT;
	}
	gcfg.tun_offload_effective = TUN_OFFLOAD_OFF;
	gcfg.tun_offload_complete = 1;
	gcfg.vnet_hdr_sz = 0;

	if (strncmp(gcfg.tundev, "tun", 3))
		do_rename = 1;

	if ((do_mktun || do_rmtun) && do_rename)
	{
		slog(LOG_CRIT,
			"tunnel interface name needs to match tun[0-9]+ pattern "
				"for --mktun to work\n");
		return ERROR_REJECT;
	}

	snprintf(devname, sizeof(devname), "/dev/%s", do_rename ? "tun" : gcfg.tundev);

	gcfg.tun_fd = open(devname, O_RDWR);
	if (gcfg.tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open %s, aborting: %s\n",
				devname, strerror(errno));
		return ERROR_REJECT;
	}

	if (do_mktun) {
		slog(LOG_NOTICE, "Created persistent tun device %s\n",
				gcfg.tundev);
		return ERROR_NONE;
	} else if (do_rmtun) {

		/* Close socket before removal */
		close(gcfg.tun_fd);

		fd = socket(PF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			slog(LOG_CRIT, "Unable to create control socket, aborting: %s\n",
					strerror(errno));
			return ERROR_REJECT;
		}

		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, gcfg.tundev);
		if (ioctl(fd, SIOCIFDESTROY, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to destroy interface %s, aborting: %s\n",
					gcfg.tundev, strerror(errno));
			return ERROR_REJECT;
		}

		close(fd);

		slog(LOG_NOTICE, "Removed persistent tun device %s\n",
				gcfg.tundev);
		return ERROR_NONE;
	}

	/* Set multi-AF mode */
	multi_af = 1;
	if (ioctl(gcfg.tun_fd, TUNSIFHEAD, &multi_af) < 0) {
			slog(LOG_CRIT, "Unable to set multi-AF on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			return ERROR_REJECT;
	}

	slog(LOG_CRIT, "Multi-AF mode set on %s\n", gcfg.tundev);

	if(set_nonblock(gcfg.tun_fd)) return ERROR_REJECT;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}

	if (do_rename) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, fdevname(gcfg.tun_fd));
		ifr.ifr_data = gcfg.tundev;
		if (ioctl(fd, SIOCSIFNAME, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to rename interface %s to %s, aborting: %s\n",
					fdevname(gcfg.tun_fd), gcfg.tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg.tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}
	close(fd);

	gcfg.mtu = ifr.ifr_mtu;

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg.tundev,
			gcfg.mtu);
	return ERROR_NONE;
}
#endif


/* tun_write: Write a single contiguous packet buffer to the TUN device.
 * TUN devices are packet-based (datagram) interfaces. Each write must send exactly
 * one complete IP packet. Partial writes cannot be resumed with subsequent writes,
 * as each write syscall represents a separate network packet to the kernel.
 * Handles EINTR interrupts safely and detects truncated writes.
 */
ssize_t tun_write(int tun_fd, const void *buf, size_t len)
{
	if (unlikely(gcfg.vnet_hdr_sz > 0)) {
		struct virtio_net_hdr_raw vhdr;
		memset(&vhdr, 0, sizeof(vhdr));
		return tun_write_vnet(tun_fd, &vhdr, buf, len);
	}

	ssize_t ret;

	for (int attempt = 0; attempt < 5; attempt++) {
		ret = write(tun_fd, buf, len);
		if (likely(ret == (ssize_t)len)) {
			if (len > 0) {
				uint8_t ver = ((const uint8_t *)buf)[0] >> 4;
				if (ver == 4)
					stats_tx4((uint32_t)len);
				else if (ver == 6)
					stats_tx6((uint32_t)len);
			}
			return ret;
		}
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			int saved_errno = errno;
			stats_error();
			slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(saved_errno));
			errno = saved_errno;
			return -1;
		}
		/* Short write: packet was truncated by kernel/device.
		 * Do not attempt to append remainder; drop, set errno = EIO, and log warning. */
		stats_error();
		slog(LOG_WARNING, "short write to tun device: wrote %zd of %zu bytes\n",
			ret, len);
		errno = EIO;
		return -1;
	}
	int saved_errno = errno;
	stats_error();
	slog(LOG_WARNING, "error writing packet to tun device: %s\n",
		strerror(saved_errno));
	errno = saved_errno;
	return -1;
}

ssize_t tun_write_vnet(int tun_fd, const struct virtio_net_hdr_raw *vhdr, const void *buf, size_t len)
{
	if (gcfg.vnet_hdr_sz > 0) {
		struct iovec iov[2];
		iov[0].iov_base = (void *)vhdr;
		iov[0].iov_len = gcfg.vnet_hdr_sz;
		iov[1].iov_base = (void *)buf;
		iov[1].iov_len = len;
		return tun_writev(tun_fd, iov, 2);
	}
	return tun_write(tun_fd, buf, len);
}

/* tun_writev: Write vectored buffers to the TUN device.
 * Retries on EINTR (up to 5 attempts) and verifies total length matches written bytes.
 */
ssize_t tun_writev(int tun_fd, const struct iovec *iov, int iovcnt)
{
	if (unlikely(gcfg.vnet_hdr_sz > 0 && iov[0].iov_len != (size_t)gcfg.vnet_hdr_sz)) {
		struct virtio_net_hdr_raw vhdr;
		memset(&vhdr, 0, sizeof(vhdr));
		return tun_writev_vnet(tun_fd, &vhdr, iov, iovcnt);
	}

	size_t total_len = 0;
	ssize_t ret;

	for (int i = 0; i < iovcnt; i++)
		total_len += iov[i].iov_len;

	for (int attempt = 0; attempt < 5; attempt++) {
		ret = writev(tun_fd, iov, iovcnt);
		if (likely(ret == (ssize_t)total_len)) {
			int ip_idx = 0;
			if (gcfg.vnet_hdr_sz > 0 && iov[0].iov_len == (size_t)gcfg.vnet_hdr_sz)
				ip_idx = 1;
#ifndef __linux__
			else if (iov[0].iov_len == sizeof(struct tun_pi))
				ip_idx = 1;
#endif
			if (ip_idx < iovcnt && iov[ip_idx].iov_len > 0) {
				uint8_t ver = ((const uint8_t *)iov[ip_idx].iov_base)[0] >> 4;
				uint32_t ip_bytes = (uint32_t)(total_len - (ip_idx > 0 ? iov[0].iov_len : 0));
				if (ver == 4)
					stats_tx4(ip_bytes);
				else if (ver == 6)
					stats_tx6(ip_bytes);
			}
			return ret;
		}
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			int saved_errno = errno;
			stats_error();
			slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(saved_errno));
			errno = saved_errno;
			return -1;
		}
		/* Short write: packet was truncated */
		stats_error();
		slog(LOG_WARNING, "short writev to tun device: wrote %zd of %zu bytes\n",
			ret, total_len);
		errno = EIO;
		return -1;
	}
	int saved_errno = errno;
	stats_error();
	slog(LOG_WARNING, "error writing packet to tun device: %s\n",
		strerror(saved_errno));
	errno = saved_errno;
	return -1;
}

ssize_t tun_writev_vnet(int tun_fd, const struct virtio_net_hdr_raw *vhdr, const struct iovec *iov, int iovcnt)
{
	if (gcfg.vnet_hdr_sz > 0) {
		struct iovec iov_with_vnet[iovcnt + 1];
		iov_with_vnet[0].iov_base = (void *)vhdr;
		iov_with_vnet[0].iov_len = gcfg.vnet_hdr_sz;
		for (int i = 0; i < iovcnt; i++)
			iov_with_vnet[i + 1] = iov[i];
		return tun_writev(tun_fd, iov_with_vnet, iovcnt + 1);
	}
	return tun_writev(tun_fd, iov, iovcnt);
}


int tun_read_packet(uint8_t * recv_buf, int tun_fd)
{
	int ret;
	struct pkt pbuf, *p = &pbuf;
	uint8_t *read_ptr = recv_buf + HEADROOM;
	size_t read_len = RECV_BUF_SIZE - HEADROOM;

	if (gcfg.vnet_hdr_sz > 0) {
		read_ptr -= gcfg.vnet_hdr_sz;
		read_len += gcfg.vnet_hdr_sz;
	}

	ret = read(tun_fd, read_ptr, read_len);
	if (unlikely(ret < 0)) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return TUN_READ_WOULDBLOCK;
		if (errno == EINTR)
			return TUN_READ_INTR;
		stats_error();
		stats_packet_done();
		slog(LOG_ERR, "received error when reading from tun "
				"device: %s\n", strerror(errno));
		return TUN_READ_FATAL;
	}
	/* A full read buffer may have truncated a larger TUN frame. The allocation
	 * includes one byte beyond the largest supported ordinary IPv6 frame, so
	 * equality is an unambiguous overflow signal in both vnet and plain mode. */
	if (unlikely((size_t)ret == read_len)) {
		stats_drop((uint32_t)ret);
		stats_packet_done();
		slog(LOG_WARNING, "dropping oversized or truncated packet (%d bytes)\n", ret);
		return TUN_READ_CONSUMED;
	}

	if (gcfg.vnet_hdr_sz > 0) {
		if (unlikely(ret <= gcfg.vnet_hdr_sz)) {
			stats_drop(ret > 0 ? (uint32_t)ret : 0);
			stats_packet_done();
			slog(LOG_WARNING, "short read with vnet header (%d bytes)\n", ret);
			return TUN_READ_CONSUMED;
		}
		*p = (struct pkt){
			.tun_fd = tun_fd,
			.ip4 = NULL,
			.ip6 = NULL,
			.ip6_frag = NULL,
			.icmp = NULL,
			.data_proto = 0,
			.data = recv_buf + HEADROOM,
			.data_len = (uint32_t)(ret - gcfg.vnet_hdr_sz),
			.header_len = 0,
			.has_vhdr = 1,
		};
		memcpy(&p->vhdr, read_ptr, gcfg.vnet_hdr_sz);
	} else {
		if (unlikely(ret < 1)) {
			stats_drop(ret > 0 ? (uint32_t)ret : 0);
			stats_packet_done();
			slog(LOG_WARNING, "short read from tun device (%d bytes)\n", ret);
			return TUN_READ_CONSUMED;
		}
		*p = (struct pkt){
			.tun_fd = tun_fd,
			.ip4 = NULL,
			.ip6 = NULL,
			.ip6_frag = NULL,
			.icmp = NULL,
			.data_proto = 0,
			.data = recv_buf + HEADROOM,
			.data_len = (uint32_t)ret,
			.header_len = 0,
			.has_vhdr = 0,
		};
	}
#ifdef __linux__
	switch (p->data[0] >> 4) {
	case 4:
		stats_rx4(p->data_len);
		handle_ip4(p);
		break;
	case 6:
		stats_rx6(p->data_len);
		handle_ip6(p);
		break;
	default:
		stats_drop(p->data_len);
		slog(LOG_WARNING, "Dropping unknown IP version %u from "
				"tun device\n", p->data[0] >> 4);
		break;
	}
#else
	{
		struct tun_pi *pi = (struct tun_pi *)(recv_buf + HEADROOM);
		if ((size_t)ret < sizeof(struct tun_pi)) {
			stats_drop(ret > 0 ? (uint32_t)ret : 0);
			slog(LOG_WARNING, "short read from tun device (%d bytes)\n", ret);
			return TUN_READ_CONSUMED;
		}
		p->data = recv_buf + HEADROOM + sizeof(struct tun_pi);
		p->data_len = ret - sizeof(struct tun_pi);
		switch (TUN_GET_PROTO(pi)) {
		case ETH_P_IP:
			stats_rx4(p->data_len);
			handle_ip4(p);
			break;
		case ETH_P_IPV6:
			stats_rx6(p->data_len);
			handle_ip6(p);
			break;
		default:
			stats_drop(p->data_len);
			slog(LOG_WARNING, "Dropping unknown proto %04x from tun device\n",
					ntohs(pi->proto));
			break;
		}
	}
#endif
	stats_packet_done();
	return TUN_READ_CONSUMED;
}

void tun_read(uint8_t * recv_buf, int tun_fd)
{
	(void)tun_read_packet(recv_buf, tun_fd);
}
