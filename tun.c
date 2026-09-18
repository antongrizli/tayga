/*
 *  tun.c -- tunnel interface routines
 *
 *  part of TAYGA <https://github.com/antongrizli/tayga>
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
#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
	snprintf(ifr.ifr_name, IFNAMSIZ, "tun_chk_%d", (int)getpid());
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		printf("OFFLOAD_CHECK: FAIL (IFF_VNET_HDR ioctl failed: %s)\n", strerror(errno));
		close(fd);
		return 1;
	}
	int sz = 0;
	if (ioctl(fd, TUNGETVNETHDRSZ, &sz) < 0) {
		sz = 10;
	}
	unsigned int offload_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
	if (ioctl(fd, TUNSETOFFLOAD, offload_flags) < 0) {
		printf("OFFLOAD_CHECK: FAIL (TUNSETOFFLOAD ioctl failed: %s)\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);
	printf("OFFLOAD_CHECK: OK (IFF_VNET_HDR supported, vnet_hdr_sz=%d, TSO4|TSO6|CSUM available)\n", sz);
	return 0;
#else
	printf("OFFLOAD_CHECK: NOT_SUPPORTED (Linux TUN only)\n");
	return 1;
#endif
}

int tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd;

	gcfg.tun_fd = open("/dev/net/tun", O_RDWR);
	if (gcfg.tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	if (gcfg.tun_offload != TUN_OFFLOAD_OFF) {
		ifr.ifr_flags |= IFF_VNET_HDR;
	}
	strcpy(ifr.ifr_name, gcfg.tundev);
	if (ioctl(gcfg.tun_fd, TUNSETIFF, &ifr) < 0) {
		if (gcfg.tun_offload == TUN_OFFLOAD_AUTO) {
			slog(LOG_WARNING, "Unable to attach tun with IFF_VNET_HDR (%s), falling back to offload=off\n",
				strerror(errno));
			gcfg.tun_offload = TUN_OFFLOAD_OFF;
			gcfg.vnet_hdr_sz = 0;
			ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
			if (ioctl(gcfg.tun_fd, TUNSETIFF, &ifr) < 0) {
				slog(LOG_CRIT, "Unable to attach tun device %s, aborting: %s\n",
					gcfg.tundev, strerror(errno));
				return ERROR_REJECT;
			}
		} else {
			slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
					"%s\n", gcfg.tundev, strerror(errno));
			return ERROR_REJECT;
		}
	}

	if (gcfg.tun_offload != TUN_OFFLOAD_OFF) {
		int sz = 0;
		if (ioctl(gcfg.tun_fd, TUNGETVNETHDRSZ, &sz) < 0) {
			slog(LOG_WARNING, "TUNGETVNETHDRSZ failed (%s), defaulting to 10 bytes\n", strerror(errno));
			sz = 10;
		}
		gcfg.vnet_hdr_sz = sz;

		unsigned int offload_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
		if (ioctl(gcfg.tun_fd, TUNSETOFFLOAD, offload_flags) < 0) {
			if (gcfg.tun_offload == TUN_OFFLOAD_AUTO) {
				slog(LOG_WARNING, "TUNSETOFFLOAD failed (%s), re-opening clean tun without offload\n", strerror(errno));
				close(gcfg.tun_fd);
				gcfg.tun_fd = open("/dev/net/tun", O_RDWR);
				if (gcfg.tun_fd < 0) {
					slog(LOG_CRIT, "Unable to re-open /dev/net/tun: %s\n", strerror(errno));
					return ERROR_REJECT;
				}
				memset(&ifr, 0, sizeof(ifr));
				ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
				strcpy(ifr.ifr_name, gcfg.tundev);
				if (ioctl(gcfg.tun_fd, TUNSETIFF, &ifr) < 0) {
					slog(LOG_CRIT, "Unable to re-attach tun without offload: %s\n", strerror(errno));
					return ERROR_REJECT;
				}
				gcfg.tun_offload = TUN_OFFLOAD_OFF;
				gcfg.vnet_hdr_sz = 0;
			} else {
				slog(LOG_CRIT, "TUNSETOFFLOAD failed: %s, aborting\n", strerror(errno));
				return ERROR_REJECT;
			}
		} else {
			slog(LOG_INFO, "TUN offload active: vnet_hdr_sz=%d, TSO4|TSO6|CSUM\n", gcfg.vnet_hdr_sz);
		}
	} else {
		gcfg.vnet_hdr_sz = 0;
	}

	if (do_mktun) {
		if (ioctl(gcfg.tun_fd, TUNSETPERSIST, 1) < 0) {
			slog(LOG_CRIT, "Unable to set persist flag on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		if (ioctl(gcfg.tun_fd, TUNSETOWNER, 0) < 0) {
			slog(LOG_CRIT, "Unable to set owner on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		if (ioctl(gcfg.tun_fd, TUNSETGROUP, 0) < 0) {
			slog(LOG_CRIT, "Unable to set group on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		slog(LOG_NOTICE, "Created persistent tun device %s\n",
				gcfg.tundev);
		return 0;
	} else if (do_rmtun) {
		if (ioctl(gcfg.tun_fd, TUNSETPERSIST, 0) < 0) {
			slog(LOG_CRIT, "Unable to clear persist flag on %s, "
					"aborting: %s\n", gcfg.tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		slog(LOG_NOTICE, "Removed persistent tun device %s\n",
				gcfg.tundev);
		return 0;
	}

	if(set_nonblock(gcfg.tun_fd)) return ERROR_REJECT;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}

	/* Query MTU from tun adapter */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg.tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}
	close(fd);

	/* MTU is less than 1280, not allowed */
	gcfg.mtu = ifr.ifr_mtu;
	if(gcfg.mtu < MTU_MIN) {
		slog(LOG_CRIT, "MTU of %d is too small, must be at least %d\n",
				gcfg.mtu, MTU_MIN);
		return ERROR_REJECT;
	}

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg.tundev,
			gcfg.mtu);

	/* Get our own device ID for the tun setup operations */
	int ifidx = if_nametoindex(gcfg.tundev);

    if (ifidx == 0) {
		slog(LOG_INFO, "Failed to get if idx from tun device %s\n",gcfg.tundev);
		return ERROR_REJECT;
    }
	/* Bring tun device up */
	if(gcfg.tun_up) {
		if(netlink_set_if_flags(ifidx,IFF_UP,IFF_UP)) return ERROR_REJECT;
		slog(LOG_INFO, "Tun device %s is UP\n",gcfg.tundev);
	}

	/* Add IPs to the tun dev */
	char addrbuf[INET6_ADDRSTRLEN];
	struct list_head *entry;
	list_for_each(entry, &gcfg.tun_ip4_list) {
		struct tun_ip4 *ip4;
		ip4 = list_entry(entry, struct tun_ip4, list);
		if(netlink_addr_modify(ifidx,AF_INET,&ip4->addr,
				ip4->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv4 address %s/%d to tun device %s\n",
			inet_ntop(AF_INET,&ip4->addr,addrbuf,INET6_ADDRSTRLEN),
			ip4->prefix_len,gcfg.tundev);
	}
	list_for_each(entry, &gcfg.tun_ip6_list) {
		struct tun_ip6 *ip6;
		ip6 = list_entry(entry, struct tun_ip6, list);
		if(netlink_addr_modify(ifidx,AF_INET6,&ip6->addr,
				ip6->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv6 address %s/%d to tun device %s\n",
			inet_ntop(AF_INET6,&ip6->addr,addrbuf,INET6_ADDRSTRLEN),
			ip6->prefix_len,gcfg.tundev);
	}

	/* Add routes to the tun dev */
	list_for_each(entry, &gcfg.tun_rt4_list) {
		struct tun_ip4 *ip4;
		ip4 = list_entry(entry, struct tun_ip4, list);
		if(netlink_route_dev_modify(ifidx,AF_INET,&ip4->addr,
				ip4->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv4 route %s/%d to tun device %s\n",
			inet_ntop(AF_INET,&ip4->addr,addrbuf,INET6_ADDRSTRLEN),
			ip4->prefix_len,gcfg.tundev);
	}
	list_for_each(entry, &gcfg.tun_rt6_list) {
		struct tun_ip6 *ip6;
		ip6 = list_entry(entry, struct tun_ip6, list);
		if(netlink_route_dev_modify(ifidx,AF_INET6,&ip6->addr,
				ip6->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv6 route %s/%d to tun device %s\n",
			inet_ntop(AF_INET6,&ip6->addr,addrbuf,INET6_ADDRSTRLEN),
			ip6->prefix_len,gcfg.tundev);
	}

	/* Setup multiqueue additional queues */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	if (gcfg.vnet_hdr_sz > 0)
		ifr.ifr_flags |= IFF_VNET_HDR;
	strcpy(ifr.ifr_name, gcfg.tundev);
	for(int i = 0; i < gcfg.workers; i++) {
		gcfg.tun_fd_addl[i] = open("/dev/net/tun", O_RDWR);
		if (gcfg.tun_fd_addl[i] < 0) {
			slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
					strerror(errno));
			exit(1);
		}
		if (ioctl(gcfg.tun_fd_addl[i], TUNSETIFF, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
					"%s\n", gcfg.tundev, strerror(errno));
			exit(1);
		}
		if (gcfg.vnet_hdr_sz > 0) {
			unsigned int offload_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
			ioctl(gcfg.tun_fd_addl[i], TUNSETOFFLOAD, offload_flags);
		}
	}

	/* Disable queue of main tun if we have >0 workers */
	if(gcfg.workers > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_DETACH_QUEUE;
		if(ioctl(gcfg.tun_fd, TUNSETQUEUE, (void *)&ifr)) slog(LOG_CRIT,"Unable to detach main queue\n");
	}

	//No error on setup
    return 0;
}
#endif /* ifdef __linux__ */

#ifdef __FreeBSD__
int tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd, do_rename = 0, multi_af;
	char devname[64];

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
		if (likely(ret == (ssize_t)len))
			return ret;
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			int saved_errno = errno;
			slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(saved_errno));
			errno = saved_errno;
			return -1;
		}
		/* Short write: packet was truncated by kernel/device.
		 * Do not attempt to append remainder; drop, set errno = EIO, and log warning. */
		slog(LOG_WARNING, "short write to tun device: wrote %zd of %zu bytes\n",
			ret, len);
		errno = EIO;
		return -1;
	}
	int saved_errno = errno;
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
		if (likely(ret == (ssize_t)total_len))
			return ret;
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			int saved_errno = errno;
			slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(saved_errno));
			errno = saved_errno;
			return -1;
		}
		/* Short write: packet was truncated */
		slog(LOG_WARNING, "short writev to tun device: wrote %zd of %zu bytes\n",
			ret, total_len);
		errno = EIO;
		return -1;
	}
	int saved_errno = errno;
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


void tun_read(uint8_t * recv_buf,int tun_fd)
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
		if (errno == EAGAIN)
			return;
		slog(LOG_ERR, "received error when reading from tun "
				"device: %s\n", strerror(errno));
		return;
	}

	if (gcfg.vnet_hdr_sz > 0) {
		if (unlikely(ret <= gcfg.vnet_hdr_sz)) {
			slog(LOG_WARNING, "short read with vnet header (%d bytes)\n", ret);
			return;
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
			slog(LOG_WARNING, "short read from tun device (%d bytes)\n", ret);
			return;
		}
		if (unlikely((uint32_t)ret == (RECV_BUF_SIZE - HEADROOM))) {
			slog(LOG_WARNING, "dropping oversized packet\n");
			return;
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
		handle_ip4(p);
		break;
	case 6:
		handle_ip6(p);
		break;
	default:
		slog(LOG_WARNING, "Dropping unknown IP version %u from "
				"tun device\n", p->data[0] >> 4);
		break;
	}
#else
	{
		struct tun_pi *pi = (struct tun_pi *)(recv_buf + HEADROOM);
		if ((size_t)ret < sizeof(struct tun_pi)) {
			slog(LOG_WARNING, "short read from tun device (%d bytes)\n", ret);
			return;
		}
		p->data = recv_buf + HEADROOM + sizeof(struct tun_pi);
		p->data_len = ret - sizeof(struct tun_pi);
		switch (TUN_GET_PROTO(pi)) {
		case ETH_P_IP:
			handle_ip4(p);
			break;
		case ETH_P_IPV6:
			handle_ip6(p);
			break;
		default:
			slog(LOG_WARNING, "Dropping unknown proto %04x from tun device\n",
					ntohs(pi->proto));
			break;
		}
	}
#endif
}
