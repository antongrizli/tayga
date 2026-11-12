/*
 *  ra_supervisor.h -- RFC 8781 Router Advertisement discovery and the
 *  --supervise-ra translator supervisor used by pref64-discover.
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RA_SUPERVISOR_H
#define RA_SUPERVISOR_H

#include <netinet/in.h>
#include <stdint.h>

int supervise_ra(int argc, char **argv);
#if defined(__linux__) || defined(__FreeBSD__)
int discover_ra_pref64(const char *ifname, int timeout_sec, struct in6_addr *out,
                       int *plen, uint32_t *lifetime);
#endif

#endif
