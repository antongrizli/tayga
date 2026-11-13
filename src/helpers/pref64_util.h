/*
 *  pref64_util.h -- Small helpers shared by the pref64-discover modules.
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PREF64_UTIL_H
#define PREF64_UTIL_H

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Skip a wire-format DNS name without following compression pointers. */
static inline ssize_t skip_dns_name(const uint8_t *resp, size_t rlen, size_t pos)
{
    size_t length = 0;
    while (pos < rlen) {
        uint8_t b = resp[pos++];
        if (!b) return (ssize_t)pos;
        if ((b & 0xc0) == 0xc0)
            return pos < rlen ? (ssize_t)(pos + 1) : -1;
        if ((b & 0xc0) || pos + b > rlen || (length += b + 1) > 255)
            return -1;
        pos += b;
    }
    return -1;
}

static inline int parse_prefix_spec(const char *spec, struct in6_addr *prefix, int *prefix_len)
{
    if (!spec || !prefix || !prefix_len)
        return -1;
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *slash = strchr(buf, '/');
    int plen = 96;
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long val = strtol(slash + 1, &end, 10);
        if (!slash[1] || (end && *end != '\0') || val < 32 || val > 96)
            return -1;
        plen = (int)val;
    }
    if (plen != 32 && plen != 40 && plen != 48 && plen != 56 && plen != 64 && plen != 96)
        return -1;
    if (inet_pton(AF_INET6, buf, prefix) != 1)
        return -1;
    *prefix_len = plen;
    return 0;
}

#endif
