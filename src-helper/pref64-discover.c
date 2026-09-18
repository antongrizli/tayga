/*
 *  pref64-discover.c -- RFC 7050 PREF64 Discovery Helper
 *
 *  Discovers the IPv6 prefix (PREF64) used for NAT64/DNS64 synthesis
 *  by querying synthesized AAAA records for ipv4only.arpa. (RFC 7050)
 *
 *  Copyright (C) 2026 Anton Grizli / TAYGA Contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DEFAULT_DOMAIN "ipv4only.arpa"
#define IPV4_WKA1_HEX 0xC00000AA /* 192.0.0.170 */
#define IPV4_WKA2_HEX 0xC00000AB /* 192.0.0.171 */

static const uint8_t wka1[4] = {192, 0, 0, 170};
static const uint8_t wka2[4] = {192, 0, 0, 171};

static int match_v4(const uint8_t *b0, const uint8_t *b1, const uint8_t *b2, const uint8_t *b3)
{
    if (*b0 == wka1[0] && *b1 == wka1[1] && *b2 == wka1[2] && *b3 == wka1[3])
        return 1;
    if (*b0 == wka2[0] && *b1 == wka2[1] && *b2 == wka2[2] && *b3 == wka2[3])
        return 1;
    return 0;
}

/*
 * Extracts RFC 6052 / RFC 7050 prefix from an IPv6 address.
 * Returns prefix length (32, 40, 48, 56, 64, 96) on success, or -1 if no WKA match.
 * Out prefix has the IPv4 and u-octet bits zeroed out.
 */
int extract_pref64(const struct in6_addr *in, struct in6_addr *out, int *prefix_len)
{
    const uint8_t *b = in->s6_addr;
    uint8_t res[16];
    memcpy(res, b, 16);

    /* /96: IPv4 at bytes 12..15 */
    if (match_v4(&b[12], &b[13], &b[14], &b[15])) {
        res[12] = res[13] = res[14] = res[15] = 0;
        *prefix_len = 96;
        memcpy(out->s6_addr, res, 16);
        return 96;
    }

    /* /64: byte 8 is u-octet (0), IPv4 at bytes 9..12, bytes 13..15 are 0 */
    if (match_v4(&b[9], &b[10], &b[11], &b[12])) {
        res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        *prefix_len = 64;
        memcpy(out->s6_addr, res, 16);
        return 64;
    }

    /* /56: IPv4 byte 0 at byte 7; byte 8 is u-octet (0); IPv4 bytes 1..3 at bytes 9..11 */
    if (match_v4(&b[7], &b[9], &b[10], &b[11])) {
        res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        *prefix_len = 56;
        memcpy(out->s6_addr, res, 16);
        return 56;
    }

    /* /48: IPv4 bytes 0..1 at bytes 6..7; byte 8 is u-octet (0); IPv4 bytes 2..3 at bytes 9..10 */
    if (match_v4(&b[6], &b[7], &b[9], &b[10])) {
        res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        *prefix_len = 48;
        memcpy(out->s6_addr, res, 16);
        return 48;
    }

    /* /40: IPv4 bytes 0..2 at bytes 5..7; byte 8 is u-octet (0); IPv4 byte 3 at byte 9 */
    if (match_v4(&b[5], &b[6], &b[7], &b[9])) {
        res[5] = res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        *prefix_len = 40;
        memcpy(out->s6_addr, res, 16);
        return 40;
    }

    /* /32: IPv4 bytes 0..3 at bytes 4..7; byte 8 is u-octet (0) */
    if (match_v4(&b[4], &b[5], &b[6], &b[7])) {
        res[4] = res[5] = res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        *prefix_len = 32;
        memcpy(out->s6_addr, res, 16);
        return 32;
    }

    return -1;
}

#ifndef PREF64_NO_MAIN
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-d domain] [--check ipv6_addr]\n", prog);
    fprintf(stderr, "Discovers NAT64/PLAT IPv6 prefix via RFC 7050.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d <domain>        Domain to query (default: ipv4only.arpa)\n");
    fprintf(stderr, "  -c, --check <ip>   Directly test IPv6 address without DNS lookup\n");
    fprintf(stderr, "  -h, --help         Show this help message\n");
}

int main(int argc, char **argv)
{
    const char *domain = DEFAULT_DOMAIN;
    const char *check_ip = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") && i + 1 < argc) {
            domain = argv[++i];
        } else if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--check")) && i + 1 < argc) {
            check_ip = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (check_ip) {
        struct in6_addr in, out;
        int plen = 0;
        if (inet_pton(AF_INET6, check_ip, &in) != 1) {
            fprintf(stderr, "Error: invalid IPv6 address: %s\n", check_ip);
            return 1;
        }
        if (extract_pref64(&in, &out, &plen) < 0) {
            fprintf(stderr, "Error: no RFC 7050 well-known address found in %s\n", check_ip);
            return 1;
        }
        char pbuf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &out, pbuf, sizeof(pbuf))) {
            fprintf(stderr, "Error: inet_ntop failed\n");
            return 1;
        }
        printf("%s/%d\n", pbuf, plen);
        return 0;
    }

    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(domain, NULL, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "RFC 7050 DNS lookup failed for %s: %s\n", domain, gai_strerror(err));
        return 1;
    }

    struct in6_addr out;
    int plen = 0;
    int found = 0;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)rp->ai_addr;
            if (extract_pref64(&sin6->sin6_addr, &out, &plen) >= 0) {
                char pbuf[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &out, pbuf, sizeof(pbuf))) {
                    printf("%s/%d\n", pbuf, plen);
                    found = 1;
                    break;
                }
            }
        }
    }

    freeaddrinfo(res);

    if (!found) {
        fprintf(stderr, "RFC 7050: no synthesized NAT64 prefix found in DNS response for %s\n", domain);
        return 1;
    }

    return 0;
}
#endif
