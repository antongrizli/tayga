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

#include <fcntl.h>
#include <strings.h>

/*
 * Parses and validates DNS response packet for RFC 7050 discovery.
 * Validates transaction ID, QR=1, TC=0, RCODE=0, QNAME, QTYPE=AAAA, QCLASS=IN,
 * and extracts synthesized IPv6 NAT64 prefix from AAAA answers.
 * Returns 0 on success (with out and prefix_len filled), or -1 on error/mismatch.
 */
int parse_dns_response(const uint8_t *resp, size_t rlen, uint16_t expected_id,
                       const char *expected_domain, struct in6_addr *out, int *prefix_len)
{
    if (!resp || rlen < 12 || !expected_domain || !out || !prefix_len)
        return -1;

    uint16_t id = ((uint16_t)resp[0] << 8) | resp[1];
    if (id != expected_id)
        return -1;

    /* QR must be 1 (response) */
    if (!(resp[2] & 0x80))
        return -1;

    /* TC must be 0 (not truncated) */
    if (resp[2] & 0x02)
        return -1;

    /* RCODE must be 0 (NoError) */
    if ((resp[3] & 0x0F) != 0)
        return -1;

    uint16_t qdcount = ((uint16_t)resp[4] << 8) | resp[5];
    if (qdcount < 1)
        return -1;

    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    if (ancount < 1)
        return -1;

    /* Validate Question: QNAME must match expected_domain */
    size_t pos = 12;
    const char *cur = expected_domain;
    while (pos < rlen && resp[pos] != 0) {
        if ((resp[pos] & 0xC0) != 0)
            return -1; /* Compressed pointers not accepted in query question */
        uint8_t llen = resp[pos++];
        if (pos + llen > rlen)
            return -1;

        const char *dot = strchr(cur, '.');
        size_t cur_len = dot ? (size_t)(dot - cur) : strlen(cur);
        if (cur_len == 0 || cur_len != llen || strncasecmp((const char *)&resp[pos], cur, llen) != 0)
            return -1;

        pos += llen;
        cur = dot ? (dot + 1) : (cur + cur_len);
    }

    if (pos >= rlen || resp[pos] != 0)
        return -1;
    pos++; /* Skip terminating 0 */

    if (*cur != '\0' && strcmp(cur, ".") != 0)
        return -1;

    /* Check QTYPE and QCLASS */
    if (pos + 4 > rlen)
        return -1;
    uint16_t qtype = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
    uint16_t qclass = ((uint16_t)resp[pos + 2] << 8) | resp[pos + 3];
    pos += 4;

    if (qtype != 28 /* AAAA */ || qclass != 1 /* IN */)
        return -1;

    /* Skip any remaining questions if qdcount > 1 */
    for (uint16_t q = 1; q < qdcount; q++) {
        while (pos < rlen && resp[pos] != 0) {
            if ((resp[pos] & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += 1 + resp[pos];
        }
        if (pos < rlen && resp[pos] == 0)
            pos++;
        if (pos + 4 > rlen)
            return -1;
        pos += 4;
    }

    /* Iterate through answers */
    for (uint16_t i = 0; i < ancount && pos < rlen; i++) {
        while (pos < rlen) {
            if ((resp[pos] & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            if (resp[pos] == 0) {
                pos++;
                break;
            }
            pos += 1 + resp[pos];
        }
        if (pos + 10 > rlen)
            break;

        uint16_t atype = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
        uint16_t aclass = ((uint16_t)resp[pos + 2] << 8) | resp[pos + 3];
        uint16_t rdlen = ((uint16_t)resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;

        if (pos + rdlen > rlen)
            break;

        if (atype == 28 /* AAAA */ && aclass == 1 /* IN */ && rdlen == 16) {
            struct in6_addr in6;
            memcpy(&in6.s6_addr, &resp[pos], 16);
            if (extract_pref64(&in6, out, prefix_len) >= 0)
                return 0;
        }
        pos += rdlen;
    }

    return -1;
}

#ifndef PREF64_NO_MAIN
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-s dns_server] [-t timeout_sec] [-d domain] [--check ipv6_addr]\n", prog);
    fprintf(stderr, "Discovers NAT64/PLAT IPv6 prefix via RFC 7050.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -s <server>        DNS server to query directly (IPv4 or IPv6)\n");
    fprintf(stderr, "  -t <timeout>       Query timeout in seconds (default: 3)\n");
    fprintf(stderr, "  -d <domain>        Domain to query (default: ipv4only.arpa)\n");
    fprintf(stderr, "  -c, --check <ip>   Directly test IPv6 address without DNS lookup\n");
    fprintf(stderr, "  -h, --help         Show this help message\n");
}

static int query_dns_server(const char *server, const char *domain, int timeout_sec, struct in6_addr *out, int *prefix_len)
{
    uint8_t qname[256];
    size_t qpos = 0;
    const char *label_start = domain;
    while (*label_start) {
        const char *dot = strchr(label_start, '.');
        size_t len = dot ? (size_t)(dot - label_start) : strlen(label_start);
        if (len == 0 || len > 63 || qpos + 1 + len >= sizeof(qname))
            return -1;
        qname[qpos++] = (uint8_t)len;
        memcpy(&qname[qpos], label_start, len);
        qpos += len;
        if (!dot) break;
        label_start = dot + 1;
    }
    qname[qpos++] = 0;

    uint16_t tx_id = 0;
    int rnd_fd = open("/dev/urandom", O_RDONLY);
    if (rnd_fd >= 0) {
        if (read(rnd_fd, &tx_id, sizeof(tx_id)) != sizeof(tx_id))
            tx_id = (uint16_t)(rand() ^ (getpid() << 8));
        close(rnd_fd);
    } else {
        tx_id = (uint16_t)(rand() ^ (getpid() << 8));
    }

    uint8_t packet[512];
    memset(packet, 0, sizeof(packet));
    packet[0] = (uint8_t)(tx_id >> 8);
    packet[1] = (uint8_t)(tx_id & 0xFF);
    packet[2] = 0x01; packet[3] = 0x00; /* RD=1 */
    packet[4] = 0x00; packet[5] = 0x01; /* QDCOUNT=1 */

    size_t plen = 12;
    memcpy(&packet[plen], qname, qpos);
    plen += qpos;
    packet[plen++] = 0x00; packet[plen++] = 0x1c; /* QTYPE=AAAA (28) */
    packet[plen++] = 0x00; packet[plen++] = 0x01; /* QCLASS=IN (1) */

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(server, "53", &hints, &res) != 0 || !res)
        return -1;

    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(fd);
        return -1;
    }
    freeaddrinfo(res);

    ssize_t sent = send(fd, packet, plen, 0);
    if (sent != (ssize_t)plen) {
        close(fd);
        return -1;
    }

    uint8_t resp[1024];
    ssize_t rlen = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (rlen < 12)
        return -1;

    return parse_dns_response(resp, (size_t)rlen, tx_id, domain, out, prefix_len);
}

int main(int argc, char **argv)
{
    const char *domain = DEFAULT_DOMAIN;
    const char *check_ip = NULL;
    const char *dns_server = NULL;
    int timeout_sec = 3;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") && i + 1 < argc) {
            domain = argv[++i];
        } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
            dns_server = argv[++i];
        } else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
            if (timeout_sec <= 0) timeout_sec = 3;
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

    struct in6_addr out;
    int plen = 0;

    if (dns_server) {
        if (query_dns_server(dns_server, domain, timeout_sec, &out, &plen) == 0) {
            char pbuf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &out, pbuf, sizeof(pbuf))) {
                printf("%s/%d\n", pbuf, plen);
                return 0;
            }
        }
        fprintf(stderr, "RFC 7050: query to DNS server %s for %s failed or no NAT64 prefix found\n", dns_server, domain);
        return 1;
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
