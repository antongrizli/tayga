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
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <strings.h>
#include <time.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#endif

#define DNS_ERR_TRUNCATED (-2)
#ifndef PREF64_DNS_PORT
#define PREF64_DNS_PORT "53"
#endif
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

    /* Exclude unspecified/IPv4-compatible, multicast and link-local space. */
    static const uint8_t zero80[10] = {0};
    static const uint8_t zero_prefix[16] = {0};
    if ((memcmp(b, zero80, sizeof(zero80)) == 0 &&
         ((b[10] == 0 && b[11] == 0) || (b[10] == 0xff && b[11] == 0xff))) ||
        b[0] == 0xff || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80))
        return -1;

    /* /96: IPv4 at bytes 12..15 */
    if (match_v4(&b[12], &b[13], &b[14], &b[15])) {
        res[12] = res[13] = res[14] = res[15] = 0;
        if (memcmp(res, zero_prefix, sizeof(res)) == 0)
            return -1;
        *prefix_len = 96;
        memcpy(out->s6_addr, res, 16);
        return 96;
    }

    /* /64: byte 8 is u-octet (0), IPv4 at bytes 9..12, bytes 13..15 are 0 */
    if (match_v4(&b[9], &b[10], &b[11], &b[12])) {
        res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        if (memcmp(res, zero_prefix, sizeof(res)) == 0)
            return -1;
        *prefix_len = 64;
        memcpy(out->s6_addr, res, 16);
        return 64;
    }

    /* /56: IPv4 byte 0 at byte 7; byte 8 is u-octet (0); IPv4 bytes 1..3 at bytes 9..11 */
    if (match_v4(&b[7], &b[9], &b[10], &b[11])) {
        res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        if (memcmp(res, zero_prefix, sizeof(res)) == 0)
            return -1;
        *prefix_len = 56;
        memcpy(out->s6_addr, res, 16);
        return 56;
    }

    /* /48: IPv4 bytes 0..1 at bytes 6..7; byte 8 is u-octet (0); IPv4 bytes 2..3 at bytes 9..10 */
    if (match_v4(&b[6], &b[7], &b[9], &b[10])) {
        res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        if (memcmp(res, zero_prefix, sizeof(res)) == 0)
            return -1;
        *prefix_len = 48;
        memcpy(out->s6_addr, res, 16);
        return 48;
    }

    /* /40: IPv4 bytes 0..2 at bytes 5..7; byte 8 is u-octet (0); IPv4 byte 3 at byte 9 */
    if (match_v4(&b[5], &b[6], &b[7], &b[9])) {
        res[5] = res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        if (memcmp(res, zero_prefix, sizeof(res)) == 0)
            return -1;
        *prefix_len = 40;
        memcpy(out->s6_addr, res, 16);
        return 40;
    }

    /* /32: IPv4 bytes 0..3 at bytes 4..7; byte 8 is u-octet (0) */
    if (match_v4(&b[4], &b[5], &b[6], &b[7])) {
        res[4] = res[5] = res[6] = res[7] = res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        if (memcmp(res, zero_prefix, sizeof(res)) == 0)
            return -1;
        *prefix_len = 32;
        memcpy(out->s6_addr, res, 16);
        return 32;
    }

    return -1;
}

/*
 * Synthesizes an IPv6 address from a NAT64 prefix and 4-byte IPv4 address per RFC 6052.
 * Supports prefix lengths 32, 40, 48, 56, 64, 96.
 * Returns 0 on success or -1 on invalid input.
 */
int synthesize_pref64(const struct in6_addr *prefix, int prefix_len, const uint8_t ipv4[4], struct in6_addr *out)
{
    if (!prefix || !ipv4 || !out)
        return -1;

    uint8_t res[16];
    memcpy(res, prefix->s6_addr, 16);

    switch (prefix_len) {
    case 96:
        res[12] = ipv4[0];
        res[13] = ipv4[1];
        res[14] = ipv4[2];
        res[15] = ipv4[3];
        break;
    case 64:
        res[8] = 0;
        res[9] = ipv4[0];
        res[10] = ipv4[1];
        res[11] = ipv4[2];
        res[12] = ipv4[3];
        res[13] = res[14] = res[15] = 0;
        break;
    case 56:
        res[7] = ipv4[0];
        res[8] = 0;
        res[9] = ipv4[1];
        res[10] = ipv4[2];
        res[11] = ipv4[3];
        res[12] = res[13] = res[14] = res[15] = 0;
        break;
    case 48:
        res[6] = ipv4[0];
        res[7] = ipv4[1];
        res[8] = 0;
        res[9] = ipv4[2];
        res[10] = ipv4[3];
        res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        break;
    case 40:
        res[5] = ipv4[0];
        res[6] = ipv4[1];
        res[7] = ipv4[2];
        res[8] = 0;
        res[9] = ipv4[3];
        res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        break;
    case 32:
        res[4] = ipv4[0];
        res[5] = ipv4[1];
        res[6] = ipv4[2];
        res[7] = ipv4[3];
        res[8] = res[9] = res[10] = res[11] = res[12] = res[13] = res[14] = res[15] = 0;
        break;
    default:
        return -1;
    }

    memcpy(out->s6_addr, res, 16);
    return 0;
}

/* Skip a wire-format DNS name without following compression pointers. */
static ssize_t skip_dns_name(const uint8_t *resp, size_t rlen, size_t pos)
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

/*
 * Parses and validates DNS response packet for RFC 7050 discovery.
 * Validates transaction ID, QR=1, TC=0, RCODE=0, QNAME, QTYPE=AAAA, QCLASS=IN,
 * and extracts synthesized IPv6 NAT64 prefix from AAAA answers.
 * Returns 0 on success, DNS_ERR_TRUNCATED for TC=1, or -1 on error/mismatch.
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

    /* A truncated response may omit the question and answers. */
    if (resp[2] & 0x02)
        return DNS_ERR_TRUNCATED;

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
        ssize_t next = skip_dns_name(resp, rlen, pos);
        if (next < 0) return -1;
        pos = (size_t)next;
        if (pos + 4 > rlen)
            return -1;
        pos += 4;
    }

    /* Iterate through answers */
    for (uint16_t i = 0; i < ancount && pos < rlen; i++) {
        ssize_t next = skip_dns_name(resp, rlen, pos);
        if (next < 0) return -1;
        pos = (size_t)next;
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
static const char *const DEFAULT_PUBLIC_DNS64_SERVERS[] = {
    "2a00:1098:2c::1",       /* nat64.net Europe (London) */
    "2a01:4f8:c2c:123f::1",  /* nat64.net Europe (Nuremberg) */
    "2a01:4f9:c010:3f02::1", /* nat64.net Europe (Helsinki) */
    "2a00:1098:2b::1",       /* nat64.net Europe (Amsterdam) */
    "2001:67c:2b0::4",       /* Tuxli Switzerland */
    "2001:67c:2b0::6",       /* Tuxli Switzerland */
    NULL
};

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-s dns_server] [-t timeout_sec] [-d domain] [--check ipv6_addr] [-p] [-v] [--json]\n", prog);
    fprintf(stderr, "Discovers NAT64/PLAT IPv6 prefix via RFC 7050.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -s <server>        DNS server to query directly (IPv4 or IPv6)\n");
    fprintf(stderr, "  -t <timeout>       Query timeout in seconds (default: 3)\n");
    fprintf(stderr, "  -d <domain>        Domain to query (default: ipv4only.arpa)\n");
    fprintf(stderr, "  -c, --check <ip>   Directly test IPv6 address without DNS lookup\n");
    fprintf(stderr, "  -p, --public       Probe public NAT64 gateways and select lowest RTT\n");
    fprintf(stderr, "  -v, --verbose      Print probe details and RTT to stderr\n");
    fprintf(stderr, "  --json             Output discovered prefix and metadata as JSON\n");
    fprintf(stderr, "  -h, --help         Show this help message\n");
}

static int encode_dns_name(const char *domain, uint8_t *qname, size_t *qpos)
{
    size_t pos = 0;
    const char *label_start = domain;
    while (*label_start) {
        const char *dot = strchr(label_start, '.');
        size_t len = dot ? (size_t)(dot - label_start) : strlen(label_start);
        if (len == 0 || len > 63 || pos + 1 + len >= 255)
            return -1;
        qname[pos++] = (uint8_t)len;
        memcpy(&qname[pos], label_start, len);
        pos += len;
        if (!dot) break;
        label_start = dot + 1;
    }
    qname[pos++] = 0;
    *qpos = pos;
    return 0;
}

static int discover_public_pref64_parallel(const char *domain, int timeout_sec,
                                           struct in6_addr *out, int *prefix_len,
                                           char *best_server, size_t server_len,
                                           double *best_rtt_ms, int verbose)
{
    uint8_t qname[256];
    size_t qpos = 0;
    if (encode_dns_name(domain, qname, &qpos) < 0) return -1;

    uint8_t packet[512];
    memset(packet, 0, 12);
    uint16_t tx_id = (uint16_t)((unsigned)time(NULL) ^ ((unsigned)getpid() << 8));
    packet[0] = (uint8_t)(tx_id >> 8);
    packet[1] = (uint8_t)tx_id;
    packet[2] = 0x01; packet[3] = 0x00; /* RD=1 */
    packet[4] = 0x00; packet[5] = 0x01; /* QDCOUNT=1 */
    packet[11] = 1; /* ARCOUNT=1 */

    size_t plen = 12;
    memcpy(&packet[plen], qname, qpos);
    plen += qpos;
    packet[plen++] = 0x00; packet[plen++] = 0x1c; /* QTYPE=AAAA (28) */
    packet[plen++] = 0x00; packet[plen++] = 0x01; /* QCLASS=IN (1) */

    const uint8_t opt[] = {0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0};
    memcpy(packet + plen, opt, sizeof(opt));
    plen += sizeof(opt);

    size_t num_servers = 0;
    while (DEFAULT_PUBLIC_DNS64_SERVERS[num_servers] != NULL)
        num_servers++;

    int fds[16];
    struct pollfd pfds[16];
    struct timespec start_times[16];
    struct addrinfo *res_list[16];

    for (size_t i = 0; i < num_servers && i < 16; i++) {
        fds[i] = -1;
        pfds[i].fd = -1;
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
        res_list[i] = NULL;

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(DEFAULT_PUBLIC_DNS64_SERVERS[i], PREF64_DNS_PORT, &hints, &res_list[i]) != 0 || !res_list[i])
            continue;

        int fd = socket(res_list[i]->ai_family, SOCK_DGRAM, 0);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if (connect(fd, res_list[i]->ai_addr, res_list[i]->ai_addrlen) < 0) {
            close(fd);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &start_times[i]);
        if (send(fd, packet, plen, 0) != (ssize_t)plen) {
            close(fd);
            continue;
        }

        fds[i] = fd;
        pfds[i].fd = fd;
    }

    struct timespec loop_start;
    clock_gettime(CLOCK_MONOTONIC, &loop_start);
    int max_ms = timeout_sec * 1000;
    if (max_ms <= 0) max_ms = 3000;

    int found = 0;
    double lowest_rtt = 1e9;
    struct in6_addr best_out;
    int best_plen = 0;
    char winning_server[INET6_ADDRSTRLEN] = "";

    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int elapsed_ms = (int)((now.tv_sec - loop_start.tv_sec) * 1000 +
                               (now.tv_nsec - loop_start.tv_nsec) / 1000000);
        int remaining_ms = max_ms - elapsed_ms;
        if (remaining_ms <= 0) break;

        if (found && remaining_ms > 250) remaining_ms = 250;

        int n = poll(pfds, (nfds_t)num_servers, remaining_ms);
        if (n <= 0) break;

        clock_gettime(CLOCK_MONOTONIC, &now);

        for (size_t i = 0; i < num_servers && i < 16; i++) {
            if (pfds[i].fd >= 0 && (pfds[i].revents & POLLIN)) {
                uint8_t resp[4096];
                ssize_t rlen = recv(pfds[i].fd, resp, sizeof(resp), 0);
                double rtt = (now.tv_sec - start_times[i].tv_sec) * 1000.0 +
                             (now.tv_nsec - start_times[i].tv_nsec) / 1000000.0;

                struct in6_addr cand_out;
                int cand_len = 0;
                int res = rlen < 12 ? -1 : parse_dns_response(resp, (size_t)rlen, tx_id, domain, &cand_out, &cand_len);
                if (res == 0) {
                    if (verbose) {
                        char pbuf[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &cand_out, pbuf, sizeof(pbuf));
                        fprintf(stderr, "Probed %s: %s/%d (RTT: %.1f ms)\n",
                                DEFAULT_PUBLIC_DNS64_SERVERS[i], pbuf, cand_len, rtt);
                    }
                    if (!found || rtt < lowest_rtt) {
                        lowest_rtt = rtt;
                        best_out = cand_out;
                        best_plen = cand_len;
                        snprintf(winning_server, sizeof(winning_server), "%s",
                                 DEFAULT_PUBLIC_DNS64_SERVERS[i]);
                        found = 1;
                    }
                } else if (verbose) {
                    fprintf(stderr, "Probed %s: invalid or non-RFC7050 response\n",
                            DEFAULT_PUBLIC_DNS64_SERVERS[i]);
                }

                close(pfds[i].fd);
                pfds[i].fd = -1;
                fds[i] = -1;
            }
        }
    }

    for (size_t i = 0; i < num_servers && i < 16; i++) {
        if (fds[i] >= 0) close(fds[i]);
        if (res_list[i]) freeaddrinfo(res_list[i]);
    }

    if (!found) return -1;

    *out = best_out;
    *prefix_len = best_plen;
    if (best_server && server_len > 0)
        snprintf(best_server, server_len, "%s", winning_server);
    if (best_rtt_ms)
        *best_rtt_ms = lowest_rtt;

    return 0;
}

static int query_dns_server(const char *server, const char *domain, int timeout_sec, struct in6_addr *out, int *prefix_len)
{
    uint8_t qname[256];
    size_t qpos = 0;
    if (encode_dns_name(domain, qname, &qpos) < 0)
        return -1;

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
    packet[11] = 1; /* ARCOUNT=1 */

    size_t plen = 12;
    memcpy(&packet[plen], qname, qpos);
    plen += qpos;
    packet[plen++] = 0x00; packet[plen++] = 0x1c; /* QTYPE=AAAA (28) */
    packet[plen++] = 0x00; packet[plen++] = 0x01; /* QCLASS=IN (1) */

    /* EDNS0 OPT, UDP payload 1232; no DNSSEC OK flag is needed for discovery. */
    const uint8_t opt[] = {0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0};
    memcpy(packet + plen, opt, sizeof(opt));
    plen += sizeof(opt);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(server, PREF64_DNS_PORT, &hints, &res) != 0 || !res)
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
    ssize_t sent = send(fd, packet, plen, 0);
    if (sent != (ssize_t)plen) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    uint8_t resp[65535];
    ssize_t rlen = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    int result = rlen < 12 ? -1 : parse_dns_response(resp, (size_t)rlen, tx_id, domain, out, prefix_len);
    if (result == DNS_ERR_TRUNCATED) {
        fd = socket(res->ai_family, SOCK_STREAM, 0);
        if (fd < 0) { freeaddrinfo(res); return -1; }
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) goto tcp_fail;
        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) goto tcp_fail;
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int err = 0; socklen_t errlen = sizeof(err);
            if (poll(&pfd, 1, timeout_sec > 2147483 ? 2147483000 : timeout_sec * 1000) <= 0 ||
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err)
                goto tcp_fail;
        }
        if (fcntl(fd, F_SETFL, flags) < 0) goto tcp_fail;
        uint8_t frame[514];
        frame[0] = (uint8_t)(plen >> 8); frame[1] = (uint8_t)plen;
        memcpy(frame + 2, packet, plen);
        size_t done = 0;
        while (done < plen + 2) {
            ssize_t n = send(fd, frame + done, plen + 2 - done, 0);
            if (n <= 0) goto tcp_fail;
            done += (size_t)n;
        }
        done = 0;
        while (done < 2) {
            ssize_t n = recv(fd, frame + done, 2 - done, 0);
            if (n <= 0) goto tcp_fail;
            done += (size_t)n;
        }
        size_t length = ((size_t)frame[0] << 8) | frame[1];
        if (length > sizeof(resp)) goto tcp_fail;
        done = 0;
        while (done < length) {
            ssize_t n = recv(fd, resp + done, length - done, 0);
            if (n <= 0) goto tcp_fail;
            done += (size_t)n;
        }
        result = parse_dns_response(resp, length, tx_id, domain, out, prefix_len);
        if (result == DNS_ERR_TRUNCATED) result = -1;
        close(fd);
    }
    freeaddrinfo(res);
    return result;
tcp_fail:
    close(fd);
    freeaddrinfo(res);
    return -1;
}

static int parse_prefix_spec(const char *spec, struct in6_addr *prefix, int *prefix_len)
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

static void split_host_port(const char *spec, const char *default_port,
                            char *host, size_t host_sz, char *port, size_t port_sz)
{
    snprintf(port, port_sz, "%s", default_port);
    if (!spec || !spec[0]) {
        host[0] = '\0';
        return;
    }
    const char *sep = strchr(spec, '#');
    if (!sep) sep = strchr(spec, '@');
    if (sep) {
        size_t hlen = (size_t)(sep - spec);
        if (hlen >= host_sz) hlen = host_sz - 1;
        memcpy(host, spec, hlen);
        host[hlen] = '\0';
        if (sep[1]) snprintf(port, port_sz, "%s", sep + 1);
        return;
    }
    if (spec[0] == '[') {
        const char *rb = strchr(spec + 1, ']');
        if (rb) {
            size_t hlen = (size_t)(rb - (spec + 1));
            if (hlen >= host_sz) hlen = host_sz - 1;
            memcpy(host, spec + 1, hlen);
            host[hlen] = '\0';
            if (rb[1] == ':' && rb[2])
                snprintf(port, port_sz, "%s", rb + 2);
            return;
        }
    }
    const char *first_colon = strchr(spec, ':');
    const char *last_colon = strrchr(spec, ':');
    if (first_colon && first_colon == last_colon && last_colon[1]) {
        size_t hlen = (size_t)(last_colon - spec);
        if (hlen >= host_sz) hlen = host_sz - 1;
        memcpy(host, spec, hlen);
        host[hlen] = '\0';
        snprintf(port, port_sz, "%s", last_colon + 1);
        return;
    }
    snprintf(host, host_sz, "%s", spec);
}

static ssize_t decode_qname(const uint8_t *pkt, size_t plen, size_t offset,
                            char *domain, size_t domain_sz)
{
    size_t pos = offset;
    size_t dpos = 0;
    while (pos < plen) {
        uint8_t llen = pkt[pos++];
        if (llen == 0) {
            if (dpos < domain_sz) domain[dpos] = '\0';
            return (ssize_t)pos;
        }
        if ((llen & 0xc0) != 0 || pos + llen > plen)
            return -1;
        if (dpos > 0) {
            if (dpos + 1 >= domain_sz) return -1;
            domain[dpos++] = '.';
        }
        if (dpos + llen >= domain_sz)
            return -1;
        memcpy(domain + dpos, pkt + pos, llen);
        dpos += llen;
        pos += llen;
    }
    return -1;
}

static size_t build_dns64_reply(const uint8_t *req, size_t qsec_len,
                                const struct in6_addr *prefix, int prefix_len,
                                uint16_t rtype, const uint8_t v4_list[][4], size_t count,
                                uint8_t rcode, uint8_t *resp, size_t resp_sz)
{
    if (12 + qsec_len > resp_sz)
        return 0;
    memset(resp, 0, 12);
    resp[0] = req[0];
    resp[1] = req[1];
    resp[2] = (uint8_t)((req[2] & 0x01) | 0x80);
    resp[3] = (uint8_t)(0x80 | (rcode & 0x0f));
    resp[4] = 0;
    resp[5] = 1;
    memcpy(resp + 12, req + 12, qsec_len);
    size_t pos = 12 + qsec_len;
    uint16_t added = 0;

    for (size_t i = 0; i < count; i++) {
        size_t rdlen = (rtype == 28) ? 16 : 4;
        if (pos + 12 + rdlen > resp_sz)
            break;
        struct in6_addr syn6;
        if (rtype == 28 && synthesize_pref64(prefix, prefix_len, v4_list[i], &syn6) < 0)
            continue;
        resp[pos++] = 0xc0;
        resp[pos++] = 0x0c;
        resp[pos++] = (uint8_t)(rtype >> 8);
        resp[pos++] = (uint8_t)(rtype & 0xff);
        resp[pos++] = 0x00;
        resp[pos++] = 0x01;
        resp[pos++] = 0x00;
        resp[pos++] = 0x00;
        resp[pos++] = 0x00;
        resp[pos++] = 0x3c;
        resp[pos++] = 0x00;
        resp[pos++] = (uint8_t)rdlen;
        if (rtype == 28)
            memcpy(resp + pos, syn6.s6_addr, 16);
        else
            memcpy(resp + pos, v4_list[i], 4);
        pos += rdlen;
        added++;
    }
    resp[6] = (uint8_t)(added >> 8);
    resp[7] = (uint8_t)(added & 0xff);
    return pos;
}

static size_t lookup_hosts_v4(const char *hosts_path, const char *qname,
                              uint8_t v4_list[][4], size_t max_v4)
{
    FILE *fp = fopen(hosts_path, "r");
    if (!fp) return 0;
    char line[512];
    size_t count = 0;
    while (fgets(line, sizeof(line), fp) && count < max_v4) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *save = NULL;
        char *ip_tok = strtok_r(line, " \t\r\n", &save);
        if (!ip_tok) continue;
        struct in_addr in4;
        if (inet_pton(AF_INET, ip_tok, &in4) != 1)
            continue;
        char *host_tok = NULL;
        while ((host_tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
            if (strcasecmp(host_tok, qname) == 0) {
                memcpy(v4_list[count++], &in4.s_addr, 4);
                break;
            }
        }
    }
    fclose(fp);
    return count;
}

static ssize_t forward_dns_udp(const char *up_host, const char *up_port,
                               const uint8_t *pkt, size_t plen,
                               uint8_t *resp, size_t resp_sz)
{
    if (!up_host || !up_host[0] || strcmp(up_host, "none") == 0)
        return -1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(up_host, up_port, &hints, &res) != 0 || !res)
        return -1;
    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ssize_t rlen = -1;
    if (connect(fd, res->ai_addr, res->ai_addrlen) == 0 &&
        send(fd, pkt, plen, 0) == (ssize_t)plen) {
        rlen = recv(fd, resp, resp_sz, 0);
    }
    close(fd);
    freeaddrinfo(res);
    return rlen;
}

static size_t extract_dns_records(const uint8_t *resp, size_t rlen,
                                  uint16_t want_type, uint8_t v4_list[][4], size_t max_v4)
{
    if (rlen < 12 || !(resp[2] & 0x80) || (resp[3] & 0x0f) != 0)
        return 0;
    uint16_t qdcount = ((uint16_t)resp[4] << 8) | resp[5];
    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    size_t pos = 12;
    for (uint16_t q = 0; q < qdcount; q++) {
        ssize_t next = skip_dns_name(resp, rlen, pos);
        if (next < 0 || (size_t)next + 4 > rlen) return 0;
        pos = (size_t)next + 4;
    }
    size_t found = 0;
    for (uint16_t a = 0; a < ancount && pos < rlen; a++) {
        ssize_t next = skip_dns_name(resp, rlen, pos);
        if (next < 0 || (size_t)next + 10 > rlen) break;
        pos = (size_t)next;
        uint16_t atype = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
        uint16_t aclass = ((uint16_t)resp[pos + 2] << 8) | resp[pos + 3];
        uint16_t rdlen = ((uint16_t)resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;
        if (pos + rdlen > rlen) break;
        if (atype == want_type && aclass == 1) {
            if (want_type == 1 && rdlen == 4 && v4_list && found < max_v4) {
                memcpy(v4_list[found++], resp + pos, 4);
            } else if (want_type == 28 && rdlen == 16) {
                found++;
            }
        }
        pos += rdlen;
    }
    return found;
}

static volatile sig_atomic_t dns64_stop = 0;
static void handle_dns64_sig(int sig)
{
    (void)sig;
    dns64_stop = 1;
}

static int serve_dns64(const char *listen_spec, const char *prefix_spec, const char *upstream_spec)
{
    for (int cfd = 3; cfd <= 4096; cfd++)
        close(cfd);
    struct in6_addr prefix;
    int prefix_len = 0;
    if (parse_prefix_spec(prefix_spec, &prefix, &prefix_len) < 0) {
        fprintf(stderr, "Error: invalid DNS64 prefix: %s\n", prefix_spec ? prefix_spec : "");
        return 1;
    }

    char lhost[128], lport[32], uhost[128], uport[32];
    split_host_port(listen_spec, "5364", lhost, sizeof(lhost), lport, sizeof(lport));
    split_host_port(upstream_spec, "53", uhost, sizeof(uhost), uport, sizeof(uport));

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(lhost[0] ? lhost : "127.0.0.1", lport, &hints, &res) != 0 || !res) {
        fprintf(stderr, "Error: failed to resolve listen address %s#%s\n", lhost, lport);
        return 1;
    }

    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        fprintf(stderr, "Error: socket failed: %s\n", strerror(errno));
        return 1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        fprintf(stderr, "Error: bind %s#%s failed: %s\n", lhost, lport, strerror(errno));
        return 1;
    }
    freeaddrinfo(res);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_dns64_sig;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    while (!dns64_stop) {
        struct sockaddr_storage cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        uint8_t req[1500];
        ssize_t qlen = recvfrom(fd, req, sizeof(req), 0, (struct sockaddr *)&cli_addr, &cli_len);
        if (qlen < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (qlen < 12 || (req[2] & 0x80))
            continue;
        uint16_t qdcount = ((uint16_t)req[4] << 8) | req[5];
        if (qdcount < 1)
            continue;

        char qname[256];
        ssize_t qend = decode_qname(req, (size_t)qlen, 12, qname, sizeof(qname));
        if (qend < 0 || (size_t)qend + 4 > (size_t)qlen)
            continue;
        uint16_t qtype = ((uint16_t)req[qend] << 8) | req[qend + 1];
        uint16_t qclass = ((uint16_t)req[qend + 2] << 8) | req[qend + 3];
        size_t qsec_len = (size_t)qend + 4 - 12;

        uint8_t resp[1500];
        size_t rlen = 0;

        if (qclass == 1 && strcasecmp(qname, "ipv4only.arpa") == 0) {
            static const uint8_t wka_pair[2][4] = {
                {192, 0, 0, 170},
                {192, 0, 0, 171}
            };
            if (qtype == 28 || qtype == 1) {
                rlen = build_dns64_reply(req, qsec_len, &prefix, prefix_len, qtype, wka_pair, 2, 0, resp, sizeof(resp));
            } else {
                rlen = build_dns64_reply(req, qsec_len, &prefix, prefix_len, qtype, NULL, 0, 0, resp, sizeof(resp));
            }
            if (rlen > 0)
                sendto(fd, resp, rlen, 0, (struct sockaddr *)&cli_addr, cli_len);
            continue;
        }

        uint8_t hosts_v4[8][4];
        size_t hosts_cnt = (qclass == 1) ? lookup_hosts_v4("/tmp/tayga-dns64.hosts", qname, hosts_v4, 8) : 0;
        if (hosts_cnt > 0) {
            if (qtype == 28)
                rlen = build_dns64_reply(req, qsec_len, &prefix, prefix_len, 28, hosts_v4, hosts_cnt, 0, resp, sizeof(resp));
            else
                rlen = build_dns64_reply(req, qsec_len, &prefix, prefix_len, qtype, NULL, 0, 0, resp, sizeof(resp));
            if (rlen > 0)
                sendto(fd, resp, rlen, 0, (struct sockaddr *)&cli_addr, cli_len);
            continue;
        }

        if (qtype == 28 && qclass == 1) {
            uint8_t up_resp[1500];
            ssize_t up_len = forward_dns_udp(uhost, uport, req, (size_t)qlen, up_resp, sizeof(up_resp));
            if (up_len >= 12 && extract_dns_records(up_resp, (size_t)up_len, 28, NULL, 0) > 0) {
                sendto(fd, up_resp, (size_t)up_len, 0, (struct sockaddr *)&cli_addr, cli_len);
                continue;
            }
            uint8_t a_req[512];
            if (12 + qsec_len <= sizeof(a_req)) {
                memset(a_req, 0, 12);
                a_req[0] = req[0];
                a_req[1] = req[1];
                a_req[2] = 0x01;
                a_req[5] = 1;
                memcpy(a_req + 12, req + 12, qsec_len);
                a_req[12 + qsec_len - 4] = 0x00;
                a_req[12 + qsec_len - 3] = 0x01;
                uint8_t a_resp[1500];
                ssize_t a_len = forward_dns_udp(uhost, uport, a_req, 12 + qsec_len, a_resp, sizeof(a_resp));
                uint8_t up_v4[16][4];
                size_t v4_cnt = (a_len >= 12) ? extract_dns_records(a_resp, (size_t)a_len, 1, up_v4, 16) : 0;
                if (v4_cnt > 0) {
                    rlen = build_dns64_reply(req, qsec_len, &prefix, prefix_len, 28, up_v4, v4_cnt, 0, resp, sizeof(resp));
                    if (rlen > 0) {
                        sendto(fd, resp, rlen, 0, (struct sockaddr *)&cli_addr, cli_len);
                        continue;
                    }
                }
            }
            if (up_len >= 12) {
                sendto(fd, up_resp, (size_t)up_len, 0, (struct sockaddr *)&cli_addr, cli_len);
                continue;
            }
        } else {
            uint8_t up_resp[1500];
            ssize_t up_len = forward_dns_udp(uhost, uport, req, (size_t)qlen, up_resp, sizeof(up_resp));
            if (up_len >= 12) {
                sendto(fd, up_resp, (size_t)up_len, 0, (struct sockaddr *)&cli_addr, cli_len);
                continue;
            }
        }

        rlen = build_dns64_reply(req, qsec_len, &prefix, prefix_len, qtype, NULL, 0, 2, resp, sizeof(resp));
        if (rlen > 0)
            sendto(fd, resp, rlen, 0, (struct sockaddr *)&cli_addr, cli_len);
    }

    close(fd);
    return 0;
}

#ifdef __linux__
static uint16_t inet_cksum(const void *buf, size_t len, uint32_t init_sum)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t sum = init_sum;
    while (len > 1) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint32_t)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

static uint16_t icmp6_cksum(const uint8_t src6[16], const uint8_t dst6[16],
                            const uint8_t *icmp, size_t icmp_len)
{
    uint8_t pseudo[40];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, src6, 16);
    memcpy(pseudo + 16, dst6, 16);
    pseudo[34] = (uint8_t)(icmp_len >> 8);
    pseudo[35] = (uint8_t)(icmp_len & 0xff);
    pseudo[39] = 58;
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(pseudo); i += 2)
        sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
    return inet_cksum(icmp, icmp_len, sum);
}

static int open_tun_dev(const char *dev)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
#ifdef IFF_MULTI_QUEUE
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
#else
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#endif
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static int tun_echo6(const char *dev)
{
    for (int cfd = 3; cfd <= 4096; cfd++)
        close(cfd);
    int fd = open_tun_dev(dev);
    if (fd < 0) return 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_dns64_sig;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    while (!dns64_stop) {
        uint8_t pkt[1500];
        ssize_t n = read(fd, pkt, sizeof(pkt));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n >= 48 && (pkt[0] >> 4) == 6 && pkt[6] == 58 && pkt[40] == 128) {
            uint8_t tmp[16];
            memcpy(tmp, pkt + 8, 16);
            memcpy(pkt + 8, pkt + 24, 16);
            memcpy(pkt + 24, tmp, 16);
            pkt[40] = 129;
            pkt[42] = pkt[43] = 0;
            uint16_t ck = icmp6_cksum(pkt + 8, pkt + 24, pkt + 40, (size_t)n - 40);
            pkt[42] = (uint8_t)(ck >> 8);
            pkt[43] = (uint8_t)(ck & 0xff);
            if (write(fd, pkt, (size_t)n) < 0)
                break;
        }
    }
    close(fd);
    return 0;
}

static int tun_client4(const char *dev, const char *src_str, const char *dst_str)
{
    struct in_addr src4, dst4;
    if (inet_pton(AF_INET, src_str, &src4) != 1 || inet_pton(AF_INET, dst_str, &dst4) != 1)
        return 1;
    int fd = open_tun_dev(dev);
    if (fd < 0) return 1;
    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[3] = 28;
    pkt[4] = 0x12; pkt[5] = 0x34;
    pkt[8] = 64;
    pkt[9] = 1;
    memcpy(pkt + 12, &src4.s_addr, 4);
    memcpy(pkt + 16, &dst4.s_addr, 4);
    uint16_t ip_ck = inet_cksum(pkt, 20, 0);
    pkt[10] = (uint8_t)(ip_ck >> 8);
    pkt[11] = (uint8_t)(ip_ck & 0xff);
    pkt[20] = 8;
    pkt[24] = 0x54; pkt[25] = 0x47;
    pkt[26] = 0x00; pkt[27] = 0x01;
    uint16_t ic_ck = inet_cksum(pkt + 20, 8, 0);
    pkt[22] = (uint8_t)(ic_ck >> 8);
    pkt[23] = (uint8_t)(ic_ck & 0xff);
    if (write(fd, pkt, sizeof(pkt)) != (ssize_t)sizeof(pkt)) {
        close(fd);
        return 1;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    for (int i = 0; i < 30; i++) {
        if ((i == 10 || i == 20) && write(fd, pkt, sizeof(pkt)) < 0) break;
        if (poll(&pfd, 1, 100) <= 0) continue;
        uint8_t rx[1500];
        ssize_t n = read(fd, rx, sizeof(rx));
        if (n >= 28 && (rx[0] >> 4) == 4 && rx[9] == 1 &&
            memcmp(rx + 12, &dst4.s_addr, 4) == 0 &&
            memcmp(rx + 16, &src4.s_addr, 4) == 0 && rx[20] == 0) {
            close(fd);
            return 0;
        }
    }
    close(fd);
    return 1;
}

static int tun_client6(const char *dev, const char *src_str, const char *dst_str)
{
    struct in6_addr src6, dst6;
    if (inet_pton(AF_INET6, src_str, &src6) != 1 || inet_pton(AF_INET6, dst_str, &dst6) != 1)
        return 1;
    int fd = open_tun_dev(dev);
    if (fd < 0) return 1;
    uint8_t pkt[48];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    pkt[5] = 8;
    pkt[6] = 58;
    pkt[7] = 64;
    memcpy(pkt + 8, src6.s6_addr, 16);
    memcpy(pkt + 24, dst6.s6_addr, 16);
    pkt[40] = 128;
    pkt[44] = 0x54; pkt[45] = 0x47;
    pkt[46] = 0x00; pkt[47] = 0x01;
    uint16_t ck = icmp6_cksum(src6.s6_addr, dst6.s6_addr, pkt + 40, 8);
    pkt[42] = (uint8_t)(ck >> 8);
    pkt[43] = (uint8_t)(ck & 0xff);
    if (write(fd, pkt, sizeof(pkt)) != (ssize_t)sizeof(pkt)) {
        close(fd);
        return 1;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    for (int i = 0; i < 30; i++) {
        if ((i == 10 || i == 20) && write(fd, pkt, sizeof(pkt)) < 0) break;
        if (poll(&pfd, 1, 100) <= 0) continue;
        uint8_t rx[1500];
        ssize_t n = read(fd, rx, sizeof(rx));
        if (n >= 48 && (rx[0] >> 4) == 6 && rx[6] == 58 &&
            memcmp(rx + 8, dst6.s6_addr, 16) == 0 &&
            memcmp(rx + 24, src6.s6_addr, 16) == 0 && rx[40] == 129) {
            close(fd);
            return 0;
        }
    }
    close(fd);
    return 1;
}
#endif

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    const char *domain = DEFAULT_DOMAIN;
    const char *check_ip = NULL;
    const char *dns_server = NULL;
    const char *syn_prefix = NULL;
    const char *syn_ipv4 = NULL;
    const char *serve_listen = NULL;
    const char *serve_prefix = NULL;
    const char *serve_upstream = NULL;
#ifdef __linux__
    const char *echo6_dev = NULL;
    const char *cli_dev = NULL;
    const char *cli_src = NULL;
    const char *cli_dst = NULL;
    int cli_fam = 0;
#endif
    int timeout_sec = 3;
    int probe_public_only = 0;
    int verbose = 0;
    int json_output = 0;

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
        } else if (!strcmp(argv[i], "--synthesize") && i + 2 < argc) {
            syn_prefix = argv[++i];
            syn_ipv4 = argv[++i];
        } else if (!strcmp(argv[i], "--serve-dns64") && i + 3 < argc) {
            serve_listen = argv[++i];
            serve_prefix = argv[++i];
            serve_upstream = argv[++i];
#ifdef __linux__
        } else if (!strcmp(argv[i], "--tun-echo6") && i + 1 < argc) {
            echo6_dev = argv[++i];
        } else if (!strcmp(argv[i], "--tun-client4") && i + 3 < argc) {
            cli_dev = argv[++i];
            cli_src = argv[++i];
            cli_dst = argv[++i];
            cli_fam = 4;
        } else if (!strcmp(argv[i], "--tun-client6") && i + 3 < argc) {
            cli_dev = argv[++i];
            cli_src = argv[++i];
            cli_dst = argv[++i];
            cli_fam = 6;
#endif
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--public")) {
            probe_public_only = 1;
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "--json")) {
            json_output = 1;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

#ifdef __linux__
    if (echo6_dev)
        return tun_echo6(echo6_dev);
    if (cli_dev && cli_src && cli_dst)
        return (cli_fam == 4) ? tun_client4(cli_dev, cli_src, cli_dst) : tun_client6(cli_dev, cli_src, cli_dst);
#endif

    if (syn_prefix && syn_ipv4) {
        struct in6_addr prefix, out6;
        struct in_addr in4;
        int plen = 0;
        if (parse_prefix_spec(syn_prefix, &prefix, &plen) < 0) {
            fprintf(stderr, "Error: invalid prefix: %s\n", syn_prefix);
            return 1;
        }
        if (inet_pton(AF_INET, syn_ipv4, &in4) != 1) {
            fprintf(stderr, "Error: invalid IPv4 address: %s\n", syn_ipv4);
            return 1;
        }
        uint8_t v4b[4];
        memcpy(v4b, &in4.s_addr, 4);
        if (synthesize_pref64(&prefix, plen, v4b, &out6) < 0) {
            fprintf(stderr, "Error: synthesis failed\n");
            return 1;
        }
        char out_buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &out6, out_buf, sizeof(out_buf)))
            return 1;
        printf("%s\n", out_buf);
        return 0;
    }

    if (serve_listen && serve_prefix && serve_upstream) {
        return serve_dns64(serve_listen, serve_prefix, serve_upstream);
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
        if (json_output) {
            printf("{\n  \"prefix\": \"%s\",\n  \"length\": %d,\n  \"source\": \"check\"\n}\n", pbuf, plen);
        } else {
            printf("%s/%d\n", pbuf, plen);
        }
        return 0;
    }

    struct in6_addr out;
    int plen = 0;
    char winning_server[INET6_ADDRSTRLEN] = "";
    double winning_rtt = 0.0;

    if (dns_server) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (query_dns_server(dns_server, domain, timeout_sec, &out, &plen) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &t2);
            winning_rtt = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1000000.0;
            snprintf(winning_server, sizeof(winning_server), "%s", dns_server);
            char pbuf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &out, pbuf, sizeof(pbuf))) {
                if (verbose) {
                    fprintf(stderr, "[RFC 7050] Discovered prefix %s/%d via %s (RTT: %.1f ms)\n",
                            pbuf, plen, winning_server, winning_rtt);
                }
                if (json_output) {
                    printf("{\n  \"prefix\": \"%s\",\n  \"length\": %d,\n  \"server\": \"%s\",\n  \"rtt_ms\": %.1f\n}\n",
                           pbuf, plen, winning_server, winning_rtt);
                } else {
                    printf("%s/%d\n", pbuf, plen);
                }
                return 0;
            }
        }
        fprintf(stderr, "RFC 7050: query to DNS server %s for %s failed or no NAT64 prefix found\n", dns_server, domain);
        return 1;
    }

    int found = 0;

    if (!probe_public_only) {
        struct addrinfo hints, *res = NULL, *rp = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_DGRAM;

        int err = getaddrinfo(domain, NULL, &hints, &res);
        if (err == 0 && res != NULL) {
            for (rp = res; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)rp->ai_addr;
                    if (extract_pref64(&sin6->sin6_addr, &out, &plen) >= 0) {
                        snprintf(winning_server, sizeof(winning_server), "system-resolver");
                        found = 1;
                        break;
                    }
                }
            }
            freeaddrinfo(res);
        }
    }

    if (!found) {
        if (discover_public_pref64_parallel(domain, timeout_sec, &out, &plen,
                                            winning_server, sizeof(winning_server),
                                            &winning_rtt, verbose) == 0) {
            found = 1;
        }
    }

    if (!found) {
        fprintf(stderr, "RFC 7050: no synthesized NAT64 prefix found for %s (local DNS and public gateways failed)\n", domain);
        return 1;
    }

    char pbuf[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, &out, pbuf, sizeof(pbuf))) {
        fprintf(stderr, "Error: inet_ntop failed\n");
        return 1;
    }

    if (verbose) {
        fprintf(stderr, "[RFC 7050] Selected NAT64 prefix %s/%d via %s (RTT: %.1f ms)\n",
                pbuf, plen, winning_server, winning_rtt);
    }

    if (json_output) {
        printf("{\n  \"prefix\": \"%s\",\n  \"length\": %d,\n  \"server\": \"%s\",\n  \"rtt_ms\": %.1f\n}\n",
               pbuf, plen, winning_server, winning_rtt);
    } else {
        printf("%s/%d\n", pbuf, plen);
    }

    return 0;
}
#endif
