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
#include "pref64_util.h"
#include "dns64_serve.h"
#include "ra_supervisor.h"
#include "tun_probe.h"

#define DNS_ERR_TRUNCATED (-2)
#ifndef PREF64_DNS_PORT
#define PREF64_DNS_PORT "53"
#endif
#define DEFAULT_DOMAIN "ipv4only.arpa"
#define IPV4_WKA1_HEX 0xC00000AA /* 192.0.0.170 */
#define IPV4_WKA2_HEX 0xC00000AB /* 192.0.0.171 */

/* Fail closed if the operating system cannot provide DNS entropy. */
static int __attribute__((unused)) random_txid(uint16_t *id)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used < sizeof(*id)) {
        ssize_t n = read(fd, (uint8_t *)id + used, sizeof(*id) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return -1; }
        used += (size_t)n;
    }
    close(fd);
    return 0;
}

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
    fprintf(stderr, "  --supervise-ra CONFIG [--network-controller PATH] -- COMMAND...  Renew RA prefix and supervise translator\n");
    fprintf(stderr, "  -i <ifname>        Try RFC 8781 (PREF64 in Router Advertisements) on this interface first\n");
    fprintf(stderr, "  --ra-only          With -i: do not fall back to RFC 7050 when no RA PREF64 is found\n");
    fprintf(stderr, "  --no-ra            Skip RFC 8781 even if -i is given\n");
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
    uint16_t tx_id;
    if (random_txid(&tx_id) < 0) return -1;
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

    uint16_t tx_id;
    if (random_txid(&tx_id) < 0) return -1;

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

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--supervise-ra")) return supervise_ra(argc, argv);
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
    const char *ra_iface = NULL;
    int no_ra = 0;
    int ra_only = 0;
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
        } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
            ra_iface = argv[++i];
        } else if (!strcmp(argv[i], "--no-ra")) {
            no_ra = 1;
        } else if (!strcmp(argv[i], "--ra-only")) {
            ra_only = 1;
        } else if (!strcmp(argv[i], "--hosts-file") && i + 1 < argc) {
            g_hosts_file = argv[++i];
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

#if defined(__linux__) || defined(__FreeBSD__)
    if (ra_iface && !no_ra) {
        uint32_t life = 0;
        int rc = discover_ra_pref64(ra_iface, timeout_sec, &out, &plen, &life);
        if (rc == 0) {
            char pbuf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &out, pbuf, sizeof(pbuf))) {
                if (verbose)
                    fprintf(stderr, "[RFC 8781] PREF64 %s/%d from RA on %s (lifetime %us)\n",
                            pbuf, plen, ra_iface, life);
                if (json_output)
                    printf("{\n  \"prefix\": \"%s\",\n  \"length\": %d,\n  \"source\": \"rfc8781\",\n  \"lifetime\": %u\n}\n",
                           pbuf, plen, life);
                else
                    printf("%s/%d\n", pbuf, plen);
                return 0;
            }
        }
        if (verbose)
            fprintf(stderr, "[RFC 8781] %s; falling back to RFC 7050\n",
                    rc == -2 ? "no CAP_NET_RAW" : "no PREF64 RA option seen");
        if (ra_only)
            return 1;
    }
#else
    (void)ra_iface; (void)no_ra; (void)ra_only;
#endif

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
