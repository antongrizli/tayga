/*
 *  dns64_serve.c -- Embedded DNS64 server (--serve-dns64) and RFC 6052
 *  address synthesis for pref64-discover.
 *
 *  Copyright (C) 2026 Anton Grizli / TAYGA Contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
#include <sys/stat.h>
#include <time.h>
#include "pref64_util.h"
#include "dns64_serve.h"

/* Optional hosts-file override for --serve-dns64 (set only via --hosts-file). */
const char *g_hosts_file __attribute__((unused)) = NULL;
volatile sig_atomic_t dns64_stop = 0;

void handle_dns64_sig(int sig)
{
    (void)sig;
    dns64_stop = 1;
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

/* Exported for unit tests. */
size_t lookup_hosts_v4(const char *hosts_path, const char *qname,
                       uint8_t v4_list[][4], size_t max_v4)
{
    if (!hosts_path) return 0;
    /* Refuse symlinks, FIFOs/devices and files not owned by us or root, so an
     * unprivileged user cannot inject or stall DNS answers. */
    int hfd = open(hosts_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (hfd < 0) return 0;
    struct stat hst;
    if (fstat(hfd, &hst) < 0 || !S_ISREG(hst.st_mode) ||
            (hst.st_uid != 0 && hst.st_uid != geteuid()) ||
            (hst.st_mode & (S_IWGRP | S_IWOTH))) {
        close(hfd);
        return 0;
    }
    FILE *fp = fdopen(hfd, "r");
    if (!fp) { close(hfd); return 0; }
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

size_t build_dns64_reply(const uint8_t *req, size_t qsec_len,
                         const struct in6_addr *prefix, int prefix_len,
                         uint16_t rtype, const uint8_t v4_list[][4], size_t count,
                         uint8_t rcode, uint32_t ttl, uint8_t *resp, size_t resp_sz)
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
        if (pos + 12 + rdlen > resp_sz) {
            resp[2] |= 0x02; /* RFC 6147 §5.1: set TC=1 on truncation */
            break;
        }
        struct in6_addr syn6;
        if (rtype == 28 && synthesize_pref64(prefix, prefix_len, v4_list[i], &syn6) < 0)
            continue;
        resp[pos++] = 0xc0;
        resp[pos++] = 0x0c;
        resp[pos++] = (uint8_t)(rtype >> 8);
        resp[pos++] = (uint8_t)(rtype & 0xff);
        resp[pos++] = 0x00;
        resp[pos++] = 0x01;
        resp[pos++] = (uint8_t)(ttl >> 24);
        resp[pos++] = (uint8_t)(ttl >> 16);
        resp[pos++] = (uint8_t)(ttl >> 8);
        resp[pos++] = (uint8_t)ttl;
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

#ifndef PREF64_NO_MAIN
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

/* Upstream resolver address, resolved once and cached (no getaddrinfo()
 * per query).  A hostname that failed to resolve is retried lazily. */
struct dns_upstream {
    const char *host, *port;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int resolved;
};

static int upstream_resolve(struct dns_upstream *u)
{
    if (u->resolved)
        return 0;
    if (!u->host || !u->host[0] || strcmp(u->host, "none") == 0)
        return -1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(u->host, u->port, &hints, &res) != 0 || !res)
        return -1;
    memcpy(&u->addr, res->ai_addr, res->ai_addrlen);
    u->addrlen = res->ai_addrlen;
    u->resolved = 1;
    freeaddrinfo(res);
    return 0;
}

/* Counts records of want_type in the answer section.  When ttl_out is given
 * it receives RFC 6147 5.1.7's TTL for a synthesized AAAA: the smallest TTL of
 * the matching records, further bounded by the SOA MINIMUM in the authority
 * section when the response carries one. */
static size_t extract_dns_records(const uint8_t *resp, size_t rlen,
                                  uint16_t want_type, uint8_t v4_list[][4], size_t max_v4,
                                  uint32_t *ttl_out)
{
    if (rlen < 12 || !(resp[2] & 0x80) || (resp[3] & 0x0f) != 0)
        return 0;
    uint16_t qdcount = ((uint16_t)resp[4] << 8) | resp[5];
    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    uint16_t nscount = ((uint16_t)resp[8] << 8) | resp[9];
    size_t pos = 12;
    for (uint16_t q = 0; q < qdcount; q++) {
        ssize_t next = skip_dns_name(resp, rlen, pos);
        if (next < 0 || (size_t)next + 4 > rlen) return 0;
        pos = (size_t)next + 4;
    }
    size_t found = 0;
    uint32_t min_ttl = UINT32_MAX;
    int complete = 1;
    for (uint16_t a = 0; a < ancount; a++) {
        ssize_t next = pos < rlen ? skip_dns_name(resp, rlen, pos) : -1;
        if (next < 0 || (size_t)next + 10 > rlen) { complete = 0; break; }
        pos = (size_t)next;
        uint16_t atype = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
        uint16_t aclass = ((uint16_t)resp[pos + 2] << 8) | resp[pos + 3];
        uint32_t rttl = ((uint32_t)resp[pos + 4] << 24) | ((uint32_t)resp[pos + 5] << 16) |
                        ((uint32_t)resp[pos + 6] << 8) | resp[pos + 7];
        uint16_t rdlen = ((uint16_t)resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;
        if (pos + rdlen > rlen) { complete = 0; break; }
        if (atype == want_type && aclass == 1) {
            if (want_type == 1 && rdlen == 4 && v4_list && found < max_v4) {
                memcpy(v4_list[found++], resp + pos, 4);
                if (rttl < min_ttl) min_ttl = rttl;
            } else if (want_type == 28 && rdlen == 16) {
                found++;
            }
        }
        pos += rdlen;
    }
    if (ttl_out) {
        for (uint16_t n = 0; complete && n < nscount; n++) {
            ssize_t next = pos < rlen ? skip_dns_name(resp, rlen, pos) : -1;
            if (next < 0 || (size_t)next + 10 > rlen) break;
            pos = (size_t)next;
            uint16_t ntype = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
            uint16_t rdlen = ((uint16_t)resp[pos + 8] << 8) | resp[pos + 9];
            pos += 10;
            if (pos + rdlen > rlen) break;
            if (ntype == 6) {	/* SOA: MNAME RNAME serial refresh retry expire minimum */
                ssize_t m = skip_dns_name(resp, pos + rdlen, pos);
                ssize_t r = m < 0 ? -1 : skip_dns_name(resp, pos + rdlen, (size_t)m);
                if (r >= 0 && (size_t)r + 20 <= pos + rdlen) {
                    uint32_t minimum = ((uint32_t)resp[r + 16] << 24) | ((uint32_t)resp[r + 17] << 16) |
                                       ((uint32_t)resp[r + 18] << 8) | resp[r + 19];
                    if (minimum < min_ttl) min_ttl = minimum;
                }
            }
            pos += rdlen;
        }
        *ttl_out = min_ttl == UINT32_MAX ? 60 : min_ttl;
    }
    return found;
}

/*
 * Concurrent DNS64 service.  Every client query that needs the upstream gets a
 * slot with its own connected socket (kernel-chosen source port) and a two
 * second deadline; one poll() loop drives all slots, so a slow authoritative
 * server delays only the names that depend on it.
 */
#define DNS_MAX_PENDING 64
#define DNS_UPSTREAM_TIMEOUT_MS 2000

enum dns_stage { DNS_FWD, DNS_AAAA, DNS_A };

struct dns_pending {
    int used, up_fd;
    enum dns_stage stage;
    struct sockaddr_storage client;
    socklen_t client_len;
    uint8_t req[1500];
    size_t req_len, qsec_len;
    uint16_t qtype;
    uint8_t aaaa_resp[1500];	/* upstream AAAA answer kept as the fallback reply */
    ssize_t aaaa_len;
    int64_t deadline_ms;
};

struct dns_ctx {
    int fd;
    struct dns_upstream *up;
    struct in6_addr prefix;
    int plen;
};

static int64_t dns_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void dns_pending_free(struct dns_pending *p)
{
    if (p->up_fd >= 0)
        close(p->up_fd);
    p->up_fd = -1;
    p->used = 0;
}

static void dns_reply(const struct dns_ctx *c, const struct dns_pending *p, const uint8_t *buf, size_t len)
{
    (void)sendto(c->fd, buf, len, 0, (const struct sockaddr *)&p->client, p->client_len);
}

static void dns_servfail(const struct dns_ctx *c, const struct dns_pending *p)
{
    uint8_t out[1500];
    size_t n = build_dns64_reply(p->req, p->qsec_len, &c->prefix, c->plen, p->qtype, NULL, 0, 2, 60, out, sizeof(out));
    if (n > 0)
        dns_reply(c, p, out, n);
}

/* (Re)start the upstream exchange of a slot with a fresh socket. */
static int dns_upstream_send(struct dns_upstream *u, struct dns_pending *p, const uint8_t *pkt, size_t len)
{
    if (p->up_fd >= 0) {
        close(p->up_fd);
        p->up_fd = -1;
    }
    if (len < 2 || upstream_resolve(u) < 0)
        return -1;
    int s = socket(u->addr.ss_family, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    (void)fcntl(s, F_SETFD, FD_CLOEXEC);
    if (connect(s, (struct sockaddr *)&u->addr, u->addrlen) != 0 || send(s, pkt, len, 0) != (ssize_t)len) {
        close(s);
        return -1;
    }
    p->up_fd = s;
    p->deadline_ms = dns_now_ms() + DNS_UPSTREAM_TIMEOUT_MS;
    return 0;
}

/* Rebuild the client's AAAA query as an A query, keeping CD and EDNS0 (DO). */
static size_t build_a_query(const uint8_t *req, size_t qlen, size_t qsec_len, uint8_t *a_req, size_t cap)
{
    if (12 + qsec_len > cap)
        return 0;
    memset(a_req, 0, 12);
    a_req[0] = req[0];
    a_req[1] = req[1];
    a_req[2] = 0x01;
    a_req[3] = req[3] & 0x10; /* preserve CD (RFC 6147 5.1) */
    a_req[5] = 1;
    memcpy(a_req + 12, req + 12, qsec_len);
    a_req[12 + qsec_len - 4] = 0x00;
    a_req[12 + qsec_len - 3] = 0x01;
    size_t a_len_req = 12 + qsec_len;
    /* Locate OPT by walking all records; never copy compressed
     * names whose offsets would change in the rebuilt query. */
    size_t pos = 12 + qsec_len;
    unsigned records = ((unsigned)req[6] << 8 | req[7]) +
        ((unsigned)req[8] << 8 | req[9]) +
        ((unsigned)req[10] << 8 | req[11]);
    for (unsigned r = 0; r < records; r++) {
        size_t start = pos;
        ssize_t end = skip_dns_name(req, qlen, pos);
        if (end < 0 || (size_t)end + 10 > qlen) break;
        pos = (size_t)end;
        unsigned type = (unsigned)req[pos] << 8 | req[pos + 1];
        size_t rdlen = (size_t)req[pos + 8] << 8 | req[pos + 9];
        if (rdlen > qlen - pos - 10) break;
        if (type == 41 && req[start] == 0 && pos == start + 1) {
            size_t bytes = 11 + rdlen;
            if (bytes <= cap - a_len_req) {
                memcpy(a_req + a_len_req, req + start, bytes);
                a_len_req += bytes;
                a_req[11] = 1;
            }
            break;
        }
        pos += 10 + rdlen;
    }
    return a_len_req;
}

/* One step of a slot: resp/rlen is the upstream answer, or rlen < 0 for none. */
static void dns_advance(struct dns_ctx *c, struct dns_pending *p, const uint8_t *resp, ssize_t rlen)
{
    uint8_t out[1500];
    if (p->stage == DNS_FWD) {
        if (rlen >= 12)
            dns_reply(c, p, resp, (size_t)rlen);
        else
            dns_servfail(c, p);
        dns_pending_free(p);
        return;
    }
    if (p->stage == DNS_AAAA) {
        if (rlen >= 12 && ((resp[2] & 0x02) ||
                           extract_dns_records(resp, (size_t)rlen, 28, NULL, 0, NULL) > 0)) {
            dns_reply(c, p, resp, (size_t)rlen);
            dns_pending_free(p);
            return;
        }
        if (rlen >= 12) {
            memcpy(p->aaaa_resp, resp, (size_t)rlen);
            p->aaaa_len = rlen;
        } else {
            p->aaaa_len = -1;
        }
        uint8_t a_req[1500];
        size_t a_len = build_a_query(p->req, p->req_len, p->qsec_len, a_req, sizeof(a_req));
        if (a_len && dns_upstream_send(c->up, p, a_req, a_len) == 0) {
            p->stage = DNS_A;
            return;
        }
    } else {
        uint8_t v4[16][4];
        uint32_t ttl = 60;
        size_t cnt = rlen >= 12 ? extract_dns_records(resp, (size_t)rlen, 1, v4, 16, &ttl) : 0;
        if (cnt > 0) {
            size_t n = build_dns64_reply(p->req, p->qsec_len, &c->prefix, c->plen, 28, v4, cnt, 0, ttl, out, sizeof(out));
            if (n > 0) {
                dns_reply(c, p, out, n);
                dns_pending_free(p);
                return;
            }
        }
    }
    /* No synthesis possible: relay the upstream's own AAAA answer (NODATA,
     * NXDOMAIN, ...) when there was one, SERVFAIL otherwise. */
    if (p->aaaa_len >= 12)
        dns_reply(c, p, p->aaaa_resp, (size_t)p->aaaa_len);
    else
        dns_servfail(c, p);
    dns_pending_free(p);
}

/* One client datagram: answer locally when possible, else open a slot. */
static void dns_intake(struct dns_ctx *c, struct dns_pending *pend, const uint8_t *req, size_t qlen,
                       const struct sockaddr_storage *cli, socklen_t cli_len)
{
    if (qlen < 12 || (req[2] & 0x80))
        return;
    uint16_t qdcount = ((uint16_t)req[4] << 8) | req[5];
    if (qdcount < 1)
        return;
    char qname[256];
    ssize_t qend = decode_qname(req, qlen, 12, qname, sizeof(qname));
    if (qend < 0 || (size_t)qend + 4 > qlen)
        return;
    uint16_t qtype = ((uint16_t)req[qend] << 8) | req[qend + 1];
    uint16_t qclass = ((uint16_t)req[qend + 2] << 8) | req[qend + 3];
    size_t qsec_len = (size_t)qend + 4 - 12;
    uint8_t resp[1500];
    size_t rlen = 0;

    if (qclass == 1 && strcasecmp(qname, "ipv4only.arpa") == 0) {
        static const uint8_t wka_pair[2][4] = { {192, 0, 0, 170}, {192, 0, 0, 171} };
        if (qtype == 28 || qtype == 1)
            rlen = build_dns64_reply(req, qsec_len, &c->prefix, c->plen, qtype, wka_pair, 2, 0, 60, resp, sizeof(resp));
        else
            rlen = build_dns64_reply(req, qsec_len, &c->prefix, c->plen, qtype, NULL, 0, 0, 60, resp, sizeof(resp));
        if (rlen > 0)
            (void)sendto(c->fd, resp, rlen, 0, (const struct sockaddr *)cli, cli_len);
        return;
    }

    uint8_t hosts_v4[8][4];
    size_t hosts_cnt = (qclass == 1) ? lookup_hosts_v4(g_hosts_file, qname, hosts_v4, 8) : 0;
    if (hosts_cnt > 0) {
        if (qtype == 28)
            rlen = build_dns64_reply(req, qsec_len, &c->prefix, c->plen, 28, hosts_v4, hosts_cnt, 0, 60, resp, sizeof(resp));
        else
            rlen = build_dns64_reply(req, qsec_len, &c->prefix, c->plen, qtype, NULL, 0, 0, 60, resp, sizeof(resp));
        if (rlen > 0)
            (void)sendto(c->fd, resp, rlen, 0, (const struct sockaddr *)cli, cli_len);
        return;
    }

    struct dns_pending *p = NULL;
    for (int i = 0; i < DNS_MAX_PENDING; i++)
        if (!pend[i].used) {
            p = &pend[i];
            break;
        }
    if (!p) {	/* table full: shed load instead of queueing */
        rlen = build_dns64_reply(req, qsec_len, &c->prefix, c->plen, qtype, NULL, 0, 2, 60, resp, sizeof(resp));
        if (rlen > 0)
            (void)sendto(c->fd, resp, rlen, 0, (const struct sockaddr *)cli, cli_len);
        return;
    }
    p->used = 1;
    p->up_fd = -1;
    p->client = *cli;
    p->client_len = cli_len;
    memcpy(p->req, req, qlen);
    p->req_len = qlen;
    p->qsec_len = qsec_len;
    p->qtype = qtype;
    p->aaaa_len = -1;
    p->stage = (qtype == 28 && qclass == 1) ? DNS_AAAA : DNS_FWD;
    if (dns_upstream_send(c->up, p, p->req, p->req_len) != 0) {
        if (p->stage == DNS_AAAA)
            dns_advance(c, p, NULL, -1);	/* still try the A query */
        else {
            dns_servfail(c, p);
            dns_pending_free(p);
        }
    }
}

int serve_dns64(const char *listen_spec, const char *prefix_spec, const char *upstream_spec)
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
    struct dns_upstream upstream = { .host = uhost, .port = uport };
    (void)upstream_resolve(&upstream);	/* once at start; retried lazily if it fails */

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

    struct dns_ctx ctx = { .fd = fd, .up = &upstream, .prefix = prefix, .plen = prefix_len };
    struct dns_pending *pend = calloc(DNS_MAX_PENDING, sizeof(*pend));
    if (!pend) {
        close(fd);
        return 1;
    }
    for (int i = 0; i < DNS_MAX_PENDING; i++)
        pend[i].up_fd = -1;

    while (!dns64_stop) {
        struct pollfd pfds[1 + DNS_MAX_PENDING];
        int slot_of[1 + DNS_MAX_PENDING];
        int n = 0, timeout = 1000;
        int64_t now = dns_now_ms();
        pfds[n].fd = fd;
        pfds[n].events = POLLIN;
        slot_of[n++] = -1;
        for (int i = 0; i < DNS_MAX_PENDING; i++) {
            if (!pend[i].used)
                continue;
            pfds[n].fd = pend[i].up_fd;
            pfds[n].events = POLLIN;
            slot_of[n++] = i;
            int64_t left = pend[i].deadline_ms - now;
            if (left < 0) left = 0;
            if (left < timeout) timeout = (int)left;
        }
        if (poll(pfds, (nfds_t)n, timeout) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Upstream answers (several queries may be in flight at once). */
        for (int k = 1; k < n; k++) {
            if (!(pfds[k].revents & (POLLIN | POLLERR | POLLHUP)))
                continue;
            struct dns_pending *p = &pend[slot_of[k]];
            if (!p->used || p->up_fd != pfds[k].fd)
                continue;
            uint8_t resp[1500];
            ssize_t rlen = recv(p->up_fd, resp, sizeof(resp), MSG_DONTWAIT);
            if (rlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                continue;
            /* The reply must echo our transaction ID; anything else is ignored. */
            if (rlen >= 2 && (resp[0] != p->req[0] || resp[1] != p->req[1]))
                continue;
            dns_advance(&ctx, p, resp, rlen);
        }

        /* Upstream silence: advance with "no answer". */
        now = dns_now_ms();
        for (int i = 0; i < DNS_MAX_PENDING; i++)
            if (pend[i].used && now >= pend[i].deadline_ms)
                dns_advance(&ctx, &pend[i], NULL, -1);

        /* New client queries. */
        if (pfds[0].revents & POLLIN) {
            for (int burst = 0; burst < 32; burst++) {
                struct sockaddr_storage cli_addr;
                socklen_t cli_len = sizeof(cli_addr);
                uint8_t req[1500];
                ssize_t qlen = recvfrom(fd, req, sizeof(req), MSG_DONTWAIT,
                                        (struct sockaddr *)&cli_addr, &cli_len);
                if (qlen < 0)
                    break;
                dns_intake(&ctx, pend, req, (size_t)qlen, &cli_addr, cli_len);
            }
        }
    }

    for (int i = 0; i < DNS_MAX_PENDING; i++)
        if (pend[i].used)
            dns_pending_free(&pend[i]);
    free(pend);
    close(fd);
    return 0;
}
#endif /* PREF64_NO_MAIN */
