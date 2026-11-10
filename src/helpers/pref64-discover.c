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
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/icmp6.h>
#include <strings.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "pref64_ra.h"
#ifdef __linux__
#include <linux/if_tun.h>
#endif

#define DNS_ERR_TRUNCATED (-2)
#ifndef PREF64_DNS_PORT
#define PREF64_DNS_PORT "53"
#endif
#define DEFAULT_DOMAIN "ipv4only.arpa"
#define IPV4_WKA1_HEX 0xC00000AA /* 192.0.0.170 */
#define IPV4_WKA2_HEX 0xC00000AB /* 192.0.0.171 */

/* Optional hosts-file override for --serve-dns64 (set only via --hosts-file). */
static const char *g_hosts_file __attribute__((unused)) = NULL;

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


/*
 * RFC 8781: PREF64 option in IPv6 Router Advertisements (ND option 38).
 *
 *  | Type=38 | Length=2 | Scaled Lifetime (13 bits) | PLC (3 bits) |
 *  | Highest 96 bits of the prefix                                 |
 *
 * ra points at the ICMPv6 message (Type 134), ra_len is its length.  On
 * success returns 0 and the longest-lived valid prefix; options with a zero
 * lifetime (deprecation), reserved PLC values or an unusable prefix are skipped.
 */
#define ND_OPT_PREF64 38

static int is_valid_pref64_prefix(const struct in6_addr *p, int plen)
{
    static const uint8_t zero[16] = {0};
    const uint8_t *b = p->s6_addr;
    if (!memcmp(b, zero, 16) || b[0] == 0xff || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80))
        return 0;
    return plen == 32 || plen == 40 || plen == 48 || plen == 56 || plen == 64 || plen == 96;
}

int parse_ra_pref64_update(const uint8_t *ra, size_t ra_len, struct in6_addr *out_prefix,
                           int *out_plen, uint32_t *out_lifetime_sec,
                           const struct in6_addr *active, int active_len)
{
    static const int plc_to_plen[8] = { 96, 64, 56, 48, 40, 32, -1, -1 };
    if (!ra || !out_prefix || !out_plen || ra_len < 16 || ra[0] != 134 || ra[1] != 0)
        return -1;

    size_t pos = 16;	/* fixed RA header */
    int found = 0, best_plen = 0, best_rank = 0;
    uint32_t best_life = 0;
    struct in6_addr best;
    memset(&best, 0, sizeof(best));

    while (pos + 2 <= ra_len) {
        uint8_t type = ra[pos];
        size_t bytes = (size_t)ra[pos + 1] * 8;
        if (bytes == 0 || pos + bytes > ra_len)
            return -1;	/* RFC 4861 4.6: invalid option, discard the RA */
        if (type == ND_OPT_PREF64 && bytes == 16) {
            uint16_t v = (uint16_t)((ra[pos + 2] << 8) | ra[pos + 3]);
            uint32_t life = (uint32_t)(v >> 3) * 8u;
            int plen = plc_to_plen[v & 7];
            if (plen > 0) {
                struct in6_addr cand;
                memset(&cand, 0, sizeof(cand));
                memcpy(cand.s6_addr, ra + pos + 4, 12);
                if (plen < 96)	/* bits beyond plen must be zero */
                    memset(cand.s6_addr + plen / 8, 0, (size_t)(16 - plen / 8));
                int same = active && active_len == plen && !memcmp(active, &cand, sizeof(cand));
                int rank = life ? (same ? 3 : 2) : (same ? 1 : 0);
                if (rank && is_valid_pref64_prefix(&cand, plen) &&
                    (!found || rank > best_rank || (rank == best_rank && life > best_life))) {
                    best = cand; best_plen = plen; best_life = life; found = 1; best_rank = rank;
                }
            }
        }
        pos += bytes;
    }
    if (!found)
        return -1;
    *out_prefix = best;
    *out_plen = best_plen;
    if (out_lifetime_sec)
        *out_lifetime_sec = best_life;
    return 0;
}

int parse_ra_pref64_option(const uint8_t *ra, size_t ra_len, struct in6_addr *out_prefix,
                           int *out_plen, uint32_t *out_lifetime_sec)
{
    return parse_ra_pref64_update(ra, ra_len, out_prefix, out_plen, out_lifetime_sec, NULL, 0);
}

/* Every valid PREF64 option of one RA, withdrawals (lifetime 0) included.
 * Returns the option count, or -1 for an RA that must be discarded. */
int parse_ra_pref64_all(const uint8_t *ra, size_t ra_len, struct ra_option *out, int max)
{
    static const int plc_to_plen[8] = { 96, 64, 56, 48, 40, 32, -1, -1 };
    if (!ra || !out || max <= 0 || ra_len < 16 || ra[0] != 134 || ra[1] != 0)
        return -1;
    size_t pos = 16;
    int count = 0;
    while (pos + 2 <= ra_len) {
        size_t bytes = (size_t)ra[pos + 1] * 8;
        if (bytes == 0 || pos + bytes > ra_len)
            return -1;
        if (ra[pos] == ND_OPT_PREF64 && bytes == 16 && count < max) {
            uint16_t v = (uint16_t)((ra[pos + 2] << 8) | ra[pos + 3]);
            int plen = plc_to_plen[v & 7];
            if (plen > 0) {
                struct ra_option *o = &out[count];
                memset(o, 0, sizeof(*o));
                memcpy(o->prefix.s6_addr, ra + pos + 4, 12);
                if (plen < 96)
                    memset(o->prefix.s6_addr + plen / 8, 0, (size_t)(16 - plen / 8));
                o->plen = plen;
                o->life = (uint32_t)(v >> 3) * 8u;
                if (is_valid_pref64_prefix(&o->prefix, plen))
                    count++;
            }
        }
        pos += bytes;
    }
    return count;
}

/*
 * Candidate table (RFC 8781): every (router, prefix) pair that currently has
 * a positive lifetime.  The supervisor keeps the translator on the active
 * prefix for as long as ANY router still advertises it, so two routers with
 * different prefixes cannot make it flap.  The active prefix changes only
 * when no live candidate for it remains (withdrawal, expiry, or the
 * advertising router replacing its own prefix set).
 */
static int same_prefix(const struct in6_addr *a, int alen, const struct in6_addr *b, int blen)
{
    return alen == blen && !memcmp(a, b, sizeof(*a));
}

void ra_table_init(struct ra_table *t)
{
    memset(t, 0, sizeof(*t));
}

/* A prefix learned out of band (container start-up): it lives until its
 * deadline or until the first real RA arrives. */
void ra_table_add_provisional(struct ra_table *t, const struct in6_addr *prefix, int plen,
                              uint32_t life, time_t now)
{
    for (int i = 0; i < RA_CANDIDATES; i++) {
        if (t->c[i].used)
            continue;
        memset(&t->c[i], 0, sizeof(t->c[i]));
        t->c[i].used = 1;
        t->c[i].provisional = 1;
        t->c[i].prefix = *prefix;
        t->c[i].plen = plen;
        t->c[i].life = life;
        t->c[i].deadline = now + (time_t)life;
        return;
    }
}

/* Apply one RA from `router`.  A router that advertises at least one prefix
 * replaces its earlier set (a renumbering router does not have to send
 * lifetime 0 for the old prefix); a pure withdrawal removes only the named
 * prefix of that router. */
void ra_table_apply(struct ra_table *t, const struct in6_addr *router,
                    const struct ra_option *opts, int n, time_t now)
{
    int positive = 0;
    for (int i = 0; i < n; i++)
        if (opts[i].life)
            positive++;
    if (positive) {
        for (int i = 0; i < RA_CANDIDATES; i++) {
            struct ra_candidate *c = &t->c[i];
            if (!c->used)
                continue;
            if (c->provisional) {
                c->used = 0;
                continue;
            }
            if (memcmp(&c->router, router, sizeof(*router)))
                continue;
            int keep = 0;
            for (int k = 0; k < n; k++)
                if (opts[k].life && same_prefix(&c->prefix, c->plen, &opts[k].prefix, opts[k].plen))
                    keep = 1;
            if (!keep)
                c->used = 0;
        }
    }
    for (int k = 0; k < n; k++) {
        struct ra_candidate *slot = NULL, *oldest = NULL;
        for (int i = 0; i < RA_CANDIDATES; i++) {
            struct ra_candidate *c = &t->c[i];
            if (!c->used) {
                if (!slot) slot = c;
                continue;
            }
            if (!oldest || c->deadline < oldest->deadline)
                oldest = c;
            if (!memcmp(&c->router, router, sizeof(*router)) &&
                same_prefix(&c->prefix, c->plen, &opts[k].prefix, opts[k].plen)) {
                slot = c;
                break;
            }
        }
        int existing = slot && slot->used;
        if (!opts[k].life) {
            if (existing)
                slot->used = 0;
            continue;
        }
        if (!slot)
            slot = oldest;
        if (!slot)
            continue;
        memset(slot, 0, sizeof(*slot));
        slot->used = 1;
        slot->router = *router;
        slot->prefix = opts[k].prefix;
        slot->plen = opts[k].plen;
        slot->life = opts[k].life;
        slot->deadline = now + (time_t)opts[k].life;
    }
}

void ra_table_expire(struct ra_table *t, time_t now)
{
    for (int i = 0; i < RA_CANDIDATES; i++)
        if (t->c[i].used && t->c[i].deadline <= now)
            t->c[i].used = 0;
}

/* Choose the prefix to run.  The active one wins while it has a live
 * candidate; otherwise the candidate that stays valid longest.  Returns 0
 * and fills the outputs, or -1 when nothing is live. */
int ra_table_pick(const struct ra_table *t, const struct in6_addr *active, int active_len,
                  time_t now, struct in6_addr *out, int *plen, time_t *deadline, uint32_t *life)
{
    const struct ra_candidate *best = NULL;
    for (int pass = 0; pass < 2 && !best; pass++) {
        for (int i = 0; i < RA_CANDIDATES; i++) {
            const struct ra_candidate *c = &t->c[i];
            if (!c->used || c->deadline <= now)
                continue;
            if (pass == 0 && !(active && same_prefix(&c->prefix, c->plen, active, active_len)))
                continue;
            if (!best || c->deadline > best->deadline)
                best = c;
        }
    }
    if (!best)
        return -1;
    *out = best->prefix;
    *plen = best->plen;
    if (deadline) *deadline = best->deadline;
    if (life) *life = best->life;
    return 0;
}

/* Exported only for unit tests. */
#ifdef PREF64_NO_MAIN
#define HOSTS_LINKAGE
#else
#define HOSTS_LINKAGE static
#endif
HOSTS_LINKAGE size_t lookup_hosts_v4(const char *hosts_path, const char *qname,
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

#ifndef PREF64_NO_MAIN
#if defined(__linux__) || defined(__FreeBSD__)
/*
 * Solicit a Router Advertisement on ifname and read PREF64 from it.
 * Needs CAP_NET_RAW; returns -2 when the socket cannot be opened so the
 * caller can fall back to RFC 7050 silently.  RAs are only accepted from
 * link-local sources with Hop Limit 255 (RFC 4861 6.1.2) on that interface.
 */
static int send_rs(int fd, unsigned ifindex);
static int open_ra_socket(const char *ifname)
{
    unsigned ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -1;
    int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
    if (fd < 0)
        return -2;

    struct icmp6_filter filt;
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
    int on = 1, hops = 255;
    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0) {
        close(fd);
        return -1;
    }

    struct ipv6_mreq mr;
    memset(&mr, 0, sizeof(mr));
    inet_pton(AF_INET6, "ff02::1", &mr.ipv6mr_multiaddr);
    mr.ipv6mr_interface = ifindex;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr, sizeof(mr));
    if (send_rs(fd, ifindex) < 0)
        { close(fd); return -1; }

    return fd;
}

/* Router Solicitation to ff02::2 (RFC 4861 6.3.7). */
static int send_rs(int fd, unsigned ifindex)
{
    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "ff02::2", &dst.sin6_addr);
    dst.sin6_scope_id = ifindex;
    struct nd_router_solicit rs;
    memset(&rs, 0, sizeof(rs));
    rs.nd_rs_type = ND_ROUTER_SOLICIT;
    return sendto(fd, &rs, sizeof(rs), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0 ? -1 : 0;
}

static long mono_ms_since(const struct timespec *t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)((now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000);
}

/*
 * Receive one acceptable RA: link-local source, Hop Limit 255, expected
 * interface (RFC 4861 6.1.2).  Returns its length (the source router in
 * *router), or -1 when the timeout elapses first.
 */
static ssize_t receive_ra(int fd, unsigned ifindex, long timeout_ms,
                          uint8_t *buf, size_t bufsz, struct in6_addr *router)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        long left = timeout_ms - mono_ms_since(&t0);
        if (left <= 0)
            return -1;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, (int)left) <= 0)
            return -1;
        uint8_t cbuf[256];
        struct sockaddr_in6 from;
        struct iovec iov = { buf, bufsz };
        struct msghdr mh = { .msg_name = &from, .msg_namelen = sizeof(from),
                             .msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
        ssize_t n = recvmsg(fd, &mh, 0);
        if (n < 16 || (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            !IN6_IS_ADDR_LINKLOCAL(&from.sin6_addr))
            continue;
        int hl = -1;
        unsigned idx = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level != IPPROTO_IPV6)
                continue;
            if (c->cmsg_type == IPV6_HOPLIMIT && c->cmsg_len >= CMSG_LEN(sizeof(int)))
                memcpy(&hl, CMSG_DATA(c), sizeof(int));
            else if (c->cmsg_type == IPV6_PKTINFO && c->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
                struct in6_pktinfo pi;
                memcpy(&pi, CMSG_DATA(c), sizeof(pi));
                idx = pi.ipi6_ifindex;
            }
        }
        if (hl != 255 || idx != ifindex)
            continue;
        *router = from.sin6_addr;
        return n;
    }
}

static int receive_ra_pref64(int fd, unsigned ifindex, int timeout_sec,
                              struct in6_addr *out, int *plen, uint32_t *lifetime,
                              const struct in6_addr *active, int active_len)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        long left = (long)timeout_sec * 1000 - mono_ms_since(&t0);
        if (left <= 0)
            break;
        uint8_t buf[1500];
        struct in6_addr router;
        ssize_t n = receive_ra(fd, ifindex, left, buf, sizeof(buf), &router);
        if (n < 0)
            break;
        if (parse_ra_pref64_update(buf, (size_t)n, out, plen, lifetime, active, active_len) == 0)
            return 0;
    }
    return -1;
}
static int discover_ra_pref64(const char *ifname, int timeout_sec, struct in6_addr *out,
                              int *plen, uint32_t *lifetime)
{
    int fd = open_ra_socket(ifname);
    if (fd < 0) return fd;
    int result = receive_ra_pref64(fd, if_nametoindex(ifname), timeout_sec, out, plen, lifetime, NULL, 0);
    close(fd);
    return result;
}

#endif

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

static volatile sig_atomic_t dns64_stop = 0;
static void handle_dns64_sig(int sig)
{
    (void)sig;
    dns64_stop = 1;
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
        if (rlen >= 12 && extract_dns_records(resp, (size_t)rlen, 28, NULL, 0, NULL) > 0) {
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

static volatile sig_atomic_t supervisor_hup, supervisor_usr1, supervisor_usr2;
static void supervisor_signal(int sig)
{
    if (sig == SIGHUP) supervisor_hup = 1;
    else if (sig == SIGUSR1) supervisor_usr1 = 1;
    else if (sig == SIGUSR2) supervisor_usr2 = 1;
    else dns64_stop = 1;
}

#if defined(__linux__) || defined(__FreeBSD__)
/* The controller owns journalled network mutations. Run it only while the
 * translator is stopped, in its own process group, with a bounded lifetime. */
static int ra_network_action(const char *controller, const char *action, const char *config)
{
    if (dns64_stop) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) {
        if (setpgid(0, 0) < 0) _exit(126);
        unsetenv("NOTIFY_SOCKET");
        execl(controller, controller, action, config, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    struct timespec started, current;
    clock_gettime(CLOCK_MONOTONIC, &started);
    int stopping = 0, status;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0 && !stopping ? 0 : -1;
        if (done < 0 && errno != EINTR) return -1;
        clock_gettime(CLOCK_MONOTONIC, &current);
        if (!stopping && (dns64_stop || current.tv_sec - started.tv_sec >= 30)) {
            kill(-pid, SIGTERM);
            started = current;
            stopping = 1;
        }
        if (stopping && current.tv_sec - started.tv_sec >= 5) {
            kill(-pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return -1;
        }
        (void)poll(NULL, 0, 50);
    }
}

static void stop_ra_child(pid_t child)
{
    /* Keep the PID reserved until the child is reaped. ECHILD means there
     * is no owned process left to signal, including after an earlier reap. */
    int status;
    pid_t done = waitpid(child, &status, WNOHANG);
    if (done == child || (done < 0 && errno == ECHILD)) return;
    kill(child, SIGTERM);
    for (int i = 0; i < 50; i++) {
        done = waitpid(child, &status, WNOHANG);
        if (done == child || (done < 0 && errno == ECHILD)) return;
        usleep(100000);
    }
    kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
}
#endif

__attribute__((unused)) static void active_prefix_path(const char *dir, char *out, size_t size)
{
    snprintf(out, size, "%s/active-prefix", dir);
}

/* Publish the prefix the translator really runs, so status and verification
 * scripts do not read the (unchanged) installed profile. */
__attribute__((unused)) static void publish_active_prefix(const char *dir, const struct in6_addr *prefix, int plen)
{
    if (!dir)
        return;
    char path[1024], tmp[1040], text[INET6_ADDRSTRLEN];
    active_prefix_path(dir, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (!inet_ntop(AF_INET6, prefix, text, sizeof(text)))
        return;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    int failed = dprintf(fd, "%s/%d rfc8781\n", text, plen) < 0;
    if (close(fd))
        failed = 1;
    if (failed || rename(tmp, path))
        unlink(tmp);
}

__attribute__((unused)) static void retract_active_prefix(const char *dir)
{
    if (!dir)
        return;
    char path[1024];
    active_prefix_path(dir, path, sizeof(path));
    unlink(path);
}

__attribute__((unused)) static time_t mono_seconds_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

/* Snapshots "<config>.ra.XXXXXX" survive a SIGKILL or power cut of an earlier
 * supervisor; one supervisor runs per profile, so every match is stale. */
__attribute__((unused)) static void remove_stale_snapshots(const char *config)
{
    char dir[1024], prefix[300];
    const char *slash = strrchr(config, '/');
    size_t dl = slash == config ? 1 : (size_t)(slash - config);
    if (dl >= sizeof(dir) || snprintf(prefix, sizeof(prefix), "%s.ra.", slash + 1) >= (int)sizeof(prefix))
        return;
    memcpy(dir, config, dl);
    dir[dl] = '\0';
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *e;
    size_t plen = strlen(prefix);
    while ((e = readdir(d)))
        if (!strncmp(e->d_name, prefix, plen) && strlen(e->d_name) == plen + 6)
            (void)unlinkat(dirfd(d), e->d_name, 0);
    closedir(d);
}

/* RFC 4861 6.3.7: three solicitations, four seconds apart, before giving up
 * on the first start.  After that the supervisor stays resident and asks
 * again with exponential back-off (RFC 7559), capped at one hour. */
#define RA_INITIAL_ATTEMPTS 3
#define RA_SOLICIT_INTERVAL 4
#define RA_SOLICIT_CAP 3600

/* Control-plane supervisor. The configured file stays unchanged; each child
 * reads a private snapshot with the currently advertised translation prefix.
 *   --supervise-ra CONFIG [--network-controller PATH] [--runtime-dir DIR]
 *                  [--initial-prefix PFX/LEN --initial-lifetime SEC] -- COMMAND... */
static int supervise_ra(int argc, char **argv)
{
    const char *controller = NULL, *runtime_dir = NULL, *initial_prefix = NULL;
    long initial_lifetime = 0;
    int command = 0;
    if (argc < 5)
        return 2;
    const char *config = argv[2];
    if (config[0] != '/')
        return 2;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--")) {
            command = i + 1;
            break;
        }
        if (i + 1 >= argc)
            return 2;
        if (!strcmp(argv[i], "--network-controller")) controller = argv[++i];
        else if (!strcmp(argv[i], "--runtime-dir")) runtime_dir = argv[++i];
        else if (!strcmp(argv[i], "--initial-prefix")) initial_prefix = argv[++i];
        else if (!strcmp(argv[i], "--initial-lifetime")) initial_lifetime = atol(argv[++i]);
        else return 2;
    }
    if (!command || command >= argc)
        return 2;
    if ((controller && controller[0] != '/') || (runtime_dir && runtime_dir[0] != '/'))
        return 2;
    FILE *in = fopen(config, "r");
    if (!in) return 1;
    char line[1024], iface[IF_NAMESIZE] = "", configured[INET6_ADDRSTRLEN + 8] = "";
    int nat66 = 0;
    while (fgets(line, sizeof(line), in)) {
        char value[IF_NAMESIZE];
        if (sscanf(line, "# installer-pref64-interface %15s", value) == 1)
            snprintf(iface, sizeof(iface), "%s", value);
        if (sscanf(line, "# installer-clat-address-mode %15s", value) == 1 && !strcmp(value, "nat66")) nat66 = 1;
        (void)sscanf(line, "prefix %53s", configured);
    }
    int read_failed = ferror(in);
    fclose(in);
    if (read_failed) return 1;
    if (!iface[0]) { execvp(argv[command], argv + command); return 1; }
#if defined(__linux__) || defined(__FreeBSD__)
    int ra_fd = open_ra_socket(iface);
    if (ra_fd < 0) {
        fprintf(stderr, "Cannot use %s for Router Advertisements%s\n", iface,
                ra_fd == -2 ? " (raw ICMPv6 socket: CAP_NET_RAW required)"
                            : " (unknown interface, or no usable link-local address)");
        return 1;
    }
    unsigned ifindex = if_nametoindex(iface);
    char snapshot[1024];
    if (snprintf(snapshot, sizeof(snapshot), "%s.ra.XXXXXX", config) >= (int)sizeof(snapshot)) { close(ra_fd); return 1; }
    remove_stale_snapshots(config);
    int fd = mkstemp(snapshot);
    if (fd < 0) { close(ra_fd); return 1; }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) { close(fd); close(ra_fd); unlink(snapshot); return 1; }
    int config_arg = 0;
    for (int i = command; i < argc; i++) if (!strcmp(argv[i], config)) config_arg = 1;
    if (!config_arg) { close(fd); close(ra_fd); unlink(snapshot); return 2; }
    for (int i = command; i < argc; i++) if (!strcmp(argv[i], config)) argv[i] = snapshot;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL); sigaction(SIGUSR1, &sa, NULL); sigaction(SIGUSR2, &sa, NULL);

    struct ra_table table;
    ra_table_init(&table);
    time_t started = mono_seconds_now();
    if (initial_prefix && initial_lifetime > 0) {
        struct in6_addr p;
        int pl;
        if (parse_prefix_spec(initial_prefix, &p, &pl) == 0 && is_valid_pref64_prefix(&p, pl))
            ra_table_add_provisional(&table, &p, pl, (uint32_t)initial_lifetime, started);
    }
    /* The prefix the host network (NAT66 firewall) was built for. */
    struct in6_addr net_prefix;
    int net_len = 0;
    memset(&net_prefix, 0, sizeof(net_prefix));
    if (parse_prefix_spec(configured, &net_prefix, &net_len))
        net_len = 0;

    pid_t child = -1;
    struct in6_addr active;
    memset(&active, 0, sizeof(active));
    int active_len = 0, result = 1, ever_started = 0, rs_sent = 1;
    time_t next_rs = started + RA_SOLICIT_INTERVAL;
    long rs_interval = RA_SOLICIT_INTERVAL;
    while (!dns64_stop) {
        if (child > 0) {
            int status;
            pid_t done = waitpid(child, &status, WNOHANG);
            /* The translator died on its own: let the service manager apply
             * its restart policy. */
            if (done == child || (done < 0 && errno == ECHILD)) {
                if (done == child && WIFEXITED(status))
                    fprintf(stderr, "Translator exited with status %d\n", WEXITSTATUS(status));
                else if (done == child && WIFSIGNALED(status))
                    fprintf(stderr, "Translator killed by signal %d\n", WTERMSIG(status));
                child = -1;
                break;
            }
            if (supervisor_hup) { supervisor_hup = 0; kill(child, SIGHUP); }
            if (supervisor_usr1) { supervisor_usr1 = 0; kill(child, SIGUSR1); }
            if (supervisor_usr2) { supervisor_usr2 = 0; kill(child, SIGUSR2); }
        }

        uint8_t ra[1500];
        struct in6_addr router;
        ssize_t ra_len = receive_ra(ra_fd, ifindex, 500, ra, sizeof(ra), &router);
        time_t now = mono_seconds_now();
        if (ra_len > 0) {
            struct ra_option opts[RA_MAX_OPTIONS];
            int count = parse_ra_pref64_all(ra, (size_t)ra_len, opts, RA_MAX_OPTIONS);
            if (count > 0) {
                ra_table_apply(&table, &router, opts, count, now);
                rs_interval = RA_SOLICIT_INTERVAL;
                next_rs = now + (long)RA_SOLICIT_INTERVAL;
            }
        }
        ra_table_expire(&table, now);

        struct in6_addr pick;
        int pick_len = 0;
        time_t pick_deadline = 0;
        uint32_t pick_life = 0;
        int have = ra_table_pick(&table, child > 0 ? &active : NULL, active_len, now,
                                 &pick, &pick_len, &pick_deadline, &pick_life) == 0;

        if (child > 0 && (!have || pick_len != active_len || memcmp(&pick, &active, sizeof(pick)))) {
            /* Active prefix withdrawn or expired everywhere. */
            stop_ra_child(child);
            child = -1;
            active_len = 0;
            retract_active_prefix(runtime_dir);
            if (!have) {
                fprintf(stderr, "PREF64 withdrawn or expired; translator stopped, soliciting a new RA\n");
                rs_interval = RA_SOLICIT_INTERVAL;
                next_rs = now;
            }
        }
        if (dns64_stop) break;

        if (child < 0 && have) {
            /* A prefix-dependent firewall must change while no translator runs. */
            int change_network = 0;
            if (nat66) {
                change_network = net_len != pick_len || memcmp(&net_prefix, &pick, sizeof(pick));
                if (change_network && !controller) {
                    fprintf(stderr, "RA prefix changed: a network controller is required for NAT66\n");
                    break;
                }
            }
            in = fopen(config, "r");
            if (ftruncate(fd, 0) || lseek(fd, 0, SEEK_SET) < 0) { if (in) fclose(in); break; }
            int copy_fd = dup(fd);
            FILE *out = copy_fd >= 0 ? fdopen(copy_fd, "w") : NULL;
            if (!out && copy_fd >= 0) close(copy_fd);
            if (!in || !out) { if (in) fclose(in); if (out) fclose(out); break; }
            char text[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &pick, text, sizeof(text));
            int replaced = 0;
            while (fgets(line, sizeof(line), in)) {
                char key[64];
                if (sscanf(line, "%63s", key) == 1 && !strcmp(key, "prefix")) {
                    fprintf(out, "prefix %s/%d\n", text, pick_len); replaced++;
                } else fputs(line, out);
            }
            int failed = ferror(in) || ferror(out);
            if (fclose(in)) failed = 1;
            if (fclose(out)) failed = 1;
            if (failed || replaced != 1) break;
            if (change_network) {
                /* down uses the existing undo journal, including the actual live
                 * prefix. up validates the snapshot and rolls back partial setup.
                 * If replacement fails, restore the saved profile without starting
                 * a translator on an unconfirmed/expired old prefix. */
                if (ra_network_action(controller, "down", config)) {
                    fprintf(stderr, "RA network teardown failed; retaining controller journal for recovery\n");
                    break;
                }
                if (ra_network_action(controller, "up", snapshot)) {
                    fprintf(stderr, "RA network replacement failed; restoring saved profile\n");
                    if (!dns64_stop && ra_network_action(controller, "up", config))
                        fprintf(stderr, "RA network restore failed; service cleanup/recovery is required\n");
                    break;
                }
                net_prefix = pick;
                net_len = pick_len;
            }
            if (dns64_stop || mono_seconds_now() >= pick_deadline) continue;
            child = fork();
            if (child < 0) break;
            if (!child) {
                execvp(argv[command], argv + command);
                fprintf(stderr, "Cannot execute %s: %s\n", argv[command], strerror(errno));
                _exit(127);
            }
            active = pick; active_len = pick_len;
            ever_started = 1;
            publish_active_prefix(runtime_dir, &active, active_len);
            rs_interval = RA_SOLICIT_INTERVAL;
            next_rs = now + (long)RA_SOLICIT_INTERVAL;
            continue;
        }

        /* Solicitations: start-up retries, last-quarter refresh and outage back-off. */
        int need_rs = 0;
        if (child < 0 && !have) {
            if (!ever_started) {
                if (rs_sent >= RA_INITIAL_ATTEMPTS && now >= next_rs) {
                    fprintf(stderr, "No PREF64 router advertisement received on %s\n", iface);
                    break;
                }
                need_rs = now >= next_rs && rs_sent < RA_INITIAL_ATTEMPTS;
            } else {
                need_rs = now >= next_rs;
            }
        } else if (child > 0 && pick_deadline - now < (time_t)(pick_life / 4)) {
            need_rs = now >= next_rs;
        }
        if (need_rs) {
            (void)send_rs(ra_fd, ifindex);
            rs_sent++;
            next_rs = now + rs_interval;
            if (ever_started)
                rs_interval = rs_interval < RA_SOLICIT_CAP / 2 ? rs_interval * 2 : RA_SOLICIT_CAP;
        }
    }
    if (child > 0) stop_ra_child(child);
    if (dns64_stop) result = 0;
    retract_active_prefix(runtime_dir);
    close(fd);
    close(ra_fd);
    unlink(snapshot);
    return result;
#else
    (void)configured; (void)nat66; (void)supervisor_signal; (void)controller;
    (void)runtime_dir; (void)initial_prefix; (void)initial_lifetime;
    return 1;
#endif
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
