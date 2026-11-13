/*
 *  pref64_ra.c -- RFC 8781 PREF64 option parsing and candidate table
 *
 *  Copyright (C) 2026 Anton Grizli / TAYGA Contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include "pref64_ra.h"

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

int is_valid_pref64_prefix(const struct in6_addr *p, int plen)
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
