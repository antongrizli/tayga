/*
 *  pref64_ra.h -- RFC 8781 PREF64 candidate table shared by pref64-discover
 *  and its unit tests.
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PREF64_RA_H
#define PREF64_RA_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define RA_CANDIDATES 8
#define RA_MAX_OPTIONS 8

struct ra_option {
    struct in6_addr prefix;
    int plen;
    uint32_t life;	/* seconds; 0 = withdrawal */
};

struct ra_candidate {
    struct in6_addr router, prefix;
    int plen;
    uint32_t life;
    time_t deadline;	/* monotonic seconds */
    int used, provisional;
};

struct ra_table {
    struct ra_candidate c[RA_CANDIDATES];
};

int is_valid_pref64_prefix(const struct in6_addr *p, int plen);
int parse_ra_pref64_update(const uint8_t *ra, size_t ra_len, struct in6_addr *out_prefix,
                           int *out_plen, uint32_t *out_lifetime_sec,
                           const struct in6_addr *active, int active_len);
int parse_ra_pref64_option(const uint8_t *ra, size_t ra_len, struct in6_addr *out_prefix,
                           int *out_plen, uint32_t *out_lifetime_sec);
int parse_ra_pref64_all(const uint8_t *ra, size_t ra_len, struct ra_option *out, int max);
void ra_table_init(struct ra_table *t);
void ra_table_add_provisional(struct ra_table *t, const struct in6_addr *prefix, int plen,
                              uint32_t life, time_t now);
void ra_table_apply(struct ra_table *t, const struct in6_addr *router,
                    const struct ra_option *opts, int n, time_t now);
void ra_table_expire(struct ra_table *t, time_t now);
int ra_table_pick(const struct ra_table *t, const struct in6_addr *active, int active_len,
                  time_t now, struct in6_addr *out, int *plen, time_t *deadline, uint32_t *life);

#endif
