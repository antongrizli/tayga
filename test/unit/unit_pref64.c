/*
 *  unit_pref64.c -- Unit tests for pref64-discover RFC 7050 extraction
 *
 *  Copyright (C) 2026 Anton Grizli / TAYGA Contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern int parse_ra_pref64_option(const uint8_t *ra, size_t ra_len, struct in6_addr *out_prefix,
                                  int *out_plen, uint32_t *out_lifetime_sec);
extern size_t lookup_hosts_v4(const char *hosts_path, const char *qname,
                              uint8_t v4_list[][4], size_t max_v4);
extern int extract_pref64(const struct in6_addr *in, struct in6_addr *out, int *prefix_len);

static void test_case(const char *in_str, const char *expected_pref, int expected_len)
{
    struct in6_addr in, out;
    int plen = 0;
    if (inet_pton(AF_INET6, in_str, &in) != 1) {
        fprintf(stderr, "FAIL: inet_pton failed for %s\n", in_str);
        exit(1);
    }
    int res = extract_pref64(&in, &out, &plen);
    if (expected_len < 0) {
        if (res >= 0) {
            fprintf(stderr, "FAIL: %s expected to fail but got len %d\n", in_str, plen);
            exit(1);
        }
        printf("PASS (negative): %s -> rejected\n", in_str);
        return;
    }

    if (res < 0 || plen != expected_len) {
        fprintf(stderr, "FAIL: %s expected len %d, got %d (ret=%d)\n", in_str, expected_len, plen, res);
        exit(1);
    }
    char out_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &out, out_str, sizeof(out_str));
    if (strcmp(out_str, expected_pref) != 0) {
        fprintf(stderr, "FAIL: %s expected prefix %s, got %s\n", in_str, expected_pref, out_str);
        exit(1);
    }
    printf("PASS: %s -> %s/%d\n", in_str, out_str, plen);
}

/* Build an RA (16-byte header) followed by one PREF64 option. */
static size_t build_ra(uint8_t *ra, unsigned lifetime_units, unsigned plc, const char *prefix96)
{
    memset(ra, 0, 64);
    ra[0] = 134;
    ra[16] = 38; ra[17] = 2;
    uint16_t v = (uint16_t)((lifetime_units << 3) | plc);
    ra[18] = (uint8_t)(v >> 8); ra[19] = (uint8_t)v;
    struct in6_addr a;
    assert(inet_pton(AF_INET6, prefix96, &a) == 1);
    memcpy(ra + 20, a.s6_addr, 12);
    return 32;
}

extern int parse_ra_pref64_update(const uint8_t *, size_t, struct in6_addr *,
                                  int *, uint32_t *, const struct in6_addr *, int);
static void test_ra_updates(void)
{
    uint8_t ra[64], other[64];
    struct in6_addr active, out;
    int plen;
    uint32_t life;
    assert(inet_pton(AF_INET6, "64:ff9b::", &active) == 1);
    build_ra(ra, 1, 0, "64:ff9b::");
    build_ra(other, 500, 0, "2001:db8:aaaa::");
    memcpy(ra + 32, other + 16, 16);
    assert(parse_ra_pref64_update(ra, 48, &out, &plen, &life, &active, 96) == 0);
    assert(life == 8 && !memcmp(&out, &active, sizeof(out)));
    /* A withdrawal of the active prefix selects a live alternative. */
    ra[18] = ra[19] = 0;
    assert(parse_ra_pref64_update(ra, 48, &out, &plen, &life, &active, 96) == 0);
    assert(life == 4000 && memcmp(&out, &active, sizeof(out)));
    assert(parse_ra_pref64_update(ra, 32, &out, &plen, &life, &active, 96) == 0);
    assert(life == 0 && !memcmp(&out, &active, sizeof(out)));
    build_ra(ra, 0, 0, "2001:db8:aaaa::");
    assert(parse_ra_pref64_update(ra, 32, &out, &plen, &life, &active, 96) != 0);
    assert(parse_ra_pref64_option(ra, 32, &out, &plen, &life) != 0);
}

static void test_ra(void)
{
    static const int plen[6] = {96, 64, 56, 48, 40, 32};
    uint8_t ra[64];
    struct in6_addr out;
    int pl;
    uint32_t life = 0;
    for (unsigned plc = 0; plc < 6; plc++) {
        size_t n = build_ra(ra, 100, plc, "2001:db8:1:2:3:4:ffff:ffff");
        assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) == 0);
        assert(pl == plen[plc] && life == 800);
        for (int i = pl / 8; i < 16; i++)
            assert(out.s6_addr[i] == 0);	/* bits beyond plen cleared */
    }
    size_t n = build_ra(ra, 100, 0, "64:ff9b::");
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) == 0 && pl == 96);
    n = build_ra(ra, 100, 6, "64:ff9b::");		/* reserved PLC */
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) != 0);
    n = build_ra(ra, 100, 7, "64:ff9b::");
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) != 0);
    n = build_ra(ra, 0, 0, "64:ff9b::");		/* lifetime 0 = deprecated */
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) != 0);
    n = build_ra(ra, 100, 0, "ff02::");		/* multicast prefix */
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) != 0);
    n = build_ra(ra, 100, 0, "64:ff9b::");
    assert(parse_ra_pref64_option(ra, n - 8, &out, &pl, &life) != 0);	/* truncated */
    ra[17] = 0;					/* zero-length option */
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) != 0);
    ra[17] = 2; ra[0] = 133;			/* not an RA */
    assert(parse_ra_pref64_option(ra, n, &out, &pl, &life) != 0);
    assert(parse_ra_pref64_option(ra, 15, &out, &pl, &life) != 0);
    /* Two options: the longer lifetime wins. */
    uint8_t two[80];
    memset(two, 0, sizeof(two));
    two[0] = 134;
    for (int k = 0; k < 2; k++) {
        uint8_t *o = two + 16 + 16 * k;
        o[0] = 38; o[1] = 2;
        uint16_t v = (uint16_t)(((k ? 500 : 100) << 3));
        o[2] = (uint8_t)(v >> 8); o[3] = (uint8_t)v;
        struct in6_addr a;
        inet_pton(AF_INET6, k ? "2001:db8:aaaa::" : "64:ff9b::", &a);
        memcpy(o + 4, a.s6_addr, 12);
    }
    assert(parse_ra_pref64_option(two, 48, &out, &pl, &life) == 0 && life == 4000);
    printf("PASS: RFC 8781 PREF64 RA option parsing\n");
}

/* SEC-002: hosts-file override must ignore symlinks, FIFOs and unsafe modes. */
static void test_hosts_file(void)
{
    char dir[] = "/tmp/pref64-hosts-XXXXXX";
    assert(mkdtemp(dir));
    char path[256], link[256], fifo[256], wr[256];
    uint8_t v4[8][4];
    snprintf(path, sizeof(path), "%s/hosts", dir);
    snprintf(link, sizeof(link), "%s/link", dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
    snprintf(wr, sizeof(wr), "%s/writable", dir);

    FILE *f = fopen(path, "w"); assert(f);
    fputs("# comment\n10.0.3.2 v4gw.example v4gw.example.lan\nbad line\n", f);
    fclose(f);
    assert(chmod(path, 0644) == 0);
    assert(lookup_hosts_v4(path, "V4GW.example", v4, 8) == 1);		/* case-insensitive */
    assert(v4[0][0] == 10 && v4[0][3] == 2);
    assert(lookup_hosts_v4(path, "other.example", v4, 8) == 0);
    assert(lookup_hosts_v4(NULL, "v4gw.example", v4, 8) == 0);		/* no implicit file */
    assert(lookup_hosts_v4("/nonexistent/hosts", "v4gw.example", v4, 8) == 0);

    assert(symlink(path, link) == 0);
    assert(lookup_hosts_v4(link, "v4gw.example", v4, 8) == 0);		/* symlink refused */

    assert(mkfifo(fifo, 0600) == 0);
    assert(lookup_hosts_v4(fifo, "v4gw.example", v4, 8) == 0);		/* FIFO must not block */

    f = fopen(wr, "w"); assert(f);
    fputs("10.9.9.9 v4gw.example\n", f); fclose(f);
    assert(chmod(wr, 0666) == 0);
    assert(lookup_hosts_v4(wr, "v4gw.example", v4, 8) == 0);		/* world-writable refused */

    unlink(path); unlink(link); unlink(fifo); unlink(wr); rmdir(dir);
    printf("PASS: hosts-file override refuses symlink, FIFO and writable files\n");
}

int main(void)
{
    printf("Running unit_pref64 tests...\n");
    test_ra();
    test_ra_updates();
    test_hosts_file();

    /* /96 with 64:ff9b:: and Telekom/ISP-style */
    test_case("64:ff9b::192.0.0.170", "64:ff9b::", 96);
    test_case("64:ff9b::192.0.0.171", "64:ff9b::", 96);
    test_case("2001:db8:1:2::c000:aa", "2001:db8:1:2::", 96);
    test_case("2001:db8:1:2::c000:ab", "2001:db8:1:2::", 96);

    /* /64: prefix bytes 0..7, b[8]=u=0, b[9..12]=v4, b[13..15]=0 */
    test_case("2001:db8:1:2:c0:0:aa00:0", "2001:db8:1:2::", 64);

    /* /56: prefix bytes 0..6, b[7]=v4[0], b[8]=u=0, b[9..11]=v4[1..3], b[12..15]=0 */
    test_case("2001:db8:1:2c0:0:aa::", "2001:db8:1:200::", 56);

    /* /48: prefix bytes 0..5, b[6..7]=v4[0..1], b[8]=u=0, b[9..10]=v4[2..3], b[11..15]=0 */
    test_case("2001:db8:1:c000:0:aa00::", "2001:db8:1::", 48);

    /* /40: prefix bytes 0..4, b[5..7]=v4[0..2], b[8]=u=0, b[9]=v4[3], b[10..15]=0 */
    test_case("2001:db8:1c0:0:aa::", "2001:db8:100::", 40);

    /* /32: prefix bytes 0..3, b[4..7]=v4[0..3], b[8]=u=0, b[9..15]=0 */
    test_case("2001:db8:c000:aa::", "2001:db8::", 32);

    test_case("0:0:c000:aa::", NULL, -1); /* zero /32 */
    test_case("0:0:c0:0:aa::", NULL, -1); /* zero /40 */
    test_case("::c000:0:aa00:0:0", NULL, -1); /* zero /48 */
    test_case("::c0:0:aa:0:0", NULL, -1); /* zero /56 */
    test_case("::c0:0:aa00:0", NULL, -1); /* zero /64 */
    test_case("::192.0.0.170", NULL, -1);
    test_case("::ffff:192.0.0.170", NULL, -1);
    test_case("fe80::192.0.0.170", NULL, -1);
    test_case("ff02::192.0.0.170", NULL, -1);

    /* Negative cases: normal non-NAT64 IPv6 addresses */
    test_case("2001:db8::1", NULL, -1);
    test_case("fe80::1", NULL, -1);
    test_case("::1", NULL, -1);
    test_case("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", NULL, -1);

    printf("Running parse_dns_response unit tests...\n");

    extern int parse_dns_response(const uint8_t *resp, size_t rlen, uint16_t expected_id,
                                  const char *expected_domain, struct in6_addr *out, int *prefix_len);

    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));

    /* Build valid response: ID=0x1234, flags=0x8180 (QR=1, RD=1, RA=1, RCODE=0), QD=1, AN=1 */
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[2] = 0x81; pkt[3] = 0x80;
    pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT = 1 */
    pkt[6] = 0x00; pkt[7] = 0x01; /* ANCOUNT = 1 */

    /* QNAME: \x08ipv4only\x04arpa\x00 */
    size_t p = 12;
    pkt[p++] = 8;
    memcpy(&pkt[p], "ipv4only", 8); p += 8;
    pkt[p++] = 4;
    memcpy(&pkt[p], "arpa", 4); p += 4;
    pkt[p++] = 0;

    /* QTYPE=AAAA (28), QCLASS=IN (1) */
    pkt[p++] = 0x00; pkt[p++] = 0x1c;
    pkt[p++] = 0x00; pkt[p++] = 0x01;

    /* Answer: pointer 0xc00c */
    pkt[p++] = 0xc0; pkt[p++] = 0x0c;
    /* TYPE=AAAA (28), CLASS=IN (1), TTL=60 */
    pkt[p++] = 0x00; pkt[p++] = 0x1c;
    pkt[p++] = 0x00; pkt[p++] = 0x01;
    pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x3c;
    /* RDLENGTH=16 */
    pkt[p++] = 0x00; pkt[p++] = 0x10;

    /* RDATA: 64:ff9b::192.0.0.170 */
    struct in6_addr wka_ip;
    inet_pton(AF_INET6, "64:ff9b::192.0.0.170", &wka_ip);
    memcpy(&pkt[p], &wka_ip.s6_addr, 16);
    p += 16;
    size_t valid_len = p;

    struct in6_addr out_p;
    int plen_p = 0;

    /* Test 1: Valid response */
    int ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == 0);
    assert(plen_p == 96);
    char out_buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &out_p, out_buf, sizeof(out_buf));
    assert(strcmp(out_buf, "64:ff9b::") == 0);
    printf("PASS: parse_dns_response valid packet -> %s/%d\n", out_buf, plen_p);

    /* Test 2: Mismatched transaction ID */
    ret = parse_dns_response(pkt, valid_len, 0x9999, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    printf("PASS: parse_dns_response ID mismatch rejected\n");

    /* Test 3: QR=0 (query, not response) */
    pkt[2] &= ~0x80;
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    pkt[2] |= 0x80;
    printf("PASS: parse_dns_response QR=0 rejected\n");

    /* Test 4: TC=1 (truncated) */
    pkt[2] |= 0x02;
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -2);
    pkt[2] &= ~0x02;
    printf("PASS: parse_dns_response TC=1 rejected\n");

    /* Test 5: RCODE=3 (NXDOMAIN) */
    pkt[3] = (pkt[3] & 0xF0) | 0x03;
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    pkt[3] = (pkt[3] & 0xF0) | 0x00;
    printf("PASS: parse_dns_response NXDOMAIN rejected\n");

    /* Test 6: QNAME mismatch */
    ret = parse_dns_response(pkt, valid_len, 0x1234, "otherdomain.com", &out_p, &plen_p);
    assert(ret == -1);
    printf("PASS: parse_dns_response QNAME mismatch rejected\n");

    /* Test 7: QTYPE mismatch */
    pkt[28] = 0x01; /* QTYPE = A (1) instead of AAAA (28) */
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    pkt[28] = 0x1c; /* Restore QTYPE = AAAA */
    printf("PASS: parse_dns_response QTYPE mismatch rejected\n");

    /* Test 8: Truncated packet buffer */
    ret = parse_dns_response(pkt, 20, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    printf("PASS: parse_dns_response truncated length rejected\n");

    /* Test 9: Invalid AAAA rdlen (e.g. 4 bytes instead of 16) */
    pkt[42] = 0x04; /* rdlen = 4 */
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    pkt[42] = 0x10; /* Restore rdlen = 16 */
    printf("PASS: parse_dns_response invalid rdlen rejected\n");

    /* Malformed answer names and unrelated records preceding the AAAA. */
    pkt[31] = 0xc0;
    assert(parse_dns_response(pkt, 32, 0x1234, "ipv4only.arpa", &out_p, &plen_p) == -1);
    pkt[31] = 0x40;
    assert(parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p) == -1);
    pkt[31] = 0x80;
    assert(parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p) == -1);
    pkt[31] = 0xc0;
    memmove(pkt + 31 + 76, pkt + 31, valid_len - 31);
    memset(pkt + 31, 0, 76);
    pkt[31] = 0xc0; pkt[32] = 0x0c;
    pkt[34] = 46; pkt[36] = 1; pkt[42] = 64;
    pkt[7] = 2;
    assert(parse_dns_response(pkt, valid_len + 76, 0x1234, "ipv4only.arpa", &out_p, &plen_p) == 0);
    pkt[34] = 5; /* CNAME */
    assert(parse_dns_response(pkt, valid_len + 76, 0x1234, "ipv4only.arpa", &out_p, &plen_p) == 0);

    printf("All unit_pref64 tests passed successfully!\n");
    return 0;
}
