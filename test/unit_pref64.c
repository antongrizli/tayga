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

int main(void)
{
    printf("Running unit_pref64 tests...\n");

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
    assert(ret == -1);
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
    pkt[27] = 0x01; /* QTYPE = A (1) instead of AAAA (28) */
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    pkt[27] = 0x1c; /* Restore QTYPE = AAAA */
    printf("PASS: parse_dns_response QTYPE mismatch rejected\n");

    /* Test 8: Truncated packet buffer */
    ret = parse_dns_response(pkt, 20, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    printf("PASS: parse_dns_response truncated length rejected\n");

    /* Test 9: Invalid AAAA rdlen (e.g. 4 bytes instead of 16) */
    pkt[39] = 0x04; /* rdlen = 4 */
    ret = parse_dns_response(pkt, valid_len, 0x1234, "ipv4only.arpa", &out_p, &plen_p);
    assert(ret == -1);
    pkt[39] = 0x10; /* Restore rdlen = 16 */
    printf("PASS: parse_dns_response invalid rdlen rejected\n");

    printf("All unit_pref64 tests passed successfully!\n");
    return 0;
}
