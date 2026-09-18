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

    printf("All unit_pref64 tests passed successfully!\n");
    return 0;
}
