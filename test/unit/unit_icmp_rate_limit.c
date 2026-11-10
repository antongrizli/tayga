#include "icmp_rate_limit.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
    struct icmp_bucket b = {0};
    assert(icmp_bucket_take(&b, 1, 100000));
    assert(!icmp_bucket_take(&b, 1, 100000));
    assert(!icmp_bucket_take(&b, 1, 100999));
    assert(icmp_bucket_take(&b, 1, 101000));
    assert(!icmp_bucket_take(&b, 1, 101000));
    b = (struct icmp_bucket){0};
    for (int i = 0; i < 3; i++) assert(icmp_bucket_take(&b, 3, 0));
    assert(!icmp_bucket_take(&b, 3, 0));
    assert(!icmp_bucket_take(&b, 3, 333));
    assert(icmp_bucket_take(&b, 3, 334));
    assert(!icmp_bucket_take(&b, 3, 666));
    assert(icmp_bucket_take(&b, 3, 667));
    assert(icmp_bucket_take(&b, 3, 1000));
    assert(!icmp_bucket_take(&b, 3, 1000));
    b = (struct icmp_bucket){0};
    for (int i = 0; i < 200; i++) assert(icmp_bucket_take(&b, 1000, 0));
    assert(!icmp_bucket_take(&b, 1000, 0));
    for (int i = 0; i < 200; i++) assert(icmp_bucket_take(&b, 1000, UINT64_MAX - 1));
    assert(!icmp_bucket_take(&b, 1000, UINT64_MAX - 1));
    assert(icmp_bucket_take(&b, 1000, UINT64_MAX));
    assert(!icmp_bucket_take(&b, 1000, UINT64_MAX));
    puts("PASS: ICMP burst, fractional refill and saturated long idle");
    return 0;
}
