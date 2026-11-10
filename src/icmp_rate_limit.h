/* Token accounting separated from synchronization and clock acquisition. */
#ifndef TAYGA_ICMP_RATE_LIMIT_H
#define TAYGA_ICMP_RATE_LIMIT_H
#include <stdbool.h>
#include <stdint.h>
struct icmp_bucket {
    uint64_t last_ms, credit;
    bool initialized;
};
/* Caller serializes access. Monotonic milliseconds supplied by the caller. */
static inline bool icmp_bucket_take(struct icmp_bucket *b, uint32_t rate, uint64_t tick)
{
    uint64_t capacity = (uint64_t)(rate < 200 ? rate : 200) * 1000;
    if (!b->initialized) {
        b->credit = capacity;
        b->initialized = true;
    } else {
        uint64_t elapsed = tick >= b->last_ms ? tick - b->last_ms : 0;
        /* Saturate before multiplying, including extremely long idle periods. */
        if (rate && elapsed >= (capacity + rate - 1) / rate)
            b->credit = capacity;
        else {
            uint64_t refill = elapsed * rate;
            b->credit = refill >= capacity - b->credit ? capacity : b->credit + refill;
        }
    }
    if (tick > b->last_ms)
        b->last_ms = tick;	/* never move back: workers read the clock before taking the lock */
    bool allow = b->credit >= 1000;
    if (allow) b->credit -= 1000;
    return allow;
}
#endif
