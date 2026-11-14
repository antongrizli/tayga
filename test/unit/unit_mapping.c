/* Regression tests for circular allocation and RFC 7757 prefix replacement. */
#include "tayga.h"
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
_Atomic time_t now = 10000;

static void configure(const char *extra)
{
    assert(config_init() == 0);
    assert(pthread_mutex_init(&gcfg.map_mutex, NULL) == 0);
    assert(pthread_mutex_init(&gcfg.cache_mutex, NULL) == 0);
    char name[] = "mapping-XXXXXX";
    int fd = mkstemp(name); assert(fd >= 0);
    FILE *f = fdopen(fd, "w"); assert(f);
    fputs("tun-device audit\nipv4-addr 192.0.2.254\nipv6-addr 2001:db8:ffff::fe\n", f);
    fputs(extra, f); assert(fclose(f) == 0);
    assert(config_read(name) == 0); assert(config_validate() == 0);
    gcfg.cache_size = 0;
    assert(unlink(name) == 0);
}

static void reclaim(void)
{
    struct list_head *entry, *next;
    if (gcfg.dynamic_pool) {
        struct list_head *heads[] = {&gcfg.dynamic_pool->mapped_list, &gcfg.dynamic_pool->dormant_list};
        for (int n = 0; n < 2; ++n) {
            list_for_each_safe(entry, next, heads[n]) {
                struct map_dynamic *d = list_entry(entry, struct map_dynamic, list);
                if (n == 0) { list_del(&d->map4.list); list_del(&d->map6.list); }
                list_del(&d->list); free(d);
            }
        }
        list_del(&gcfg.dynamic_pool->map4.list); free(gcfg.dynamic_pool);
    }
    list_for_each_safe(entry, next, &gcfg.map4_list) {
        struct map_static *m = list_entry(entry, struct map_static, map4.list);
        list_del(&m->map4.list); list_del(&m->map6.list); free(m);
    }
    pthread_mutex_destroy(&gcfg.map_mutex); pthread_mutex_destroy(&gcfg.cache_mutex);
}

static void test_circular_pool(void)
{
    configure("prefix fd64::/96\ndynamic-pool 198.18.0.0/29\n");
    unsigned allocated = 0, seen = 0;
    for (unsigned i = 1; i < 1024; ++i) {
        char text[64]; struct in6_addr client;
        snprintf(text, sizeof(text), "2001:db8::%x", i);
        assert(inet_pton(AF_INET6, text, &client) == 1);
        uint32_t hash = 0;
        for (int n = 0; n < 4; ++n) {
            hash += client.s6_addr32[n];
            while (hash & ~7u) hash = (hash & 7u) + (hash >> 3);
        }
        if (hash != 7) continue;
        struct map6 *m = assign_dynamic(&client);
        if (allocated == 7) { assert(!m); break; }
        assert(m);
        struct map_dynamic *d = container_of(m, struct map_dynamic, map6);
        unsigned slot = ntohl(d->map4.addr.s_addr) & 7;
        assert(slot && !(seen & (1u << slot)));
        if (!allocated) assert(slot == 7);
        seen |= 1u << slot; ++allocated;
    }
    assert(allocated == 7 && seen == 254);
    /* True exhaustion may reuse the oldest dormant lease. */
    struct list_head *entry;
    list_for_each(entry, &gcfg.dynamic_pool->mapped_list) {
        list_entry(entry, struct map_dynamic, list)->last_use = 0;
    }
    dynamic_maint(gcfg.dynamic_pool, 0);
    struct in6_addr other;
    assert(inet_pton(AF_INET6, "2001:db8:1::abcd", &other) == 1);
    assert(assign_dynamic(&other));
    reclaim();
    puts("PASS: colliding final-slot allocations wrap, exhaust, then reuse dormant leases");
}

/* STAB-003/004: leases are aged on a monotonic tick (a wall-clock jump does
 * not expire them); dynamic.map is 0600, keeps the wall-epoch format, and
 * survives a reload. */
static void test_dynamic_persistence(void)
{
    configure("prefix fd64::/96\ndynamic-pool 198.18.0.0/29\n");
    snprintf(gcfg.data_dir, sizeof(gcfg.data_dir), "%s", ".");
    struct in6_addr client;
    assert(inet_pton(AF_INET6, "2001:db8::77", &client) == 1);
    struct map6 *m = assign_dynamic(&client);
    assert(m);
    struct map_dynamic *d = container_of(m, struct map_dynamic, map6);
    struct in_addr leased = d->map4.addr;
    d->last_use = now - 100;	/* idle for 100 monotonic seconds */
    dynamic_maint(gcfg.dynamic_pool, 1);

    struct stat st;
    assert(stat("dynamic.map", &st) == 0 && (st.st_mode & 0777) == 0600);
    FILE *f = fopen("dynamic.map", "r"); assert(f);
    char line[256], a4[64], a6[64]; long long stamp = 0; int rows = 0;
    while (fgets(line, sizeof(line), f))
        if (line[0] != '#' && sscanf(line, "%63s %63s %lld", a4, a6, &stamp) == 3) rows++;
    fclose(f);
    assert(rows == 1);
    /* Wall-clock epoch, aged by the 100 s idle time (not the tick value). */
    long long wall = (long long)time(NULL);
    assert(stamp <= wall - 99 && stamp >= wall - 105);

    /* Temporaries left by a killed daemon are removed on the next load. */
    FILE *stale = fopen("dynamic.map.AbC123", "w"); assert(stale); fclose(stale);
    stale = fopen("dynamic.map.keep", "w"); assert(stale); fclose(stale);	/* not a mkstemp name */
    reclaim();
    configure("prefix fd64::/96\ndynamic-pool 198.18.0.0/29\n");
    load_dynamic(gcfg.dynamic_pool);
    assert(access("dynamic.map.AbC123", F_OK) != 0 && access("dynamic.map.keep", F_OK) == 0);
    assert(unlink("dynamic.map.keep") == 0);
    struct in_addr again;
    assert(map_ip6_to_ip4(&again, &client, 0) == 0 && again.s_addr == leased.s_addr);
    assert(unlink("dynamic.map") == 0);
    reclaim();
    gcfg.data_dir[0] = 0;
    puts("PASS: dynamic.map is 0600 wall-epoch and survives reload with monotonic ageing");
}

static void check_pair(const char *v4, const char *v6)
{
    struct in_addr a4, translated4; struct in6_addr a6, translated6;
    assert(inet_pton(AF_INET, v4, &a4) == 1);
    assert(inet_pton(AF_INET6, v6, &a6) == 1);
    assert(map_ip4_to_ip6(&translated6, &a4) == 0);
    assert(IN6_ARE_ADDR_EQUAL(&translated6, &a6));
    assert(map_ip6_to_ip4(&translated4, &a6, 0) == 0);
    assert(translated4.s_addr == a4.s_addr);
}

static void test_eam(void)
{
    const struct { const char *mapping, *v6; } cases[] = {
        {"map 198.51.100.90/32 2001:db8:aaaa::/128\n", "2001:db8:aaaa::"},
        {"map 198.51.100.90/32 2001:db8:aaaa::/64\n", "2001:db8:aaaa::"},
        {"map 198.51.100.0/24 2001:db8:aaaa::/48\n", "2001:db8:aaaa:5a00::"},
        {"map 198.51.100.0/24 2001:db8:aaaa:bbbb::/64\n", "2001:db8:aaaa:bbbb:5a00::"},
        {"map 198.51.100.0/24 2001:db8:aaaa:bbb8::/61\n", "2001:db8:aaaa:bbba:d000::"},
        {"map 198.51.100.0/24 2001:db8:aaaa::/120\n", "2001:db8:aaaa::5a"},
    };
    for (unsigned n = 0; n < sizeof(cases)/sizeof(cases[0]); ++n) {
        configure(cases[n].mapping);
        check_pair("198.51.100.90", cases[n].v6);
        reclaim();
        /* The same syntax and algorithm must work through map-file reload. */
        configure("prefix fd64::/96\n");
        strcpy(gcfg.map_file, "mapping-reload.conf");
        FILE *f = fopen(gcfg.map_file, "w"); assert(f);
        fputs(cases[n].mapping, f); assert(fclose(f) == 0);
        gcfg.maps_immutable = 0;
        assert(addrmap_reload() == 0);
        check_pair("198.51.100.90", cases[n].v6);
        unlink(gcfg.map_file); reclaim();
    }
    configure("map 0.0.0.0/0 2001:db8:aaaa::/96\n");
    check_pair("198.51.100.90", "2001:db8:aaaa::c633:645a");
    {
        struct in_addr test_v4; struct in6_addr test_v6;
        /* Martian/loopback, multicast, broadcast, and local_addr4 must be rejected */
        assert(inet_pton(AF_INET6, "2001:db8:aaaa::7f00:0001", &test_v6) == 1);
        assert(map_ip6_to_ip4(&test_v4, &test_v6, 0) == ERROR_DROP);
        assert(inet_pton(AF_INET6, "2001:db8:aaaa::e000:0001", &test_v6) == 1);
        assert(map_ip6_to_ip4(&test_v4, &test_v6, 0) == ERROR_DROP);
        assert(inet_pton(AF_INET6, "2001:db8:aaaa::ffff:ffff", &test_v6) == 1);
        assert(map_ip6_to_ip4(&test_v4, &test_v6, 0) == ERROR_DROP);
        assert(inet_pton(AF_INET6, "2001:db8:aaaa::c000:02fe", &test_v6) == 1); /* 192.0.2.254 = local_addr4 */
        assert(map_ip6_to_ip4(&test_v4, &test_v6, 0) == ERROR_DROP);
    }
    reclaim();
    configure("map 198.51.100.0/24 2001:db8:aaaa::/48\n");
    gcfg.maps_immutable = 0; gcfg.cache_size = 16; gcfg.hash_bits = 2; gcfg.rand[0] = 1;
    assert(create_cache() == 0);
    void *cache_storage = list_entry(gcfg.cache_pool.next, struct cache_entry, list);
    struct in6_addr noncanonical; struct in_addr v4;
    assert(inet_pton(AF_INET6, "2001:db8:aaaa:5a00::1", &noncanonical) == 1);
    assert(map_ip6_to_ip4(&v4, &noncanonical, 0) == 0);
    check_pair("198.51.100.90", "2001:db8:aaaa:5a00::");
    free(cache_storage); free(gcfg.hash_table4); free(gcfg.hash_table6);
    gcfg.cache_size = 0; reclaim();
    /* Longest-prefix IPv4 overrides remain supported; overshadowed v6 mapping is dropped (RFC 7757). */
    configure("map 198.51.100.0/24 2001:db8:aaaa::/48\nmap 198.51.100.90 2001:db8:bbbb::1\n");
    check_pair("198.51.100.90", "2001:db8:bbbb::1");
    check_pair("198.51.100.91", "2001:db8:aaaa:5b00::");
    {
        struct in_addr test_v4; struct in6_addr overshadowed;
        assert(inet_pton(AF_INET6, "2001:db8:aaaa:5a00::", &overshadowed) == 1);
        assert(map_ip6_to_ip4(&test_v4, &overshadowed, 0) == ERROR_DROP);
    }
    reclaim();
    configure("map 198.51.100.90/32 2001:db8:aaaa::/64\n");
    /* Exact duplicate IPv6 EAM prefixes are still rejected. */
    FILE *overlap = fopen("mapping-invalid.conf", "w"); assert(overlap);
    fputs("map 198.51.100.91/32 2001:db8:aaaa::/64\n", overlap); fclose(overlap);
    assert(config_read("mapping-invalid.conf") == ERROR_REJECT);
    unlink("mapping-invalid.conf");
    check_pair("198.51.100.90", "2001:db8:aaaa::");
    reclaim();
    /* Overlapping IPv6 static EAM entries of different prefix lengths resolve via LPM (RFC 7757). */
    configure("map 198.51.100.90/32 2001:db8:aaaa::/64\nmap 198.51.100.91 2001:db8:aaaa::1\n");
    check_pair("198.51.100.90", "2001:db8:aaaa::");
    check_pair("198.51.100.91", "2001:db8:aaaa::1");
    strcpy(gcfg.map_file,"mapping-reload.conf");gcfg.maps_immutable=0;
    overlap=fopen(gcfg.map_file,"w");assert(overlap);
    fputs("map 198.51.100.92 2001:db8:aaaa::2\nmap 192.0.2.254 2001:db8:bbbb::1\n",overlap);fclose(overlap);
    assert(addrmap_reload()==0); /* Conflicting fixed/self entries are skipped. */
    check_pair("198.51.100.90", "2001:db8:aaaa::");
    check_pair("198.51.100.92", "2001:db8:aaaa::2");
    struct in_addr local;struct in6_addr unused;
    inet_pton(AF_INET,"192.0.2.254",&local);
    assert(map_ip4_to_ip6(&unused,&local)==0);
    assert(IN6_ARE_ADDR_EQUAL(&unused,&gcfg.local_addr6));
    overlap=fopen(gcfg.map_file,"w");assert(overlap);
    fputs("map 127.0.0.1 2001:db8:bbbb::1\n",overlap);fclose(overlap);
    assert(addrmap_reload()==ERROR_REJECT);
    check_pair("198.51.100.90", "2001:db8:aaaa::");
    unlink(gcfg.map_file);reclaim();

    /* RFC 6052 §2.2: ignore u-octet (s6_addr[8]) and trailing suffix bits for non-/96 prefixes. */
    {
        const struct {
            const char *prefix;
            const char *v6_with_bits;
            const char *expected_v4;
        } rfc6052_cases[] = {
            {"prefix fd00::/32\n",           "fd00:0:c633:645a:ff:0012:3456:789a",     "198.51.100.90"},
            {"prefix 2001:db8:100::/40\n",   "2001:db8:1c6:3364:ff5a:0012:3456:789a", "198.51.100.90"},
            {"prefix 2001:db8:123::/48\n",   "2001:db8:123:c633:ff64:5a12:3456:789a", "198.51.100.90"},
            {"prefix 2001:db8:1234::/56\n",  "2001:db8:1234:00c6:ff33:645a:1234:5678", "198.51.100.90"},
            {"prefix 2001:db8:1:2::/64\n",   "2001:db8:1:2:ffc6:3364:5a12:3456",     "198.51.100.90"},
        };
        for (size_t i = 0; i < sizeof(rfc6052_cases) / sizeof(rfc6052_cases[0]); i++) {
            configure(rfc6052_cases[i].prefix);
            struct in6_addr in6; struct in_addr out4, exp4;
            assert(inet_pton(AF_INET6, rfc6052_cases[i].v6_with_bits, &in6) == 1);
            assert(inet_pton(AF_INET, rfc6052_cases[i].expected_v4, &exp4) == 1);
            assert(map_ip6_to_ip4(&out4, &in6, 0) == 0);
            assert(out4.s_addr == exp4.s_addr);
            reclaim();
        }
    }

    /* RFC 7526: 192.88.99.0/24 is rejected under wkpf-strict=yes with 64:ff9b::/96. */
    configure("prefix 64:ff9b::/96\n");
    gcfg.wkpf_strict = 1;
    {
        struct in6_addr v6_6to4; struct in_addr out4;
        assert(inet_pton(AF_INET6, "64:ff9b::c058:6301", &v6_6to4) == 1); /* 192.88.99.1 */
        assert(map_ip6_to_ip4(&out4, &v6_6to4, 0) == ERROR_REJECT);
    }
    reclaim();
    puts("PASS: host/subnet EAM, reload, RFC 7757 LPM, RFC 6052 §2.2, RFC 7526");
}

int main(void)
{
    FILE *stale = fopen("dynamic.map", "w"); assert(stale);
    fputs("192.0.2.1 2001:db8::1 10000\n", stale); assert(fclose(stale) == 0);
    load_dynamic(NULL);
    assert(unlink("dynamic.map") == 0);
    test_circular_pool(); test_dynamic_persistence(); test_eam(); return 0;
}
