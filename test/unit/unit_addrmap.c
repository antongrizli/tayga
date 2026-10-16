/* Mapping publication and mask boundaries; no network privileges required. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tayga.h"
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
_Atomic time_t now = 100;
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static int armed, reached, release_lookup;
static atomic_bool reload_started, reload_done;
void addrmap_test_before_publish(void)
{
    pthread_mutex_lock(&gate_mutex);
    if (armed) {
        armed = 0; reached = 1; pthread_cond_broadcast(&gate_cond);
        while (!release_lookup) pthread_cond_wait(&gate_cond, &gate_mutex);
    }
    pthread_mutex_unlock(&gate_mutex);
}
#ifdef __linux__
static int fail_read, read_calls;
static ssize_t failed_file_read(void *cookie, char *buffer, size_t capacity)
{
    (void)cookie;
    const char *line = "map 192.0.2.99 2001:db8::99\n";
    if (read_calls++) { errno = EIO; return -1; }
    assert(capacity >= strlen(line)); memcpy(buffer, line, strlen(line)); return strlen(line);
}
#endif
FILE *addrmap_test_open_file(const char *path)
{
#ifdef __linux__
    if (fail_read) {
        read_calls = 0;
        return fopencookie(NULL, "r", (cookie_io_functions_t){.read = failed_file_read});
    }
#endif
    return fopen(path, "r");
}
static void write_maps(const char *text)
{
    FILE *f = fopen(gcfg.map_file, "w"); assert(f);
    assert(fputs(text, f) >= 0); assert(fclose(f) == 0);
}
static void *reload_thread(void *unused)
{
    (void)unused; atomic_store(&reload_started, true);
    assert(addrmap_reload() == 0); atomic_store(&reload_done, true); return NULL;
}
static void *lookup_thread(void *direction)
{
    struct in_addr v4; struct in6_addr v6;
    assert(inet_pton(AF_INET, "192.0.2.9", &v4) == 1);
    assert(inet_pton(AF_INET6, "2001:db8::9", &v6) == 1);
    if (direction) assert(map_ip6_to_ip4(&v4, &v6, 0) == 0);
    else assert(map_ip4_to_ip6(&v6, &v4) == 0);
    return NULL;
}
static void boundary_masks(void)
{
    struct in_addr mask4, addr4 = {0}; struct in6_addr mask6, addr6 = {0};
    for (int n = 0; n <= 32; n++) {
        assert(calc_ip4_mask(&mask4, &addr4, n) == 0);
        assert(ntohl(mask4.s_addr) == (n ? UINT32_MAX << (32-n) : 0));
        if (n < 32) { addr4.s_addr = htonl(1); assert(calc_ip4_mask(&mask4, &addr4, n) < 0); addr4.s_addr = 0; }
    }
    for (int n = 0; n <= 128; n++) {
        assert(calc_ip6_mask(&mask6, &addr6, n) == 0);
        for (int bit = 0; bit < 128; bit++) assert(!!(mask6.s6_addr[bit/8] & (0x80 >> (bit%8))) == (bit < n));
        if (n < 128) { addr6.s6_addr[15] = 1; assert(calc_ip6_mask(&mask6, &addr6, n) < 0); addr6.s6_addr[15] = 0; }
    }
    assert(calc_ip4_mask(&mask4, NULL, -1) < 0); assert(calc_ip4_mask(&mask4, NULL, 33) < 0);
    assert(calc_ip6_mask(&mask6, NULL, -1) < 0); assert(calc_ip6_mask(&mask6, NULL, 129) < 0);
}
static void test_immutable_maps(void)
{
    assert(config_init() == 0);
    assert(pthread_mutex_init(&gcfg.map_mutex, NULL) == 0);
    assert(pthread_mutex_init(&gcfg.cache_mutex, NULL) == 0);
    char filename[] = "/tmp/tayga-immutable-XXXXXX";
    int fd = mkstemp(filename); assert(fd >= 0); FILE *f = fdopen(fd, "w"); assert(f);
    fputs("tun-device review\nipv4-addr 192.0.2.254\nipv6-addr 2001:db8::fe\nprefix fd64::/96\nmap 192.0.2.9 2001:db8::9\n", f);
    assert(fclose(f) == 0); assert(config_read(filename) == 0); assert(config_validate() == 0); unlink(filename);
    assert(gcfg.maps_immutable && !gcfg.cache_size);
    pthread_mutex_lock(&gcfg.map_mutex); pthread_mutex_lock(&gcfg.cache_mutex);
    alarm(5); lookup_thread(NULL); lookup_thread((void *)1); alarm(0);
    pthread_mutex_unlock(&gcfg.cache_mutex); pthread_mutex_unlock(&gcfg.map_mutex);
    struct list_head *entry, *next;
    list_for_each_safe(entry, next, &gcfg.map4_list) {
        struct map_static *m = list_entry(entry, struct map_static, map4.list);
        list_del(&m->map4.list); list_del(&m->map6.list); free(m);
    }
    pthread_mutex_destroy(&gcfg.map_mutex); pthread_mutex_destroy(&gcfg.cache_mutex);
    puts("PASS: validated immutable maps bypass both held mutexes and cache");
}

static atomic_bool dynamic_finished;
static void *dynamic_lookup(void *unused)
{
    (void)unused;
    struct in6_addr client; struct in_addr mapped, returned;
    inet_pton(AF_INET6, "2001:db8:5::1", &client);
    for (int i = 0; i < 10000; i++) {
        assert(map_ip6_to_ip4(&mapped, &client, 1) == 0);
        struct in6_addr inverse;
        assert(map_ip4_to_ip6(&inverse, &mapped) == 0);
        assert(IN6_ARE_ADDR_EQUAL(&client, &inverse));
        assert(map_ip6_to_ip4(&returned, &inverse, 1) == 0 && mapped.s_addr == returned.s_addr);
    }
    atomic_store(&dynamic_finished, true); return NULL;
}
static void *clock_updates(void *unused)
{
    (void)unused;
    for (int i = 0; i < 10000; i++) atomic_store_explicit(&now, 100 + i % 10, memory_order_relaxed);
    return NULL;
}
static void test_dynamic_dump(void)
{
    assert(config_init() == 0);
    assert(pthread_mutex_init(&gcfg.map_mutex, NULL) == 0);
    assert(pthread_mutex_init(&gcfg.cache_mutex, NULL) == 0);
    char directory[] = "/tmp/tayga-dynamic-review-XXXXXX";
    assert(mkdtemp(directory));
    int cwd = open(".", O_RDONLY); assert(cwd >= 0); assert(chdir(directory) == 0);
    FILE *f = fopen("config", "w"); assert(f);
    fprintf(f, "tun-device review\nipv4-addr 192.0.2.254\nipv6-addr 2001:db8::fe\nprefix fd64::/96\ndynamic-pool 198.18.0.0/24\ndata-dir %s\n", directory);
    assert(fclose(f) == 0); assert(config_read("config") == 0); assert(config_validate() == 0);
    gcfg.cache_size = 16; gcfg.hash_bits = 2; gcfg.rand[0] = 1;
    assert(create_cache() == 0);
    void *storage = list_entry(gcfg.cache_pool.next, struct cache_entry, list);
    atomic_store(&dynamic_finished, false); atomic_store(&now, 100);
    pthread_t lookup, clock;
    assert(pthread_create(&lookup, NULL, dynamic_lookup, NULL) == 0);
    assert(pthread_create(&clock, NULL, clock_updates, NULL) == 0);
    do { addrmap_maint(); dynamic_maint(gcfg.dynamic_pool, 1); } while (!atomic_load(&dynamic_finished));
    pthread_join(lookup, NULL); pthread_join(clock, NULL); dynamic_maint(gcfg.dynamic_pool, 1);
    f = fopen("dynamic.map", "r"); assert(f);
    char line[512]; int found = 0;
    while (fgets(line, sizeof(line), f)) if (strstr(line, "2001:db8:5::1")) found++;
    fclose(f); assert(found == 1);
    struct in6_addr client; struct in_addr allocated, subnet, mask;
    inet_pton(AF_INET6, "2001:db8:5::1", &client);
    assert(map_ip6_to_ip4(&allocated, &client, 1) == 0);
    struct map_dynamic *host = container_of(find_map4(&allocated), struct map_dynamic, map4);
    assert(host->cache_entry);
    assert(calc_ip4_mask(&mask, NULL, 25) == 0); subnet.s_addr = allocated.s_addr & mask.s_addr;
    char address[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &subnet, address, sizeof(address));
    strcpy(gcfg.map_file, "replacement.map"); f = fopen(gcfg.map_file, "w"); assert(f);
    fprintf(f, "map %s/25 2001:db8:8::/121\n", address); assert(fclose(f) == 0);
    assert(addrmap_reload() == 0); assert(!host->cache_entry);
    assert(map_ip6_to_ip4(&allocated, &client, 1) == 0); assert(host->cache_entry);
    unlink("replacement.map");
    /* These structures are no longer shared; reclaim the fixture. */
    struct list_head *entry, *next;
    list_for_each_safe(entry, next, &gcfg.dynamic_pool->mapped_list) {
        struct map_dynamic *d = list_entry(entry, struct map_dynamic, list);
        list_del(&d->map4.list); list_del(&d->map6.list); list_del(&d->list); free(d);
    }
    list_del(&gcfg.dynamic_pool->map4.list); free(gcfg.dynamic_pool);
    list_for_each_safe(entry, next, &gcfg.map4_list) {
        struct map_static *m = list_entry(entry, struct map_static, map4.list);
        list_del(&m->map4.list); list_del(&m->map6.list); free(m);
    }
    free(storage); free(gcfg.hash_table4); free(gcfg.hash_table6);
    unlink("config"); unlink("dynamic.map"); assert(fchdir(cwd) == 0); close(cwd); assert(rmdir(directory) == 0);
    pthread_mutex_destroy(&gcfg.map_mutex); pthread_mutex_destroy(&gcfg.cache_mutex);
    puts("PASS: concurrent dynamic lookup, maintenance, disk snapshot and atomic clock");
}

int main(void)
{
    boundary_masks(); assert(config_init() == 0);
    assert(pthread_mutex_init(&gcfg.map_mutex, NULL) == 0);
    assert(pthread_mutex_init(&gcfg.cache_mutex, NULL) == 0);
    gcfg.cache_size = 16; gcfg.hash_bits = 2; gcfg.rand[0] = 1;
    assert(create_cache() == 0);
    void *cache_storage = list_entry(gcfg.cache_pool.next, struct cache_entry, list);
    strcpy(gcfg.map_file, "/tmp/tayga-map-review-XXXXXX");
    int fd = mkstemp(gcfg.map_file); assert(fd >= 0); close(fd);
    for (int direction = 0; direction < 2; direction++) {
        write_maps("map 192.0.2.9 2001:db8::9\n"); assert(addrmap_reload() == 0);
        pthread_mutex_lock(&gate_mutex); armed = 1; reached = release_lookup = 0; pthread_mutex_unlock(&gate_mutex);
        atomic_store(&reload_started, false); atomic_store(&reload_done, false);
        pthread_t lookup, reload;
        assert(pthread_create(&lookup, NULL, lookup_thread, (void *)(intptr_t)direction) == 0);
        pthread_mutex_lock(&gate_mutex);
        while (!reached) pthread_cond_wait(&gate_cond, &gate_mutex);
        /* The reload cannot acquire map_mutex before cache publication. */
        assert(pthread_mutex_trylock(&gcfg.map_mutex) == EBUSY);
        write_maps(direction ? "map 192.0.2.10 2001:db8::9\n" : "map 192.0.2.9 2001:db8::10\n");
        assert(pthread_create(&reload, NULL, reload_thread, NULL) == 0);
        while (!atomic_load(&reload_started)) usleep(1000);
        assert(!atomic_load(&reload_done)); release_lookup = 1; pthread_cond_broadcast(&gate_cond); pthread_mutex_unlock(&gate_mutex);
        pthread_join(lookup, NULL); pthread_join(reload, NULL);
        struct in_addr v4; struct in6_addr v6, expected;
        inet_pton(AF_INET, "192.0.2.9", &v4); inet_pton(AF_INET6, "2001:db8::9", &v6);
        if (direction) { assert(map_ip6_to_ip4(&v4, &v6, 0) == 0); struct in_addr e; inet_pton(AF_INET, "192.0.2.10", &e); assert(v4.s_addr == e.s_addr); }
        else { assert(map_ip4_to_ip6(&v6, &v4) == 0); inet_pton(AF_INET6, "2001:db8::10", &expected); assert(IN6_ARE_ADDR_EQUAL(&v6, &expected)); }
        /* A malformed replacement must retain both old maps and cache. */
        write_maps("map 192.0.2.99 2001:db8::99\nmap broken 2001:db8::10\n"); assert(addrmap_reload() < 0);
        assert(map_ip6_to_ip4(&v4, &v6, 0) == 0);
#ifdef __linux__
        fail_read = 1; assert(addrmap_reload() < 0); fail_read = 0;
        assert(map_ip6_to_ip4(&v4, &v6, 0) == 0);
#endif
    }
    write_maps("map 192.0.2.9 2001:db8::9\n"); assert(addrmap_reload() == 0);
    pthread_t threads[8];
    for (int i = 0; i < 8; i++) assert(pthread_create(&threads[i], NULL, lookup_thread, (void *)(intptr_t)(i%2)) == 0);
    for (int i = 0; i < 8; i++) pthread_join(threads[i], NULL);
    int count = 0; struct list_head *item;
    list_for_each(item, &gcfg.cache_active) count++;
    assert(count == 1);
    write_maps(""); assert(addrmap_reload() == 0); unlink(gcfg.map_file);
    free(cache_storage); free(gcfg.hash_table4); free(gcfg.hash_table6);
    pthread_mutex_destroy(&gcfg.map_mutex); pthread_mutex_destroy(&gcfg.cache_mutex);
    test_immutable_maps();
    test_dynamic_dump();
    puts("PASS: all masks, bidirectional reload publication, malformed transaction, concurrent miss deduplication");
    return 0;
}
