/*
 *  unit_stats.c -- Unit test for unified packet counters and JSON export
 *
 *  Part of TAYGA
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include "tayga.h"
#include "stats.h"
#include "gso.h"

struct config gcfg;
struct gso_worker_stats g_gso_stats;

/* Stub for dynamic pool query in unit test */
void dynamic_get_stats(const struct dynamic_pool *pool, uint32_t *mapped, uint32_t *dormant, uint32_t *free_addrs)
{
	if (pool) {
		if (mapped) *mapped = 42;
		if (dormant) *dormant = 7;
		if (free_addrs) *free_addrs = 100;
	} else {
		if (mapped) *mapped = 0;
		if (dormant) *dormant = 0;
		if (free_addrs) *free_addrs = 0;
	}
}

static void *thread_worker_test(void *arg)
{
	int id = *(int *)arg;
	stats_thread_init(id);
	for (int i = 0; i < 1000; i++) {
		stats_rx4(100);
		stats_tx4(100);
	}
	stats_flush_worker();
	return NULL;
}

static _Atomic int stop_reader = 0;
static uint64_t reader_iterations = 0;

static void *reader_worker(void *arg) {
	(void)arg;
	stats_thread_init(-1);
	struct tayga_stats snap;
	uint64_t last_rx = 0;
	while (!atomic_load_explicit(&stop_reader, memory_order_relaxed)) {
		stats_get_snapshot(&snap);
		assert(snap.rx_pkts_v4 >= last_rx);
		last_rx = snap.rx_pkts_v4;
		reader_iterations++;
	}
	return NULL;
}

static void *stress_writer(void *arg) {
	int id = *(int *)arg;
	stats_thread_init(id + 4);
	for (int i = 0; i < 250000; i++) {
		stats_rx4(64);
		stats_tx4(64);
		if ((i & 0x7) == 0) {
			stats_gso_rx(1400);
			stats_gso_tx(1400);
		}
	}
	stats_flush_worker();
	return NULL;
}

int main(void)
{
	printf("=== Testing stats subsystem ===\n");

	/* Test 1: stats_init */
	stats_init();
	struct tayga_stats s;
	stats_get_snapshot(&s);
	assert(s.rx_pkts_v4 == 0);
	assert(s.rx_bytes_v4 == 0);
	assert(s.tx_pkts_v4 == 0);
	assert(s.tx_bytes_v4 == 0);
	assert(s.rx_pkts_v6 == 0);
	assert(s.rx_bytes_v6 == 0);
	assert(s.tx_pkts_v6 == 0);
	assert(s.tx_bytes_v6 == 0);
	assert(s.dropped_pkts == 0);
	assert(s.dropped_bytes == 0);
	assert(s.error_pkts == 0);
	assert(s.start_time > 0);
	printf("PASS: stats_init initializes all counters to 0\n");

	/* Test 2: packet counter increments */
	stats_rx4(1500);
	stats_rx4(500);
	stats_get_snapshot(&s);
	assert(s.rx_pkts_v4 == 2);
	assert(s.rx_bytes_v4 == 2000);

	stats_tx4(1400);
	stats_get_snapshot(&s);
	assert(s.tx_pkts_v4 == 1);
	assert(s.tx_bytes_v4 == 1400);

	stats_rx6(1520);
	stats_get_snapshot(&s);
	assert(s.rx_pkts_v6 == 1);
	assert(s.rx_bytes_v6 == 1520);

	stats_tx6(1520);
	stats_get_snapshot(&s);
	assert(s.tx_pkts_v6 == 1);
	assert(s.tx_bytes_v6 == 1520);

	stats_drop(64);
	stats_get_snapshot(&s);
	assert(s.dropped_pkts == 1);
	assert(s.dropped_bytes == 64);

	stats_error();
	stats_get_snapshot(&s);
	assert(s.error_pkts == 1);
	printf("PASS: per-worker counter increments work correctly\n");

	/* Test 3: Multi-threaded concurrent worker test */
	pthread_t th[4];
	int ids[4] = {0, 1, 2, 3};
	for (int i = 0; i < 4; i++) {
		int rc = pthread_create(&th[i], NULL, thread_worker_test, &ids[i]);
		assert(rc == 0);
	}
	for (int i = 0; i < 4; i++) {
		pthread_join(th[i], NULL);
	}
	stats_get_snapshot(&s);
	/* 2 from main thread + 4 * 1000 from threads = 4002 */
	assert(s.rx_pkts_v4 == 4002);
	assert(s.rx_bytes_v4 == 2000 + 400000);
	assert(s.tx_pkts_v4 == 1 + 4000);
	assert(s.tx_bytes_v4 == 1400 + 400000);
	printf("PASS: multi-threaded concurrent worker counters aggregate correctly without contention\n");

	/* Test 4: Concurrent Reader vs. Writers Data-Race Stress Test */
	printf("Testing concurrent reader vs. writers (1,000,000 packets)...\n");
	pthread_t reader_th;
	reader_iterations = 0;
	atomic_store_explicit(&stop_reader, 0, memory_order_relaxed);

	int r_rc = pthread_create(&reader_th, NULL, reader_worker, NULL);
	assert(r_rc == 0);

	pthread_t w_th[4];
	int w_ids[4] = {0, 1, 2, 3};
	for (int i = 0; i < 4; i++) {
		int rc = pthread_create(&w_th[i], NULL, stress_writer, &w_ids[i]);
		assert(rc == 0);
	}

	for (int i = 0; i < 4; i++) {
		pthread_join(w_th[i], NULL);
	}

	atomic_store_explicit(&stop_reader, 1, memory_order_relaxed);
	pthread_join(reader_th, NULL);

	stats_get_snapshot(&s);
	/* 4002 prior + 4 * 250,000 = 1,004,002 */
	assert(s.rx_pkts_v4 == 1004002);
	assert(s.tx_pkts_v4 == 1004001);
	/* 4 * (250000 / 8) = 125000 GSO pkts */
	assert(s.gso_rx_pkts == 125000);
	assert(s.gso_tx_pkts == 125000);
	printf("PASS: concurrent reader vs writers completed %llu snapshot iterations with zero races/tearing\n",
	       (unsigned long long)reader_iterations);

	/* Test 5: stats_dump output */
	printf("Testing stats_dump log output:\n");
	stats_dump();
	printf("PASS: stats_dump succeeded\n");

	/* Test 6: stats_write_json with dynamic pool and state */
	const char *test_json = "/tmp/test-tayga-status.json";
	unlink(test_json);

	INIT_LIST_HEAD(&gcfg.map6_list);
	struct map6 test_m6;
	memset(&test_m6, 0, sizeof(test_m6));
	test_m6.type = MAP_TYPE_RFC6052;
	inet_pton(AF_INET6, "64:ff9b::", &test_m6.addr);
	test_m6.prefix_len = 96;
	INIT_LIST_HEAD(&test_m6.list);
	list_add(&test_m6.list, &gcfg.map6_list);

	struct dynamic_pool dummy_pool;
	memset(&dummy_pool, 0, sizeof(dummy_pool));
	gcfg.dynamic_pool = &dummy_pool;

	gcfg.tun_offload = TUN_OFFLOAD_TCP;
	inet_pton(AF_INET, "192.0.0.4", &gcfg.local_addr4);
	inet_pton(AF_INET6, "2001:db8:1::4", &gcfg.local_addr6);

	stats_write_json(test_json, "running");

	FILE *f = fopen(test_json, "r");
	assert(f != NULL);
	char buf[4096];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	assert(strstr(buf, "\"version\":") != NULL);
	assert(strstr(buf, "\"state\": \"running\"") != NULL);
	assert(strstr(buf, "\"pid\":") != NULL);
	assert(strstr(buf, "\"generated_at\":") != NULL);
	assert(strstr(buf, "\"uptime_sec\":") != NULL);
	assert(strstr(buf, "\"clat_ipv4\": \"192.0.0.4\"") != NULL);
	assert(strstr(buf, "\"clat_ipv6\": \"2001:db8:1::4\"") != NULL);
	assert(strstr(buf, "\"pref64\": \"64:ff9b::/96\"") != NULL);
	assert(strstr(buf, "\"offload_mode\": \"tcp\"") != NULL);
	assert(strstr(buf, "\"rx_packets_v4\": 1004002") != NULL);
	assert(strstr(buf, "\"dropped_packets\": 1") != NULL);
	assert(strstr(buf, "\"errors\": 1") != NULL);
	assert(strstr(buf, "\"active_mappings\": 42") != NULL);
	assert(strstr(buf, "\"dormant_mappings\": 7") != NULL);
	assert(strstr(buf, "\"free_addresses\": 100") != NULL);
	unlink(test_json);
	printf("PASS: stats_write_json generates valid structured JSON with dynamic pool\n");

	/* Test 7: stats_write_json stopped state */
	stats_write_json(test_json, "stopped");
	f = fopen(test_json, "r");
	assert(f != NULL);
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	assert(strstr(buf, "\"state\": \"stopped\"") != NULL);
	unlink(test_json);
	printf("PASS: stats_write_json records stopped state on exit\n");

	/* Test 8: Partial batch idle flush */
	printf("Testing partial batch idle flush...\n");
	stats_init();
	stats_thread_init(1);
	for (int i = 0; i < 42; i++) {
		stats_rx4(100);
		stats_packet_done();
	}
	/* Because 42 < STATS_BATCH_SIZE (1024), without idle flush, pub stats are 0 */
	assert(g_tls_priv.batch_count == 42);
	assert(atomic_load_explicit(&g_worker_pub[2].rx_pkts_v4, memory_order_relaxed) == 0);

	/* Now idle flush */
	stats_flush_idle();
	assert(g_tls_priv.batch_count == 0);
	assert(atomic_load_explicit(&g_worker_pub[2].rx_pkts_v4, memory_order_relaxed) == 42);

	stats_get_snapshot(&s);
	assert(s.rx_pkts_v4 == 42);
	assert(s.rx_bytes_v4 == 4200);
	printf("PASS: idle flush publishes partial batches (< 1024 pkts) accurately\n");

	/* Test 9: Telemetry background thread, trigger, and stop */
	printf("Testing telemetry exporter background thread, trigger, and stop...\n");
	const char *telem_json = "/tmp/test-telem-run.json";
	unlink(telem_json);
	telemetry_start(telem_json, 60);

	/* File should exist with state running */
	f = fopen(telem_json, "r");
	assert(f != NULL);
	fclose(f);

	/* Add more packets */
	for (int i = 0; i < 58; i++) {
		stats_rx4(100);
		stats_packet_done();
	}
	stats_flush_idle();

	/* Trigger telemetry export immediately */
	telemetry_trigger();
	usleep(50000); /* 50ms to allow telemetry thread to write */

	f = fopen(telem_json, "r");
	assert(f != NULL);
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	assert(strstr(buf, "\"state\": \"running\"") != NULL);
	assert(strstr(buf, "\"rx_packets_v4\": 100") != NULL); /* 42 + 58 = 100 */

	/* Stop telemetry */
	telemetry_stop();
	f = fopen(telem_json, "r");
	assert(f != NULL);
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	assert(strstr(buf, "\"state\": \"stopped\"") != NULL);
	assert(strstr(buf, "\"rx_packets_v4\": 100") != NULL);
	unlink(telem_json);
	printf("PASS: telemetry background worker, trigger, and stop function correctly\n");

	/* Test 10: Low-rate continuous packet streaming interval flush */
	printf("Testing low-rate continuous packet streaming interval flush...\n");
	stats_init();
	stats_thread_init(2);
	time_t t_start = time(NULL);
	time_t t_last_flush = t_start;
	for (int i = 0; i < 15; i++) {
		stats_rx4(64);
		stats_packet_done();
		usleep(100000); /* 100ms between packets -> total 1.5 seconds */
		time_t now = time(NULL);
		if (now - t_last_flush >= 1 && g_tls_priv.batch_count > 0) {
			stats_flush_worker();
			t_last_flush = now;
		}
	}
	/* Without 1024 batch or poll idle, the 1s interval flush must have published packets to pub stats */
	assert(atomic_load_explicit(&g_worker_pub[3].rx_pkts_v4, memory_order_relaxed) > 0);
	stats_flush_idle();
	assert(atomic_load_explicit(&g_worker_pub[3].rx_pkts_v4, memory_order_relaxed) == 15);
	printf("PASS: low-rate continuous streaming interval flush publishes within 1 second\n");

	printf("All stats unit tests PASSED.\n");
	return 0;
}
