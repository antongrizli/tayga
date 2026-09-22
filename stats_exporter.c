/*
 *  stats_exporter.c -- JSON telemetry snapshot exporter for TAYGA
 *
 *  Part of TAYGA CLAT / NAT64
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tayga.h"
#include "stats.h"
#include "gso.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

static pthread_t g_telemetry_thread;
static _Atomic bool g_telemetry_running = false;
static bool g_telemetry_triggered = false;
static pthread_mutex_t g_telemetry_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_telemetry_cond = PTHREAD_COND_INITIALIZER;
static char g_telemetry_path[256] = "/run/tayga-status.json";
static int g_telemetry_interval = 5;

void stats_write_json(const char *path, const char *state)
{
	char tmp_path[512];
	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

	FILE *f = fopen(tmp_path, "w");
	if (!f) {
		slog(LOG_WARNING, "Unable to open %s for writing stats JSON: %s\n",
			tmp_path, strerror(errno));
		return;
	}

	char ip4_buf[INET_ADDRSTRLEN] = "none";
	char ip6_buf[INET6_ADDRSTRLEN] = "none";
	char prefix_buf[INET6_ADDRSTRLEN + 8] = "none";

	if (gcfg.local_addr4.s_addr)
		inet_ntop(AF_INET, &gcfg.local_addr4, ip4_buf, sizeof(ip4_buf));
	if (!IN6_IS_ADDR_UNSPECIFIED(&gcfg.local_addr6))
		inet_ntop(AF_INET6, &gcfg.local_addr6, ip6_buf, sizeof(ip6_buf));

	struct list_head *entry;
	if (gcfg.map6_list.next && gcfg.map6_list.prev) {
		list_for_each(entry, &gcfg.map6_list) {
			struct map6 *m6 = list_entry(entry, struct map6, list);
			if (m6->type == MAP_TYPE_RFC6052) {
				char pfx[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &m6->addr, pfx, sizeof(pfx));
				snprintf(prefix_buf, sizeof(prefix_buf), "%s/%d", pfx, m6->prefix_len);
				break;
			}
		}
	}

	const char *offload_str = "off";
	if (gcfg.tun_offload == TUN_OFFLOAD_TCP)
		offload_str = "tcp";
	else if (gcfg.tun_offload == TUN_OFFLOAD_AUTO)
		offload_str = "auto";

	time_t now = time(NULL);

	/* Cache /run/clat-info.json to prevent continuous disk reads */
	static char pref64_source[64] = "configured";
	static time_t last_info_read = 0;
	if (last_info_read == 0 || now - last_info_read >= 30) {
		last_info_read = now;
		FILE *info = fopen("/run/clat-info.json", "r");
		if (info) {
			char line[256];
			while (fgets(line, sizeof(line), info)) {
				char *p = strstr(line, "\"pref64_source\": \"");
				if (p) {
					p += strlen("\"pref64_source\": \"");
					char *end = strchr(p, '"');
					if (end && (size_t)(end - p) < sizeof(pref64_source)) {
						size_t len = end - p;
						memcpy(pref64_source, p, len);
						pref64_source[len] = '\0';
					}
					break;
				}
			}
			fclose(info);
		}
	}

	uint32_t active_map = 0, dormant_map = 0, free_addr = 0;
	if (gcfg.dynamic_pool) {
		dynamic_get_stats(gcfg.dynamic_pool, &active_map, &dormant_map, &free_addr);
	}

	struct tayga_stats s;
	stats_get_snapshot(&s);

	long uptime = (long)(now - s.start_time);
	if (uptime < 0) uptime = 0;

	char ts_buf[64];
	struct tm tm_info;
	gmtime_r(&now, &tm_info);
	strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_info);

	const char *status_state = state ? state : "running";

	fprintf(f, "{\n");
	fprintf(f, "  \"version\": \"%s\",\n", TAYGA_VERSION);
	fprintf(f, "  \"pid\": %ld,\n", (long)getpid());
	fprintf(f, "  \"state\": \"%s\",\n", status_state);
	fprintf(f, "  \"generated_at\": \"%s\",\n", ts_buf);
	fprintf(f, "  \"uptime_sec\": %ld,\n", uptime);
	fprintf(f, "  \"clat_ipv4\": \"%s\",\n", ip4_buf);
	fprintf(f, "  \"clat_ipv6\": \"%s\",\n", ip6_buf);
	fprintf(f, "  \"pref64\": \"%s\",\n", prefix_buf);
	fprintf(f, "  \"pref64_source\": \"%s\",\n", pref64_source);
	fprintf(f, "  \"offload_mode\": \"%s\",\n", offload_str);
	fprintf(f, "  \"traffic\": {\n");
	fprintf(f, "    \"rx_packets_v4\": %llu,\n", (unsigned long long)s.rx_pkts_v4);
	fprintf(f, "    \"rx_bytes_v4\": %llu,\n", (unsigned long long)s.rx_bytes_v4);
	fprintf(f, "    \"tx_packets_v4\": %llu,\n", (unsigned long long)s.tx_pkts_v4);
	fprintf(f, "    \"tx_bytes_v4\": %llu,\n", (unsigned long long)s.tx_bytes_v4);
	fprintf(f, "    \"rx_packets_v6\": %llu,\n", (unsigned long long)s.rx_pkts_v6);
	fprintf(f, "    \"rx_bytes_v6\": %llu,\n", (unsigned long long)s.rx_bytes_v6);
	fprintf(f, "    \"tx_packets_v6\": %llu,\n", (unsigned long long)s.tx_pkts_v6);
	fprintf(f, "    \"tx_bytes_v6\": %llu,\n", (unsigned long long)s.tx_bytes_v6);
	fprintf(f, "    \"dropped_packets\": %llu,\n", (unsigned long long)s.dropped_pkts);
	fprintf(f, "    \"dropped_bytes\": %llu,\n", (unsigned long long)s.dropped_bytes);
	fprintf(f, "    \"errors\": %llu\n", (unsigned long long)s.error_pkts);
	fprintf(f, "  },\n");
	fprintf(f, "  \"gso\": {\n");
	fprintf(f, "    \"rx_packets\": %llu,\n", (unsigned long long)s.gso_rx_pkts);
	fprintf(f, "    \"tx_packets\": %llu,\n", (unsigned long long)s.gso_tx_pkts);
	fprintf(f, "    \"rx_bytes\": %llu,\n", (unsigned long long)s.gso_rx_bytes);
	fprintf(f, "    \"tx_bytes\": %llu,\n", (unsigned long long)s.gso_tx_bytes);
	fprintf(f, "    \"split_tail_packets\": %llu,\n", (unsigned long long)s.gso_split_tail_pkts);
	fprintf(f, "    \"sw_seg_packets\": %llu,\n", (unsigned long long)s.gso_sw_seg_pkts);
	fprintf(f, "    \"sw_seg_out_packets\": %llu,\n", (unsigned long long)s.gso_sw_seg_out_pkts);
	fprintf(f, "    \"fallback_packets\": %llu,\n", (unsigned long long)s.gso_fallback_pkts);
	fprintf(f, "    \"invalid_packets\": %llu,\n", (unsigned long long)s.gso_invalid_pkts);
	fprintf(f, "    \"tun_write_errors\": %llu\n", (unsigned long long)s.gso_tun_write_errors);
	fprintf(f, "  },\n");
	fprintf(f, "  \"dynamic_pool\": {\n");
	fprintf(f, "    \"active_mappings\": %u,\n", active_map);
	fprintf(f, "    \"dormant_mappings\": %u,\n", dormant_map);
	fprintf(f, "    \"free_addresses\": %u\n", free_addr);
	fprintf(f, "  }\n");
	fprintf(f, "}\n");

	fclose(f);
	rename(tmp_path, path);
}

static void *telemetry_worker_loop(void *arg)
{
	(void)arg;
	stats_thread_init(-1); /* Dedicated telemetry thread */
	pthread_mutex_lock(&g_telemetry_mutex);
	while (atomic_load_explicit(&g_telemetry_running, memory_order_relaxed)) {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += g_telemetry_interval;

		while (atomic_load_explicit(&g_telemetry_running, memory_order_relaxed) && !g_telemetry_triggered) {
			int rc = pthread_cond_timedwait(&g_telemetry_cond, &g_telemetry_mutex, &ts);
			if (rc == ETIMEDOUT)
				break;
		}

		if (!atomic_load_explicit(&g_telemetry_running, memory_order_relaxed))
			break;

		g_telemetry_triggered = false;
		pthread_mutex_unlock(&g_telemetry_mutex);
		stats_write_json(g_telemetry_path, "running");
		pthread_mutex_lock(&g_telemetry_mutex);
	}
	pthread_mutex_unlock(&g_telemetry_mutex);
	return NULL;
}

void telemetry_trigger(void)
{
#ifndef STATS_DISABLED
	if (!atomic_load_explicit(&g_telemetry_running, memory_order_relaxed))
		return;
	pthread_mutex_lock(&g_telemetry_mutex);
	g_telemetry_triggered = true;
	pthread_cond_signal(&g_telemetry_cond);
	pthread_mutex_unlock(&g_telemetry_mutex);
#endif
}

void telemetry_start(const char *status_path, int interval_sec)
{
#ifdef STATS_DISABLED
	(void)status_path;
	(void)interval_sec;
	return;
#else
	if (atomic_load_explicit(&g_telemetry_running, memory_order_relaxed))
		return;
	if (status_path && status_path[0]) {
		strncpy(g_telemetry_path, status_path, sizeof(g_telemetry_path) - 1);
		g_telemetry_path[sizeof(g_telemetry_path) - 1] = '\0';
	}
	if (interval_sec > 0)
		g_telemetry_interval = interval_sec;

	atomic_store_explicit(&g_telemetry_running, true, memory_order_relaxed);
	/* Write initial snapshot immediately */
	stats_write_json(g_telemetry_path, "running");

	if (pthread_create(&g_telemetry_thread, NULL, telemetry_worker_loop, NULL) != 0) {
		slog(LOG_WARNING, "Failed to start background telemetry thread: %s\n", strerror(errno));
		atomic_store_explicit(&g_telemetry_running, false, memory_order_relaxed);
	}
#endif
}

void telemetry_stop(void)
{
#ifndef STATS_DISABLED
	if (!atomic_load_explicit(&g_telemetry_running, memory_order_relaxed))
		return;
	atomic_store_explicit(&g_telemetry_running, false, memory_order_relaxed);
	pthread_mutex_lock(&g_telemetry_mutex);
	pthread_cond_signal(&g_telemetry_cond);
	pthread_mutex_unlock(&g_telemetry_mutex);

	pthread_join(g_telemetry_thread, NULL);
	/* Final snapshot with stopped status */
	stats_write_json(g_telemetry_path, "stopped");
#endif
}
