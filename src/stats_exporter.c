/*
 *  stats_exporter.c -- JSON telemetry snapshot exporter for TAYGA
 *
 *  Part of TAYGA CLAT / NAT64
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tayga.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "stats.h"
#include "experimental_io.h"
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
static pthread_mutex_t s_stats_export_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_telemetry_path[768] = "/run/tayga-status.json";
static int g_telemetry_interval = 5;

/* Length of the well-formed UTF-8 sequence at c (1..4), or 0 when invalid. */
static int utf8_sequence(const unsigned char *c)
{
	if (*c < 0x80) return 1;
	int n = (*c & 0xe0) == 0xc0 ? 2 : (*c & 0xf0) == 0xe0 ? 3 : (*c & 0xf8) == 0xf0 ? 4 : 0;
	if (!n || *c == 0xc0 || *c == 0xc1 || *c > 0xf4) return 0;
	for (int i = 1; i < n; i++)
		if ((c[i] & 0xc0) != 0x80) return 0;
	if (n == 3 && ((*c == 0xe0 && c[1] < 0xa0) || (*c == 0xed && c[1] >= 0xa0))) return 0;
	if (n == 4 && ((*c == 0xf0 && c[1] < 0x90) || (*c == 0xf4 && c[1] >= 0x90))) return 0;
	return n;
}

/* Valid UTF-8 passes through unchanged; control characters and invalid bytes
 * are escaped so the document always stays valid JSON. */
static void json_string(FILE *out, const char *value)
{
	fputc('"', out);
	for (const unsigned char *c = (const unsigned char *)value; *c; ) {
		int n = utf8_sequence(c);
		if (n > 1) { fwrite(c, 1, (size_t)n, out); c += n; continue; }
		if (*c == '"' || *c == '\\') { fputc('\\', out); fputc(*c, out); }
		else if (*c < 32 || *c == 127) fprintf(out, "\\u%04x", *c);
		else if (*c > 127) fputs("\\ufffd", out);
		else fputc(*c, out);
		c++;
	}
	fputc('"', out);
}

/* The status directory is opened before chroot() so later snapshots can still
 * be published with openat()/renameat() once the absolute path is unreachable. */
static int g_status_dirfd = -1;
static char g_status_base[256];
/* Same for the clat-info.json metadata read for pref64_source. */
static int g_info_dirfd = -1;
static char g_info_base[256];

static void open_info_dir(const char *path)
{
	if (!path || path[0] != '/')
		return;
	const char *slash = strrchr(path, '/');
	char dir[768];
	size_t dl = slash == path ? 1 : (size_t)(slash - path);
	if (dl >= sizeof(dir) || strlen(slash + 1) >= sizeof(g_info_base) || !slash[1])
		return;
	memcpy(dir, path, dl); dir[dl] = '\0';
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (g_info_dirfd >= 0) close(g_info_dirfd);
	g_info_dirfd = fd;
	strcpy(g_info_base, slash + 1);
}

/* NEW-4: a crash between mkstemp-style creation and rename leaves
 * ".tayga-status.<pid>.<seq>" behind; remove those from earlier runs. */
static void remove_stale_status_tmp(int dirfd)
{
	int dup_fd = dup(dirfd);
	if (dup_fd < 0)
		return;
	DIR *d = fdopendir(dup_fd);
	if (!d) { close(dup_fd); return; }
	struct dirent *e;
	while ((e = readdir(d))) {
		if (strncmp(e->d_name, ".tayga-status.", 14))
			continue;
		/* Only files whose writer is gone: another daemon may share the directory. */
		char *end = NULL;
		long pid = strtol(e->d_name + 14, &end, 10);
		if (pid > 0 && end && *end == '.' && pid != (long)getpid() &&
				kill((pid_t)pid, 0) < 0 && errno == ESRCH)
			(void)unlinkat(dirfd, e->d_name, 0);
	}
	closedir(d);
}

void telemetry_prepare_dir(const char *path)
{
	open_info_dir(gcfg.clat_info_path[0] ? gcfg.clat_info_path : "/run/clat-info.json");
	if (!path || path[0] != '/')
		return;
	const char *slash = strrchr(path, '/');
	char dir[768];
	size_t dl = slash == path ? 1 : (size_t)(slash - path);
	if (dl >= sizeof(dir) || strlen(slash + 1) >= sizeof(g_status_base))
		return;
	memcpy(dir, path, dl); dir[dl] = '\0';
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		slog(LOG_WARNING, "Unable to open status directory %s: %s\n", dir, strerror(errno));
		return;
	}
	if (g_status_dirfd >= 0) close(g_status_dirfd);
	g_status_dirfd = fd;
	strcpy(g_status_base, slash + 1);
	remove_stale_status_tmp(fd);
}

/* Keep publication ordering per destination only while writers are in flight.
 * A slow older write must not replace a newer snapshot after its I/O finishes. */
struct export_destination {
    char *path;
    unsigned writers;
    uint64_t published;
    pthread_mutex_t publish_lock;
    struct export_destination *next;
};
static pthread_mutex_t s_publish_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct export_destination *s_destinations;

static struct export_destination *export_begin(const char *path)
{
    pthread_mutex_lock(&s_publish_mutex);
    struct export_destination *d;
    for (d = s_destinations; d; d = d->next)
        if (!strcmp(d->path, path)) break;
    if (!d) {
        d = calloc(1, sizeof(*d));
        if (d) {
            d->path = strdup(path);
            if (!d->path || pthread_mutex_init(&d->publish_lock, NULL)) { free(d->path); free(d); d = NULL; }
            else { d->next = s_destinations; s_destinations = d; }
        }
    }
    if (d) d->writers++;
    pthread_mutex_unlock(&s_publish_mutex);
    return d;
}

static void export_end(struct export_destination *d)
{
    pthread_mutex_lock(&s_publish_mutex);
    if (!--d->writers) {
        struct export_destination **link = &s_destinations;
        while (*link != d) link = &(*link)->next;
        *link = d->next;
        pthread_mutex_destroy(&d->publish_lock);
        free(d->path); free(d);
    }
    pthread_mutex_unlock(&s_publish_mutex);
}

/* Reserve cache refresh under its own short lock; all metadata I/O is outside
 * both this lock and snapshot serialization. Reject FIFO/device/symlink input. */
static void pref64_source_snapshot(char source[64])
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static char cached[64] = "configured";
    static time_t next_read;
    static uint64_t generation;
    time_t tick = tayga_mono_sec();
    pthread_mutex_lock(&lock);
    bool refresh = tick >= next_read;
    if (refresh) { next_read = tick + 30; generation++; }
    uint64_t reserved = generation;
    memcpy(source, cached, sizeof(cached));
    pthread_mutex_unlock(&lock);
    if (!refresh) return;

    const char *path = gcfg.clat_info_path[0] ? gcfg.clat_info_path : "/run/clat-info.json";
    int fd = g_info_dirfd >= 0 && !strcmp(path, gcfg.clat_info_path[0] ? gcfg.clat_info_path : "/run/clat-info.json")
        ? openat(g_info_dirfd, g_info_base, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        : open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return; }
    char *data = malloc(65537);
    if (!data) { close(fd); return; }
    size_t used = 0;
    bool failed = false;
    while (used < 65536) {
        ssize_t n = read(fd, data + used, 65536 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { failed = true; break; }
        if (!n) break;
        used += (size_t)n;
    }
    close(fd);
    data[used] = 0;
    char value[64] = "";
    char *start = failed ? NULL : strstr(data, "\"pref64_source\"");
    if (start) {
        start += strlen("\"pref64_source\"");
        while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') start++;
        if (*start == ':') {
            start++;
            while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') start++;
        } else start = NULL;
    }
    if (start && *start == '"') {
        start++;
        char *end = strchr(start, '"');
        if (end && (size_t)(end - start) < sizeof(value))
            memcpy(value, start, (size_t)(end - start));
    }
    free(data);
    if (*value) {
        pthread_mutex_lock(&lock);
        if (reserved == generation) memcpy(cached, value, sizeof(cached));
        memcpy(source, cached, sizeof(cached));
        pthread_mutex_unlock(&lock);
    }
}

void stats_write_json(const char *path, const char *state)
{
    if (!path || !*path || strlen(path) >= sizeof(g_telemetry_path)) return;
    struct export_destination *destination = export_begin(path);
    if (!destination) { slog(LOG_WARNING, "Unable to allocate JSON publication state\n"); return; }
    char pref64_source[64];
    pref64_source_snapshot(pref64_source);
    char *json = NULL;
    size_t json_length = 0;
    FILE *f = open_memstream(&json, &json_length);
    if (!f) { export_end(destination); return; }

    /* Only snapshot synchronization and in-memory rendering are serialized.
     * Main must acknowledge sync requests while waiting for another collector. */
    if (g_tls_priv.slot_idx == 0) {
        while (pthread_mutex_trylock(&s_stats_export_mutex) == EBUSY) {
            stats_check_sync_request();
            usleep(250);
        }
    } else pthread_mutex_lock(&s_stats_export_mutex);
	char ip4_buf[INET_ADDRSTRLEN] = "none";
	char ip6_buf[INET6_ADDRSTRLEN] = "none";
	char prefix_buf[INET6_ADDRSTRLEN + 8] = "none";

	if (gcfg.local_addr4.s_addr)
		inet_ntop(AF_INET, &gcfg.local_addr4, ip4_buf, sizeof(ip4_buf));
	if (!IN6_IS_ADDR_UNSPECIFIED(&gcfg.local_addr6))
		inet_ntop(AF_INET6, &gcfg.local_addr6, ip6_buf, sizeof(ip6_buf));

	struct list_head *entry;
	if (gcfg.map6_list.next && gcfg.map6_list.prev) {
		if (!gcfg.maps_immutable) pthread_mutex_lock(&gcfg.map_mutex);
		list_for_each(entry, &gcfg.map6_list) {
			struct map6 *m6 = list_entry(entry, struct map6, list);
			if (m6->type == MAP_TYPE_RFC6052) {
				char pfx[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &m6->addr, pfx, sizeof(pfx));
				snprintf(prefix_buf, sizeof(prefix_buf), "%s/%d", pfx, m6->prefix_len);
				break;
			}
		}
		if (!gcfg.maps_immutable) pthread_mutex_unlock(&gcfg.map_mutex);
	}

	const char *offload_str = tun_offload_name(gcfg.tun_offload);

	time_t wall_now = time(NULL);

	uint32_t active_map = 0, dormant_map = 0, free_addr = 0;
	if (gcfg.dynamic_pool) {
		dynamic_get_stats(gcfg.dynamic_pool, &active_map, &dormant_map, &free_addr);
	}

	struct tayga_stats s;
	stats_get_snapshot(&s);

	long uptime = (long)(tayga_mono_sec() - g_stats_start_mono);
	if (uptime < 0) uptime = 0;

	char ts_buf[64];
	struct tm tm_info;
	gmtime_r(&wall_now, &tm_info);
	strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_info);

	uint64_t snap_seq = atomic_fetch_add_explicit(&g_stats_snapshot_seq, 1, memory_order_relaxed) + 1;

	const char *status_state = state ? state : "running";
	fprintf(f, "{\n");
	fprintf(f, "  \"version\": \"%s\",\n", TAYGA_VERSION);
	fprintf(f, "  \"pid\": %ld,\n", (long)getpid());
	fprintf(f, "  \"network_namespace\": %llu,\n", gcfg.runtime_netns);
	fprintf(f, "  \"process_start_ticks\": \"%s\",\n", gcfg.process_start_ticks);
	fprintf(f, "  \"tun_device\": ");
	json_string(f, gcfg.tundev);
	fprintf(f, ",\n");
	fprintf(f, "  \"snapshot_sequence\": %llu,\n", (unsigned long long)snap_seq);
	fprintf(f, "  \"workers_synced\": %s,\n", s.workers_synced ? "true" : "false");
	fprintf(f, "  \"unacknowledged_worker_slots\": [");
	bool first_unacked = s.main_synced;
	if (!s.main_synced) fprintf(f, "0");
	for (int i = 0; i < 64; i++) {
		if (s.unacked_mask & (1ULL << i)) {
			int slot = i + 1;
			fprintf(f, "%s%d", first_unacked ? "" : ", ", slot);
			first_unacked = false;
		}
	}
	fprintf(f, "],\n");
	fprintf(f, "  \"state\": ");
	json_string(f, status_state);
	fprintf(f, ",\n");
	fprintf(f, "  \"generated_at\": \"%s\",\n", ts_buf);
	fprintf(f, "  \"uptime_sec\": %ld,\n", uptime);
	fprintf(f, "  \"clat_ipv4\": \"%s\",\n", ip4_buf);
	fprintf(f, "  \"clat_ipv6\": \"%s\",\n", ip6_buf);
	fprintf(f, "  \"pref64\": \"%s\",\n", prefix_buf);
	fprintf(f, "  \"pref64_source\": ");
	json_string(f, pref64_source);
	fprintf(f, ",\n");
	fprintf(f, "  \"offload_mode\": \"%s\",\n", offload_str);
	fprintf(f,"  \"dispatch_mode\": \"%s\", \"packet_io\": \"%s\",\n",gcfg.dispatch_mode?"flows":"kernel",gcfg.async_tun?"uring":"sync");
	fprintf(f,"  \"dispatch_drops\": %llu, \"dispatch_held\": %llu, \"dispatch_expired\": %llu,\n",(unsigned long long)atomic_load(&dispatch_drops),(unsigned long long)atomic_load(&dispatch_held),(unsigned long long)atomic_load(&dispatch_expired));
	fprintf(f,"  \"async_accepted\": %llu, \"async_completed\": %llu, \"async_errors\": %llu, \"async_pressure\": %llu,\n",(unsigned long long)atomic_load(&async_accepted),(unsigned long long)atomic_load(&async_completed),(unsigned long long)atomic_load(&async_errors),(unsigned long long)atomic_load(&async_pressure));
	fprintf(f, "  \"steering_requested\": \"%s\",\n", gcfg.tun_steering_flows ? "flows" : (gcfg.tun_steering_groups ? "groups" : "kernel"));
	fprintf(f, "  \"steering_effective\": \"%s\",\n", gcfg.tun_steering_effective ? (gcfg.tun_steering_flows ? "flows" : "groups") : "kernel");
	fprintf(f, "  \"steering_fallback_errno\": %d,\n", gcfg.tun_steering_errno);
	fprintf(f, "  \"steering_buckets\": %u,\n", gcfg.tun_steering_effective ? 65536 : 0);
	fprintf(f, "  \"offload_effective\": \"%s\",\n", tun_offload_name(gcfg.tun_offload_effective));
	fprintf(f, "  \"offload_flags\": %u,\n", gcfg.tun_offload_flags);
	fprintf(f, "  \"udp_offload_available\": %s,\n", gcfg.tun_has_uso ? "true" : "false");
	fprintf(f, "  \"vnet_hdr_sz\": %d,\n", gcfg.vnet_hdr_sz);
	fprintf(f, "  \"offload_negotiation_complete\": %s,\n", gcfg.tun_offload_complete ? "true" : "false");
	fprintf(f, "  \"offload_fallback_reason\": ");
	json_string(f, gcfg.tun_offload_reason ? gcfg.tun_offload_reason : "none");
	fprintf(f, ",\n");
	fprintf(f, "  \"offload_fallback_errno\": %d,\n", gcfg.tun_offload_errno);
	fprintf(f, "  \"offload_fallback_queue\": %d,\n", gcfg.tun_offload_queue);
	fprintf(f, "  \"tx_failed_frames\": %llu,\n", (unsigned long long)s.tx_failed_frames);
	fprintf(f, "  \"tx_eagain\": %llu,\n", (unsigned long long)s.tx_eagain);
	fprintf(f, "  \"tx_enobufs\": %llu,\n", (unsigned long long)s.tx_enobufs);
	fprintf(f, "  \"tx_eintr\": %llu,\n", (unsigned long long)s.tx_eintr);
	fprintf(f, "  \"tx_short\": %llu,\n", (unsigned long long)s.tx_short);
	fprintf(f, "  \"tx_fatal\": %llu,\n", (unsigned long long)s.tx_fatal);
	fprintf(f, "  \"tx_other\": %llu,\n", (unsigned long long)s.tx_other);
	fprintf(f, "  \"warnings_suppressed\": %llu,\n", (unsigned long long)s.warnings_suppressed);
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
	fprintf(f, "    \"self_packets\": %llu,\n", (unsigned long long)s.self_pkts);
	fprintf(f, "    \"icmp_sent_packets\": %llu,\n", (unsigned long long)s.icmp_sent_pkts);
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
	fprintf(f, "    \"tun_write_errors\": %llu,\n", (unsigned long long)s.gso_tun_write_errors);
	fprintf(f, "    \"dropped_segments\": %llu,\n", (unsigned long long)s.gso_dropped_segments);
	fprintf(f, "    \"udp_rx_aggregates\": %llu,\n", (unsigned long long)s.udp_gso_rx_aggregates);
	fprintf(f, "    \"udp_rx_bytes\": %llu,\n", (unsigned long long)s.udp_gso_rx_bytes);
	fprintf(f, "    \"udp_tx_aggregates\": %llu,\n", (unsigned long long)s.udp_gso_tx_aggregates);
	fprintf(f, "    \"udp_tx_bytes\": %llu,\n", (unsigned long long)s.udp_gso_tx_bytes);
	fprintf(f, "    \"udp_sw_fallbacks\": %llu,\n", (unsigned long long)s.udp_gso_sw_fallbacks);
	fprintf(f, "    \"udp_sw_segments\": %llu\n", (unsigned long long)s.udp_gso_sw_segments);
	fprintf(f, "  },\n");
	fprintf(f, "  \"dynamic_pool\": {\n");
	fprintf(f, "    \"active_mappings\": %u,\n", active_map);
	fprintf(f, "    \"dormant_mappings\": %u,\n", dormant_map);
	fprintf(f, "    \"free_addresses\": %u\n", free_addr);
	fprintf(f, "  },\n");
	fprintf(f, "  \"workers\": [\n");
	int num_workers = gcfg.workers;
	for (int i = 0; i <= num_workers && i < STATS_MAX_SLOTS; i++) {
		struct worker_pub_stats *p = &g_worker_pub[i];
		fprintf(f, "    {\n");
		fprintf(f, "      \"slot\": %d,\n", i);
		fprintf(f, "      \"worker_id\": %d,\n", i == 0 ? 0 : i - 1);
		fprintf(f, "      \"rx_packets_v4\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->rx_pkts_v4, memory_order_relaxed));
		fprintf(f, "      \"rx_bytes_v4\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->rx_bytes_v4, memory_order_relaxed));
		fprintf(f, "      \"tx_packets_v4\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->tx_pkts_v4, memory_order_relaxed));
		fprintf(f, "      \"tx_bytes_v4\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->tx_bytes_v4, memory_order_relaxed));
		fprintf(f, "      \"rx_packets_v6\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->rx_pkts_v6, memory_order_relaxed));
		fprintf(f, "      \"rx_bytes_v6\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->rx_bytes_v6, memory_order_relaxed));
		fprintf(f, "      \"tx_packets_v6\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->tx_pkts_v6, memory_order_relaxed));
		fprintf(f, "      \"tx_bytes_v6\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->tx_bytes_v6, memory_order_relaxed));
		fprintf(f, "      \"dropped_packets\": %llu,\n", (unsigned long long)atomic_load_explicit(&p->dropped_pkts, memory_order_relaxed));
		fprintf(f, "      \"error_packets\": %llu\n", (unsigned long long)atomic_load_explicit(&p->error_pkts, memory_order_relaxed));
		fprintf(f, "    }%s\n", (i == num_workers || i == STATS_MAX_SLOTS - 1) ? "" : ",");
	}
	fprintf(f, "  ]\n");
	fprintf(f, "}\n");

    int failed = ferror(f);
    if (fclose(f)) failed = 1;
    pthread_mutex_unlock(&s_stats_export_mutex);
    if (failed) { free(json); export_end(destination); return; }
#ifdef STATS_EXPORT_TEST_HOOK
    extern void stats_export_test_before_io(const char *state);
    stats_export_test_before_io(state);
#endif

    char tmp_path[864], tmp_base[96];
    snprintf(tmp_base, sizeof(tmp_base), ".tayga-status.%ld.%llu", (long)getpid(),
             (unsigned long long)snap_seq);
    const char *slash = strrchr(path, '/');
    size_t directory_length = slash ? (size_t)(slash - path) + 1 : 0;
    snprintf(tmp_path, sizeof(tmp_path), "%.*s%s", (int)directory_length, path, tmp_base);
    bool use_dirfd = g_status_dirfd >= 0 && !strcmp(path, g_telemetry_path);
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC;
    int fd = use_dirfd ? openat(g_status_dirfd, tmp_base, flags, 0644) : open(tmp_path, flags, 0644);
    if (fd < 0) {
        slog(LOG_WARNING, "Unable to open stats JSON temporary file: %s\n", strerror(errno));
        free(json); export_end(destination); return;
    }
    f = fdopen(fd, "w");
    if (!f) { close(fd); failed = 1; }
    else {
        failed = fwrite(json, 1, json_length, f) != json_length;
        if (fclose(f)) failed = 1;
    }
    free(json);

    bool published = false;
    pthread_mutex_lock(&destination->publish_lock);
    if (!failed && snap_seq > destination->published) {
        failed = use_dirfd ? renameat(g_status_dirfd, tmp_base, g_status_dirfd, g_status_base)
                           : rename(tmp_path, path);
        if (!failed) { destination->published = snap_seq; published = true; }
    }
    pthread_mutex_unlock(&destination->publish_lock);
    if (!published) {
        if (failed) slog(LOG_WARNING, "Unable to publish stats JSON: %s\n", strerror(errno));
        if (use_dirfd) unlinkat(g_status_dirfd, tmp_base, 0);
        else unlink(tmp_path);
    }
    export_end(destination);
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

	if (g_status_dirfd < 0 && g_telemetry_path[0] == '/') {
		/* No chroot: clean up temporary files an earlier crashed run left behind. */
		char dir[768];
		const char *slash = strrchr(g_telemetry_path, '/');
		size_t dl = slash == g_telemetry_path ? 1 : (size_t)(slash - g_telemetry_path);
		if (dl < sizeof(dir)) {
			memcpy(dir, g_telemetry_path, dl); dir[dl] = '\0';
			int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			if (dfd >= 0) { remove_stale_status_tmp(dfd); close(dfd); }
		}
	}
	atomic_store_explicit(&g_telemetry_running, true, memory_order_relaxed);
	/* Write initial snapshot immediately */
	stats_write_json(g_telemetry_path, "running");

	int ret = pthread_create(&g_telemetry_thread, NULL, telemetry_worker_loop, NULL);
	if (ret != 0) {
		slog(LOG_WARNING, "Failed to start background telemetry thread: %s\n", strerror(ret));
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

void telemetry_write_status(const char *state)
{
#ifndef STATS_DISABLED
	stats_write_json(g_telemetry_path, state ? state : "running");
#else
	(void)state;
#endif
}
