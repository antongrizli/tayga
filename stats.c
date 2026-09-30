/*
 *  stats.c -- Core high-performance packet counters
 *
 *  Part of TAYGA CLAT / NAT64
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tayga.h"
#include "stats.h"
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

struct worker_pub_stats g_worker_pub[STATS_MAX_SLOTS] __attribute__((aligned(128)));
__thread struct worker_priv_stats g_tls_priv;
time_t g_stats_start_time = 0;
atomic_uint_fast64_t g_stats_sync_req = 0;
atomic_uint_fast64_t g_stats_sync_ack[STATS_MAX_SLOTS] = {0};
atomic_uint_fast64_t g_stats_snapshot_seq = 0;
atomic_bool g_worker_slot_active[STATS_MAX_SLOTS];

void stats_init(void)
{
	memset(g_worker_pub, 0, sizeof(g_worker_pub));
	memset(&g_tls_priv, 0, sizeof(g_tls_priv));
	g_tls_priv.slot_idx = 0;
	g_stats_start_time = time(NULL);
	atomic_store_explicit(&g_stats_sync_req, 0, memory_order_relaxed);
	for (int i = 0; i < STATS_MAX_SLOTS; i++) {
		atomic_store_explicit(&g_stats_sync_ack[i], 0, memory_order_relaxed);
		atomic_store_explicit(&g_worker_slot_active[i], false, memory_order_relaxed);
	}
	atomic_store_explicit(&g_worker_slot_active[0], true, memory_order_relaxed);
	atomic_store_explicit(&g_stats_snapshot_seq, 0, memory_order_relaxed);
}

void stats_thread_init(int worker_idx)
{
	memset(&g_tls_priv, 0, sizeof(g_tls_priv));
	if (worker_idx >= 0 && worker_idx < STATS_MAX_SLOTS - 1) {
		g_tls_priv.slot_idx = worker_idx + 1;
		atomic_store_explicit(&g_worker_slot_active[worker_idx + 1], true, memory_order_release);
	} else {
		g_tls_priv.slot_idx = -1;
	}
}

void stats_thread_exit(void)
{
	int slot = g_tls_priv.slot_idx;
	if (slot > 0 && slot < STATS_MAX_SLOTS) {
		atomic_store_explicit(&g_worker_slot_active[slot], false, memory_order_release);
	}
}

void stats_check_sync_request(void)
{
	int slot = g_tls_priv.slot_idx;
	if (slot < 0 || slot >= STATS_MAX_SLOTS)
		return;
	uint64_t req = atomic_load_explicit(&g_stats_sync_req, memory_order_acquire);
	if (req != atomic_load_explicit(&g_stats_sync_ack[slot], memory_order_relaxed)) {
		stats_flush_worker();
		atomic_store_explicit(&g_stats_sync_ack[slot], req, memory_order_release);
	}
}

atomic_int g_workers_running = 0;

int stats_sync_workers(bool *synced_out, uint64_t *unacked_mask_out)
{
#ifdef __linux__
	uint64_t target_mask = 0;
	int active_count = 0;

	for (int i = 0; i < gcfg.workers && i < 64; i++) {
		int slot = i + 1;
		if (atomic_load_explicit(&g_worker_slot_active[slot], memory_order_acquire)) {
			target_mask |= (1ULL << i);
			active_count++;
		}
	}

	if (active_count == 0) {
		if (g_tls_priv.slot_idx >= 0)
			stats_flush_worker();
		if (synced_out) *synced_out = true;
		if (unacked_mask_out) *unacked_mask_out = 0;
		return 0;
	}

	uint64_t req = atomic_fetch_add_explicit(&g_stats_sync_req, 1, memory_order_acq_rel) + 1;
	/* Publish before waking idle workers, so their first check sees this request. */
	for (int i = 0; i < gcfg.workers && i < 64; i++)
		if (target_mask & (1ULL << i))
			pthread_kill(gcfg.threads[i], SIGURG);

	if (g_tls_priv.slot_idx >= 0) {
		stats_flush_worker();
		atomic_store_explicit(&g_stats_sync_ack[g_tls_priv.slot_idx], req, memory_order_release);
	}

	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	const uint64_t timeout_ns = 100000000ULL; /* 100 ms overall deadline */
	uint64_t unacked_mask = 0;

	for (;;) {
		bool all_acked = true;
		for (int i = 0; i < gcfg.workers && i < 64; i++) {
			if (!(target_mask & (1ULL << i)))
				continue;
			int slot = i + 1;
			if (!atomic_load_explicit(&g_worker_slot_active[slot], memory_order_acquire))
				continue;
			if (atomic_load_explicit(&g_stats_sync_ack[slot], memory_order_acquire) < req) {
				all_acked = false;
				break;
			}
		}
		if (all_acked) {
			if (synced_out) *synced_out = true;
			if (unacked_mask_out) *unacked_mask_out = 0;
			return 0;
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		uint64_t elapsed_ns = (uint64_t)(now.tv_sec - start.tv_sec) * 1000000000ULL +
		                      (uint64_t)(now.tv_nsec - start.tv_nsec);
		if (elapsed_ns >= timeout_ns) {
			for (int i = 0; i < gcfg.workers && i < 64; i++) {
				if (!(target_mask & (1ULL << i)))
					continue;
				int slot = i + 1;
				if (!atomic_load_explicit(&g_worker_slot_active[slot], memory_order_acquire))
					continue;
				if (atomic_load_explicit(&g_stats_sync_ack[slot], memory_order_acquire) < req) {
					unacked_mask |= (1ULL << i);
					slog(LOG_WARNING, "stats_sync_workers: worker slot %d did not acknowledge sync req %llu\n",
					     slot, (unsigned long long)req);
				}
			}
			if (synced_out) *synced_out = (unacked_mask == 0);
			if (unacked_mask_out) *unacked_mask_out = unacked_mask;
			return (unacked_mask == 0) ? 0 : -1;
		}
		usleep(250);
	}
#else
	if (g_tls_priv.slot_idx >= 0)
		stats_flush_worker();
	if (synced_out) *synced_out = true;
	if (unacked_mask_out) *unacked_mask_out = 0;
	return 0;
#endif
}

void stats_flush_worker(void)
{
	int idx = g_tls_priv.slot_idx;
	if (idx < 0 || idx >= STATS_MAX_SLOTS)
		return;
	struct worker_pub_stats *p = &g_worker_pub[idx];

	atomic_store_explicit(&p->rx_pkts_v4, g_tls_priv.rx_pkts_v4, memory_order_relaxed);
	atomic_store_explicit(&p->rx_bytes_v4, g_tls_priv.rx_bytes_v4, memory_order_relaxed);
	atomic_store_explicit(&p->tx_pkts_v4, g_tls_priv.tx_pkts_v4, memory_order_relaxed);
	atomic_store_explicit(&p->tx_bytes_v4, g_tls_priv.tx_bytes_v4, memory_order_relaxed);

	atomic_store_explicit(&p->rx_pkts_v6, g_tls_priv.rx_pkts_v6, memory_order_relaxed);
	atomic_store_explicit(&p->rx_bytes_v6, g_tls_priv.rx_bytes_v6, memory_order_relaxed);
	atomic_store_explicit(&p->tx_pkts_v6, g_tls_priv.tx_pkts_v6, memory_order_relaxed);
	atomic_store_explicit(&p->tx_bytes_v6, g_tls_priv.tx_bytes_v6, memory_order_relaxed);

	atomic_store_explicit(&p->dropped_pkts, g_tls_priv.dropped_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->dropped_bytes, g_tls_priv.dropped_bytes, memory_order_relaxed);
	atomic_store_explicit(&p->error_pkts, g_tls_priv.error_pkts, memory_order_relaxed);

	atomic_store_explicit(&p->gso_rx_pkts, g_tls_priv.gso_rx_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_rx_bytes, g_tls_priv.gso_rx_bytes, memory_order_relaxed);
	atomic_store_explicit(&p->gso_tx_pkts, g_tls_priv.gso_tx_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_tx_bytes, g_tls_priv.gso_tx_bytes, memory_order_relaxed);
	atomic_store_explicit(&p->gso_split_tail_pkts, g_tls_priv.gso_split_tail_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_sw_seg_pkts, g_tls_priv.gso_sw_seg_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_sw_seg_out_pkts, g_tls_priv.gso_sw_seg_out_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_fallback_pkts, g_tls_priv.gso_fallback_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_invalid_pkts, g_tls_priv.gso_invalid_pkts, memory_order_relaxed);
	atomic_store_explicit(&p->gso_tun_write_errors, g_tls_priv.gso_tun_write_errors, memory_order_relaxed);
	atomic_store_explicit(&p->udp_gso_rx_aggregates, g_tls_priv.udp_gso_rx_aggregates, memory_order_relaxed);
	atomic_store_explicit(&p->udp_gso_rx_bytes, g_tls_priv.udp_gso_rx_bytes, memory_order_relaxed);
	atomic_store_explicit(&p->udp_gso_tx_aggregates, g_tls_priv.udp_gso_tx_aggregates, memory_order_relaxed);
	atomic_store_explicit(&p->udp_gso_tx_bytes, g_tls_priv.udp_gso_tx_bytes, memory_order_relaxed);
	atomic_store_explicit(&p->udp_gso_sw_fallbacks, g_tls_priv.udp_gso_sw_fallbacks, memory_order_relaxed);
	atomic_store_explicit(&p->udp_gso_sw_segments, g_tls_priv.udp_gso_sw_segments, memory_order_relaxed);

	g_tls_priv.batch_count = 0;
}

void stats_get_snapshot(struct tayga_stats *out)
{
	memset(out, 0, sizeof(*out));
	out->start_time = g_stats_start_time;

	stats_sync_workers(&out->workers_synced, &out->unacked_mask);

	for (int i = 0; i < STATS_MAX_SLOTS; i++) {
		struct worker_pub_stats *p = &g_worker_pub[i];
		out->rx_pkts_v4 += atomic_load_explicit(&p->rx_pkts_v4, memory_order_relaxed);
		out->rx_bytes_v4 += atomic_load_explicit(&p->rx_bytes_v4, memory_order_relaxed);
		out->tx_pkts_v4 += atomic_load_explicit(&p->tx_pkts_v4, memory_order_relaxed);
		out->tx_bytes_v4 += atomic_load_explicit(&p->tx_bytes_v4, memory_order_relaxed);

		out->rx_pkts_v6 += atomic_load_explicit(&p->rx_pkts_v6, memory_order_relaxed);
		out->rx_bytes_v6 += atomic_load_explicit(&p->rx_bytes_v6, memory_order_relaxed);
		out->tx_pkts_v6 += atomic_load_explicit(&p->tx_pkts_v6, memory_order_relaxed);
		out->tx_bytes_v6 += atomic_load_explicit(&p->tx_bytes_v6, memory_order_relaxed);

		out->dropped_pkts += atomic_load_explicit(&p->dropped_pkts, memory_order_relaxed);
		out->dropped_bytes += atomic_load_explicit(&p->dropped_bytes, memory_order_relaxed);
		out->error_pkts += atomic_load_explicit(&p->error_pkts, memory_order_relaxed);

		out->gso_rx_pkts += atomic_load_explicit(&p->gso_rx_pkts, memory_order_relaxed);
		out->gso_rx_bytes += atomic_load_explicit(&p->gso_rx_bytes, memory_order_relaxed);
		out->gso_tx_pkts += atomic_load_explicit(&p->gso_tx_pkts, memory_order_relaxed);
		out->gso_tx_bytes += atomic_load_explicit(&p->gso_tx_bytes, memory_order_relaxed);
		out->gso_split_tail_pkts += atomic_load_explicit(&p->gso_split_tail_pkts, memory_order_relaxed);
		out->gso_sw_seg_pkts += atomic_load_explicit(&p->gso_sw_seg_pkts, memory_order_relaxed);
		out->gso_sw_seg_out_pkts += atomic_load_explicit(&p->gso_sw_seg_out_pkts, memory_order_relaxed);
		out->gso_fallback_pkts += atomic_load_explicit(&p->gso_fallback_pkts, memory_order_relaxed);
		out->gso_invalid_pkts += atomic_load_explicit(&p->gso_invalid_pkts, memory_order_relaxed);
		out->gso_tun_write_errors += atomic_load_explicit(&p->gso_tun_write_errors, memory_order_relaxed);
		out->udp_gso_rx_aggregates += atomic_load_explicit(&p->udp_gso_rx_aggregates, memory_order_relaxed);
		out->udp_gso_rx_bytes += atomic_load_explicit(&p->udp_gso_rx_bytes, memory_order_relaxed);
		out->udp_gso_tx_aggregates += atomic_load_explicit(&p->udp_gso_tx_aggregates, memory_order_relaxed);
		out->udp_gso_tx_bytes += atomic_load_explicit(&p->udp_gso_tx_bytes, memory_order_relaxed);
		out->udp_gso_sw_fallbacks += atomic_load_explicit(&p->udp_gso_sw_fallbacks, memory_order_relaxed);
		out->udp_gso_sw_segments += atomic_load_explicit(&p->udp_gso_sw_segments, memory_order_relaxed);
	}
}

void stats_dump(void)
{
	struct tayga_stats s;
	stats_get_snapshot(&s);

	slog(LOG_NOTICE, "Stats: IPv4 RX pkts=%llu bytes=%llu, TX pkts=%llu bytes=%llu\n",
		(unsigned long long)s.rx_pkts_v4, (unsigned long long)s.rx_bytes_v4,
		(unsigned long long)s.tx_pkts_v4, (unsigned long long)s.tx_bytes_v4);
	slog(LOG_NOTICE, "Stats: IPv6 RX pkts=%llu bytes=%llu, TX pkts=%llu bytes=%llu\n",
		(unsigned long long)s.rx_pkts_v6, (unsigned long long)s.rx_bytes_v6,
		(unsigned long long)s.tx_pkts_v6, (unsigned long long)s.tx_bytes_v6);
	slog(LOG_NOTICE, "Stats: Drops pkts=%llu bytes=%llu, Errors=%llu\n",
		(unsigned long long)s.dropped_pkts, (unsigned long long)s.dropped_bytes,
		(unsigned long long)s.error_pkts);

	for (int i = 0; i <= gcfg.workers && i < STATS_MAX_SLOTS; i++) {
		struct worker_pub_stats *p = &g_worker_pub[i];
		uint64_t w_rx4 = atomic_load_explicit(&p->rx_pkts_v4, memory_order_relaxed);
		uint64_t w_rx6 = atomic_load_explicit(&p->rx_pkts_v6, memory_order_relaxed);
		uint64_t w_tx4 = atomic_load_explicit(&p->tx_pkts_v4, memory_order_relaxed);
		uint64_t w_tx6 = atomic_load_explicit(&p->tx_pkts_v6, memory_order_relaxed);
		uint64_t w_drp = atomic_load_explicit(&p->dropped_pkts, memory_order_relaxed);
		if (w_rx4 || w_rx6 || w_tx4 || w_tx6 || w_drp) {
			slog(LOG_NOTICE, "Stats: Worker %d (slot %d): rx4=%llu rx6=%llu tx4=%llu tx6=%llu dropped=%llu\n",
				i == 0 ? 0 : i - 1, i,
				(unsigned long long)w_rx4, (unsigned long long)w_rx6,
				(unsigned long long)w_tx4, (unsigned long long)w_tx6,
				(unsigned long long)w_drp);
		}
	}
}
