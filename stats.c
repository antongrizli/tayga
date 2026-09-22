/*
 *  stats.c -- Core high-performance packet counters
 *
 *  Part of TAYGA CLAT / NAT64
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tayga.h"
#include "stats.h"
#include <string.h>

struct worker_pub_stats g_worker_pub[STATS_MAX_SLOTS] __attribute__((aligned(128)));
__thread struct worker_priv_stats g_tls_priv;
time_t g_stats_start_time = 0;

void stats_init(void)
{
	memset(g_worker_pub, 0, sizeof(g_worker_pub));
	memset(&g_tls_priv, 0, sizeof(g_tls_priv));
	g_tls_priv.slot_idx = 0;
	g_stats_start_time = time(NULL);
}

void stats_thread_init(int worker_idx)
{
	memset(&g_tls_priv, 0, sizeof(g_tls_priv));
	if (worker_idx >= 0 && worker_idx < STATS_MAX_SLOTS - 1)
		g_tls_priv.slot_idx = worker_idx + 1;
	else
		g_tls_priv.slot_idx = -1;
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

	g_tls_priv.batch_count = 0;
}

void stats_get_snapshot(struct tayga_stats *out)
{
	if (g_tls_priv.slot_idx >= 0)
		stats_flush_worker();

	memset(out, 0, sizeof(*out));
	out->start_time = g_stats_start_time;

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
}
