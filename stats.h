/*
 *  stats.h -- Unified high-performance packet counters and telemetry
 *
 *  Part of TAYGA CLAT / NAT64
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAYGA_STATS_H__
#define __TAYGA_STATS_H__

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#define STATS_MAX_SLOTS 65
#define STATS_BATCH_SIZE 1024

/*
 * Published stats structure per worker slot.
 * Aligned to 128 bytes to prevent false-sharing across CPU cores.
 * Read concurrently by snapshot reader via atomic loads (data-race-free).
 */
struct worker_pub_stats {
	_Atomic uint64_t rx_pkts_v4;
	_Atomic uint64_t rx_bytes_v4;
	_Atomic uint64_t tx_pkts_v4;
	_Atomic uint64_t tx_bytes_v4;

	_Atomic uint64_t rx_pkts_v6;
	_Atomic uint64_t rx_bytes_v6;
	_Atomic uint64_t tx_pkts_v6;
	_Atomic uint64_t tx_bytes_v6;

	_Atomic uint64_t dropped_pkts;
	_Atomic uint64_t dropped_bytes;
	_Atomic uint64_t error_pkts;

	/* GSO telemetry integrated per worker */
	_Atomic uint64_t gso_rx_pkts;
	_Atomic uint64_t gso_rx_bytes;
	_Atomic uint64_t gso_tx_pkts;
	_Atomic uint64_t gso_tx_bytes;
	_Atomic uint64_t gso_split_tail_pkts;
	_Atomic uint64_t gso_sw_seg_pkts;
	_Atomic uint64_t gso_sw_seg_out_pkts;
	_Atomic uint64_t gso_fallback_pkts;
	_Atomic uint64_t gso_invalid_pkts;
	_Atomic uint64_t gso_tun_write_errors;
	_Atomic uint64_t udp_gso_rx_aggregates;
	_Atomic uint64_t udp_gso_rx_bytes;
	_Atomic uint64_t udp_gso_tx_aggregates;
	_Atomic uint64_t udp_gso_tx_bytes;
	_Atomic uint64_t udp_gso_sw_fallbacks;
	_Atomic uint64_t udp_gso_sw_segments;
} __attribute__((aligned(128)));

/*
 * Private thread-local stats on the fast path.
 * Updated purely in thread-local storage/registers without ANY atomic instructions.
 */
struct worker_priv_stats {
	uint64_t rx_pkts_v4;
	uint64_t rx_bytes_v4;
	uint64_t tx_pkts_v4;
	uint64_t tx_bytes_v4;

	uint64_t rx_pkts_v6;
	uint64_t rx_bytes_v6;
	uint64_t tx_pkts_v6;
	uint64_t tx_bytes_v6;

	uint64_t dropped_pkts;
	uint64_t dropped_bytes;
	uint64_t error_pkts;

	uint64_t gso_rx_pkts;
	uint64_t gso_rx_bytes;
	uint64_t gso_tx_pkts;
	uint64_t gso_tx_bytes;
	uint64_t gso_split_tail_pkts;
	uint64_t gso_sw_seg_pkts;
	uint64_t gso_sw_seg_out_pkts;
	uint64_t gso_fallback_pkts;
	uint64_t gso_invalid_pkts;
	uint64_t gso_tun_write_errors;
	uint64_t udp_gso_rx_aggregates;
	uint64_t udp_gso_rx_bytes;
	uint64_t udp_gso_tx_aggregates;
	uint64_t udp_gso_tx_bytes;
	uint64_t udp_gso_sw_fallbacks;
	uint64_t udp_gso_sw_segments;

	uint32_t batch_count;
	int slot_idx;
};

/* Unified snapshot struct for reporting and JSON telemetry */
struct tayga_stats {
	uint64_t rx_pkts_v4;
	uint64_t rx_bytes_v4;
	uint64_t tx_pkts_v4;
	uint64_t tx_bytes_v4;

	uint64_t rx_pkts_v6;
	uint64_t rx_bytes_v6;
	uint64_t tx_pkts_v6;
	uint64_t tx_bytes_v6;

	uint64_t dropped_pkts;
	uint64_t dropped_bytes;
	uint64_t error_pkts;

	uint64_t gso_rx_pkts;
	uint64_t gso_rx_bytes;
	uint64_t gso_tx_pkts;
	uint64_t gso_tx_bytes;
	uint64_t gso_split_tail_pkts;
	uint64_t gso_sw_seg_pkts;
	uint64_t gso_sw_seg_out_pkts;
	uint64_t gso_fallback_pkts;
	uint64_t gso_invalid_pkts;
	uint64_t gso_tun_write_errors;
	uint64_t udp_gso_rx_aggregates;
	uint64_t udp_gso_rx_bytes;
	uint64_t udp_gso_tx_aggregates;
	uint64_t udp_gso_tx_bytes;
	uint64_t udp_gso_sw_fallbacks;
	uint64_t udp_gso_sw_segments;

	time_t start_time;
	bool workers_synced;
	uint64_t unacked_mask;
};

extern struct worker_pub_stats g_worker_pub[STATS_MAX_SLOTS];
extern __thread struct worker_priv_stats g_tls_priv;
extern time_t g_stats_start_time;
extern atomic_uint_fast64_t g_stats_sync_req;
extern atomic_uint_fast64_t g_stats_sync_ack[STATS_MAX_SLOTS];
extern atomic_uint_fast64_t g_stats_snapshot_seq;
extern atomic_int g_workers_running;
extern atomic_bool g_worker_slot_active[STATS_MAX_SLOTS];

void stats_init(void);
void stats_thread_init(int worker_idx);
void stats_thread_exit(void);
void stats_flush_worker(void);
int stats_sync_workers(bool *synced_out, uint64_t *unacked_mask_out);
void stats_check_sync_request(void);
void stats_get_snapshot(struct tayga_stats *out);
void stats_dump(void);
void stats_write_json(const char *path, const char *state);

#ifdef STATS_DISABLED
static inline void stats_packet_done(void) {}
static inline void stats_flush_idle(void) {}
static inline void stats_rx4(uint32_t bytes) { (void)bytes; }
static inline void stats_tx4(uint32_t bytes) { (void)bytes; }
static inline void stats_rx6(uint32_t bytes) { (void)bytes; }
static inline void stats_tx6(uint32_t bytes) { (void)bytes; }
static inline void stats_drop(uint32_t bytes) { (void)bytes; }
static inline void stats_error(void) {}
static inline void stats_gso_rx(uint32_t bytes) { (void)bytes; }
static inline void stats_gso_tx(uint32_t bytes) { (void)bytes; }
static inline void stats_gso_split_tail(void) {}
static inline void stats_gso_sw_seg(void) {}
static inline void stats_gso_sw_seg_out(uint32_t count) { (void)count; }
static inline void stats_gso_fallback(void) {}
static inline void stats_gso_invalid(void) {}
static inline void stats_gso_tun_write_error(void) {}
static inline void stats_udp_gso_rx(uint32_t bytes) { (void)bytes; }
static inline void stats_udp_gso_tx(uint32_t bytes) { (void)bytes; }
static inline void stats_udp_gso_sw_fallback(void) {}
static inline void stats_udp_gso_sw_segment(void) {}
#else
/* Per-packet accounting: called exactly once per TUN read datagram */
static inline void stats_packet_done(void) {
	if (++g_tls_priv.batch_count >= STATS_BATCH_SIZE) {
		stats_flush_worker();
	}
}

static inline void stats_flush_idle(void) {
	if (g_tls_priv.batch_count > 0) {
		stats_flush_worker();
	}
}

static inline void stats_rx4(uint32_t bytes) {
	g_tls_priv.rx_pkts_v4++;
	g_tls_priv.rx_bytes_v4 += bytes;
}

static inline void stats_tx4(uint32_t bytes) {
	g_tls_priv.tx_pkts_v4++;
	g_tls_priv.tx_bytes_v4 += bytes;
}

static inline void stats_rx6(uint32_t bytes) {
	g_tls_priv.rx_pkts_v6++;
	g_tls_priv.rx_bytes_v6 += bytes;
}

static inline void stats_tx6(uint32_t bytes) {
	g_tls_priv.tx_pkts_v6++;
	g_tls_priv.tx_bytes_v6 += bytes;
}

static inline void stats_drop(uint32_t bytes) {
	g_tls_priv.dropped_pkts++;
	g_tls_priv.dropped_bytes += bytes;
}

static inline void stats_error(void) {
	g_tls_priv.error_pkts++;
}

/* GSO fast-path hooks */
static inline void stats_gso_rx(uint32_t bytes) {
	g_tls_priv.gso_rx_pkts++;
	g_tls_priv.gso_rx_bytes += bytes;
}

static inline void stats_gso_tx(uint32_t bytes) {
	g_tls_priv.gso_tx_pkts++;
	g_tls_priv.gso_tx_bytes += bytes;
}

static inline void stats_gso_split_tail(void) {
	g_tls_priv.gso_split_tail_pkts++;
}

static inline void stats_gso_sw_seg(void) {
	g_tls_priv.gso_sw_seg_pkts++;
}

static inline void stats_gso_sw_seg_out(uint32_t count) {
	g_tls_priv.gso_sw_seg_out_pkts += count;
}

static inline void stats_gso_fallback(void) {
	g_tls_priv.gso_fallback_pkts++;
}

static inline void stats_gso_invalid(void) {
	g_tls_priv.gso_invalid_pkts++;
}

static inline void stats_gso_tun_write_error(void) {
	g_tls_priv.gso_tun_write_errors++;
}

static inline void stats_udp_gso_rx(uint32_t bytes) {
	g_tls_priv.udp_gso_rx_aggregates++;
	g_tls_priv.udp_gso_rx_bytes += bytes;
}

static inline void stats_udp_gso_tx(uint32_t bytes) {
	g_tls_priv.udp_gso_tx_aggregates++;
	g_tls_priv.udp_gso_tx_bytes += bytes;
}

static inline void stats_udp_gso_sw_fallback(void) {
	g_tls_priv.udp_gso_sw_fallbacks++;
}

static inline void stats_udp_gso_sw_segment(void) {
	g_tls_priv.udp_gso_sw_segments++;
}
#endif

#endif /* __TAYGA_STATS_H__ */
