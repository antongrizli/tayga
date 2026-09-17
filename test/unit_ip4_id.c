#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "tayga.h"

#define NUM_THREADS 4
#define IDS_PER_THREAD 16384 /* 4 * 16384 = 65,536 total IDs (exactly 1 full 16-bit cycle) */

static uint16_t thread_ids[NUM_THREADS][IDS_PER_THREAD];
static pthread_barrier_t barrier_start;

static void *worker_fn(void *arg)
{
	int tid = *(int *)arg;

	/* Wait for all threads to be ready before starting */
	pthread_barrier_wait(&barrier_start);

	for (int i = 0; i < IDS_PER_THREAD; i++) {
		thread_ids[tid][i] = next_ip4_ident();
	}
	return NULL;
}

/* Skewed worker test: 1 slow worker and 1 fast worker.
 * Total IDs generated between both is exactly 65,536.
 * We record every single ID generated across both threads in chronological order
 * and verify that within this 65,536-ID window, every ID is strictly unique (0 collisions).
 */
#define SKEW_TOTAL_IDS 65536
#define SLOW_SAMPLES 100

static uint16_t recorded_slow[SLOW_SAMPLES];
static uint16_t recorded_fast[SKEW_TOTAL_IDS - SLOW_SAMPLES];
static pthread_barrier_t barrier_skewed;

static void *slow_worker(void *arg)
{
	(void)arg;
	pthread_barrier_wait(&barrier_skewed);

	for (int i = 0; i < SLOW_SAMPLES; i++) {
		recorded_slow[i] = next_ip4_ident();
		usleep(100);
	}
	return NULL;
}

int main(void)
{
	pthread_t th[NUM_THREADS];
	int tids[NUM_THREADS];

	printf("Running unit_ip4_id tests...\n");

	/* Test 1: Full 65,536 cycle across 4 threads.
	 * Verify that all 65,536 generated IDs are 100% unique (zero collisions).
	 */
	set_ip4_ident_counter(0);
	pthread_barrier_init(&barrier_start, NULL, NUM_THREADS);

	for (int i = 0; i < NUM_THREADS; i++) {
		tids[i] = i;
		pthread_create(&th[i], NULL, worker_fn, &tids[i]);
	}
	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(th[i], NULL);
	}
	pthread_barrier_destroy(&barrier_start);

	uint8_t seen[65536] = {0};
	int unique_count = 0;
	for (int t = 0; t < NUM_THREADS; t++) {
		for (int i = 0; i < IDS_PER_THREAD; i++) {
			uint16_t id = thread_ids[t][i];
			if (!seen[id]) {
				seen[id] = 1;
				unique_count++;
			}
		}
	}
	assert(unique_count == 65536);
	printf("PASS: 65,536 IDs across 4 threads are 100%% unique within 16-bit cycle (0 collisions).\n");

	/* Test 2: Natural 16-bit wrap-around */
	set_ip4_ident_counter(65530);
	uint16_t prev = next_ip4_ident();
	int wrapped = 0;
	for (int i = 0; i < 20; i++) {
		uint16_t cur = next_ip4_ident();
		if (cur < prev)
			wrapped++;
		prev = cur;
	}
	assert(wrapped == 1);
	printf("PASS: Natural wrap-around across 65,535 -> 0 operates monotonically.\n");

	/* Test 3: Skewed thread test.
	 * Fast thread generates 65,436 IDs while slow thread generates 100 IDs with delays.
	 * Across all 65,536 IDs collected, exactly 65,536 unique values MUST be present.
	 */
	set_ip4_ident_counter(0x55aa);
	pthread_barrier_init(&barrier_skewed, NULL, 2);
	pthread_t slow_th;
	pthread_create(&slow_th, NULL, slow_worker, NULL);

	pthread_barrier_wait(&barrier_skewed);
	for (int i = 0; i < (int)(SKEW_TOTAL_IDS - SLOW_SAMPLES); i++) {
		recorded_fast[i] = next_ip4_ident();
	}
	pthread_join(slow_th, NULL);
	pthread_barrier_destroy(&barrier_skewed);

	memset(seen, 0, sizeof(seen));
	int skew_unique = 0;
	for (int i = 0; i < SLOW_SAMPLES; i++) {
		if (!seen[recorded_slow[i]]) {
			seen[recorded_slow[i]] = 1;
			skew_unique++;
		}
	}
	for (int i = 0; i < (int)(SKEW_TOTAL_IDS - SLOW_SAMPLES); i++) {
		if (!seen[recorded_fast[i]]) {
			seen[recorded_fast[i]] = 1;
			skew_unique++;
		}
	}
	assert(skew_unique == 65536);
	printf("PASS: Skewed thread scenario: 65,536 IDs partitioned between slow/fast threads have 0 collisions.\n");

	printf("PASS: All unit_ip4_id tests passed.\n");
	return 0;
}
