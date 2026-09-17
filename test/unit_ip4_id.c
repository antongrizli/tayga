#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "tayga.h"

#define NUM_THREADS 4
#define IDS_PER_THREAD 10000

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

/* Skewed worker test variables */
#define SLOW_SAMPLES 50
static uint16_t slow_ids[SLOW_SAMPLES];
static pthread_barrier_t barrier_skewed;

static void *slow_worker(void *arg)
{
	(void)arg;
	/* Synchronize start with the main fast thread */
	pthread_barrier_wait(&barrier_skewed);

	for (int i = 0; i < SLOW_SAMPLES; i++) {
		slow_ids[i] = next_ip4_ident();
		usleep(200);
	}
	return NULL;
}

int main(void)
{
	pthread_t th[NUM_THREADS];
	int tids[NUM_THREADS];

	printf("Running unit_ip4_id tests...\n");

	/* Test 1: Multithreaded concurrent generation from production next_ip4_ident() */
	set_ip4_ident_counter(0x1000);
	pthread_barrier_init(&barrier_start, NULL, NUM_THREADS);

	for (int i = 0; i < NUM_THREADS; i++) {
		tids[i] = i;
		pthread_create(&th[i], NULL, worker_fn, &tids[i]);
	}
	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(th[i], NULL);
	}
	pthread_barrier_destroy(&barrier_start);

	/* Verify no adjacent duplicates within any thread */
	for (int t = 0; t < NUM_THREADS; t++) {
		for (int i = 1; i < IDS_PER_THREAD; i++) {
			assert(thread_ids[t][i] != thread_ids[t][i - 1]);
		}
	}

	/* Verify 40,000 unique IDs across 40,000 parallel requests (within 65,536 cycle) */
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
	assert(unique_count == 40000);
	printf("PASS: 40,000 IDs across 4 threads are 100%% unique within single cycle.\n");

	/* Test 2: Wrap-around across 65,536 (16-bit) boundary */
	reset_ip4_ident_local();
	set_ip4_ident_counter(65500);
	uint16_t prev = next_ip4_ident();
	int wrapped = 0;
	for (int i = 0; i < 200; i++) {
		uint16_t cur = next_ip4_ident();
		if (cur < prev)
			wrapped++;
		prev = cur;
	}
	assert(wrapped >= 1);
	printf("PASS: Wrap-around past 65,536 operates smoothly.\n");

	/* Test 3: Wrap-around across UINT32_MAX (32-bit counter overflow) */
	reset_ip4_ident_local();
	set_ip4_ident_counter(UINT32_MAX - 100);
	uint16_t prev32 = next_ip4_ident();
	int wrapped32 = 0;
	for (int i = 0; i < 250; i++) {
		uint16_t cur32 = next_ip4_ident();
		if (cur32 < prev32)
			wrapped32++;
		prev32 = cur32;
	}
	assert(wrapped32 >= 1);
	printf("PASS: Wrap-around past UINT32_MAX (32-bit overflow) operates smoothly.\n");

	/* Test 4: Skewed worker rates with deterministic barrier start.
	 * Slow worker generates exactly SLOW_SAMPLES while fast thread generates
	 * across multiple cycles (> 70,000 IDs).
	 */
	pthread_barrier_init(&barrier_skewed, NULL, 2);
	pthread_t slow_th;
	pthread_create(&slow_th, NULL, slow_worker, NULL);

	/* Main thread waits at barrier so slow_worker has started */
	pthread_barrier_wait(&barrier_skewed);

	for (int i = 0; i < 70000; i++) {
		(void)next_ip4_ident();
	}
	pthread_join(slow_th, NULL);
	pthread_barrier_destroy(&barrier_skewed);

	/* Verify slow worker generated all expected samples without hanging */
	for (int i = 1; i < SLOW_SAMPLES; i++) {
		assert(slow_ids[i] != slow_ids[i - 1]);
	}
	printf("PASS: Skewed thread rates executed deterministically (%d slow samples collected).\n",
		SLOW_SAMPLES);

	printf("PASS: All unit_ip4_id tests passed.\n");
	return 0;
}
