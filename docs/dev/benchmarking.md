# Benchmarking

Start with [bench/README.md](../../bench/README.md) and the
[Lima workflow](../../bench/lima/README.md). Install or generate a standalone
benchmark before freezing it for A/B comparisons; its embedded helper code must
match the selected source revision.

Separate correctness, unrestricted capacity, paced operating points and profiling.
Record executable and source hashes, CPU affinity, queue/offload negotiation,
workers, traffic settings and raw accepted/rejected results. A moved runner or a
passing unit suite does not demonstrate a throughput improvement.
