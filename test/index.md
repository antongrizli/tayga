# Test Cases for TAYGA

TAYGA's test suite is broken up into integration tests (which test end-to-end packet processing) and unit tests.

## Unit Tests

Each unit test is a `c` file in the test directory. To run all of the unit tests, run `make test`. The Makefile will compile with `-Werror` for unit testing, and then run each test. It will stop on the first failure.

## Integration Tets

`tayga` integration tests are run on Linux using network namespaces. `tayga` is developed on Debian. `tayga` requires CAP_NET_ADMIN to bind to the tun device and the test suite requires sufficient permissions to create and manage network namespaces.

The following packages are required:

```sh
# Python and dependencies
apt install -y python3 python3-scapy python3-pyroute
```

To run the full suite, run `make fullsuite`, which will run the unit tests followed by the integration tests. Each test has an expected number of passes and failure, and if these differ, the test will terminate with failure. The test requires sudo to manage network namespaces. If sudo is not available, override SUDO= with the path to your equivalent, or nothing if running the tests as root.

To run an individual test suite:

```sh
# Create new network namespace
ip netns add tayga-test
# Execute the test
ip netns exec tayga-test python3 test/addressing.py
# Delete network namespace
ip netns del tayga-test
```

## Worker readiness and performance diagnostics

`test/test_worker_burst.py` runs the actual Linux worker loop with a test-only
fault library. It checks bounded continuation after full bursts, immediate return
to polling after EAGAIN, fatal descriptor handling, idle CPU use and shutdown.
Run as root with an explicitly selected binary and a new output directory:

```sh
sudo python3 test/test_worker_burst.py --binary /usr/sbin/tayga --output /tmp/worker-burst-results
```

Memory observations are separate from capacity measurements. Install gperftools
in the test guest, then run `tools/diagnose-memory.sh OUTPUT SOURCE_SESSION` as
root. `SOURCE_SESSION` is a completed Lima capture containing the installed
executable's hash and source identity. The script refuses a mismatched binary,
uses the workflow lock, records process memory and tcmalloc heap snapshots, and
restores the startup script. Use a new absolute output directory. When editing the project
concurrently, execute an immutable copy and set `MEMORY_REPO` to this repository
so the sampler can be found. `MEMORY_DURATION` controls seconds per direction;
its default is 120. `MEMORY_RATE` defaults to unrestricted `0` and may select a
steady offered rate for a separate memory-only observation. Allocator profiling is excluded from ordinary throughput A/B
measurements. See [the perf/memory investigation](../docs/PERF-OPTIMISATION-INVESTIGATION-2026-09-30.md).

### CPU placement capacity study

`PATH=/opt/homebrew/bin:$PATH python3 tools/run-affinity-study.py --stamp affinity-YYYYMMDD`
performs three alternating scheduler/separate-CPU pairs for unrestricted TCP and UDP,
both directions, followed by separate 15-second perf captures. It needs the prepared
four-CPU Lima guest and reserves CPUs 0 (TAYGA), 1 (clients), and 2–3 (servers) in
the separate arm. It uses one worker and two clients; it does not change service defaults.
Choose a new stamp; existing output is never overwritten. An incomplete workload stops
collection and retains its ledger. UDP zero-loss acceptance is independent of capture
validity and is never relaxed. Review `perf-sessions/<stamp>/summary.md` and `ledger.json`.
Use this on an otherwise idle VM and keep the source unchanged during collection.
Run `python3 test/test_affinity_study.py` for orchestration regression checks.

### Native UDP endpoint batching and experimental TUN NAPI

`tools/udp-batch-endpoint.c` is a Linux diagnostic endpoint, not part of TAYGA.
Compile with `cc -O3 -Wall -Wextra -Werror tools/udp-batch-endpoint.c -o /tmp/udp-batch-endpoint`.
Run `sudo python3 tools/run-udp-batch-study.py --endpoint /tmp/udp-batch-endpoint
--binary /path/to/frozen/tayga --output /tmp/new-batch-study` in the prepared Linux guest.
The runner first validates eight finite full-payload/short-tail cases. Then it compares
ordinary UDP, sender UDP_SEGMENT, receiver UDP_GRO, and both together in alternating
unrestricted rounds, and captures separate profiles. This local-sender/TUN/veth
microbenchmark excludes NAT44 and must not be pooled with iperf/physical-router results.
The receiver reconstructs GRO datagrams and counts unique sequences using a bounded
bitmap (128 MiB virtual allocation); its memory is not TAYGA's heap usage.
`python3 test/test_udp_batch_endpoint.py` checks native accounting and corruption rejection.

`-DTAYGA_EXPERIMENTAL_NAPI` enables a build-only research candidate on Linux. Every
initial, fallback and worker queue requests IFF_NAPI; startup verifies it and fails
if unavailable. Normal builds do not request NAPI. This flag does not select
IFF_NAPI_FRAGS or change runtime offload defaults. Preserve the exact build flags
and source snapshot, and validate the frozen executable before performance testing:
`test_auto_negotiation.py`, `test_auto_persistent.py`, `test_worker_burst.py`,
`test_udp_gso_kernel.py --modes auto udp tcp off`, `test_napi_initialization.py`,
and the native endpoint correctness matrix. The Linux tests accept `--binary` and
`--output`; use new output directories. Preflight/TCP integrity and PMTU tests use
the installed binary and require serialized temporary installation/restoration.

`sudo python3 tools/run-napi-study.py --baseline /path/to/baseline
--candidate /path/to/napi --source-snapshot /path/to/source.tar.gz
--git-revision <frozen-build-revision> --output /tmp/new-napi-study` measures already validated frozen ELFs with ordinary
iperf endpoints. It alternates complete pairs, preserves invalid attempts, retries
at most twice, records process profiles plus system UDP profiles, and restores the
original installed binary in a finally block. Use the prepared, otherwise idle guest.
UDP acceptance thresholds remain zero; valid overloaded workloads may fail acceptance.
Do not promote NAPI from lower process CPU alone; check system CPU, delivered bytes,
loss, latency, sparse traffic and cleanup, and repeat on physical hardware.

### UDP application fallback and iperf receive diagnostics

The native endpoint accepts `UDP_ENDPOINT_OFFLOAD=auto` to fall back to individual
UDP datagrams when UDP_SEGMENT/GRO is unavailable. Unset/`strict` keeps requested
measurement capabilities mandatory. `run-udp-batch-study.py --offload-policy auto`
selects automatic operation; `--batch-sizes 3 32` controls its capacity sweep.
Results distinguish requested and effective settings. Endpoint regressions include
unsupported initialization, fatal unexpected errors and first-send fallback without
replaying data; the fault shim is test-only.

`python3 test/test_iperf_read_diagnostic.py` checks the diagnostic preload library's
result/errno preservation. `sudo python3 tools/run-iperf-read-diagnostic.py
--library /absolute/path/to/iperf-read-diagnostic.so --output /tmp/new-diagnostic`
runs three bounded alternating drain comparisons at unrestricted load. Compile the
library with `cc -shared -fPIC tools/iperf-read-diagnostic.c -ldl -o diagnostic.so`.
Read/recv evidence includes thread/socket identity and handshake payload bytes.
Keep these instrumented runs separate from capacity results; an iperf error message
alone does not distinguish data reads from UDP handshake validation or control errors.

### Iperf UDP initialization synchronization and batch-size study

`make iperf-start-tools` builds a benchmark-only `iperf_init_test` barrier. Install
`tools/iperf-start-gate.so` under `/usr/local/lib/tayga-perf/` and
`tools/iperf-start-control` under `/usr/local/libexec/tayga-perf/`. The Lima and UDP
matrix runners do this automatically. `IPERF_START_GATE=on` is the UDP benchmark
default; `off` reproduces the old launch behavior. TCP does not preload the barrier.
It requires dynamically linked iperf and is validated with version 3.18. Requalify
initialization ordering for other versions. Every client/server must reach the
barrier after stream setup; test timers and data threads start only after release.
Warmup has a separate barrier. Readiness/release timeout or missing interposition
fails visibly; fatal startup failures stop subsequent directions before cleanup.

`python3 test/test_iperf_start_gate.py` checks delayed setup in both directions,
early release rejection and invalid/reused controls. `test_iperf_read_diagnostic.py`
also checks UDP setup writes and the connect-function return/errno. Instrumented
runs must remain separate from capacity measurements.

For allocation tradeoffs, use `run-udp-batch-study.py --batch-sizes 3 8 32
--gro-values 1`; finite checks and separate profiles cover each requested size.
`tools/summarize-udp-batch-study.py ROOT --output NEW_JSON` rejects incomplete,
invalid, mixed-identity or silently falling-back capacity matrices and excludes
profiles from capacity medians. Tests: `test_udp_batch_study.py` and
`test_udp_batch_summary.py`.

`tools/run-iperf-start-study.py` freezes a benchmark script and runs alternating
on/off startup comparisons, no-drain observation, warmup/TCP regressions and
separate process/system profiles. It requires explicit source identity of the
unchanged installed TAYGA executable. Invalid original workloads are retained,
not pooled with complete ones. A no-drain result-exchange failure is retained as
a separate observation; it is not considered fixed by initialization readiness.
