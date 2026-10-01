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

`sudo python3 test/test_benchmark_start_gate_failure.py` injects a missing warmup
participant, verifies bounded failure, stops the next direction and checks cleanup.
Use an otherwise idle guest; `IPERF_START_FAILURE_OUTPUT` can retain its artifacts.

### Final-result control tracing and retained server logs

`tools/run-iperf-read-diagnostic.py --start-gate on --clients 4` performs bounded,
maximum-load diagnostic comparisons with and without receiver drain. Its optional
`--benchmark` freezes the selected benchmark into the artifact directory. Supply
`--git-revision` and `--source-tree-sha256` from the installed TAYGA executable's
verified build, rather than from a different current checkout. Instrumented runs
are excluded from capacity comparisons.

The preload diagnostic records TCP control read lengths, short/EOF/error results
and exchange begin/end timestamps while preserving syscall results and errno.
Server logs are stored inside each warmup/direction directory. Run
`python3 test/test_iperf_read_diagnostic.py` on Linux and
`python3 test/test_iperf_server_logs.py` for evidence-preservation regressions.
See [the result-exchange investigation](../docs/UDP-RESULT-EXCHANGE-INVESTIGATION-2026-10-01.md)
and [the backend design](../docs/TUN-BACKEND-OPTIMISATION-DESIGN-2026-10-01.md).

`--control-only` avoids socket-type queries on successful UDP data reads and logs
TCP framing select results and iperf state transitions. Four diagnostic tests cover
errno, timeout/EOF/short reads and the absence of UDP socket queries.

`python3 test/test_udp_common_stop.py` checks that zero-drain UDP stops at the
common measurement boundary before result exchange, validates stop/attachment
state and allows zero blocked writes when senders finish naturally. TCP retains
its normal end sequence. See [the common-stop fix](../docs/UDP-COMMON-STOP-FIX-2026-10-01.md).

### Matched TCP benchmark and worker distribution

`tools/run-tcp-worker-study.py` requires Linux root, explicit before/after benchmark
scripts, a new output folder and the source identity of the measured installed
TAYGA executable. It freezes both scripts and holds the workflow lock. Three
alternating one-worker A/B pairs precede three balanced-order rounds with
1/2/3 workers. All capacity directions use four TCP clients, one flow each,
RATE=0, identical settings and no profiler. Separate process/system perf captures
follow for one and three workers. Incomplete TCP captures/workloads or acceptance
failures stop the study and preserve evidence.

Client tuples and worker counters are retained. Tuples are recorded, not fixed;
this reveals natural queue variability rather than isolating worker count from
flow hash placement. `tools/summarize-tcp-worker-study.py OUTPUT` rejects missing
or duplicated groups, mixed executable identities, capped traffic and mismatched
treatment metadata. Worker shares use IPv4 input for upload and IPv6 input for
download, excluding the main slot and the opposite-family ACK input. They count
input frames, including aggregates; they are not byte or CPU shares.

Run `python3 test/test_tcp_worker_study.py` for schedule/summary tests.

### TCP flow count and CPU placement

`tools/run-tcp-flow-study.py` freezes the installed benchmark and runner, holds
the workflow lock and records all connection tuples and daemon/startup hashes.
It alternates four and sixteen streams over three pairs at two and three
workers. Capacity uses RATE=0 without profiling. Ports are recorded rather
than fixed; distribution represents natural kernel placement.

Use `tools/summarize-tcp-flow-study.py OUTPUT` to validate the complete matrix,
workload settings, executable identity, stream counts and all acceptance gates.
A change in stream count is a workload change, not an implementation speedup.

The runner's `--placement-study` option requires four guest CPUs and uses
sixteen streams throughout. It alternates unrestricted scheduler affinity with
partitioned process affinity. Two workers use CPUs 0,1, with client CPU 2 and
server CPU 3. Three workers use CPUs 0,1,2; both endpoints share CPU 3. These
are explicit experimental layouts, not defaults or kernel steering settings.
Separate process/system profiles follow capacity runs for each treatment.
`tools/summarize-tcp-placement-study.py OUTPUT` rejects missing profiles,
incomplete pairs and unexpected affinity, and keeps profiles out of capacity
statistics. Degraded complete profiles remain labelled as diagnostics; capacity
requires all acceptance gates. `--resume` verifies frozen identities/settings,
retains the original runner and records the resumed runner, refusing partial
cases and rejected capacity. Run `python3 test/test_tcp_flow_study.py` for eight
validation tests.

### Experimental address-group steering and reference adapter

`--tun-steering=kernel` is the default. Linux-only `--tun-steering=groups` requires a fresh disposable TUN and is an experimental address-pair policy; it failed the measured CLAT throughput gate. See [implementation and results](../docs/TUN-STEERING-AND-REFERENCE-ADAPTER-IMPLEMENTATION-2026-10-01.md).

`make test` includes `unit_packet_io`. On Linux as root, run `python3 test/test_tun_steering.py` for real queue ordering/concurrency/descriptor-pressure tests, and `python3 test/test_tun_steering_lifecycle.py /path/to/frozen/tayga` for reload, termination, existing-device rejection and fallback. Both reserve the workflow lock. UDP wire tests accept `--steering groups` in addition to the default kernel policy.

In the prepared guest, `sudo python3 tools/run-tun-steering-study.py --candidate /path/to/frozen/tayga --revision BUILD_REVISION --source-sha SOURCE_SNAPSHOT_SHA --output /tmp/new-steering-study` captures unrestricted alternating capacity and separate perf sessions, restoring installed files on exit. `--reference-only` selects sixteen-stream TCP pairs; `--verification-only` selects final-image kernel/groups TCP/UDP checks; `--profiles-only --kernel-only` selects final production-policy profiles. Use immutable sources and new output directories. Resume only with matching frozen identities/settings. UDP zero-loss rejection is preserved. Run `python3 tools/summarize-tun-steering-study.py /tmp/new-steering-study` to validate and summarize.

`sudo python3 tools/run-steering-integrity.py --binary /path/to/frozen/tayga --output /tmp/new-steering-integrity` temporarily installs the selected image for TCP/UDP integrity and PMTU checks, then restores the original files. `python3 test/test_tun_steering_study.py` validates the measurement tooling. These experiments require serialized use of the prepared Linux guest.

### UDP operating-envelope and frame-lifetime gates

`make test` now also includes `unit_packet_io_lifetime`. The experimental helper models fixed frame storage, generation/pool identity, ownership transitions, completion and shutdown; it is not an asynchronous backend. See [next-stage design](../docs/FLOW-STEERING-AND-ASYNC-OWNERSHIP-NEXT-STAGE-2026-10-01.md).

Compile the diagnostic endpoint with `cc -O3 -Wall -Wextra -Werror tools/udp-batch-endpoint.c -o /tmp/udp-envelope-endpoint`. In an otherwise idle Linux guest, run `sudo python3 tools/run-udp-envelope-study.py --binary /path/to/frozen/tayga --endpoint /tmp/udp-envelope-endpoint --output /tmp/new-envelope`. The default rates include unrestricted maximum load (`0`). Paced cases are separate operating points; a requested rate must be reached within 5% and every full packet/byte count and pressure gate must pass. The topology excludes NAT44 and ordinary iperf; do not pool these results with those studies. `--duration 30 --pairs 1 --rates 100 500 0` selects a longer conservative observation. `--receive-buffer 4194304` explicitly requests a larger receiver socket buffer and records the actual kernel value; `0` retains the kernel default. This is diagnostic endpoint configuration, not a TAYGA setting.

Run `python3 test/test_udp_envelope_study.py` for summary checks and, on Linux, `python3 test/test_udp_batch_endpoint.py` for endpoint fallback, integrity, pacing and receive-buffer checks. All studies reserve the workflow lock and retain rejected/under-offered runs. Native endpoint pacing sleeps to absolute deadlines and limits catch-up bursts; at high rates the scheduler can prevent achieving the requested rate. Such a run cannot establish capacity at that rate.

For matched socket-buffer A/B, use `--receive-buffers 0 4194304 --rates 1000 0 --pairs 3`. The guest may clamp SO_RCVBUF to rmem_max, so inspect `receiver.json`'s actual value. Add `--force-receive-buffer` only for an explicit privileged diagnostic; it uses SO_RCVBUFFORCE without changing global sysctls. `--profiles-only --receive-buffers 0 4194304 --force-receive-buffer` records separate unrestricted process/system profiles with raw data, self/caller reports and zero-lost-sample validation. Profile results are excluded from operating-point summaries.

Results and limitations: [UDP envelope/ownership follow-up](../docs/UDP-ENVELOPE-AND-OWNERSHIP-FOLLOWUP-2026-10-01.md).


### Experimental flow dispatch and asynchronous TUN TX

Build using `make WITH_URING=1 VERSION=0.9.12` with liburing development headers. Default builds do not require liburing. Runtime defaults remain kernel multiqueue and synchronous writes. Experimental selections are `--dispatch=flows --packet-io=uring`; flow dispatch requires static inline maps and a fresh disposable Linux TUN.

```sh
make WITH_URING=1 test unit_async_tun
./unit_async_tun
sudo python3 test/test_dispatch_fragments.py ./tayga /tmp/dispatch-fragments-new
sudo python3 test/test_tun_steering_lifecycle.py ./tayga --dispatch=flows --packet-io=uring
sudo python3 test/test_udp_gso_kernel.py --binary ./tayga --dispatch flows --packet-io uring --output /tmp/dispatch-wire-new --modes auto off --workers 3 --mtus 1280 1500
```

`unit_dispatch` is included in `make test`. The async unit requires `WITH_URING=1`; it tests owned gather-copy lifetime, completion ordering, failed writes and stopping. The lifecycle test retains its original group-steering behavior when no extra flags are supplied.

`tools/run-dispatch-study.py` runs reversible max-rate policy or previous-binary campaigns and separate process/system perf sessions. Supply verified `GIT_REVISION` and `SOURCE_TREE_SHA256` environment metadata for the frozen candidate. Output directories must be new. Failed UDP zero-loss gates are overload evidence, not a sustainable capacity result. See [measured results and restrictions](../docs/DISPATCH-URING-IMPLEMENTATION-2026-10-01.md). These prototypes failed the performance gate and must remain opt-in.
