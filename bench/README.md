# Benchmark tools

From the repository root:

```sh
python3 -m pip install -e 'bench[dev]'
python3 -m taygabench --help
python3 -m taygabench study udp-batch --help
python3 -m taygabench summarize tcp-flow --help
make bench-tools benchmark-script
```

Alternatively use `PYTHONPATH=bench python3 -m taygabench ...` without installing.
Study modules are importable using underscore names; hyphenated script paths
remain compatibility entrypoints. Runtime Python dependencies are standard-library
only, while native workloads require Linux tooling (iperf3, perf, iproute2 and
root for namespaces).

The source CLAT entrypoint sources `clat/lib` functions. `make benchmark-script`
assembles `build/benchmark-clat.sh` for installation or archival; it runs without
those source libraries. Runners freeze sourced code when given the source entrypoint.
Build shims live under `build/shims`; explicit old helper targets retain copies in
`tools` for scripts deployed before the migration.

Results default to `$PERF_SESSION_ROOT` or
`${XDG_STATE_HOME:-$HOME/.local/state}/tayga/perf-sessions`. Comparisons use
`$PERF_COMPARISON_ROOT` or the corresponding `tayga/perf-comparisons` state folder.
Preserve existing local results before migrating them. Most studies require an
explicit new output directory and reject incomplete or mixed-identity datasets.

Use [the Lima workflow](lima/README.md) for host collection and guest measurements.
Container recipes use the repository root as their build context:

```sh
docker build -f bench/containers/benchmark.Containerfile -t tayga-benchmark .
```

That image runs the self-contained CLAT benchmark and has no sibling workspace
dependency. It replaces the former external NAT64 comparison container; use the
owning project's tools when comparing that different implementation.

See [benchmarking guidance](../docs/dev/benchmarking.md) for measurement boundaries.

## TCP recovery acceptance

Run `bench/lima/run-recovery.sh` on the prepared Lima host for five alternating
kernel/flows pairs, four clients, three workers, 20 seconds per direction and a
five-second warmup. `CLIENT_PORT_BASE` assigns reproducible data ports; the runner
uses a different base per pair and separate warmup/upload ranges to avoid
TIME_WAIT collisions. Control connections still use normal ephemeral ports.
Scheduled ports are reserved from ephemeral allocation inside the disposable
client namespace, so a control socket cannot claim a data port before its bind.
The existing reservation list is preserved and the effective list is recorded
in `client-reserved-ports.txt`. Deterministic mode supports up to 1,000 streams
per client and checks the final stream's port against the 16-bit limit.
`REPEATS=5..20` and a unique `RECOVERY_STAMP` select the study. Every session,
including failures, is retained. Do not change source/settings during the study.
The default compares configurations of the same source/build. For an original
source versus a corrected source comparison, set `RECOVERY_MODE=build`,
`BASELINE_REPO=/absolute/baseline/tree` and
`CANDIDATE_REPO=/absolute/candidate/tree`. Both trees must be available at those
paths inside Lima and contain the current benchmark harness; preserve the
original production sources when preparing a baseline. The archived sources,
compiler identity and flags identify the actual builds, including local edits.

The runner writes acceptance JSON and Markdown beside the sessions and returns
nonzero for failed or missing evidence. To re-evaluate existing paired sessions:

```sh
PYTHONPATH=bench python3 -m taygabench acceptance \
  --baseline /path/kernel-r1 /path/kernel-r2 /path/kernel-r3 /path/kernel-r4 /path/kernel-r5 \
  --candidate /path/flows-r1 /path/flows-r2 /path/flows-r3 /path/flows-r4 /path/flows-r5 \
  --json /tmp/recovery.json --markdown /tmp/recovery.md
```

Inputs are paired in supplied order. The gate checks synchronized process/worker
identities, effective steering, raw client reports, source/archive identities,
interface and daemon errors, worker activity, medians/ranges and paired deltas.
Default throughput floors are the saved original result, **76.178/70.639 Gbps**
download/upload, which is stricter than the plan's 75/70 Gbps minimum. The gate
also requires at least 45% fewer
retransmissions per **sent decimal GB**. Both the candidate median and the median
paired throughput change must improve over the same-environment baseline in
each direction. Equal throughput and any median degradation fail; there is no
regression allowance. A one-sided paired sign test must also reach p ≤ 0.05:
five pairs require improvement in all five, so a noisy positive median alone
cannot pass. These are study gates, not a promise for every environment.
The gate also verifies raw client stream counts, direction and scheduled data
ports, reconstructs source identity from the archive, and requires matching
before/after kernel backlog and receive-budget settings across both arms.
Compiler and optimization/link flags must match in both comparison modes;
temporary build paths in prefix-remapping flags are normalized. Repeated paths
cannot count as independent trials, and incomplete manifests fail acceptance.
Packet shares do not establish exact flow counts. Retransmissions are reported
even when daemon drops are zero. The earlier `retransmits_per_gbyte` summary
field retains its historical received-byte denominator; acceptance computes its
sent-byte metric from raw reports.
