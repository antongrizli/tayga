# Throughput diagnostics and steering ablations

The diagnostics tools preserve observed evidence and never grant product
acceptance. Capacity studies continue to use the strict recovery evaluator.

## Directional worker bytes and saved results

Result schema 7 retains `rx_bytes_v4`, `tx_bytes_v4`, `rx_bytes_v6` and
`tx_bytes_v6` in `worker_metrics`. `byte_counters_available=false` and null byte
values identify legacy snapshots with no byte counters. Partially populated
snapshots, duplicate slots, changed identities and counter resets are errors.
Use `slot`, not `worker_id`, as the key: main and worker zero share worker ID 0.
The packet-share acceptance gate remains unchanged.

Inspect saved sessions, individual `result.json` files, or acceptance JSON:

```sh
PYTHONPATH=bench python3 -m taygabench diagnostics /path/to/sessions \
  --output /tmp/throughput-diagnostics.json
```

The report reads synchronized raw worker snapshots when present and retains
errors for every invalid window. It reports directional packet/byte shares,
effective worker count, GSO input sizes and split/fallback rates, per-thread
scheduler running/wait times and CPU-seconds per received application GB.
GSO IP bytes, application bytes and wire bytes remain distinct. The historical
`retransmits_per_gbyte` field uses received bytes and is explicitly labelled that
way; strict acceptance independently reconstructs its sent-byte denominator.

## Bounded TCP sequence tracing

Run inside the Linux guest as root, with BTF and bpftrace available. Use the
same workflow lock as other TAYGA namespace studies. Do not overlap this command
with another benchmark or system suite.
The collector starts probes before starting the workload and saves its command,
exit status, generated BPF program/hash, tool/kernel versions, namespace IDs,
interface inventory, raw logs and normalized JSONL. Output directories must not
exist. An interrupted/timed-out workload is stopped as a process group.
The collector holds the guest workflow flock for the capture; the benchmark
it launches uses its independent topology lock.

```sh
sudo env PYTHONPATH=bench python3 -m taygabench.trace_tcp \
  --output /tmp/tcp-trace-low-v1 --timeout 90 --limit 10000 \
  --ports 5201 5202 5203 5204 -- \
  env ARTIFACT_DIR=/tmp/tcp-trace-low-workload-v1 PERF_MODE=none \
    CLIENTS=4 FLOWS=1 WORKERS=3 PROTOCOL=tcp RATE=64M \
    DURATION=3 WARMUP=0 DIRECTIONS=upload CLAT_STEERING=kernel \
    sh build/benchmark-clat.sh
```

Build the harness first with `make benchmark-script`. It uses the installed
TAYGA/startup/helpers; record their identities and prepare the environment using
the regular guest workflow before interpreting daemon-specific behavior.

For unlimited-load diagnosis, use a small selected time window:

```sh
sudo env PYTHONPATH=bench python3 -m taygabench.trace_tcp \
  --output /tmp/tcp-trace-window-v1 --timeout 90 --limit 100000 \
  --ports 5201 --window-ms 3 --ring-pages 16384 -- \
  env ARTIFACT_DIR=/tmp/tcp-trace-window-workload-v1 PERF_MODE=none \
    CLIENTS=4 FLOWS=1 WORKERS=3 PROTOCOL=tcp RATE=0 \
    DURATION=3 WARMUP=0 DIRECTIONS=upload CLAT_STEERING=kernel \
    sh build/benchmark-clat.sh
```

The window starts at the first selected IP-output packet with at least 10 KB of
TCP payload. `complete` refers only to this selected observation window, not
the entire TCP connection. A capture with no events, a failed command/tracer,
reported event loss, normalization truncation or exhausted per-stage/CPU budget
is incomplete. Inspect both `raw.stdout` and `raw.stderr` as well as
`capture.json`: bpftrace can report lost events on either stream. Do not treat
an incomplete capture as zero loss. `--max-events` bounds normalized output
(default 500,000); omitted events invalidate completeness.

`--ring-pages` sets perf buffer pages per CPU (power of two, default 256, maximum
16,384). At 4 KB pages the maximum uses 64 MiB per CPU. Prefer guest-local
`/tmp` for raw output at unlimited load, then archive it after collection; slow
shared-filesystem writes can overflow the consumer buffer. A larger ring does
not guarantee a complete capture: always check the retained loss counters.
The map budget is an upper safety bound, not a measured reorder rate.

Probe points cover kernel IP egress (including TSQ/softirq contexts), device
transmit, TUN transmit enqueue, skb copy during TUN read, and TCP receive. The
TUN-copy point precedes successful read return. Basic unfragmented IPv4 TCP and
IPv6 TCP without extension headers are supported. No post-translation userspace
write probe is claimed. Concurrent CPU timestamps do not establish wire FIFO.
Instrumentation changes scheduling and is never a capacity measurement.

Analyze sequence intervals:

```sh
PYTHONPATH=bench python3 -m taygabench sequence /tmp/tcp-trace-window-v1 \
  --output /tmp/tcp-sequence.json
```

Optional `--aliases /path/aliases.json` supplies explicit address mappings and
`--paths /path/paths.json` supplies ordered observation points, for example:

```json
[
  {"name": "one-direction", "points": [
    {"stage": "dev_xmit", "netns": 123, "ifindex": 2},
    {"stage": "tun_enqueue", "netns": 456, "ifindex": 3}
  ]}
]
```

Use actual namespace/interface IDs from the capture, never the illustrative IDs
above. Address-only aliases cannot express NAT port rewriting; verify the full
tuple mapping before merging translated flows. The original capture is preserved.

The analyzer handles sequence wrap, SYN/FIN consumption, aggregate/segment
coverage, overlap and late gap filling. It excludes pure ACKs from data coverage
and never compares packet counts across segmentation. Sequence unwrapping assumes
adjacent observations differ by less than 2^31. Missing capture prefixes/suffixes
are not counted as loss. Cross-stage output identifies handoff candidates when
an upstream range was already observed before a downstream gap. It deliberately
requires further serialization/duplicate/DSACK verification before attribution.

## One-factor steering sources

Research patches are stored in [bench/experiments/steering](../../bench/experiments/steering/README.md).
They apply only to separately frozen source trees:

```sh
PYTHONPATH=bench python3 -m taygabench study steering-ablation \
  --output /absolute/path/new-ablation-v1
```

The command creates baseline, flat+hints, hierarchical+hints and
hierarchical+hints+NAPI sources, a separate frozen harness and a preregistered
A2/A3 design. The daemon main/worker affinity code is identical in every arm.
A2 changes admission only; A3 changes NAPI only. Patch errors stop preparation.
No experiment modifies the production source or selects flows by default.

Run Linux unit/system/BPF gates for every selected executable before capacity.
Use the frozen harness `run-recovery.sh` with `RECOVERY_MODE=build`,
`RECOVERY_PURPOSE=diagnostic`, both steering policies `flows`, the corresponding
source directories, five fixed pairs and unique study IDs. Preserve raw sessions
and restore installed guest artifacts afterward. New guest workflows retain
`tayga.elf` beside its SHA256 so correctness gates can run against the exact
capacity executable. Product acceptance remains the
separate kernel-to-flows protocol with its original throughput, retransmission,
drop and worker-share requirements.

## Ingress CPU backlog localization

Use `--ingress` with the collector to add veth transmit, `netif_rx`,
`enqueue_to_backlog` (including target CPU), `__netif_receive_skb`, GRO entry and
IPv4/IPv6 receive probes. Kernel symbols and tracepoints must exist; a failed
attach is retained as an incomplete capture. Capture metadata includes actual
per-interface RPS/RFS/XPS masks from each disposable namespace. The extra probes
increase scheduling overhead and remain diagnostic only.

Events also retain the skb address, hash and ingress ifindex. The sequence
analyzer matches backlog observations by namespace/interface, full tuple, skb
address, sequence and length. It reports adjacent enqueue-order inversions and
bounded witnesses, including different target backlogs. Ambiguous matches and
unmatched observations remain visible. An address can be reused, the enqueue
probe precedes insertion/return, and some receive paths use lists/GRO; missing
matches are never treated as packet loss. Timestamp ties invalidate ordering
interpretation even if the collector reports no lost events.

Cross-stage analysis explicitly identifies overlapping gaps already seen
upstream. Upstream coverage alone does not establish a new defect at the next
handoff: a gap may have filled upstream before propagating downstream.

## Optional CLAT ingress RPS experiment

`CLAT_INGRESS_RPS_CPUS=unchanged` is the default and performs no mask writes.
For a controlled Linux experiment, a hexadecimal Linux CPU mask such as `f`
selects CPUs 0–3. The benchmark applies it only to RX queues of the disposable
`clatns/veth-nat64`, before traffic starts. It saves the original and readback
masks in `clat-ingress-rps.json`; rejected writes or mismatched readback stop
setup. Namespace cleanup removes the modified interface. RFS and other
interfaces are unchanged. Kernels without RPS controls still support the default
`unchanged` mode; an explicit mask requires the controls.

Host/guest runners forward this parameter and results retain
`clat_ingress_rps_cpus` as a treatment identity. Historical results default to
`unchanged`. Strict product acceptance rejects different masks between arms;
a configuration diagnostic with deliberately different masks must remain a
separate study. Enabling RPS is not a production recommendation: a stable flow
CPU can reduce one source of reorder while adding cross-CPU work or exposing
an earlier handoff. It needs throughput, retransmission, CPU and share evidence.
