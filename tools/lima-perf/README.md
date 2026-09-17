# Debian ARM64 perf workflow

This workflow creates a Debian 13 ARM64 Lima VM, builds the current TAYGA tree,
and runs the existing CLAT benchmark twice: once with `perf stat` and once with
`perf record`. It stores raw counters, `perf.data`, a text report, system
metadata, and the source hash under `tayga-clat-perf/perf-sessions/`.

Lima is used because it provides a scriptable ARM64 Linux guest and exposes the
Linux performance counters. The Debian netinst ISO in `~/Downloads` is suitable
for a manual UTM installation, but an unattended ISO install would add no value
to this repeatable benchmark; the Lima Debian 13 template is used by default.

From macOS, after reviewing the command, run:

```sh
bash /Users/antongrizli/Documents/MikroTik/tayga-clat-perf/tools/lima-perf/run-host.sh
```

The default VM is named `tayga-perf`, uses 4 vCPUs, 4 GiB RAM, 24 GiB disk, and
the Apple Virtualization driver. Override these with `INSTANCE`, `CPUS`,
`MEMORY_GB`, `DISK_GB`, or `VM_TYPE=qemu`.

The default workload is 20 TCP clients, one flow each, 15 MiB/s per client,
60 seconds after a 10 second warmup. Override `CLIENTS`, `FLOWS`, `RATE`,
`DURATION`, `WARMUP`, `PROTOCOL`, `DIRECTIONS`, and `WORKERS` when invoking the
host script. The target aggregate is intentionally close to 300 Mbps. The
Set `PERF_MODES=none` for CPU baseline without perf sampling; the default is
`PERF_MODES="stat record"`.

`TUN_TXQLEN` is an optional lab-only queue-size experiment. It is unset by
default, preserving the kernel default. Test one value at a time and record
TUN drops and latency; do not transfer a winning VM value to RouterOS without
checking the container/veth implementation there.

default is strict (`MAX_TUN_DROPS=0`); for a deliberate saturation profile set
an explicit threshold such as `MAX_TUN_DROPS=100000`. The benchmark output
reports the exact drop and retransmit counts and marks such a run degraded.

Compare two exported sessions without rerunning traffic:

```sh
bash /Users/antongrizli/Documents/MikroTik/tayga-clat-perf/tools/lima-perf/compare-session.sh \
  /path/to/baseline-session /path/to/candidate-session
```

The comparison writes JSON and Markdown with medians, ranges, percentage
changes, workload mismatches, and invalid-result warnings. A zero-drop run is
required for strict acceptance; a stress run with drops is reported as
degraded.

The guest installs `linux-perf`, builds with debug symbols and frame pointers,
and captures `perf report` and `perf script` after recording. If the guest was
created manually in UTM, run `run-guest.sh` inside the mounted repository after
installing the same dependencies.
