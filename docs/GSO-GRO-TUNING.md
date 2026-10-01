# TAYGA CLAT Hardware Offloads: GSO & GRO Tuning Guide

This document describes the high-performance GSO (Generic Segmentation Offload) and GRO (Generic Receive Offload) architecture implemented in TAYGA, configuration options, initialization capability detection, and tuning guidelines.

---

## 1. Overview and Architecture

Without aggregation, TAYGA handles each packet through userspace and the TUN/kernel path. The resulting CPU and syscall cost depends on packet size, traffic direction, kernel, and workload; do not treat one fixed-rate result as a general capacity limit.

With **GSO/GRO Offload**, TAYGA interacts with the Linux kernel TUN driver using VirtIO network headers (`IFF_VNET_HDR`):
- **GSO (Transmit / Forwarding)**: The kernel delivers aggregated TCP super-packets (up to 64 KB) to TAYGA in a single `read()`. TAYGA translates the headers in-place (updating TCP/IP pseudo-checksum seeds) and forwards them back into the TUN device via a single vectored `writev()` system call with `VIRTIO_NET_HDR_GSO_TCPV4` or `VIRTIO_NET_HDR_GSO_TCPV6`.
- **GRO (Receive-Side)**: When enabled on ingress interfaces (`ethtool -K <iface> gro on`), the kernel coalesces incoming TCP packets of the same flow before delivering them to TUN.
- **RFC 7915 packet policy**: Experimental UDP USO reserves consecutive IPv4 IDs for aggregates whose output packets all have DF=0. Linux completes their checksums and increments IDs during segmentation. Aggregates crossing the 1,260-byte IPv4 length boundary use software segmentation because their packets require different DF policies. This path has been checked on Debian Linux 6.12 ARM64; validation on other target kernels remains required.

TCP and UDP results are workload-specific. The current TCP measurements used aggregates averaging tens of kilobytes and reached high synthetic Lima throughput. UDP USO was disabled in those measurements, and UDP losses occurred at higher offered rates. See the [session investigation](PERFORMANCE-SESSION-INVESTIGATION-2026-09-29.md) for measured directions, rates, drops, perf scope, and limitations. No hardware capacity claim follows from those VM results.

---

## 2. Configuration Options

### 2.1. `tayga.conf` Directives

```conf
# tun-offload: Controls hardware/kernel offload support
# Options:
#   off  - Standard packet-by-packet operation (explicit legacy baseline)
#   tcp  - Enforce TCP GSO/CSUM offloads (requires IFF_VNET_HDR support)
#   udp  - Experimental TCP/UDP segmentation and checksum offload; requires kernel validation
#   auto - Default; negotiate UDP + TCP, then TCP, then off at initialization
tun-offload auto
```

### 2.2. Command-Line Arguments

```sh
# Start with explicit offload mode
tayga --tun-offload auto -c /etc/tayga.conf

# Check kernel and TUN driver offload capabilities without starting daemon
tayga --check-offload
```

When the configuration file contains `tun-offload`, that directive takes precedence over the CLI mode. Set the directive in the configuration file for an explicit rollback.

### 2.3. Environment Variables (Container & CLAT startup scripts)

```sh
# Set CLAT_OFFLOAD environment variable before starting clat-start.sh:
export CLAT_OFFLOAD=auto   # Recommended for automatic safe offload
# export CLAT_OFFLOAD=tcp  # Enforce offload
# export CLAT_OFFLOAD=udp  # Experimental UDP segmentation test only
# export CLAT_OFFLOAD=off  # Explicitly disable offload
```

---

## 3. Preflight Self-Test and Runtime Detection

### 3.1. Standalone Preflight Check

You can verify whether the host kernel and `/dev/net/tun` support full offload before deploying TAYGA:

```sh
tayga --check-offload
```

Output on supported systems:
```text
OFFLOAD_CHECK: OK (IFF_VNET_HDR supported, vnet_hdr_sz=10, TSO4|TSO6|CSUM available)
```

Output on unsupported systems:
```text
OFFLOAD_CHECK: FAIL (IFF_VNET_HDR ioctl failed: Invalid argument)
```

### 3.2. Automatic Initialization Fallback (`tun-offload auto`)

When configured with `tun-offload auto`, TAYGA checks virtual header framing and
attaches its worker queues before starting packet processing. It requests
`CSUM | TSO4 | TSO6 | USO4 | USO6`; if unavailable, it retries `CSUM | TSO4 | TSO6`,
then verified offload disabled. A worker failure restarts the candidate across
all descriptors. Invalid framing or inability to establish the disabled state
fails startup. Requested policy and effective capabilities appear separately in
telemetry. Explicit `tcp` and `udp` remain strict operational overrides.

Initialization establishes kernel capability, while packet-level fallback
handles valid aggregates outside the fast path. Forwarding GRO must be available
on the ingress path to aggregate ordinary UDP senders; TAYGA does not modify
physical NIC settings. The owned TUN is held down during negotiation and its
previous UP state is restored. Only one TAYGA may own a device in a network
namespace. Other programs must not share that interface.

---

## 4. MikroTik RouterOS / Container Recommendations

When running TAYGA in a Container on MikroTik RouterOS (e.g. CCR2004, CCR2116, RB5009, CHR):

1. **Recommended Setting**: Use `CLAT_OFFLOAD=auto` (or `tun-offload auto` in `tayga.conf`).
2. **Container Privileges**: Ensure the RouterOS container has access to `/dev/net/tun` (`tun` device permitted).
3. **Ingress Interface GRO**: Inside the container environment, ensure GRO is enabled on the virtual ethernet interface:
   ```sh
   ethtool -K eth0 gro on 2>/dev/null || true
   ```
4. **Verification**: Check container logs on startup:
   - `TUN offload active: vnet_hdr_sz=10, TSO4|TSO6|CSUM` indicates offloads are engaged.
   - `Unable to attach tun with IFF_VNET_HDR (...), falling back to offload=off` indicates safe fallback.

---

## 5. Verification Test Suite

The repository provides automated validation scripts in the `test/` directory:

| Test Script | Scope |
|---|---|
| `test/test_auto_negotiation.py` | Default UDP selection, fallback failures and capability telemetry |
| `test/test_auto_persistent.py` | Persistent addresses/routes, restart, exclusive ownership and removal |
| [`test/test_correctness.py`](file:///Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/test_correctness.py) | ICMP ping, 20 MB TCP upload/download SHA-256 integrity, UDP datagrams |
| [`test/test_pmtud.py`](file:///Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/test_pmtud.py) | End-to-end PMTUD & ICMPv6 Packet Too Big (1280 → 1260) translation |
| [`test/test_preflight.py`](file:///Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/test_preflight.py) | CLI `--check-offload`, mode startups (`auto`, `tcp`, `off`), and data path |

Run the complete test suite:
```sh
sudo python3 test/test_correctness.py
sudo python3 test/test_pmtud.py
sudo python3 test/test_preflight.py
```

## 6. Bounded UDP sender buffering in the benchmark

On the tested Linux 6.12.107 veth path, a queued sender can retain packets
while the peer receive ring is temporarily full. The benchmark exposes this
treatment independently of socket rate limiting:

```sh
SENDER_FQ=on SENDER_FQ_LIMIT=4096 SENDER_FQ_FLOW_LIMIT=1024 \
VETH_QUEUES=4 SENDER_FQ_TOPOLOGY=auto FQ_RATE=0 \
PROTOCOL=udp RATE=0 DIRECTIONS="upload download" \
tools/lima-perf/run-host.sh
```

`RATE=0` leaves offered load unrestricted. `FQ_RATE=0` adds no socket pacing
rate cap. Offload defaults to `auto`, which now negotiates UDP USO when supported. Explicit
`CLAT_OFFLOAD=udp` requires full support. Other socket, TUN and application pacing controls
remain explicit treatments.

`SENDER_FQ_TOPOLOGY=auto` uses one fq scheduler for one active TX channel and
an `mq` root with a separate fq scheduler per TX channel otherwise. `single`
and `mq` select a topology explicitly. `SENDER_FQ_LIMIT` is the total packet
budget per sender interface: multiqueue partitions it across the leaf
schedulers without multiplying the budget. Each leaf's effective flow limit
is the smaller of its packet budget and `SENDER_FQ_FLOW_LIMIT`. Actual qdisc
settings, counters and channel settings are saved with each session.

`VETH_QUEUES=0` preserves existing channel counts. A positive value configures
both ends of all disposable benchmark pairs and fails setup if unsupported.
The control changes queue capacity, not a guarantee of balanced flow mapping.
Per-leaf packet counters expose the resulting distribution.

Optional `TAYGA_CPUSET`, `CLIENT_CPUSET` and `SERVER_CPUSET` accept `all` (the
default) or CPU lists such as `2,3`. They constrain child processes only and
are recorded as distinct treatments. They do not isolate CPUs from unrelated
guest tasks. Unsupported CPU lists fail before topology setup.

Interface drops/errors now affect UDP acceptance independently of qdisc and
socket counters. TUN transmit drops continue to use `MAX_TUN_DROPS`. Parent
and leaf qdisc counts can overlap and must not be added together. Queues are
removed with the disposable namespaces; production interfaces are unaffected.

This treatment does not guarantee lossless overload or resolve all TUN
pressure. See [the buffer investigation](UDP-BUFFER-PRESSURE-INVESTIGATION-0.9.12.md)
for the evidence and validation criteria.

### Benchmark-only UDP draining and accounting

The runners build `make udp-drain-tools` and install a native iperf3 drain guard. UDP sending stops at the active-window boundary while TCP control and receiver threads remain live, including when `RECEIVER_DRAIN_SECONDS=0`. Positive drain settings add an explicit receiver drain period. The stop flag remains set through normal endpoint termination. No process pause/resume or fake successful writes are used. iperf3 3.18 is the tested writer; other generators or write APIs require separate validation. Direct harness users must install `tools/udp-drain-guard.so` at `/usr/local/lib/tayga-perf/udp-drain-guard.so` and `tools/udp-drain-control` at `/usr/local/libexec/tayga-perf/udp-drain-control`, even when drain seconds is zero. Zero now selects no added drain period; it does not disable the common sender stop. Historical zero-drain captures without the stop guard are a different workload, distinguished by `receiver_drain_method` and the guard hash.

Schema 6 records drain method/hash and guard counters. UDP accounting v3 derives sent and received datagram counts from their successful byte totals and retains the raw sender sequence count separately. iperf can sample its incremented sequence during a pending soft-error write, so the sequence count alone may include an unsent attempt. Sequence gaps, reordering, and estimated duplicates remain separate diagnostics; byte totals do not prove exact unique delivery when duplicates are possible. Original iperf throughput averages over its extended timer; `received_active_window_mbps` uses the recorded active traffic window. A drain fixes end-of-test accounting, not loss from sustained overload.
