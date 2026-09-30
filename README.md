# TAYGA

TAYGA is an out-of-kernel stateless NAT64 implementation for Linux and FreeBSD.  It uses the TUN driver to exchange packets with the kernel, which is the same driver used by OpenVPN and QEMU/KVM.  TAYGA needs no kernel patches or out-of-tree modules on either Linux or FreeBSD.

TAYGA was originally developed by Nathan Lutchansky [(litech.org)](http://www.litech.org/tayga/) through version `0.9.2`. Following the last release in 2011, TAYGA was maintained by several Linux distributions independently, including patches from the Debian project, and FreeBSD. These patches have been collected and merged together, and is now maintained from [@apalrd](https://github.com/apalrd) and from contributors here on Github.

If you are interested in the mechanics of NAT64 and Stateless IP / ICMP Translation, see the [overview on the docs page](docs/README.md).

## Installation & Basic Configuration

Pre-built statically linked binaries are available from [Releases](https://github.com/antongrizli/tayga/releases) for `amd64` and `arm64` architectures. Container images are also available.

## Compiling

`tayga` requires GNU `make` to build. If you would like to run the test suite, see [Test Documentation](test/index.md) for additional dependencies.

```sh
git clone https://github.com/antongrizli/tayga.git
cd tayga
make
```

This will build the `tayga` executable in the current directory.

Next, if you would like dynamic maps to be persistent between `tayga` restarts, create a directory to store the dynamic.map file:

```sh
mkdir -p /var/db/tayga
```

Now create your site-specific `tayga.conf` configuration file.  The installed `tayga.conf.example` file can be copied to `tayga.conf` and modified to suit your site. Additionally, many example configurations are available in the [docs](docs/README.md).

Before starting the `tayga` daemon, the routing setup on your system will need to be changed to send IPv4 and IPv6 packets to `tayga`.  First create the TUN network interface:

```sh
tayga --mktun
```

If `tayga` prints any errors, you will need to fix your config file before continuing. Otherwise, the new interface (`nat64` in this example) can be configured and the proper routes can be added to your system.

Firewalling your NAT64 prefix from outside access is highly recommended:

```sh
ip6tables -A FORWARD -s 2001:db8:1::/48 -d 2001:db8:1:ffff::/96 -j ACCEPT
ip6tables -A FORWARD -d 2001:db8:1:ffff::/96 -j DROP
```

At this point, you may start the `tayga` process:

```sh
tayga
```

Check your system log (`/var/log/syslog` or `/var/log/messages`) for status
information.

```sh
tayga -d
```

## Hardware Offload & Performance (GSO / GRO)

On Linux, TAYGA uses TUN virtio headers for TCP/UDP segmentation and checksum offload. The default `auto` checks capabilities during initialization and selects UDP plus TCP when supported, falling back to TCP and then ordinary packets. Explicit `tcp` and `udp` require their complete feature set. Capability negotiation does not guarantee aggregation or loss-free throughput; ordinary UDP and packet-level software fallback remain supported.

```conf
# In tayga.conf:
# off  - Standard packet-by-packet operation (explicit baseline)
# tcp  - Require TCP GSO/checksum offload support
# udp  - Experimental: require TCP and UDP segmentation/checksum support
# auto - Default; negotiate UDP + TCP, then TCP, then off during initialization
tun-offload auto
```

Or via command-line flags:
```sh
# Start with auto-detected offloads
tayga --tun-offload auto

# Explicit lab-only UDP segmentation experiment
tayga --tun-offload udp

# Test host kernel & TUN offload capabilities before launch
tayga --check-offload
```

For container and script deployments:
```sh
export CLAT_OFFLOAD=auto
```

See the [**GSO & GRO Tuning Guide**](docs/GSO-GRO-TUNING.md) for configuration and the [**2026-09-29 session investigation**](docs/PERFORMANCE-SESSION-INVESTIGATION-2026-09-29.md) for current synthetic Linux measurements and their limits.

## CLAT performance harness

`benchmark-clat.sh` creates a LAN → NAT44 → CLAT → IPv6-server laboratory.
It starts distinct IPv4 source addresses and iperf3 ports for every simulated
client, saves the exact TAYGA PID and retains the JSON/log/counter artefacts.

Build the profiling image from the parent workspace, then run it with Linux
network namespace and TUN privileges:

```sh
docker build -t tayga-clat:bench -f tayga-clat-perf/Dockerfile.benchmark \
  --build-arg TAYGA_SOURCE=tayga-clat-perf .
docker run --privileged --device /dev/net/tun --rm \
  --entrypoint /usr/local/sbin/benchmark-clat.sh \
  -e CLIENTS=20 -e FLOWS=1 -e WORKERS=3 -e RATE=15M \
  -e DURATION=60 -e WARMUP=10 -e DIRECTIONS='upload download' \
  tayga-clat:bench
```

The example's `RATE` is applied to each client; it is a sample workload, not a
capacity limit. Use the adaptive UDP capacity search to increase offered load
until a boundary is bracketed and then probe for a delivered-throughput
plateau. There is no fixed 300 Mbit/s ceiling. `WARMUP` is a separate run.
Always use measured `received_mbps`, not the requested rate. `DIRECTIONS` also
accepts `bidir`; `PROTOCOL=udp` and `DATAGRAM_SIZE=1200` select UDP, while
`BLOCK_SIZE` supplies iperf3 `-l` for a packet-size experiment.

Every run saves a monotonic window, per-thread state, TUN/router link counter
deltas, softirq/softnet snapshots, JSON/stderr and process CPU. TCP reports
retransmits; UDP reports loss, jitter, packet count and out-of-order packets.
By default `MAX_TUN_DROPS=0` and `MAX_UDP_LOSS_PERCENT=0`: a run crossing either
limit is retained as an artifact and fails acceptance. Workload validity and
capture validity are reported separately. Schema 3 fixes UDP accounting:
receiver sequence counts include losses, while actual datagram receipts come
from received bytes and the configured datagram size. Legacy UDP loss metrics
must be reprocessed from raw reports before comparison.
Results are written under `ARTIFACT_DIR` (default `/tmp/tayga-clat-results`).

To measure a sustainable UDP rate and probe maximum delivered throughput in
both directions without a fixed rate ceiling, use the adaptive search:

```sh
sudo tools/run-udp-matrix.sh
```

The runner starts at `INITIAL_TOTAL_RATE_MBIT`, increases offered load, refines
the acceptance boundary, and retains invalid or overload runs. `MAX_SEARCH_RUNS`
and `MAX_OVERLOAD_RUNS` bound experiment time; reaching those limits is reported
as an unresolved bound, not a maximum. Use `MAX_TOTAL_RATE_MBIT` only when an
explicit operational cap is desired.

For an explicit lab experiment with ordinary UDP forwarding aggregation, set
`FORWARDING_GRO=on` and `CLAT_OFFLOAD=udp`. The harness changes and records features
only on disposable namespace interfaces. Check nonzero UDP aggregate counters;
accepted ethtool settings alone do not prove aggregation or a throughput gain.
The default is `FORWARDING_GRO=off` and `CLAT_OFFLOAD=auto`.

For real Linux TUN packet validation against a selected executable:

```sh
sudo python3 test/test_udp_gso_kernel.py --binary ./tayga --output /tmp/tayga-udp-kernel-results
```

This saves independent post-segmentation captures and checks both directions,
worker modes, MTUs, payloads, checksums, tails and IPv4 IDs. It does not measure
throughput; broader malformed-input and PMTU tests remain necessary.

To compare worker counts and UDP payload sizes, set `SIZES` and other workload
variables on that runner:

```sh
docker run --privileged --device /dev/net/tun --rm \
  --entrypoint /usr/local/sbin/benchmark-matrix.sh \
  -e CLIENTS=10 -e RATE=10M -e DURATION=10 -e WARMUP=2 \
  -e PAYLOADS='64 256 512 1200' -e WORKERS_LIST='0 1 2 3' \
  -e MATRIX_DIR=/tmp/tayga-clat-matrix \
  tayga-clat:bench
```

`summary.tsv` contains the status and numeric results for each combination.
On drops or UDP loss, the runner returns a non-zero exit code while preserving the JSON,
stderr, and counter artifacts for analysis.

Set `PERF_MODE=stat` or `PERF_MODE=record` only in a Linux environment where
the `perf` command and PMU/tracepoint permissions are available. The harness
records process-relative perf data after the warm-up window; warm-up artifacts
are kept below `warmup-<direction>/` and measured artifacts below
`<direction>/`. Docker Desktop on
macOS may not expose perf; it writes a `perf-unavailable.txt` artifact instead.
