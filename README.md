# TAYGA

TAYGA is an out-of-kernel stateless NAT64 implementation for Linux and FreeBSD.  It uses the TUN driver to exchange packets with the kernel, which is the same driver used by OpenVPN and QEMU/KVM.  TAYGA needs no kernel patches or out-of-tree modules on either Linux or FreeBSD.

TAYGA was originally developed by Nathan Lutchansky [(litech.org)](http://www.litech.org/tayga/) through version `0.9.2`. Following the last release in 2011, TAYGA was mainatined by several Linux distributions independently, including patches from the Debian project, and FreeBSD. These patches have been collected and merged together, and is now maintained from [@apalrd](https://github.com/apalrd) and from contributors here on Github.

If you are interested in the mechanics of NAT64 and Stateless IP / ICMP Translation, see the [overview on the docs page](docs/README.md).

## Installation & Basic Configuration

Pre-built statically linked binaries are available from [Releases](https://github.com/apalrd/tayga/releases) for `amd64` and `arm64` architectures. Container images are also available.

## Compiling

`tayga` requires GNU `make` to build. If you would like to run the test suite, see [Test Documentation](test/index.md) for additional dependencies.

```sh
git clone git@github.com:apalrd/tayga.git
cd tayga
make
```

This will build the `tayga` executable in the current directory.

Next, if you would like dynamic maps to be persistent between `tayga` restarts, create a directory to store the dynamic.map file:

```sh
mkdir -p /var/db/tayga
```

Now create your site-specific `tayga.conf` configuration file.  The installed `tayga.conf.example` file can be copied to `tayga.conf` and modified to suit your site. Additionally, many example configurations are available in the [docs](docs/README.md))

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

If you are having difficulty configuring `tayga`, use the `-d` option to run the
`tayga` process in the foreground and send all log messages to stdout:

```sh
tayga -d
```

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

The example aims for approximately 300 Mbit/s because `RATE` is applied to
each of 20 one-flow clients. `WARMUP` is a separate unmeasured run; the actual
run has no iperf `-O`, so its traffic, CPU and counter windows coincide.
Always use measured `received_mbps`, not the requested rate. `DIRECTIONS` also
accepts `bidir`; `PROTOCOL=udp` and `DATAGRAM_SIZE=1200` select UDP, while
`BLOCK_SIZE` supplies iperf3 `-l` for a packet-size experiment.

Every run saves a monotonic window, per-thread state, TUN/router link counter
deltas, softirq/softnet snapshots, JSON/stderr and process CPU. TCP reports
retransmits; UDP reports loss, jitter, packet count and out-of-order packets.
By default `MAX_TUN_DROPS=0` and `MAX_UDP_LOSS_PERCENT=0`: a run crossing either
limit is retained as an artifact but exits non-zero and is not valid for A/B.
Results are written under `ARTIFACT_DIR` (default `/tmp/tayga-clat-results`).

Для сравнения worker и размера UDP-пакета используйте matrix runner:

```sh
docker run --privileged --device /dev/net/tun --rm \
  --entrypoint /usr/local/sbin/benchmark-matrix.sh \
  -e CLIENTS=10 -e RATE=10M -e DURATION=10 -e WARMUP=2 \
  -e PAYLOADS='64 256 512 1200' -e WORKERS_LIST='0 1 2 3' \
  -e MATRIX_DIR=/tmp/tayga-clat-matrix \
  tayga-clat:bench
```

`summary.tsv` содержит статус каждого сочетания и его числовые результаты.
При drops или UDP loss runner возвращает ненулевой код, но сохраняет JSON,
stderr и счётчики для анализа.

Set `PERF_MODE=stat` or `PERF_MODE=record` only in a Linux environment where
the `perf` command and PMU/tracepoint permissions are available. The harness
records process-relative perf data after the warm-up window; warm-up artifacts
are kept below `warmup-<direction>/` and measured artifacts below
`<direction>/`. Docker Desktop on
macOS may not expose perf; it writes a `perf-unavailable.txt` artifact instead.