[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/antongrizli/badge.svg)](https://hub.xerj.org/contributors/antongrizli)

# TAYGA

TAYGA is an out-of-kernel stateless NAT64 implementation for Linux and FreeBSD.  It uses the TUN driver to exchange packets with the kernel, which is the same driver used by OpenVPN and QEMU/KVM.  TAYGA needs no kernel patches or out-of-tree modules on either Linux or FreeBSD.

TAYGA was originally developed by Nathan Lutchansky [(litech.org)](http://www.litech.org/tayga/) through version `0.9.2`. Following the last release in 2011, TAYGA was maintained by several Linux distributions independently, including patches from the Debian project, and FreeBSD. These patches have been collected and merged together, and is now maintained from [@apalrd](https://github.com/apalrd) and from contributors here on Github.

If you are interested in the mechanics of NAT64 and Stateless IP / ICMP Translation, see the [overview on the docs page](docs/README.md).

## Installation & Basic Configuration

Pre-built statically linked binaries are available from [Releases](https://github.com/antongrizli/tayga/releases) for `amd64` and `arm64` architectures. Container images are also available.

## Compiling

`tayga` requires GNU `make` to build. If you would like to run the test suite, see [Test Documentation](test/README.md) for additional dependencies.

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

See the [**GSO & GRO Tuning Guide**](docs/performance/gso-gro-tuning.md) for configuration. Hardware capacity must be established with a reproducible measurement on the target system.

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
sudo python3 test/system/test_udp_gso_kernel.py --binary ./tayga --output /tmp/tayga-udp-kernel-results
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

### DNS64 and DNSSEC

In NAT64 mode, the bundled DNS64 resolver validates DNSSEC by default using the root trust anchor installed in the container. Set `DNS64_DNSSEC=off` to disable validation when needed, or `DNS64_TRUST_ANCHOR_FILE` to use a different readable Unbound trust anchor file. The packaged root anchor is maintained through image updates; keep the container image current for root key rollovers. DNS64 synthesis can produce unsigned answers, so a validating client may require its own DNS64 strategy. The resolver advertises a 1232-byte EDNS UDP limit and supports TCP.

### Self-extracting installer

Release assembly builds installers for Linux amd64/arm64/armv7 and FreeBSD
amd64/arm64, plus `tayga-installer-universal.sh` with all five platforms.
FreeBSD binaries are built and smoke-tested natively by CI before assembly.
Check the release's `SHA256SUMS` before running an installer.

```sh
# Interactive wizard (reads /dev/tty, also when the script is piped to sh).
sudo sh tayga-installer-universal.sh

# Unattended Linux NAT64 installation and service activation.
sudo sh tayga-installer-universal.sh --mode=nat64 --yes

# CLAT requires your routed IPv6 addresses and a working upstream NAT64.
sudo sh tayga-installer-universal.sh --mode=clat --yes --pref64=auto \
  --clat-ipv6=2001:db8:1::464 --tayga-ipv6=2001:db8:1::2

# Review a configuration or extract the payload without root/network changes.
sh tayga-installer-universal.sh --mode=nat64 --configure-only=nat64.conf
sh tayga-installer-universal.sh --extract-only /tmp/tayga-payload
sudo sh tayga-installer-universal.sh --mode=binary-only
```

Replace documentation addresses with addresses assigned and routed to your host.
CLAT discovery uses the embedded RFC 7050 helper; `--dns64-server=ADDRESS`
selects a resolver. Discovery failure requires an explicit `--pref64`; the DNS
server address is never guessed to be a translation prefix. The wizard uses
route information and an IPv4 HTTP probe to suggest CLAT or NAT64.

Configuration accepts `--pref64`, `--pool4`, `--mtu`, `--workers`, `--offload`,
`--tayga-ipv4`, `--tayga-ipv6`, `--tun-ipv6`, `--clat-ipv6` and `--firewall` as
`--name=value`. `--workers=auto` leaves CPU-count selection to the daemon.
For NAT64, the host TUN source (`--tun-ipv6`, default `fd64::1`) must differ
from the daemon identity (`--tayga-ipv6`, default `fd64::2`). SIIT can be activated with `--mode=siit --yes --map-ipv4=... --map-ipv6=...`,
or generated without activation with `--configure-only=siit.conf`. The mapped
IPv4 address/range must be routed to this gateway, and the mapped IPv6 endpoint
must be reachable over its native network. SIIT installs translation routes
and bidirectional forwarding rules without NAT44. SIIT readiness checks TUN
and routes; a peer traffic test is required to establish end-to-end connectivity.
FreeBSD profile generation uses `tun64`, disables Linux TUN offload, and selects `pf` in profile metadata. Automatic FreeBSD networking and firewall activation are not implemented yet.

Managed CLAT/NAT64/SIIT activation supports **Linux systemd and OpenRC**. It requires
`iproute2`, `sysctl`, `curl`, `setsid`, `flock`, `timeout`, and either `iptables`/`ip6tables` or `nft`.
Use `--firewall=nft` for native nftables; `auto` prefers iptables when both
iptables tools are installed and otherwise selects nftables. The controller owns
separate `TAYGA_SFX_*` iptables chains or `tayga_sfx_*` nftables tables, NAT44
rules, TCP MSS clamping, routes
and runtime sysctl changes. It preserves IPv6 router advertisements before
forwarding, and protects private/metadata/IAP/SSH IPv4 access routes for CLAT.
CLAT currently requires an existing IPv4 gateway for those access routes.
Only one managed profile can be active per host. Independent nftables/firewalld
policies may still block traffic and require administrator review.

A required TCP/HTTP readiness probe runs after startup. Failure stops the daemon,
cleans up owned network changes, restores prior files/configuration and restarts
the previous managed profile when it was running. NAT64 probes traverse the
translation prefix rather than native IPv4. Readiness currently requires a
canonical /96 prefix ending in `::` and HTTP access to 1.1.1.1. An independent
activation watchdog arms before service/network changes, with a default deadline
of 120 seconds (`--watchdog-seconds=30..600` or `TAYGA_WATCHDOG_SECONDS`).
It survives installer SIGKILL, cancels hung commands in the activation session,
and restores owned networking, prior files/configuration and the previous
service state. A successful commit cancels rollback atomically. This is an
activation deadline, not a continuous service monitor.

```sh
sudo tayga-ctl status       # defaults to the recorded current profile
sudo tayga-ctl test
sudo tayga-ctl reconfigure  # interactive, supports switching clat/nat64
sudo tayga-ctl uninstall    # removes this managed profile; last profile removes owned files
sudo tayga-ctl recover      # retries an interrupted armed activation from retained backups
# Equivalent SFX operations: --diagnose, --reconfigure, --uninstall.
```

Reconfiguration refuses configurations edited outside the installer. Uninstall
preserves modified files and persistent mapping data. Unchanged installer-owned
files are removed; pre-existing binaries/manuals/helpers are restored from the
installation backup. Binary-only installations can be removed with
`tayga-ctl uninstall binary-only`.

For a local build on a supported host, `make installer` writes
`build/tayga-installer.sh`. Use a static toolchain for standalone binaries.
`test/system/installer-network-smoke.sh` runs only in a disposable container:
it checks NAT64 and CLAT-to-NAT64 HTTP/ICMP, readiness failure and firewall
cleanup against a binary compiled from the current sources. Portable tests cover
wizard input, file ownership, profile switching and rollback with fake init tools.

FreeBSD network/rc.d activation, firewalld/pf integration, broader DNS manager
support and automatic routed IPv6 allocation remain under development. FreeBSD installers currently support binary installation,
extraction and configuration generation.

Optional DNS services are selected explicitly:

```sh
sudo sh tayga-installer-universal.sh --mode=nat64 --yes --dns64=yes \
  --dns64-listen=2001:db8:1::53 --dns64-allow=2001:db8:2::/64
# CLAT public DNS through an existing systemd-resolved stub:
sudo sh tayga-installer-universal.sh --mode=clat --yes --pref64=auto \
  --clat-ipv6=2001:db8:1::464 --tayga-ipv6=2001:db8:1::2 --host-dns=public
```

DNS64 requires the distribution's `unbound` tools/service account and a DNSSEC
root trust anchor (usually `dnssec-root` or the Unbound package). It runs a
separate process owned by the TAYGA profile, with an isolated runtime config;
the system Unbound configuration is preserved. Defaults are a loopback listener,
loopback client ACL, upstream 1.1.1.1 and DNSSEC validation. Use
`--dns64-upstream=ADDRESS` (optional `@PORT`) and `--dns64-dnssec=validate|off`
to configure it. The service runs RFC 7050 readiness checks before accepting
startup. Serving remote clients also requires the host's INPUT firewall to allow
DNS to the selected listener; TAYGA forwarding rules do not open an INPUT port.

`--host-dns=public` changes only the newly created CLAT resolver link, selects
1.1.1.1/8.8.8.8, and reverts that link on stop or error. Applications must
already use the systemd-resolved stub (first nameserver 127.0.0.53). Other
resolver managers and direct `/etc/resolv.conf` rewriting are not implemented;
`--host-dns=keep` is the default. The owned-link resolver operations are covered
by portable fault-injection tests and a real systemd-resolved VM test.

The DNS64 container smoke test uses a deterministic unsigned upstream and
explicit DNSSEC=off for that fixture. It verifies RFC 7050 prefix discovery,
DNS-resolved IPv6 HTTP through NAT64, a byte-for-byte 1 MiB transfer and listener
cleanup. A validating production configuration is also checked with
`unbound-checkconf`. A separate Debian 13 VM test verifies systemd-resolved
link assignment and cleanup, RFC 7050 synthesis, live DNSSEC validation of a
signed answer, and rejection of a bogus signature. The managed Unbound config
uses an owned directory under `/etc/unbound`, which is readable under Debian's
AppArmor profile; the installer refuses an existing unmanaged directory.

Watchdog recovery uses persistent transaction snapshots under
`/var/lib/tayga-installer/operation.lock/`, an atomic commit/rollback decision
and a kernel file lock to serialize recovery. Diagnostics are appended to
`/var/lib/tayga-installer/watchdog.log`. `tayga-ctl recover` or the SFX's
`--recover` retries a retained armed transaction in the current boot/namespace.
An early `tayga-recovery` service is registered before profile changes. After a
reboot it restores an uncommitted activation's persistent configuration and
previous service enablement before managed profiles start; it never signals old
PIDs or replays old route/sysctl/DNS journals. A committed profile is preserved;
only its transaction backups are retired.
Recovery checks the saved machine ID (or a persistent installation identity on
systems without `/etc/machine-id`). Current-boot PID/network namespace mismatches
remain refused. Snapshots and committed changes are synced before proceeding.
The deadline protects activation after arming; interruption of the earlier
binary-copy/recovery-registration phase can still require manual review.

`test/system/installer-boot-smoke.sh` provides `install`, `check`, `arm`,
`check-recovery` and `uninstall` phases for a **dedicated disposable VM** with
`TAYGA_ISOLATED_TEST=yes`. Reboot between install/check; force power off between
arm/check-recovery. The test uses native init, real TUN/routes/firewall and a
local IPv6 uplink fixture. After uninstall, `arm-first` /
`check-first-recovery` checks rollback of a staged first installation across a
second power cut. It checks boot enablement and rollback to SIIT after
an interrupted NAT64 activation, with poison hooks detecting old-kernel cleanup.
The fixture checks SIIT routes; mapped-peer end-to-end traffic has separate
container coverage. Native install, reboot, interrupted switch, uninstall and
interrupted first-install phases passed on Debian 13/systemd and Alpine
3.23/OpenRC arm64 VMs on 2026-10-29. VM boot tests are run separately from the
container CI gates.

The disposable watchdog kernel test kills the installer while CLAT split routes
are active and verifies restoration of the original IPv4/IPv6 route tables,
TUN removal and firewall cleanup on both iptables and nftables. Portable fault
injection also covers hung starts, orphan child groups, SIGKILL of the runner,
restoration of staged binaries, cancellation after commit and stale guard IDs.

Explicit alternative CLAT DNS policies are `--host-dns=public-resolvconf`
(own `clat.tayga` record) and `--host-dns=public-file` (regular files only).
The latter retains a persistent original/expected snapshot, restores it on stop,
and refuses to overwrite administrator edits during recovery. Symlinked resolver
files must use their resolver manager. These alternatives have portable fault
coverage and native Debian/openresolv tests (`installer-host-dns-smoke.sh`),
including application DNS queries, preservation of unrelated records and
recovery after runtime-marker loss. NetworkManager policy is described below.

`--host-dns=public-nm` uses NetworkManager's temporary device DNS settings on
an already active, managed CLAT link. It requires `nmcli` and `busctl`, retains
a checkpoint scoped to that link, and rolls back on stop or assignment failure.
The checkpoint is tied to the daemon's unique D-Bus owner, so a restarted daemon
cannot receive an old rollback request. Saved connection profiles are not edited.
`test/system/installer-nm-dns-smoke.sh` checks real TUN DNS assignment, restoration
and unchanged IPv4 routes in a dedicated Debian VM. This test checks resolver
configuration; translated DNS traffic has separate network smoke coverage.

Linux CLAT supports explicit IPv6 delivery policies:

- `--clat-address-mode=routed` preserves the existing routed-address behavior.
- `--clat-address-mode=proxy-ndp` advertises the supplied CLAT and daemon IPv6
  addresses on the IPv6 uplink using owned proxy entries. This requires the
  upstream to permit those additional addresses; it does not allocate addresses
  from a provider's single `/128` assignment.
- `--clat-address-mode=nat66 --nat66-address=UPLINK_IPV6` translates the supplied
  ULA CLAT/daemon source addresses to an existing uplink IPv6 address. Only those
  two sources and the NAT64 destination prefix match the SNAT rules. The source
  must match the spelling displayed by `ip -6 addr show` on the uplink.

The additional policies currently require Linux with iptables or nftables;
FreeBSD/pf and firewalld reject them. All proxy entries, changed sysctls and
firewall objects have owned rollback entries. No uplink address is moved or
invented. `installer-network-smoke.sh` exercises routed, Proxy NDP and NAT66
CLAT through NAT64 with HTTP, ICMP and a byte-checked 1 MiB download; Proxy NDP
uses neighbor discovery without static host routes, and NAT66 uses ULA endpoints
behind an uplink `/128`.

When the bundle has no binary for this host, fallback is explicit:

```sh
sh tayga-installer.sh --mode=binary-only --yes --fallback=build
sh tayga-installer.sh --mode=binary-only --yes --fallback=download \
  --fallback-url=https://example.org/releases/VERSION \
  --fallback-tayga-sha256=TRUSTED_64_HEX_DIGEST \
  --fallback-helper-sha256=TRUSTED_64_HEX_DIGEST
```

All SFX bundles now embed the build sources inside the checked payload. Build
fallback requires a native `cc`, GNU make and static development libraries;
it builds locally without fetching a source archive or installing dependencies.
Download fallback fetches `tayga-OS-ARCH` and `pref64-discover-OS-ARCH`, requires
HTTPS (also for redirects), verifies both user-supplied SHA-256 digests before
execution, and checks the daemon version and helper behavior before file staging.
Obtain the hashes through a trusted release channel. The URL is explicit to
avoid silently following a mutable latest release.
Linux fallback platform identifiers additionally include armv6, riscv64,
ppc64le and s390x; this is not a promise of published or CI-certified binaries
for those CPUs. ARMv6 is never substituted with ARMv7. Native embedded-source
fallback, staging and uninstall passed on Linux arm64 and FreeBSD arm64;
download validation is covered by offline fault-injection tests.

Dependency installation is explicit and separate from native TAYGA packages:

```sh
sh tayga-installer.sh --mode=nat64 --firewall=nft --check-deps
sudo sh tayga-installer.sh --mode=nat64 --firewall=nft --install-deps --yes
```

`--check-deps` prints the selected package manager and missing package list,
returning 1 when dependencies are missing. It never installs packages.
`--install-deps` uses apk, apt-get or dnf/yum for the selected profile, firewall,
DNS policy and source-build fallback. It does not run a distribution upgrade;
package changes remain managed by the distribution if profile activation fails.
The shell/base64/tar/SHA-256 tools needed to open the SFX must already exist.
Binary-only mode requests no networking dependencies. On OpenWrt the dependency
planner detects apk/opkg separately and uses `coreutils-install` when needed;
network activation and source fallback remain refused. Use the SDK package below
for installation on OpenWrt. SFX file staging refuses
existing files owned by dpkg, RPM, APK, opkg or FreeBSD pkg; migration must use a
separate package-manager workflow. Native `.apk`/`.deb`/`.rpm` test artifacts and their guarded upgrade/removal
hooks are described below.


Native package builds use `scripts/build-native-packages.py` with nFPM 2.48.0.
Supply verified static Linux binaries (musl static inputs are used in the tests):

```sh
python3 scripts/build-native-packages.py --version 0.9.14 --release 1 \
  --arch arm64 --tayga build/tayga --helper build/pref64-discover \
  --maintainer 'YOUR NAME <YOUR EMAIL>' --output build/native-packages
```

The builder emits APK/DEB/RPM plus an input/artifact SHA-256 manifest. It validates
ELF architecture and rejects dynamic interpreters and FreeBSD ABI inputs. Packages
install binaries under `/usr/sbin` and helpers/templates under `/usr/libexec/tayga`;
installation never enables a TAYGA service or applies routes. Their sample config
is a package-manager conffile; runtime profile configs/data are not package payload.
Choose a real maintainer identity when preparing distributable packages.
These initial artifacts are **unsigned**; the local VM tests explicitly allow
unsigned APKs. Signing and release publication remain separate pending work.
The package CI job builds and tests arm64 artifacts; amd64/armv7 format metadata
is supported by the builder but has not yet had the same native package tests.

Generate a candidate with `/usr/libexec/tayga/configure.sh`, then explicitly use
`sudo tayga-ctl apply /path/to/candidate.conf`. Before package upgrade/removal,
save the configuration and run `tayga-ctl uninstall PROFILE` for each managed
profile. Configured-profile upgrades are deliberately refused; there is no live
package-upgrade rollback guarantee. On APK, the controller installs a virtual
`.tayga-managed-profile` dependency pinned to the exact installed version before
activation, and releases it after the last profile is removed or an activation
is rolled back. This uses the APK dependency solver because failed APK scripts
do not reliably prevent package replacement. Do not remove that virtual package
while profiles remain configured. `tayga-ctl recover` releases a stale pin when
there is no profile or pending activation. Profile data remains after removal;
DEB purge explicitly removes the packaged example configuration.

`installer-native-package-smoke.sh` tests install, blocked configured-profile
upgrade, successful upgrade, config/data retention and removal on Debian,
Alpine and Fedora. `installer-native-activation-smoke.sh` additionally passed
native `/usr` activation and readiness-failure rollback on systemd and OpenRC,
including the APK pin lifecycle. Existing SFX/manual installations must be removed
before native installation; SFX staging also refuses native package ownership.

OpenWrt packages use the separate `packaging/openwrt/Makefile` recipe through an
official, checksum-verified OpenWrt SDK. Generic nFPM APKs and SFX installation
are refused on OpenWrt. Extract a fresh SDK on a compatible Linux build host, then
stage the current source tree with explicit target identity:

```sh
# Initialize a fresh SDK with minimal userspace selection.
if [ ! -e /path/to/openwrt-sdk/.config ]; then
  printf '%s\n' '# CONFIG_ALL is not set' '# CONFIG_ALL_KMODS is not set' \
    '# CONFIG_ALL_NONSHARED is not set' > /path/to/openwrt-sdk/.config
fi
make -C /path/to/openwrt-sdk defconfig
python3 scripts/prepare-openwrt-package.py --sdk /path/to/openwrt-sdk \
  --target armsr --subtarget armv8 --architecture aarch64_generic \
  --version "$(cat VERSION)"
echo 'CONFIG_PACKAGE_tayga-managed-openwrt=m' >> /path/to/openwrt-sdk/.config
# Optional service package; omit for a tools-only package build.
echo 'CONFIG_PACKAGE_tayga-managed-openwrt-procd=m' >> /path/to/openwrt-sdk/.config
# Optional owned NAT64/SIIT networking:
echo 'CONFIG_PACKAGE_tayga-managed-openwrt-network=m' >> /path/to/openwrt-sdk/.config
make -C /path/to/openwrt-sdk defconfig
make -C /path/to/openwrt-sdk package/tayga-managed-openwrt/compile V=s -j2
```

The preparer checks all three identity fields and musl in the SDK `.config`,
refuses an existing staging directory, and records source/recipe/config SHA-256
digests in `package/tayga-managed-openwrt/source-manifest.json`. It copies only
source/build inputs, excluding local build outputs and repository metadata.
The SDK compiles for its own CPU/ABI/libc and chooses IPK/APK packaging according
to its OpenWrt branch; Alpine APKs are not interchangeable. Use a matching SDK
for each firmware release/target and check package architecture on the device.

This first OpenWrt package is **binary-only**: `/usr/sbin/tayga`,
`pref64-discover`, a preserved example config, license and ownership marker.
It declares TUN/pthread dependencies and conflicts with the distribution TAYGA
package. TUN is a runtime dependency; SDK compilation does not rebuild its
kernel-module package directory. It installs no init service and changes no UCI/network/firewall/DNS
configuration. The separate optional procd package is described below;
the general Linux managed-profile controller must not be used as an
OpenWrt service. `installer-openwrt-package-smoke.sh` checks installation,
binary execution, retained edits/data and removal in a disposable matching
rootfs without mounting host kernel filesystems or activating networking.
Pass matching dependency archives as additional arguments; the smoke performs
offline installation with dependency checking and does not fetch feeds.
The SDK CI job pins OpenWrt 24.10.8 armsr/armv8 and its rootfs by SHA-256;
full-system QEMU and the newer OpenWrt APK branch remain separate checks.
The 24.10.8 armsr/armv8 SDK IPK passed the offline rootfs smoke locally, including
both executable checks, unchanged network/firewall/DHCP configuration, retained
modified example config and profile data after removal. This is a file/package
test, not a booted OpenWrt networking certification.

`tayga-managed-openwrt-procd` adds `/etc/init.d/tayga-managed` and its own
`/etc/config/tayga_managed` UCI file. It depends on the matching base package,
procd, UCI and flock. UCI `enabled` defaults to `0`. Its current `external`
network mode requires an already configured TUN, routes and firewall; it
supervises one foreground TAYGA process with bounded respawn and graceful stop.
Optional netifd/WAN tracking and the separate managed NAT64/SIIT network package
are described below. The r5 network package also implements DNS integration and
post-start readiness rollback; verification status is recorded below.

After preparing external networking and reviewing `/etc/tayga/managed.conf`:

```sh
tayga --check-config --config /etc/tayga/managed.conf
uci set tayga_managed.main.config='/etc/tayga/managed.conf'
uci set tayga_managed.main.network_mode='external'
uci set tayga_managed.main.enabled='1'
uci commit tayga_managed
/etc/init.d/tayga-managed start
/etc/init.d/tayga-managed enable
```

The new `--check-config` validates configuration without root, TUN access,
runtime/data directory creation or worker startup. Service preparation requires
an existing TUN and copies the validated configuration into
`/etc/tayga-managed/active.conf`, rewriting `data-dir` to
`/etc/tayga-managed/data` on persistent overlay. Candidate files must be regular
files directly under `/etc/tayga`; external `map-file` inputs are refused so the
snapshot contains its complete mapping configuration. State publication uses
flock, sync and an atomic journal transition. An interrupted publication restores
the previous snapshot. Boot uses that accepted snapshot rather than replaying
edits to the candidate file. A rejected `reload` leaves the previous procd
definition intact. Stop/restart use procd process supervision; external network
configuration remains administrator-managed. Runtime PID/status files use tmpfs
`/var/run/tayga-managed`. Removing the optional package preserves edited UCI
configuration and the persistent state/data directory.

Portable tests cover disabled startup, the procd command/respawn contract,
rejected reloads, boot snapshot selection and interrupted file publication.
`installer-openwrt-service-state-smoke.sh` passed with real SDK packages and UCI
in a clean 24.10.8 rootfs, including unprivileged daemon validation and retained
state after removal. The chroot does not run a procd/ubus instance; real process
and boot coverage is provided by the separate VM test below.

`test/system/run-openwrt-vm.py` boots the pinned 24.10.8 armsr/armv8 squashfs
image with a real ext4 overlay and procd/ubus. It verifies disabled package
installation, start/stop/restart, idempotent start, failed/valid reload,
single-process ownership, SIGKILL respawn, accepted-snapshot boot, persistent
data and package removal. It also kills QEMU after preparing a durable pending
journal and interrupted active configuration, then checks recovery on a new
kernel boot. This tests that interruption point, not every possible storage
failure. LAN/firewall/DHCP configurations are compared before and after.

```sh
python3 test/system/run-openwrt-vm.py \
  --kernel /path/to/openwrt-24.10.8-armsr-armv8-generic-kernel.bin \
  --image /path/to/openwrt-24.10.8-armsr-armv8-generic-squashfs-combined-efi.img.gz \
  --base /path/to/tayga-managed-openwrt_0.9.14-r6_aarch64_generic.ipk \
  --procd /path/to/tayga-managed-openwrt-procd_0.9.14-r6_aarch64_generic.ipk \
  --tun /path/to/kmod-tun.ipk --flock /path/to/flock.ipk \
  --work build/openwrt-procd-vm
```

The runner verifies kernel/image/dependency SHA-256 pins, requires a new work
directory, uses no shared host directories and restricts guest networking to
an ephemeral loopback-only SSH forward. It generates and removes its own SSH
private key and ignores the user's SSH configuration. The disk, serial/phase
logs and JSON report remain in the work directory. Acceleration is selected
automatically (HVF/KVM when available, otherwise TCG); CI uses `--accel tcg`
and uploads reports/logs. This process/overlay gate passed locally on Apple
Silicon with both HVF and TCG. Pass the optional network package and its offline
dependencies to also exercise managed networking as described below. Rootfs
smoke tests cover both `opkg` and OpenWrt `apk` package-manager branches; GitHub
CI has not run yet.

The optional service can track one logical netifd uplink. Empty `uplink`
(the default) keeps the existing external-network behavior. To bind it:

```sh
uci set tayga_managed.main.uplink='wan6'
uci commit tayga_managed
/etc/init.d/tayga-managed reload
```

An explicitly started or boot-enabled service waits while the selected uplink
is down and resumes from its accepted snapshot when it returns. Hotplug events
for other interfaces are ignored. IPv4/IPv6 addresses, delegated prefixes,
routes/gateways and L3 device identity determine whether procd restarts the
process. Event duplicates, address ordering, uptime and DHCP/RA lifetime
counters do not cause a restart. Manual `stop` disarms automatic resume until
the next explicit start/restart or enabled boot. UCI `enabled=0` also prevents
event-driven startup. Events reuse the accepted snapshot; edits to the source
candidate require explicit reload/start. Prefixes and addresses inside that
snapshot remain explicit administrator-managed values.

The VM test also checks actual netifd down/up, IPv6 renumbering, L3 device
handover, DHCPv6/RA (`odhcp6c`) dynamic uplink reconciliation, duplicate/unrelated
hotplug events and manual-stop behavior using isolated test uplinks. It verifies
late WAN availability after reboot and prepared-journal power-cut recovery. The
stable-state hash is separately tested with real jshn against reordered address
lists, changing lifetimes and gateway changes.

The optional `tayga-managed-openwrt-network` package adds managed CLAT/NAT64/SIIT
networking, runtime `dnsmasq`/DNS64 integration and post-start traffic-readiness
verification with automatic rollback. It requires matching base/procd packages,
fw4/nftables and `coreutils-timeout`. Installation stays disabled; reboot after
first installing this package so netifd discovers its protocol handler. Keep
ordinary router IPv4/IPv6 forwarding enabled and fw4 automatic includes enabled.

Generate a NAT64, CLAT or SIIT profile with explicit addresses, then select
logical WAN and inside interfaces whose L3 devices are distinct:

```sh
sh /usr/libexec/tayga/configure.sh --mode=nat64 --pref64=fd64:100::/96 \
  --tayga-ipv6=fd64::2 --tun-ipv6=fd64::1 --enable-dns64=yes --offload=off --workers=0 \
  --output=/etc/tayga/managed-nat64.conf
uci set tayga_managed.main.network_mode='managed'
uci set tayga_managed.main.config='/etc/tayga/managed-nat64.conf'
uci set tayga_managed.main.uplink='wan'
uci set tayga_managed.main.inside='lan'
uci set tayga_managed.main.enabled='1'
uci commit tayga_managed
/etc/init.d/tayga-managed start
```

Choose a routed PREF64 and unused addresses/pool appropriate to the deployment.
The accepted snapshot normalizes the TUN to `tmg0`. An owned dynamic netifd
interface assigns addresses and routes (`0.0.0.0/1`, `128.0.0.0/1` and `<clat6>/128`
for CLAT; pool and PREF64 routes for NAT64/SIIT); static fw4 adapters include
only runtime rules for that TUN, selected devices and translation addresses.
NAT64 adds IPv4 masquerading on WAN and optional local DNS64 synthesis (`pref64-discover --serve-dns64`
with a runtime `/tmp/dnsmasq*.d/95-tayga-managed.conf` drop-in); CLAT adds TCP MSS
clamping, LAN-to-CLAT IPv4 masquerading, optional `proxy-ndp`/`nat66` adaptation
and optional public DNS forwarding in `/tmp/dnsmasq*.d/95-tayga-managed.conf`;
SIIT requires a native IPv6 route to its mapped endpoint and adds no masquerading.
Existing UCI network/firewall/DHCP files, global forwarding settings and
administrator-owned TUNs/routes are preserved. Stop, WAN loss and network-package
removal clean up owned resources.

Coordinated `/etc/init.d/tayga-managed reload` (or `start`/`restart`) validates
readiness (`/usr/libexec/tayga/openwrt-network verify`, including optional
`tayga_managed.main.verify_target` or `# installer-verify-target` probes) after
procd starts the daemon; if setup or readiness verification fails, `openwrt-state rollback`
automatically restores the previous working snapshot and network configuration.
Direct uncoordinated `openwrt-state prepare ... managed` calls while the network
is active remain fenced.

For the full VM test, add `--network /path/to/tayga-managed-openwrt-network.ipk`
and repeat `--extra-package` for matching `coreutils` and `coreutils-timeout`
archives. The runner adds a second isolated virtual NIC for translation tests;
no guest connection to the outside network is permitted. CI pins these dependency
archives by SHA-256 and retains failure diagnostics alongside phase logs.

The reviewed r5 managed matrix passed locally with HVF and TCG: NAT64 ICMP + DNS64/`dnsmasq`
synthesis before/after WAN device handover and inside-interface replacement,
forwarded LAN-client traffic across NAT64/SIIT/CLAT, foreign-TUN protection,
injected fw4 failure cleanup, fw4 reload, readiness verification failure with
automatic rollback to the previous profile, real SIIT and CLAT packet translation,
DHCPv6/RA (`odhcp6c`) uplink reconciliation and active package removal.

The reviewed r5 packages passed the complete HVF VM run, including removal and
unchanged network/firewall/DHCP UCI files. Portable installer coverage: 81 tests,
2 platform skips on macOS. TCG also passed the complete matrix; WAN handover waits for both the new
process and target L3 device. The expanded phase budget is 480 seconds.

OpenWrt 25.12.6 APK package coverage is available for armsr/armv8
(`aarch64_generic`, musl). The official GCC 14.3 SDK built all three r6 APKs;
matching disposable rootfs tests passed binary installation/execution/removal,
config/data retention, disabled service defaults, validator execution and
persistent state publication/rollback/recovery. Package metadata retains exact
base/procd revision dependencies and root ownership. APK-only runtime dependency
constraints are emitted separately from the existing IPK syntax.

The `test-openwrt-apk` CI job pins SDK/rootfs/kmod/flock SHA-256 values and repeats
these offline package tests. Local test archives are unsigned; the disposable
rootfs tests disable package scripts and permit non-repository APK installation
without a persistent cache. The IPK 24.10.8 r6 build and both rootfs tests also
passed. These package/file tests are complemented by the booted 25.12.6 gate
below. Package live upgrade and signed publication remain pending. The r5 full VM reports above
cover 24.10.8 networking; GitHub CI has not been run for this change.

The VM runner accepts `--release 25.12.6` for APK images and defaults to
`--release 24.10.8` for IPK images. Supply matching kernel/image/kmod/flock and
base/procd/network archives with their correct `.apk` or `.ipk` suffixes; use
`--extra-package` for matching coreutils/coreutils-timeout packages. Kernel,
image, TUN and flock pins are release-specific; mixed package formats are
rejected before boot and the running firmware release is checked over SSH.

The 25.12.6 HVF and TCG runs passed the complete procd, WAN, reboot/power-cut,
NAT64/DNS64/SIIT/CLAT, forwarded traffic, readiness rollback and active-removal
matrix. The same updated runner passed the 24.10.8 IPK regression. The DHCPv6
fixture stops the stock wan6 client on its test NIC before starting a second
logical client, then explicitly checks its IPv6 address. This uses QEMU's RA
responder, not a dedicated DHCPv6 lease server. CI repeats the APK matrix with
TCG and uploads phase/serial logs and the JSON report, including failures.
The local 25.12.6 TCG verification also passed the complete matrix.

OpenWrt r7 adds the optional `tayga-managed-openwrt-upgrade` package. Install it
alongside an r7-or-newer compatible base/procd/network set before using coordinated
updates. It owns the coordinator and an independent boot recovery hook (START=94),
so replacing the other three packages cannot remove the recovery program. Core
archives must declare upgrade API 1; the first transition from older packages
requires an ordinary stopped installation of the new baseline.

Prepare two directories containing `base.ipk`, `procd.ipk`, `network.ipk` (or
`.apk` for all three). The old directory must contain the exact installed package
versions; the new directory must contain one matching target revision. Keep the
independent coordinator installed; it is deliberately outside the updated set.

```sh
/usr/libexec/tayga/openwrt-upgrade apply /root/tayga-old /root/tayga-new
# Explicit opt-in for local unsigned APK test builds:
/usr/libexec/tayga/openwrt-upgrade apply /root/tayga-old /root/tayga-new --allow-untrusted
# Retry an interrupted transaction manually:
/usr/libexec/tayga/openwrt-upgrade recover
```

Preflight validates package identities, installed rollback revisions and both
manager plans. Plans touching other packages are rejected. An upgrade mutex and
profile lock protect staging; the service stops and its writer PID exits before
configuration/data snapshots are taken. Both package sets and snapshots are
checksummed in `/etc/tayga-managed/package-upgrade` on persistent overlay. Reserve
flash space for both sets, the data snapshot and package-manager working space.

Package hooks run normally, but start/reload/restart and profile publication are
fenced while the journal exists. Only the coordinator can start the accepted
snapshot for validation. Previously active services resume with readiness checks;
previously stopped services remain stopped. Candidate-file edits are not imported.
An installation or validation failure reinstalls the old set and restores its own
UCI file, accepted configuration and data. Boot recovery retries an interrupted
transaction before the normal service. A failed recovery retains the journal and
startup fence. Removing/updating the recovery package during a transaction is
refused. This updates TAYGA packages, not firmware or unrelated dependencies.

The VM upgrade fixtures build the same source at a next-patch test version; that
version is not a published release. Tests cover invalid archives, rejected plans
for unrelated packages, manager and readiness failures, a power cut after target
installation with core files removed, accepted-state/data recovery, active upgrade
and stopped reinstall. Final verification status is recorded with the r7 build
manifests. The crash test exercises that specific package/file interruption point;
it does not certify arbitrary corruption of the package database or flash.

The VM runner's optional `--dhcpv6-server` gate adds a second disposable OpenWrt
VM of the same pinned release. Stock odhcpd serves stateful IA_NA addresses and
IA_PD /62 delegations over a private AF_UNIX datagram socketpair to the client's
third NIC. SLAAC is disabled on this test link. The gate checks initial leases,
renewal without a TAYGA restart, and server-side prefix replacement without
restarting odhcp6c, followed by TAYGA reconciliation and accepted-config retention.
Renumbering overlaps the old and new prefixes before retiring the old one and
checks that its address/delegation disappear. Temporary lease loss during the
transition is allowed within a bounded wait; odhcp6c must remain the same process,
and TAYGA must resume the accepted configuration when the uplink returns.
Both OpenWrt CI jobs enable this gate. Peer logs and its report live under the
run's `dhcpv6-server/` directory and are uploaded alongside client evidence.
For focused networking reruns, `--network-only` runs install/lifecycle/WAN,
one reboot to load the installed netifd protocol, optional DHCPv6, managed traffic
and removal on a fresh VM. It requires `--network` and excludes `--upgrade-*`;
power-cut and package-upgrade phases stay in the full gate.
