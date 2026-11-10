# Changelog

Changes for this fork are recorded here. Releases use semantic version tags.

## [Unreleased]

## [0.9.16] - 2026-11-10

### Added

- RA prefix supervision for managed CLAT profiles: lifetime renewal, withdrawal/expiry shutdown, foreground translator restart on prefix change, and forwarding of service signals. Managed NAT66 prefix changes stop the translator while the network controller rebuilds owned rules; failed replacement attempts restore the saved network profile and exit without starting a stale translator.
- Deterministic ICMP token accounting regressions and Linux/FreeBSD RA-supervisor lifecycle scenarios; extended DNS64 regressions cover all RFC 6052 prefix lengths and large/non-first EDNS OPT records.

- RFC 8781 PREF64 discovery from Router Advertisements now also works on FreeBSD (`pref64-discover -i <if>`); the installer picks the IPv6 default-route interface via `route(8)`.
- `flow-label zero|compute` (RFC 6437): optional keyed-hash IPv6 Flow Label for IPv4-to-IPv6 translation, including the GSO paths; default stays `zero` per RFC 7915.
- Flat per-prefix-length index for immutable configurations with at least 9 static maps; `find_map4`/`find_map6` become O(lengths x log N) instead of a linear list scan (about 30x faster at 3000 entries).
- Status JSON counters `icmp_sent_packets` (ICMP originated by the daemon) and `self_packets` (packets answered locally). For scalar one-input/one-output traffic these counters support `rx == (tx - icmp_sent) + dropped + self`; covered by `test/system/test_stats_balance.py`.

- `worker-affinity` also accepts a CPU list (`worker-affinity 4-6,8`: worker i on the i-th listed CPU); CPUs outside the allowed set are skipped with a warning.
- `pref64-discover --supervise-ra` options `--runtime-dir DIR` (publishes `active-prefix`), `--initial-prefix` and `--initial-lifetime`; `tayga-ctl status` and the NAT64 readiness probe report the prefix the translator really runs.
- Status JSON `gso.dropped_segments`: segments of a software-GSO aggregate that were not delivered (exact after a mid-stream write failure).
- `scripts/ci/openwrt_feed.py` fetches OpenWrt feed packages through the usign-signed `Packages` index; CI no longer pins per-package hashes that break when a feed is rebuilt.

### Changed

- The RA supervisor keeps the active PREF64 while any router still advertises it instead of restarting the translator on every advertisement with another prefix, solicits three times at start-up and keeps running (soliciting with back-off) after the prefix is withdrawn or expires instead of exiting and consuming the service restart budget.
- `hash-bits` defaults to a size derived from `cache-size` (128 to 16384 buckets) unless set explicitly.
- `uptime_sec` in the status JSON uses the monotonic clock; JSON strings keep valid UTF-8 and escape invalid bytes.
- `pref64-discover --serve-dns64` handles queries concurrently (a slow upstream name no longer delays other names; table of 64 in-flight queries, then SERVFAIL) and sets the synthesized AAAA TTL from the A record, bounded by an SOA MINIMUM in the response (RFC 6147 5.1.7) instead of a fixed 60 s.
- New `worker-affinity on|off` directive (Linux, default off): pins worker thread i to the i-th allowed CPU. Verified on a live daemon (4 workers on CPUs 0-3). A/B on an 8-vCPU Lima guest (flows, 3 workers, clients pinned per CPU, 10 pairs) was slower with it on in every pair (about -28% download, -30% upload, 2-3x retransmits/GB), so it stays off by default; enable only after measuring your own topology.
- eBPF `tun-steering=flows` now hashes the ports of DCCP (33), SCTP (132) and UDP-Lite (136) in addition to TCP/UDP, so those flows spread across queues instead of sticking to one address-pair bucket.

### Fixed

- Hardware-GSO IPv4 validation did not require the transport header to lie inside the packet: an IPv4 header whose IHL consumed the whole buffer made `gso_translate_tcp_4to6` read one byte past it (found by the `fuzz_gso` CI smoke run; regression input kept in `test/fuzz/regress/fuzz_gso/`).
- An unusable `NOTIFY_SOCKET` inherited from the environment is a warning, not a start failure.
- ICMP error rate limiter no longer spins on its flag or reads the clock inside the critical section; a worker that loses the race refuses the error.
- With `flow-label compute` the quoted datagram inside a translated ICMP error keeps a zero Flow Label.
- Leftover temporary files of a killed process (`dynamic.map.XXXXXX`, `.tayga-status.<pid>.<n>`, `<profile>.conf.ra.XXXXXX`) are removed at start-up; status files of other live daemons are left alone.
- `clat-info.json` (`pref64_source`) is read through a directory descriptor opened before `chroot()`; its parser accepts any JSON whitespace.
- Render telemetry JSON in memory and write it outside the shared collection lock; retain per-destination publication order so a slow old export cannot replace a newer snapshot. Metadata cache reads use monotonic refresh scheduling and reject non-regular input files.
- Make the package-upgrade operation-lock fixture portable to FreeBSD and retain coverage for refusing to delete a foreign stale lock. Find Bash through PATH in benchmark regressions and build the UDP drain guard test helpers in an isolated temporary directory instead of silently skipping a stale binary path.

- FreeBSD managed profile now restarts a crashed translator (`daemon -r`, 3 s delay, at most 5 starts per 120 s) and rebuilds the tun(4) addresses, routes and PF anchor before every start, because FreeBSD drops them when the translator dies; `service tayga-managed status` now reports the supervisor correctly.
- OpenRC managed profile now restarts a crashed translator through `supervise-daemon` (2 s delay, at most 5 restarts per 120 s, like the systemd unit) and clears stale network state before a manual restart.
- Prepare systemd readiness sockets before chroot and send READY independently of the logging destination.
- Honor the configured initial ICMP burst and preserve fractional token refill; retain separate PMTU budgets.
- Require operating-system entropy for DNS discovery TXIDs and preserve larger EDNS OPT records in synthesized A queries.
- Support non-/96 DNS64 prefixes in managed readiness and translated HTTP verification.
- Count originated ICMP only after successful TX/completion and avoid duplicate synchronous software-GSO drop accounting.
- Save dynamic mappings with unique owner-only temporary files and report directory synchronization failures.
- Retain a controller-owned configuration for network undo, including FreeBSD TUN removal after an RA supervisor snapshot has been deleted.

- Packets rejected with an ICMP error (Time Exceeded, Packet Too Big, unknown protocol to self) and unknown ICMP types addressed to the daemon are now counted as drops, consistently with the other reject paths.

## [0.9.15] - 2026-11-02

### Changed

- FreeBSD CLAT Proxy NDP now uses a proxy neighbor for the translated address and an owned uplink alias for the daemon identity, avoiding conflicting TUN assignments.

- FreeBSD PF activation now requires administrator-provisioned root NAT/filter calls for `tayga_sfx/*`. The controller only loads its child anchor; root ruleset reconstruction and reload were removed after a real VM gate demonstrated global limit resets. Missing root calls fail activation with network rollback.

### Fixed

- Initialize the BSD TUN address-family header on normal IPv6-to-IPv4 data output; previously TCP/UDP replies could be discarded by the kernel.
- Detect byte order through compiler-defined macros on FreeBSD as well as Linux, restoring valid ICMP echo checksum translation.

### Added

- Document the production Minisign public key and release verification procedure; provide an isolated manual signing-credential check without release publication.
- A shared release platform contract drives seven Linux binary/SFX/native-package targets, FreeBSD installers, required OpenWrt IPK/APK3 subpackages and RouterOS assets; assembly rejects incomplete or unexpected bundles.
- Read-only signed bundle preflight and candidate-only CI with temporary signing keys, immutable source SHA selection and independent publication guards.
- Native archive metadata validation and real nFPM format/architecture gates; pinned SDK export checks OpenWrt package identity before publishing CI candidates.

- Isolated two-VM OpenWrt DHCPv6 gate with odhcpd IA_NA/IA_PD leases, renew stability and live prefix renumbering through odhcp6c; enabled for IPK/APK CI.

- Optional independent OpenWrt package upgrade/recovery coordinator with a persistent archive/state journal, startup fencing, manager/readiness rollback and boot recovery tests.

- Booted OpenWrt 25.12.6 APK lifecycle/networking gate with release-specific input pins, live package hooks and mixed-format rejection; shared IPK regression coverage.

- Pinned OpenWrt 25.12.6 SDK/APK package gate, APK versioned runtime dependencies and matching rootfs lifecycle tests; retained 24.10.8 IPK compatibility.

- Optional OpenWrt NAT64/SIIT netifd/fw4 package with owned TUN/routes, bounded firewall checks, stale-teardown protection and cleanup on stop/removal.

- Optional netifd uplink tracking and filtered OpenWrt iface hotplug handling, with WAN suspension/resume, stable address/prefix/route fingerprints and manual-stop protection.

- Booted OpenWrt QEMU procd/overlay lifecycle gate with real reboot, prepared-journal power-cut recovery, process ownership checks and saved reports/logs.

- Optional OpenWrt procd/UCI service for preconfigured external networking, persistent configuration publication/recovery, and an unprivileged `--check-config` daemon mode.

- Target/ABI-checked OpenWrt SDK binary-only package recipe and source snapshot manifest; separate apk/opkg dependency planning and opkg file ownership protection.

- Native unsigned APK/DEB/RPM package builder with standard `/usr` paths, package ownership isolation, config/data retention tests and an APK dependency pin for managed profiles.

- Self-extracting release installers with verified payloads, per-platform binaries, a universal bundle and native FreeBSD artifact gates.
- Linux CLAT/NAT64/SIIT profile wizard, systemd/OpenRC activation, readiness checks, owned iptables/nftables rules and transactional reconfiguration/uninstall.
- Disposable-container CLAT-to-NAT64 HTTP/ICMP and cleanup gates, plus portable installer ownership/rollback regressions.

- Debian AppArmor-compatible owned Unbound configuration, verified with live DNSSEC and systemd-resolved.

- Optional profile-owned Unbound DNS64 and CLAT public DNS through systemd-resolved, with scoped cleanup.

- Early systemd/OpenRC recovery of interrupted activations after reboot, without replaying old kernel journals; native VM reboot/power-cut tests.

- Independent activation watchdog with SIGKILL recovery, atomic commit, owned-session cancellation, persistent snapshots and manual `tayga-ctl recover`.

### Fixed

- Ignore stale dynamic mapping state when no dynamic pool is configured.
- MikroTik RouterOS deployment: add `bridge-clat` and `bridge-nat64` to interface list `LAN` so default firewall allows forwarded container traffic.
- MikroTik RouterOS deployment: register static IPv6 neighbor for container VETH interface, resolving RouterOS 7 neighbor discovery drops on secondary bridges.
- MikroTik RouterOS deployment: remove duplicate blocking container image archive check in `routeros-install-nat64.rsc` to allow registry pulls (`useRegistry=true`).
- MikroTik RouterOS removal: clean up project-owned static IPv6 neighbors and interface list memberships in `routeros-remove.rsc`.
- Observability: add portable POSIX shell/sed fallback for `TAYGA_PID` detection in `tayga-status` when `python3` is not present in minimal container environments.

## [0.9.14] - 2026-10-19

### Fixed

- Reject a missing configuration path before calling libc, avoiding a static musl amd64 crash.

- Resolve release tags to one verified source commit and reject unprepared or mismatched version metadata.
- Require compiler, platform, sanitizer and kernel gates before publishing saved, smoke-tested release artifacts.
- Parse supported release tag prefixes consistently and keep prereleases from updating `latest`.

- Keep eBPF flow buckets on their first worker across packet sizes and reloads.
- Reserve IPv4 IDs for empty software GSO output and offload split-tail TCP checksums.
- Clear segmentation metadata on single TCP packets, preventing kernel forwarding drops with TCP options.
- Validate direct software GSO inputs and avoid expected startup errors for disposable TUNs.

- Complete circular dynamic-pool allocation before reclaiming dormant leases.
- Restore the default build, header dependencies, build-flag tracking and static linkage transitions.
- Repair paths after the source, benchmark and test directory migration.
- Make man-page drift checks fail on generator errors and preserve build metadata.

### Added

- Direct groups/flows BPF, lifecycle and TCP checksum-completion wire regressions.
- Alternating TCP recovery trials with deterministic data ports and fail-closed acceptance reports.

- RFC 7757 explicit mappings with arbitrary IPv6 prefix lengths that can hold the IPv4 suffix.
- Isolated unit outputs, a shared test library, benchmark and fault-shim build targets.
- An installable `taygabench` package, CLI and standalone benchmark assembly.
- Contributor, security, architecture, testing and release documentation.

## [0.9.13]

The historical release predates this changelog. See the repository's tagged release
for its original notes; this entry makes no additional validation claims.
