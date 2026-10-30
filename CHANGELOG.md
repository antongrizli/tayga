# Changelog

Changes for this fork are recorded here. Releases use semantic version tags.

## [Unreleased]

### Added

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
