# Changelog

Changes for this fork are recorded here. Releases use semantic version tags.

## [Unreleased]

### Fixed

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
