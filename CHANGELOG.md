# Changelog

Changes for this fork are recorded here. Releases use semantic version tags.

## [Unreleased]

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
