# Testing

Use `make test` for C regressions and `make test-portable` for non-root Python
checks. Linux-only native modules skip explicitly on other systems. All C unit
binaries are in `build/test-bin`; fixture output is in `build/test-output/unit`.
Explicit targets such as `make unit_addrmap` retain a root compatibility copy.

```sh
make BUILDDIR=build/asan CC=clang CFLAGS='-O1 -g -Wall -fsanitize=address,undefined -fno-sanitize-recover=all' LDFLAGS='-fsanitize=address,undefined' test
ASAN_OPTIONS=detect_leaks=1 build/asan/test-bin/unit_addrmap
ASAN_OPTIONS=detect_leaks=1 build/asan/test-bin/unit_mapping
```

Legacy config fixtures retain allocations: run their general sanitizer suite with
`ASAN_OPTIONS=detect_leaks=0`; that is not evidence that all configuration lifetimes
are leak-free. Mapping regressions must separately pass leak detection.

On an isolated Linux system with root, Scapy, pyroute2, iproute2 and tcpdump:

```sh
sudo make integration
sudo make system-test
make bench-tools
make test-linux-tools
```

Integration uses a private namespace with guaranteed cleanup, `TAYGA_BIN` for the
executable and `TAYGA_TEST_OUT` for reports, packet captures and configuration.
Defaults come from the selected Make build directory. Individual system suites
own disposable namespaces and reserve `/tmp/tayga-perf-workflow.lock`. The
`system-test` target runs the self-contained negotiation, persistence, rollback,
burst, NAPI, UDP wire and lifecycle gates. Historical installed-environment tests
such as preflight/PMTUD require the prepared benchmark environment separately.

`python3 scripts/ci/check-build.py` checks clean helper/default builds, incremental
header tracking and static/dynamic/compiler transitions in a temporary build tree.
`make check-docs` checks local Markdown links. Man verification is described in
[release.md](release.md). FreeBSD, ARMv7 and RouterOS validation need their own hosts.
