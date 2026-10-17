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
burst, NAPI, UDP/TCP wire, recovery-port allocation, direct groups/flows BPF and
lifecycle gates. Historical installed-environment tests
such as preflight/PMTUD require the prepared benchmark environment separately.

`python3 scripts/ci/check-build.py` checks clean helper/default builds, incremental
header tracking and static/dynamic/compiler transitions in a temporary build tree.
`make check-docs` checks local Markdown links. Man verification is described in
[release.md](release.md). FreeBSD, ARMv7 and RouterOS validation need their own hosts.

Direct eBPF checks support `--steering groups` and `--steering flows` on
`test/system/test_tun_steering.py`. They require a capable Linux root environment
and fail visibly if the program cannot load. Userspace `--dispatch=flows` is a
separate backend. `test_tcp_split_tail_kernel.py` builds a source-linked fixture
and verifies checksum completion after kernel segmentation on disposable veth
links. Payload integrity/PMTUD can additionally exercise unmodified production
startup with `run-steering-integrity.py --production-startup --steering flows` in
the prepared benchmark VM; that runner restores the installed files afterwards.
