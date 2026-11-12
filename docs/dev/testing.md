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

The review-gates workflow runs all unit tests with `ASAN_OPTIONS=detect_leaks=1`.
Keep leak detection enabled for the full sanitizer suite; investigate retained
fixtures rather than treating a run with leak detection disabled as acceptance.

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

## Unit coverage

`make coverage` builds the unit tests with `COVERAGE=1` in `build/coverage`, runs them
and writes `build/coverage/summary.txt` and `build/coverage/html/index.html` with
`gcovr` (install it with `pip install gcovr==8.8`, the version CI pins). It fails when line coverage of `src/`
drops below `COVERAGE_MIN` (default 66 in `mk/config.mk`; override on the command line,
for example `make coverage COVERAGE_MIN=100` to see the gate fail). The `portable` job
in `review-gates.yml` runs it on Linux and uploads the HTML report as `coverage-html`.

Baseline: 68.4% of lines (4384 of 6406), measured on 2026-11-12 at commit `7e61584`
(Debian GCC 14.2, gcovr 8.8). The floor is two points below the integer part of that value.
The least-covered files are `src/tun_steering.h` (0%), `src/log.c` (6%) and
`src/tun.c` (13%). Unit coverage excludes paths only reached by the root system tests
(TUN, netlink, steering and the daemon main loop), so low figures there do not mean
those paths are untested. Raise `COVERAGE_MIN` when coverage improves; never lower it
to make a change pass without a stated reason.

## Nightly fuzzing

The `Nightly fuzzing` workflow (`.github/workflows/fuzz-nightly.yml`, 02:17 UTC and
on manual dispatch) runs `make fuzz-check CC=clang FUZZ_TIME=600`. Each harness keeps
its working corpus in `build/fuzz/fuzz-run/<target>/`; the workflow restores that
directory from the Actions cache before the run and saves it afterwards, so coverage
accumulates from night to night. Do not run `make clean` before `make fuzz-check` if you
want to keep a local corpus. If a harness fails, the run uploads the `crash-*`,
`leak-*` and `timeout-*` inputs as the `fuzz-findings` artifact (kept 30 days);
download it from the workflow run page or with `gh run download <run-id> -n fuzz-findings`.
Fix a finding together with a regression input in `test/fuzz/regress/<target>/`, which
every later run replays.

See [the audit acceptance scenarios](audit-acceptance.md) for the pending Linux/FreeBSD
RA-supervisor, service lifecycle, DNS64, TX accounting and persistence matrix.
