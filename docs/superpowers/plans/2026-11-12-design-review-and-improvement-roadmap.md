# Design Review and Improvement Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gaps a design review of `0fa9d68` (0.9.16) found: no stable way to measure translator cost, no metrics in a standard format, shallow fuzzing and no static analysis in CI, one oversized helper source, and a compliance document that contradicts the code.

**Architecture:** Eight independent tasks. None changes default packet-path behaviour; the one new runtime feature (a Prometheus metrics file) is opt-in and reuses the existing status-file publication code. Larger features are listed in "Feature candidates" and each needs its own spec before a plan.

**Tech Stack:** C (gcc and clang), GNU make (`mk/*.mk`), libFuzzer, GitHub Actions, Python 3 for tooling.

**Spec:** There is no separate spec. The "Design assessment" section below is the spec; it was produced by reading the code, `docs/dev/architecture.md`, `docs/performance/audit-2026-11-09.md` and `improvenments/plan_10.11.2026.md`. No tests or benchmarks were run for this review.

## Global Constraints

- Default behaviour of `tayga` is unchanged; every new option is off unless set.
- No new runtime dependency for the daemon or `pref64-discover`.
- Code builds on Linux and FreeBSD with gcc and clang under `-Wall -Wextra -Wshadow -Wformat=2 -Werror` (the `strict-warnings` CI job).
- `make test` and `make test-portable` pass after every task; sanitizer runs keep `ASAN_OPTIONS=detect_leaks=1`.
- A new or changed CLI option or config directive updates `docs/man/*.md`, the regenerated man pages (`make man`, then `make check-man`), `usage()` in `src/tayga.c` and `CHANGELOG.md` under `[Unreleased]`.
- `struct config` changes update the struct-size expectation in `test/unit/unit_conffile.c` (see commit `fb5857f`).
- Commit subjects follow the existing `area: summary` style (`stats:`, `ci:`, `bench:`, `docs:`).

## Design assessment

### What is well designed

- **Clear module boundaries in the daemon.** Start-up and workers (`tayga.c`), configuration (`conffile.c`), mapping (`addrmap.c`, `dynamic.c`), scalar translation (`nat64.c`), offload (`gso.c`), device I/O (`tun.c`), telemetry (`stats*.c`).
- **Safe defaults.** Kernel steering and synchronous I/O are the production path; group steering, flow dispatch and io_uring are explicit opt-ins.
- **Testing depth is unusual for a project this size.** 15 C unit suites, 7 libFuzzer harnesses with stored regressions, ASan/UBSan/TSan in CI, netns integration, root system tests, and VM gates for FreeBSD and OpenWrt.
- **Release engineering.** Signed bundles, a platform contract (`packaging/release-platforms.json`), transactional interface set-up with rollback.
- **Performance work is evidence-led.** The cache-lock question was settled by measurement and the sharding idea was dropped.

### Weaknesses found

| # | Finding | Evidence | Addressed by |
|---|---|---|---|
| D1 | `docs/rfc.md` says unequal EAM suffix lengths make TAYGA fail to start. The code accepts them and a unit test covers them. | `src/conffile.c:580`, `src/addrmap.c:742-752`, `test/unit/unit_mapping.c:142` | Task 1 |
| D2 | Performance acceptance could not separate signal from noise: throughput on the Lima guest is bimodal (about 65 and 105 Gbit/s) for both builds, so gate B1 was closed as "regression not proven". There is no benchmark of the translator alone. | `docs/performance/audit-2026-11-09.md` | Task 2 |
| D3 | Telemetry is a custom JSON file only. Monitoring it needs a bespoke parser. | `src/stats_exporter.c` | Task 3 |
| D4 | CI fuzzing is 60 s per harness from seeds, with no saved corpus. The last memory-safety bug (`2329e88`) was found by that smoke run by chance. | `.github/workflows/review-gates.yml:71-75` | Task 4 |
| D5 | No static analysis and no coverage figure in CI, although `COVERAGE=1` exists in `mk/config.mk`. | `.github/workflows/` | Tasks 5, 6 |
| D6 | `src/helpers/pref64-discover.c` is 2549 lines (11% of all C) and holds four programs: RFC 7050 discovery, RA parsing and candidate table, a DNS64 server, and a process supervisor. Three of the last audit's P1/P2 defects were in this file. | `wc -l`, `improvenments/plan_10.11.2026.md` NEW-1, NEW-2, NEW-7 | Task 7 |
| D7 | `src/experimental_io.c` is written in a dense one-line style that ignores `.clang-format`, which makes review of the riskiest code hardest. | `src/experimental_io.c:185-260` | Task 8 |
| D8 | Experimental modes carry cost without a demonstrated benefit: `groups` steering measured about 40 Gbit/s against 105 with all traffic on one worker; `flows` and io_uring TX did not pass the throughput gate. They add 82 references in `src/*.c` and 11 status keys. | `docs/performance/audit-2026-11-09.md` | Feature candidates (decision) |
| D9 | `struct config gcfg` mixes parsed configuration, runtime state, thread handles and mutexes; `main()` is 615 lines. This blocks a full configuration reload and makes unit set-up heavy. | `src/tayga.h:387-474`, `src/tayga.c:402` | Feature candidates |
| D10 | Tracked documents cite evidence in the git-ignored `improvenments/` directory, so other contributors cannot open it. Some tracked docs are in Russian, the rest in English. | `docs/performance/audit-2026-11-09.md:74`, `.gitignore` | Not planned; owner's call |

### Optimization: what the measurements say

The pktgen profile shows 83% of samples in the kernel TUN read and write path, 11.6% in libc and 5.4% in TAYGA. Micro-optimizing the translator can gain a few percent at most. The two levers that remain are (1) keeping aggregates intact through GSO, which is already done, and (2) not crossing the TUN device per packet, which is a new feature (see candidates). This plan therefore adds measurement (Task 2) and does not change the packet path.

## Review Focus

1. Metrics file path equal to the status file path: the daemon must refuse to start, not let two writers replace each other. Test in Task 3.
2. Metrics file with `--chroot`: the file must still be written after `chroot()`. Test in Task 3.
3. Microbenchmark handler that silently drops its packet (wrong addresses for the map set) would report a fast, meaningless number. Self-check in Task 2.
4. Nightly fuzz job that restores an empty or missing corpus cache must still run from seeds and pass. Step in Task 4.
5. After the helper split, a `pref64-discover` built without `-DPREF64_NO_MAIN` must still expose every mode (`--ra-only`, `--supervise-ra`, `--serve-dns64`). Check in Task 7.

---

### Task 1: Correct the RFC 7757 section of `docs/rfc.md`

**Files:**
- Modify: `docs/rfc.md` (section "Unequal Suffix Lenghts")

- [ ] **Step 1: Rewrite the section.** New heading `### Unequal Suffix Lengths`. State: a `map` entry is accepted when the IPv6 prefix leaves at least as many suffix bits as the IPv4 prefix (`32 - len4 <= 128 - len6`); the IPv4 suffix is copied directly after the IPv6 prefix and trailing bits are zero; a map with fewer IPv6 suffix bits is rejected at start-up. Keep the link to upstream Issue #37 as historical context. Use `docs/dev/architecture.md` lines 21-25 as the source of truth.

- [ ] **Step 2: Verify**

Run: `make check-docs`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add docs/rfc.md
git commit -m "docs: rfc.md describes the implemented RFC 7757 suffix handling"
```

---

### Task 2: Translator microbenchmark (`make microbench`)

Measures userspace cost per packet with the kernel TUN path removed, so two builds can be compared on a noisy host.

**Files:**
- Create: `bench/micro/bench_xlate.c`
- Modify: `mk/bench.mk` (targets `$(BUILDDIR)/bench_xlate`, `microbench`)
- Modify: `bench/README.md` (section "Translator microbenchmark")
- Test: `bench/tests/test_microbench.py`

**Interfaces:**
- Consumes: `fuzz_setup_maps()` and `fuzz_null_fd` from `test/fuzz/fuzz_common.h`; `handle_ip4()`, `handle_ip6()` from `src/tayga.h`; `$(TEST_LIB)` from `mk/test.mk`.
- Produces: `build/bench_xlate [--iters N] [--runs R]`, printing one JSON object per line: `{"case": "<name>", "ns_per_pkt": <float>, "iters": <int>, "runs": <int>}`. Defaults: `--iters 2000000 --runs 5`. `ns_per_pkt` is the minimum over the runs.

Cases, in this order (addresses come from the map set in `fuzz_setup_maps()`: IPv4 host `192.0.0.1` ↔ `fd9b:64:1:ff::10`, remote `198.51.100.1` ↔ `64:ff9b::c633:6401`):

| case | packet |
|---|---|
| `baseline_write_1400` | no handler: `memcpy` of the template into the work buffer, then `write()` of 1428 bytes to `/dev/null` |
| `udp4to6_64` | IPv4/UDP, 64-byte payload, src `192.0.0.1`, dst `198.51.100.1` |
| `udp4to6_1400` | same, 1400-byte payload |
| `udp6to4_64` | IPv6/UDP, 64-byte payload, src `64:ff9b::c633:6401`, dst `fd9b:64:1:ff::10` |
| `udp6to4_1400` | same, 1400-byte payload |
| `tcp4to6_1400` | IPv4/TCP ACK segment, 1400-byte payload |
| `tcp6to4_1400` | IPv6/TCP ACK segment, 1400-byte payload |
| `icmp_echo4to6` | ICMPv4 echo request, 56-byte payload |

All templates carry valid IP, UDP, TCP and ICMP checksums. `has_vhdr = 0`, `gcfg.vnet_hdr_sz = 0`, `gcfg.tun_offload_effective = TUN_OFFLOAD_OFF`.

- [ ] **Step 1: Write the failing test** in `bench/tests/test_microbench.py`

```python
import json, subprocess, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = ["baseline_write_1400", "udp4to6_64", "udp4to6_1400", "udp6to4_64",
         "udp6to4_1400", "tcp4to6_1400", "tcp6to4_1400", "icmp_echo4to6"]

class MicrobenchTest(unittest.TestCase):
    def test_reports_every_case(self):
        subprocess.run(["make", "-C", str(ROOT), "build/bench_xlate"], check=True)
        out = subprocess.run([str(ROOT / "build/bench_xlate"), "--iters", "1000", "--runs", "2"],
                             check=True, capture_output=True, text=True).stdout
        rows = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([r["case"] for r in rows], CASES)
        for r in rows:
            self.assertGreater(r["ns_per_pkt"], 0)
            self.assertEqual((r["iters"], r["runs"]), (1000, 2))

    def test_rejects_zero_iterations(self):
        res = subprocess.run([str(ROOT / "build/bench_xlate"), "--iters", "0"], capture_output=True)
        self.assertEqual(res.returncode, 2)
```

Skip both tests with `unittest.skipUnless(sys.platform.startswith("linux") or sys.platform.startswith("freebsd"), ...)`.

- [ ] **Step 2: Run it to see it fail**

Run: `python3 -m unittest bench/tests/test_microbench.py -v`
Expected: FAIL, `make` has no rule for `build/bench_xlate`.

- [ ] **Step 3: Implement `bench/micro/bench_xlate.c`**

Per iteration: `memcpy` the template to `buf + HEADROOM`, fill a zeroed `struct pkt` (`tun_fd`, `data`, `data_len`), call the handler. Time each run with `clock_gettime(CLOCK_MONOTONIC)` around the whole loop.

Self-check before timing each handler case (Review Focus 3): create a `pipe()`, run the handler once with `p.tun_fd` set to the write end, `read()` the result and require a non-empty packet whose version nibble is the opposite family (6 for `*4to6`, 4 for `*6to4`). On failure print `self-check failed: <case>` to stderr and exit 1.

Exit 2 with a usage line when `--iters` or `--runs` is not a positive integer.

- [ ] **Step 4: Add the make rules in `mk/bench.mk`**

`$(BUILDDIR)/bench_xlate` compiles `bench/micro/bench_xlate.c` with `$(CPPFLAGS) $(CFLAGS) -Itest/fuzz` and links `$(TEST_LIB) $(LDLIBS)`. `microbench` is `.PHONY`, depends on it and runs it with default arguments.

- [ ] **Step 5: Run the test**

Run: `python3 -m unittest bench/tests/test_microbench.py -v`
Expected: 2 tests pass.

- [ ] **Step 6: Document in `bench/README.md`.** Explain: what the number includes (translation, checksum work, one `write()` to `/dev/null`); subtract `baseline_write_1400` to estimate translation alone; compare two commits by running `make microbench` on each on the same idle machine, three times, and comparing the minimum per case; a difference under 3% is noise.

- [ ] **Step 7: Commit**

```bash
git add bench/micro/bench_xlate.c mk/bench.mk bench/README.md bench/tests/test_microbench.py
git commit -m "bench: translator microbenchmark independent of the TUN path"
```

---

### Task 3: Prometheus metrics file (`--metrics-file`)

Writes counters in Prometheus text exposition format for the node_exporter textfile collector. No listening socket.

**Files:**
- Modify: `src/stats_exporter.c`, `src/stats.h`, `src/tayga.h` (`struct config`), `src/tayga.c` (option, validation, `usage()`)
- Modify: `docs/man/tayga.8.md`, `docs/man/tayga.8`, `CHANGELOG.md`, `test/unit/unit_conffile.c` (struct size)
- Test: `test/unit/unit_stats.c`, `test/system/test_stats_balance.py`

**Interfaces:**
- Produces: `void stats_write_prometheus(const char *path);` in `src/stats.h`; `char metrics_path[768];` in `struct config`; CLI `--metrics-file FILE`; environment `TAYGA_METRICS_FILE` (the option wins, as for `--status-file`).

Behaviour:
- Off unless a path is given. The path must be absolute, at most 767 bytes, and differ from the status path; otherwise `die()` at start-up with `metrics-file must be an absolute path of at most 767 bytes` or `metrics-file must differ from status-file`.
- Written whenever the status JSON is written (every 5 s, on SIGUSR2, at shutdown), through the same temporary-file-and-rename publication used by `stats_write_json()` (`export_begin()`/`export_end()`), so a reader never sees a partial file.
- `telemetry_prepare_dir()` is also called for the metrics path before `chroot()`; extend it to keep one directory descriptor per destination.

Metric set (every counter has `# HELP` and `# TYPE` lines; names and labels are fixed):

```
tayga_info{version="<TAYGA_VERSION>",offload="<effective>",steering="<effective>"} 1          gauge
tayga_uptime_seconds                                                                          gauge
tayga_rx_packets_total{family="ipv4"|"ipv6"}                                                  counter
tayga_rx_bytes_total{family}                                                                  counter
tayga_tx_packets_total{family}                                                                counter
tayga_tx_bytes_total{family}                                                                  counter
tayga_dropped_packets_total                                                                   counter
tayga_dropped_bytes_total                                                                     counter
tayga_self_packets_total                                                                      counter
tayga_icmp_sent_packets_total                                                                 counter
tayga_error_packets_total                                                                     counter
tayga_tx_failures_total{reason="eagain"|"enobufs"|"eintr"|"short"|"fatal"|"other"}            counter
tayga_gso_packets_total{direction="rx"|"tx"}                                                  counter
tayga_gso_software_segmented_packets_total                                                    counter
tayga_gso_dropped_segments_total                                                              counter
tayga_dynamic_pool_mappings{state="active"|"dormant"}                                         gauge
tayga_dynamic_pool_free_addresses                                                             gauge
tayga_worker_rx_packets_total{worker="<slot>",family}                                         counter
```

Values come from the same `struct tayga_stats` snapshot and `g_worker_pub[]` fields the JSON uses. Label values are escaped per the exposition format (`\\`, `\"`, `\n`).

- [ ] **Step 1: Write the failing unit test** `test_prometheus_export()` in `test/unit/unit_stats.c`, called from `main()` after the existing JSON tests. Use the counter set-up of the existing "Test 6" block, record three IPv4 receives of 100 bytes, flush, then:

```c
stats_write_prometheus(path);            /* path in the unit output directory */
/* read the file into buf */
expect(strstr(buf, "# TYPE tayga_rx_packets_total counter\n") != NULL, "prom: TYPE line");
expect(strstr(buf, "tayga_rx_packets_total{family=\"ipv4\"} 3\n") != NULL, "prom: rx packets v4");
expect(strstr(buf, "tayga_rx_bytes_total{family=\"ipv4\"} 300\n") != NULL, "prom: rx bytes v4");
expect(strstr(buf, "tayga_rx_packets_total{family=\"ipv6\"} 0\n") != NULL, "prom: zero series present");
expect(strstr(buf, "tayga_info{version=\"") != NULL, "prom: info metric");
expect(buf[strlen(buf) - 1] == '\n', "prom: ends with newline");
```

Also assert that no temporary file is left in the output directory, with the same check the JSON test at `unit_stats.c:61-78` uses.

- [ ] **Step 2: Run it to see it fail**

Run: `make unit_stats`
Expected: link error, `stats_write_prometheus` undefined.

- [ ] **Step 3: Implement `stats_write_prometheus()`** in `src/stats_exporter.c`. Render to an `open_memstream()` buffer under `s_stats_export_mutex`, write outside it, exactly as `stats_write_json()` does.

- [ ] **Step 4: Run the unit test**

Run: `make unit_stats && build/test-bin/unit_stats`
Expected: all checks pass, exit 0.

- [ ] **Step 5: Wire the option.** Add `--metrics-file` next to `--status-file` in the long-option table of `src/tayga.c` with the next unused code, read `TAYGA_METRICS_FILE`, validate as specified, call `telemetry_prepare_dir()` and the writer alongside the JSON calls in `telemetry_*`.

- [ ] **Step 6: Add start-up tests** in `test/portable/test_metrics_file_option.py`. Run the built binary with `--check-config -c <minimal valid config>`: the status-path validation at `src/tayga.c:613-616` runs before the `check_config` exit at line 622, so placing the metrics validation directly after it makes both checks reachable without root. `run()` returns the completed process. Assertions:

```python
# relative path
self.assertIn("metrics-file must be an absolute path", run("--metrics-file", "m.prom").stderr)
# same as status file (Review Focus 1)
self.assertIn("metrics-file must differ from status-file",
              run("--status-file", "/tmp/a", "--metrics-file", "/tmp/a").stderr)
```

Both runs must exit non-zero. A third run with a valid absolute metrics path different from the status path must exit 0.

- [ ] **Step 7: Extend `test/system/test_stats_balance.py`** (root, Linux) with one case that starts the daemon with `--chroot` and `--metrics-file <runtime-dir>/tayga.prom`, sends 10 echo requests, sends SIGUSR2 and asserts the file exists outside the chroot view and contains `tayga_rx_packets_total{family="ipv6"}` with a value of at least 10 (Review Focus 2).

- [ ] **Step 8: Docs.** Add the option to `usage()`, `docs/man/tayga.8.md` (with a two-line node_exporter example: `--metrics-file /var/lib/node_exporter/textfile_collector/tayga.prom`), run `make man && make check-man`, add a `CHANGELOG.md` entry under `[Unreleased]` → `### Added`, update the `struct config` size in `test/unit/unit_conffile.c`.

- [ ] **Step 9: Full check**

Run: `make test && make test-portable`
Expected: both exit 0.

- [ ] **Step 10: Commit**

```bash
git add src/stats_exporter.c src/stats.h src/tayga.h src/tayga.c docs/man CHANGELOG.md test/unit/unit_stats.c test/unit/unit_conffile.c test/portable/test_metrics_file_option.py test/system/test_stats_balance.py
git commit -m "stats: optional Prometheus text metrics file (--metrics-file)"
```

---

### Task 4: Nightly fuzzing with a saved corpus

**Files:**
- Create: `.github/workflows/fuzz-nightly.yml`
- Modify: `docs/dev/testing.md` (short "Nightly fuzzing" paragraph)

`make fuzz-check` already keeps each harness's working corpus in `build/fuzz/fuzz-run/<target>/` and replays `test/fuzz/regress/<target>/`. The workflow only has to keep that directory between runs.

- [ ] **Step 1: Write the workflow.**
  - Triggers: `schedule: cron '17 2 * * *'` and `workflow_dispatch`.
  - `permissions: contents: read`; `runs-on: ubuntu-24.04`; `timeout-minutes: 120`.
  - Steps: checkout (same pinned action and `persist-credentials: false` as `review-gates.yml`); install `clang`; restore cache with path `build/fuzz/fuzz-run`, key `fuzz-corpus-${{ github.run_id }}`, restore-keys `fuzz-corpus-`; run `make fuzz-check CC=clang FUZZ_TIME=600`; save the cache with `if: always()`; on failure upload `build/fuzz/fuzz-run/**/crash-*`, `**/leak-*`, `**/timeout-*` as artifact `fuzz-findings` with 30-day retention.
  - Do not run `make clean` in this job: it deletes the restored corpus.
  - Use the action major versions already pinned elsewhere in `.github/workflows/`; add any new action to `.github/dependabot.yml` coverage if it is not matched already.

- [ ] **Step 2: Lint**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/fuzz-nightly.yml'))"` and, if installed, `actionlint .github/workflows/fuzz-nightly.yml`
Expected: no output, exit 0.

- [ ] **Step 3: Prove the cold start locally** (Review Focus 4)

Run: `rm -rf build/fuzz && make fuzz-check CC=clang FUZZ_TIME=5`
Expected: last line `fuzz-check passed`.

- [ ] **Step 4: Prove the warm start**

Run: `make fuzz-check CC=clang FUZZ_TIME=5` again without removing `build/fuzz`
Expected: `fuzz-check passed`, and `ls build/fuzz/fuzz-run/fuzz_gso | wc -l` is not smaller than after Step 3.

- [ ] **Step 5: Document** in `docs/dev/testing.md`: where the corpus lives, how to download `fuzz-findings`, and that a finding is fixed together with a regression input in `test/fuzz/regress/<target>/`.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/fuzz-nightly.yml docs/dev/testing.md
git commit -m "ci: nightly 10-minute fuzzing with a persistent corpus"
```

---

### Task 5: Static analysis gate

**Files:**
- Modify: `mk/test.mk` (target `analyze`), `Makefile` (`help` text)
- Modify: `.github/workflows/review-gates.yml` (job `static-analysis`)
- Create: `.github/workflows/codeql.yml`

- [ ] **Step 1: Add `make analyze`** (`.PHONY`). It requires `scan-build` on `PATH` and runs:

```make
scan-build --status-bugs -o $(BUILDDIR)/analyze-report \
  $(MAKE) BUILDDIR=$(BUILDDIR)/analyze $(BUILDDIR)/analyze/tayga $(BUILDDIR)/analyze/pref64-discover
```

- [ ] **Step 2: Run it**

Run: `make analyze`
Expected on first run: either `scan-build: No bugs found.` or a list of reports.

- [ ] **Step 3: Resolve every report.** A true defect is fixed with a unit test that fails before the fix, one commit per defect. A false positive is silenced only by making the invariant explicit in code (an early return or `assert`), never by excluding a checker or a file. Repeat Step 2 until it prints `No bugs found.` and exits 0.

- [ ] **Step 4: Add the CI job `static-analysis`** to `review-gates.yml`, same checkout block as `sanitizers`: install `clang-tools`, run `make analyze`, upload `build/analyze-report` as an artifact on failure.

- [ ] **Step 5: Add `.github/workflows/codeql.yml`.** Triggers: push to `main`, pull requests, weekly cron. Languages `c-cpp` (manual build: `make tayga pref64-discover`) and `python`. `permissions: security-events: write, contents: read`.

- [ ] **Step 6: Verify nothing regressed**

Run: `make test`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add mk/test.mk Makefile .github/workflows/review-gates.yml .github/workflows/codeql.yml
git commit -m "ci: clang static analyzer gate and CodeQL"
```

---

### Task 6: Coverage report with a floor

**Files:**
- Modify: `mk/test.mk` (target `coverage`), `Makefile` (`help`), `docs/dev/testing.md`
- Modify: `.github/workflows/review-gates.yml` (step in job `portable`)

- [ ] **Step 1: Add `make coverage`** (`.PHONY`). It runs `$(MAKE) BUILDDIR=$(BUILDDIR)/coverage COVERAGE=1 CFLAGS='-O0 -g -Wall' LDFLAGS= test`, then:

```make
gcovr --root . --filter 'src/' --object-directory $(BUILDDIR)/coverage \
  --txt $(BUILDDIR)/coverage/summary.txt --html-details $(BUILDDIR)/coverage/html/index.html \
  --fail-under-line $(COVERAGE_MIN)
```

`COVERAGE_MIN ?= 0` in `mk/config.mk`.

- [ ] **Step 2: Measure**

Run: `make coverage && tail -3 build/coverage/summary.txt`
Expected: a `TOTAL` line with a line-coverage percentage `P`.

- [ ] **Step 3: Set the floor.** Change the default to `COVERAGE_MIN ?= <floor(P) - 2>`. Record `P`, the date and the commit in `docs/dev/testing.md`, with the three least-covered files from `summary.txt`. Note in the doc that unit coverage excludes paths only reached by the root system tests.

- [ ] **Step 4: Prove the gate fails when it should**

Run: `make coverage COVERAGE_MIN=100`
Expected: non-zero exit with gcovr's `failed minimum line coverage` message.

- [ ] **Step 5: CI.** In job `portable`, install `gcovr`, run `make coverage`, upload `build/coverage/html` as artifact `coverage-html`.

- [ ] **Step 6: Commit**

```bash
git add mk/test.mk mk/config.mk Makefile docs/dev/testing.md .github/workflows/review-gates.yml
git commit -m "ci: unit coverage report with a regression floor"
```

---

### Task 7: Split `src/helpers/pref64-discover.c` by responsibility

A move-only refactor. No behaviour, option or output changes.

**Files:**
- Create: `src/helpers/pref64_ra.c` — RA option parsing and the candidate table (`parse_ra_pref64_all`, `is_valid_pref64_prefix`, every `ra_table_*`). Its header `src/helpers/pref64_ra.h` already exists.
- Create: `src/helpers/dns64_serve.c`, `src/helpers/dns64_serve.h` — the embedded DNS64 server (`struct dns_upstream`, `struct dns_pending`, `struct dns_ctx`, `upstream_resolve`, `dns_upstream_send`, `dns_intake`, the serve loop) and `synthesize_pref64`.
- Create: `src/helpers/ra_supervisor.c`, `src/helpers/ra_supervisor.h` — RA socket open, `send_rs`, `receive_ra`, `stop_ra_child`, the `--supervise-ra` loop, active-prefix publication.
- Modify: `src/helpers/pref64-discover.c` — keeps RFC 7050 DNS discovery (`query_dns_server`, probing), `tun_echo6`, `print_usage`, `main`.
- Modify: `mk/tayga.mk` (`$(BUILDDIR)/pref64-discover` links four objects), `mk/test.mk` (`$(TESTOBJDIR)/pref64.o` becomes `PREF64_TEST_OBJS`, used by `unit_pref64` and `fuzz_pref64`), `packaging/openwrt/Makefile` and `scripts/ci/check-build.py` if they name the single source file.

**Interfaces:**
- Produces: `dns64_serve.h` and `ra_supervisor.h` declare exactly the functions `main()` calls into each module plus any symbol the unit or fuzz tests already reference. Everything else stays `static`. Shared small helpers used by more than one module (for example monotonic time, `random_txid`) go to `src/helpers/pref64_util.h` as `static inline`.

- [ ] **Step 1: Record the baseline**

```bash
make pref64-discover && ./pref64-discover --help > /tmp/pref64-help.before 2>&1; echo $? > /tmp/pref64-help.rc
make unit_pref64 && build/test-bin/unit_pref64 > /tmp/unit_pref64.before
```

- [ ] **Step 2: Move the code** into the four files as listed. Move whole functions and their file-scope state together; do not edit bodies. Each new `.c` includes only the headers it needs.

- [ ] **Step 3: Update the build rules.** Object files go under `$(OBJDIR)/helpers/`; test objects keep `-DPREF64_NO_MAIN` on the file that contains `main` only.

- [ ] **Step 4: Compare with the baseline** (Review Focus 5)

```bash
make clean && make pref64-discover
./pref64-discover --help 2>&1 | diff - /tmp/pref64-help.before
make unit_pref64 && build/test-bin/unit_pref64 | diff - /tmp/unit_pref64.before
nm build/pref64-discover | grep -c ' T main$'
```

Expected: both `diff` commands print nothing; the `nm` count is 1.

- [ ] **Step 5: Whole-suite check**

Run: `make test && make test-portable && make fuzz-check CC=clang FUZZ_TIME=10 && python3 scripts/ci/check-build.py`
Expected: all exit 0. `wc -l src/helpers/*.c` shows no file above 1000 lines.

- [ ] **Step 6: Root system tests** (Linux with root, or leave to CI and say so in the commit body)

Run: `sudo python3 test/system/test_ra_pref64.py && sudo python3 test/system/test_ra_supervisor.py && sudo python3 test/system/test_dns64_serve.py`
Expected: all pass.

- [ ] **Step 7: Commit, then record the hash**

```bash
git add src/helpers mk/tayga.mk mk/test.mk packaging/openwrt/Makefile scripts/ci/check-build.py
git commit -m "pref64: split discovery, RA table, DNS64 server and supervisor into separate files"
git rev-parse HEAD >> .git-blame-ignore-revs
git add .git-blame-ignore-revs && git commit -m "chore: ignore the pref64 split in blame"
```

---

### Task 8: Format `src/experimental_io.c` to the project style

**Files:**
- Modify: `src/experimental_io.c`, `.git-blame-ignore-revs`

- [ ] **Step 1: Baseline**

Run: `make WITH_URING=1 unit_dispatch unit_async_tun && build/test-bin/unit_dispatch && build/test-bin/unit_async_tun` (Linux with liburing; on other hosts run `unit_dispatch` only and state that in the commit body)
Expected: exit 0.

- [ ] **Step 2: Format**

Run: `clang-format -i src/experimental_io.c`
Then check `git diff --stat` touches only that file and `git diff -w --word-diff=porcelain src/experimental_io.c | grep -c '^[+-][^+-]'` shows only whitespace-adjacent token moves (no identifier or literal changes).

- [ ] **Step 3: Re-run Step 1 and the strict build**

Run: `make clean && make WITH_URING=1 CFLAGS='-O2 -Wall -Wextra -Wshadow -Wformat=2 -Werror' && make WITH_URING=1 test`
Expected: exit 0.

- [ ] **Step 4: Commit and ignore in blame**

```bash
git add src/experimental_io.c && git commit -m "style: clang-format experimental_io.c (no functional change)"
git rev-parse HEAD >> .git-blame-ignore-revs
git add .git-blame-ignore-revs && git commit -m "chore: ignore the experimental_io reformat in blame"
```

---

## Feature candidates (each needs its own spec before a plan)

Ranked by expected value for this project. None is scheduled by this plan.

| # | Candidate | Why | Size | Recommendation |
|---|---|---|---|---|
| F1 | **Retire `tun-steering groups`; time-box `dispatch flows` and io_uring TX** | D8: `groups` is 2.5x slower with all load on one worker; the other two have no proven gain. Removing them shrinks the riskiest code and the status schema. | Small to medium | Do first. Remove `groups` in 0.10; keep `flows` and io_uring one more release behind the microbenchmark and a bare-metal run, then keep or remove. |
| F2 | **Performance rig without bimodality** | D2: a bare-metal Linux box or a non-Virtualization.framework hypervisor, running the existing A/B harness. Without it no throughput claim can be accepted. | Small (hardware) | Do before any packet-path optimization. |
| F3 | **Kernel fast path (tc/eBPF) for stateless RFC 6052 and static maps**, userspace kept for ICMP errors, fragments and dynamic maps | The only remaining large gain: 83% of CPU is the TUN crossing. Android's clatd uses this design. Not usable inside RouterOS containers, so the gain is for Linux hosts and OpenWrt. | Large | Write a spec and a prototype measurement first; go only if the target platforms justify it. |
| F4 | **Control socket** (`tayga-ctl show maps|cache|stats`, add and remove a static map at runtime) | Today the only runtime controls are SIGHUP (map-file) and SIGUSR2. Needs D9 addressed first: split `struct config` into immutable configuration and runtime state. | Medium | Worth doing if operators manage maps dynamically; otherwise defer. |
| F5 | **RFC gaps from `docs/rfc.md`**: RFC 7757 hairpinning (packets are dropped today), tolerate non-zero RFC 6052 suffix bits (a SHOULD), RFC 6791 source pool and extension | Compliance; hairpinning matters for SIIT-DC edge relays. | Small each | Hairpinning first; the suffix-bit change is a few lines plus tests. |
| F6 | **Full configuration reload on SIGHUP** | Avoids a restart (and a traffic gap) for prefix or pool changes. Depends on the same `struct config` split as F4. | Medium | Pair with F4. |
| F7 | **FreeBSD multi-worker** | `MAX_WORKERS` is 0 on FreeBSD; tun(4) has no multiqueue, so this needs several devices and route distribution. | Large | Not recommended now. |

## Self-review notes

- Every weakness D1-D7 has a task; D8-D10 are deliberately left as owner decisions and say so.
- Review Focus items 1-5 are pinned by Task 3 Steps 6-7, Task 2 Step 3, Task 4 Steps 3-4 and Task 7 Step 4.
- Names used across tasks: `stats_write_prometheus`, `metrics_path`, `--metrics-file`, `TAYGA_METRICS_FILE`, `build/bench_xlate`, `make microbench`, `make analyze`, `make coverage`, `COVERAGE_MIN`.
- Not read in full for this review, so the implementer reads them first: `export_begin()`/`export_end()` and `telemetry_prepare_dir()` in `src/stats_exporter.c` (Task 3), and the function boundaries inside `src/helpers/pref64-discover.c` (Task 7).
