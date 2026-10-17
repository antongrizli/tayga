# Contributing

Build with GNU Make and a C compiler on Linux or FreeBSD:

```sh
make
make test
make test-portable check-docs
```

Use `gmake` on FreeBSD. macOS supports the portable Python suite and standalone
packet ownership checks; the daemon uses Linux/FreeBSD TUN APIs.

Choose an independent `BUILDDIR` for simultaneous builds. Compiler, feature and
linker flag changes in one build directory are tracked automatically. Build with
`WITH_URING=1` only when liburing development headers/libraries are installed.
See [testing](docs/dev/testing.md) and [benchmarking](docs/dev/benchmarking.md).

Keep changes focused and add regression tests for behavioral fixes. Use
Conventional Commit subjects such as `fix(mapping): preserve allocation wraparound`.
Update man sources and generated pages when changing user-visible behavior.
`make check-man PANDOC=scripts/ci/pandoc-container.sh` uses the pinned generator.

The canonical product sources are in `src`; benchmark implementations live in
`bench/taygabench` and `bench/clat/lib`. Old hyphenated Python filenames are
compatibility entrypoints. Generate a standalone benchmark with
`make benchmark-script` before installing or freezing a measurement script.

Upstream is [apalrd/tayga](https://github.com/apalrd/tayga). Separate mechanical
moves from behavioral changes when practical. Preserve upstream attribution.
Optional local navigation settings:

```sh
git config merge.renameLimit 2000
git config diff.renames true
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

Do not pool profiled, paced, degraded or rejected measurements with unrestricted
accepted capacity results. Retain raw evidence and identify the exact executable
and source snapshot used. Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.
