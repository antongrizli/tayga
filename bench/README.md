# Benchmark tools

From the repository root:

```sh
python3 -m pip install -e 'bench[dev]'
python3 -m taygabench --help
python3 -m taygabench study udp-batch --help
python3 -m taygabench summarize tcp-flow --help
make bench-tools benchmark-script
```

Alternatively use `PYTHONPATH=bench python3 -m taygabench ...` without installing.
Study modules are importable using underscore names; hyphenated script paths
remain compatibility entrypoints. Runtime Python dependencies are standard-library
only, while native workloads require Linux tooling (iperf3, perf, iproute2 and
root for namespaces).

The source CLAT entrypoint sources `clat/lib` functions. `make benchmark-script`
assembles `build/benchmark-clat.sh` for installation or archival; it runs without
those source libraries. Runners freeze sourced code when given the source entrypoint.
Build shims live under `build/shims`; explicit old helper targets retain copies in
`tools` for scripts deployed before the migration.

Results default to `$PERF_SESSION_ROOT` or
`${XDG_STATE_HOME:-$HOME/.local/state}/tayga/perf-sessions`. Comparisons use
`$PERF_COMPARISON_ROOT` or the corresponding `tayga/perf-comparisons` state folder.
Preserve existing local results before migrating them. Most studies require an
explicit new output directory and reject incomplete or mixed-identity datasets.

Use [the Lima workflow](lima/README.md) for host collection and guest measurements.
Container recipes use the repository root as their build context:

```sh
docker build -f bench/containers/benchmark.Containerfile -t tayga-benchmark .
```

That image runs the self-contained CLAT benchmark and has no sibling workspace
dependency. It replaces the former external NAT64 comparison container; use the
owning project's tools when comparing that different implementation.

See [benchmarking guidance](../docs/dev/benchmarking.md) for measurement boundaries.
