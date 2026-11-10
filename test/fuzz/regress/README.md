# Fuzzer regression inputs

Put a minimised crashing or hang-inducing input for a target in
`test/fuzz/regress/<target>/` (for example `regress/fuzz_pkt6/crash-<hash>`).
`make fuzz-check` passes these directories to libFuzzer as seed corpora, so every
stored input is replayed on each run. Generated seeds live in `make_seeds.py`
and are not stored.
