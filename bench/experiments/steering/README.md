# Isolated steering research patches

These patches preserve the rejected 2026-10-18 experiments for controlled
ablations. They are not production fixes and must not be applied to `src/`
without a new successful correctness and performance acceptance.

Preparation is implemented by `taygabench study steering-ablation`. It freezes
the current source, applies each patch to a separate copy, records hashes and
preregisters five AB/BA pairs for each comparison:

- `reply-hints.patch`: publish translated TCP reply queue preferences on SYN;
  existing primary owners and CAS winners keep priority.
- `hierarchical-admission.patch`: cold admissions are striped within generic
  endpoint groups while primary owners remain permanent.
- `flows-napi.patch`: enable and verify NAPI for flows on every attachment.

The resulting variants contain no worker-affinity change. A2 compares flat
hints against hierarchical hints. A3 compares hierarchical hints against the
same source plus NAPI.

Real BPF verification, inside the Linux guest as root:

```sh
python3 bench/experiments/steering/verify_reply_hints.py /path/variant /tmp/new-hint-evidence
python3 bench/experiments/steering/verify_hierarchical.py /path/hierarchical-variant /tmp/new-group-evidence
```

The first verifies hint priority, stable ownership, reverse bucket vectors,
concurrent behavior and FD lifetime. The second verifies interleavings and
concurrent first-group admissions through the actual BPF factory with a hint-map
FD. They do not measure TCP wire integrity or capacity; run the system suite
against the selected binary separately.

See [the diagnostic workflow](../../../docs/performance/throughput-diagnostics.md)
for data collection, limitations and evidence interpretation.
