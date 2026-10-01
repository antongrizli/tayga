#!/usr/bin/env python3
"""Validate repeated flow-count measurements before reporting capacity."""
import argparse
import json
from pathlib import Path
import statistics
from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location('worker_summary', Path(__file__).with_name('summarize-tcp-worker-study.py'))
worker_summary = module_from_spec(spec)
spec.loader.exec_module(worker_summary)


def summarize(rows, rounds=3):
    expected = {(w, f, d, n) for w in (2, 3) for f in (1, 4)
                for d in ('upload', 'download') for n in range(1, rounds + 1)}
    seen = set()
    identities = set()
    startup = set()
    groups = {}
    invariants = None
    for row in rows:
        r = row['result']
        key = row['workers'], row['flows'], row['direction'], row['round']
        if key in seen or key not in expected:
            raise ValueError('duplicated or unexpected measurement')
        seen.add(key)
        if row['status'] != 0 or not all(r.get(k) for k in ('capture_valid', 'workload_valid', 'acceptance_pass')):
            raise ValueError('invalid measurement')
        if (r.get('workers'), r.get('flows_per_client'), r.get('clients'), r.get('direction')) != (key[0], key[1], 4, key[2]):
            raise ValueError('treatment metadata mismatch')
        if r.get('workload_protocol') != 'tcp' or r.get('perf_mode') != 'none' or str(r.get('rate_per_flow')) != '0':
            raise ValueError('not unrestricted unprofiled TCP')
        if len(row.get('flow_tuples', [])) != 4 * key[1]:
            raise ValueError('incomplete recorded stream tuples')
        identities.add(r['tayga_sha256'])
        startup.add(r['clat_start_sha256'])
        current = tuple(r.get(k) for k in ('offload_requested', 'offload_effective', 'forwarding_gro',
                    'offlink_mtu', 'duration_seconds', 'guest_cpu_count', 'client_cpuset', 'server_cpuset', 'tayga_cpuset'))
        if invariants is None:
            invariants = current
        if current != invariants:
            raise ValueError('unmatched workload settings')
        if r['received_mbps'] <= 0:
            raise ValueError('nonpositive throughput')
        groups.setdefault(key[:3], []).append(row)
    if seen != expected or len(identities) != 1 or len(startup) != 1:
        raise ValueError('incomplete matrix or mixed executable/startup identity')
    result = []
    for (workers, flows, direction), selected in sorted(groups.items()):
        selected.sort(key=lambda row: row['round'])
        rates = [row['result']['received_mbps'] / 1000 for row in selected]
        dist = [worker_summary.distribution(row['result'], direction) for row in selected]
        result.append(dict(workers=workers, streams=4 * flows, direction=direction,
                           median_gbps=statistics.median(rates), min_gbps=min(rates), max_gbps=max(rates),
                           active_workers=[d['active_workers'] for d in dist],
                           worker_shares=[d['shares'] for d in dist]))
    return dict(tayga_sha256=next(iter(identities)), clat_start_sha256=next(iter(startup)), groups=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    settings = json.loads((args.root / 'settings.json').read_text())
    result = summarize(json.loads((args.root / 'ledger.json').read_text()), settings['rounds'])
    (args.root / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
