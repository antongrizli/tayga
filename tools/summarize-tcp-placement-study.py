#!/usr/bin/env python3
"""Keep capacity and profiling separate in the sixteen-stream placement study."""
import argparse
import json
from pathlib import Path
import statistics
import re
from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location('worker_summary', Path(__file__).with_name('summarize-tcp-worker-study.py'))
worker_summary = module_from_spec(spec)
spec.loader.exec_module(worker_summary)


def summarize(rows, rounds=3):
    expected = {(w, a, d, n, 'none', 'process') for w in (2, 3)
                for a in ('scheduler', 'partitioned') for d in ('upload', 'download')
                for n in range(1, rounds + 1)}
    expected |= {(w, a, d, 0, 'record', s) for w in (2, 3)
                 for a in ('scheduler', 'partitioned') for d in ('upload', 'download')
                 for s in ('process', 'system')}
    seen = set()
    identities = set()
    invariant = None
    groups = {}
    profiles = []
    for row in rows:
        r = row['result']
        w, a, d, n, mode, scope = key = (row['workers'], row['placement'], row['direction'], row['round'], row['mode'], row['scope'])
        if key not in expected or key in seen:
            raise ValueError('duplicate or unexpected case')
        seen.add(key)
        gates = ('capture_valid', 'workload_valid') if mode == 'record' else ('capture_valid', 'workload_valid', 'acceptance_pass')
        if row['status'] != 0 or not all(r.get(k) for k in gates):
            raise ValueError('invalid measurement')
        if (r.get('workers'), r.get('clients'), r.get('flows_per_client'), r.get('direction'), r.get('perf_mode'), r.get('perf_scope')) != (w, 4, 4, d, mode, scope):
            raise ValueError('treatment metadata mismatch')
        if r.get('workload_protocol') != 'tcp' or str(r.get('rate_per_flow')) != '0' or len(row.get('flow_tuples', [])) != 16:
            raise ValueError('not unrestricted sixteen-stream TCP')
        masks = ('all', 'all', 'all') if a == 'scheduler' else (('0,1', '2', '3') if w == 2 else ('0,1,2', '3', '3'))
        if tuple(r.get(k) for k in ('tayga_cpuset', 'client_cpuset', 'server_cpuset')) != masks:
            raise ValueError('CPU placement mismatch')
        identities.add((r['tayga_sha256'], r['clat_start_sha256']))
        current = tuple(r.get(k) for k in ('offload_requested', 'offload_effective', 'forwarding_gro', 'offlink_mtu', 'guest_cpu_count', 'duration_seconds'))
        if invariant is None:
            invariant = current
        if current != invariant:
            raise ValueError('unmatched workload settings')
        dist = worker_summary.distribution(r, d)
        if mode == 'none':
            groups.setdefault((w, a, d), []).append((n, r['received_mbps'] / 1000, dist))
        else:
            profiles.append(dict(label=row['label'], workers=w, placement=a, direction=d, scope=scope,
                                 gbps=r['received_mbps'] / 1000, distribution=dist, path=row['path'],
                                 acceptance_pass=r['acceptance_pass'], degraded_reasons=r.get('degraded_reasons', [])))
    if seen != expected or len(identities) != 1:
        raise ValueError('incomplete matrix or mixed executable/startup identities')
    output = []
    pairs = []
    for (w, a, d), values in sorted(groups.items()):
        values.sort()
        rates = [v[1] for v in values]
        output.append(dict(workers=w, placement=a, direction=d, median_gbps=statistics.median(rates),
                           min_gbps=min(rates), max_gbps=max(rates), active_workers=[v[2]['active_workers'] for v in values],
                           worker_shares=[v[2]['shares'] for v in values]))
    for w in (2, 3):
        for d in ('upload', 'download'):
            scheduler = {v[0]: v[1] for v in groups[w, 'scheduler', d]}
            changes = [100 * (v[1] / scheduler[v[0]] - 1) for v in sorted(groups[w, 'partitioned', d])]
            pairs.append(dict(workers=w, direction=d, paired_change_percent=changes,
                              median_paired_change_percent=statistics.median(changes)))
    return dict(identities=list(identities), groups=output, pairs=pairs, profiles=profiles)


def profile_evidence(root, profiles):
    evidence = []
    for profile in profiles:
        folder = root / profile['label'] / profile['direction']
        report = (folder / 'perf-report-self.txt').read_text()
        lost = re.search(r'^# Total Lost Samples: (\d+)$', report, re.M)
        samples = re.search(r'^# Samples: (.+)$', report, re.M)
        if not lost or int(lost[1]) != 0 or not samples:
            raise ValueError('missing sample evidence or lost profiling samples')
        if not (folder / 'perf.data').is_file() or not (folder / 'perf-report-caller.txt').is_file():
            raise ValueError('missing raw profile or caller report')
        symbols = []
        for line in report.splitlines():
            match = re.match(r'\s*([\d.]+)%\s+\[([k.])\]\s+(\S+)', line)
            if match:
                symbols.append(dict(self_percent=float(match[1]), domain=match[2], symbol=match[3]))
        if not symbols:
            raise ValueError('empty self profile')
        evidence.append(dict(**profile, lost_samples=0, samples=samples[1], top_symbols=symbols[:10],
            copy_to_user_percent=sum(s['self_percent'] for s in symbols if s['symbol'] == '__arch_copy_to_user'),
            copy_from_user_percent=sum(s['self_percent'] for s in symbols if s['symbol'] == '__arch_copy_from_user'),
            socket_notification_percent=sum(s['self_percent'] for s in symbols if s['symbol'] == 'sock_def_readable'),
            page_clearing_percent=sum(s['self_percent'] for s in symbols if s['symbol'] in ('clear_page', '__pi_clear_page'))))
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    settings = json.loads((args.root / 'settings.json').read_text())
    result = summarize(json.loads((args.root / 'ledger.json').read_text()), settings['rounds'])
    result['profile_evidence'] = profile_evidence(args.root, result['profiles'])
    (args.root / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
