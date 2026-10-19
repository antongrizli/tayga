"""Offline directional worker, GSO and scheduler evidence; never grants acceptance."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

from .compare import WORKLOAD_KEYS, TREATMENT_KEYS


BYTE_FIELDS = ('rx_bytes_v4', 'tx_bytes_v4', 'rx_bytes_v6', 'tx_bytes_v6')


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid nonnegative counter')
    return value


def ratio(a, b, scale=1):
    a, b = number(a), number(b)
    return scale * a / b if b else None


def snapshot_workers(before, after):
    """Legacy bytes are unavailable; partial snapshots and resets are errors."""
    if (before['pid'] != after['pid'] or after['snapshot_sequence'] <= before['snapshot_sequence'] or
        any(s.get('workers_synced') is not True or s.get('unacknowledged_worker_slots') for s in (before, after))):
        raise ValueError('worker snapshot identity/freshness/synchronization failure')
    slots = [{w['slot']: w for w in s['workers']} for s in (before, after)]
    if any(len(v) != len(s['workers']) for v, s in zip(slots, (before, after))) or slots[0].keys() != slots[1].keys():
        raise ValueError('duplicate/changed worker slots')
    available = any(k in w for s in slots for w in s.values() for k in BYTE_FIELDS)
    rows = []
    for slot in sorted(slots[0]):
        b, a = (s[slot] for s in slots)
        if b.get('worker_id') != a.get('worker_id'):
            raise ValueError('worker identity changed')
        row = dict(slot=slot, worker_id=a.get('worker_id'), byte_counters_available=available)
        for key in ('rx_packets_v4', 'rx_packets_v6') + BYTE_FIELDS:
            if key in BYTE_FIELDS and not available:
                row[key] = None
                continue
            if type(a[key]) is not int or type(b[key]) is not int:
                raise ValueError('worker counter is not an integer: ' + key)
            delta = number(a[key]) - number(b[key])
            if delta < 0:
                raise ValueError('worker counter reset: ' + key)
            row[key] = delta
        rows.append(row)
    return rows


def distribution(workers, key):
    if len({w['slot'] for w in workers}) != len(workers):
        raise ValueError('duplicate worker slot')
    rows = sorted((w for w in workers if w['slot'] > 0), key=lambda w: w['slot'])
    if not rows or any(w.get(key) is None for w in rows):
        return dict(available=False, slots=[w['slot'] for w in rows], shares=None)
    values = [number(w[key]) for w in rows]
    total = sum(values)
    shares = [v / total for v in values] if total else None
    return dict(available=True, slots=[w['slot'] for w in rows], values=values, total=total,
                shares=shares, min_share=min(shares) if shares else None,
                effective_workers=total * total / sum(v*v for v in values) if total else None)


def summarize_result(result, workers=None):
    direction = result['direction']
    if direction not in ('upload', 'download'):
        raise ValueError('unknown direction')
    family = 'v4' if direction == 'upload' else 'v6'
    workers = result.get('worker_metrics') if workers is None else workers
    workers = workers or []
    gso = result.get('gso_stats_delta') or {}
    gso_values = {}
    for name, numerator in (('mean_input_ip_bytes', 'rx_bytes'), ('split_tail_per_input', 'split_tail')):
        gso_values[name] = ratio(gso[numerator], gso['rx_pkts']) if numerator in gso and 'rx_pkts' in gso else None
    for key in ('fallback_pkts', 'sw_seg_pkts', 'sw_seg_out', 'invalid_pkts', 'tun_write_err'):
        gso_values[key] = number(gso[key]) if key in gso else None
    scheduler = []
    for t in (result.get('thread_metrics') or {}).get('threads', []):
        running, wait = t.get('scheduler_running_ns'), t.get('runqueue_wait_ns')
        scheduler.append(dict(tid=t['tid'], main_thread=t.get('main_thread'), cpu_cores=t.get('cpu_cores'),
                              running_ns=running, runqueue_wait_ns=wait,
                              wait_per_running=ratio(wait, running) if running is not None and wait is not None else None,
                              migrations=t.get('migrations')))
    rate = result.get('received_mbps')
    cpu = result.get('tayga_cpu_cores')
    return dict(direction=direction, capture_valid=result.get('capture_valid') is True,
                workload_valid=result.get('workload_valid') is True,
                packet_distribution=distribution(workers, 'rx_packets_' + family),
                byte_distribution=distribution(workers, 'rx_bytes_' + family), gso=gso_values,
                scheduler=scheduler, system_busy_cores=result.get('system_busy_cores'),
                system_softirq_cores=result.get('system_softirq_cores'),
                tayga_cpu_seconds_per_received_application_gb=(ratio(cpu, rate, 8000) if cpu is not None and rate is not None else None),
                received_mbps=rate, retransmits=result.get('retransmits'),
                # Existing retransmits_per_gbyte uses receiver bytes. Never relabel it as sender GB.
                retransmits_per_received_gb=result.get('retransmits_per_gbyte'),
                identity={k: result.get(k) for k in ('source_tree_sha256', 'tayga_sha256') + WORKLOAD_KEYS + TREATMENT_KEYS})


def inspect(path):
    evidence = {}
    def read(p):
        data = p.read_bytes()
        evidence[str(p)] = hashlib.sha256(data).hexdigest()
        return json.loads(data)
    row = dict(path=str(path), errors=[])
    try:
        result = read(path)
        workers = None
        snapshots = [path.parent/f'tayga-status.{p}.json' for p in ('before', 'after')]
        before = after = None
        if any(p.exists() for p in snapshots):
            before, after = (read(p) for p in snapshots)
            workers = snapshot_workers(before, after)
        row.update(summarize_result(result, workers))
        for key in ('steering_effective', 'packet_io', 'dispatch_mode'):
            if before is not None and before.get(key) != after.get(key):
                raise ValueError('datapath identity changed: ' + key)
            row['identity'][key] = before.get(key) if before is not None else None
        experiment = path.resolve().parents[2]/'experiment.json'
        row['identity']['study_id'] = str(path.resolve().parents[2])
        if experiment.exists():
            row['experiment'] = read(experiment)
            exp = row['experiment']
            if exp.get('experiment_id'):
                row['identity']['study_id'] = exp['experiment_id']
                row['identity']['arm_id'] = exp.get('arm_id')
            row['identity']['harness_archive_sha256'] = exp.get('harness_archive_sha256')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        row['errors'].append(str(exc))
    row['evidence_sha256'] = evidence
    return row


def grouped(rows):
    """Descriptive medians only; retain invalid windows and never grant PASS."""
    groups = {}
    for row in rows:
        identity = row.get('identity', {})
        # Unknown datapath identity is not evidence of equal treatments.
        key = json.dumps(identity, sort_keys=True) if identity.get('steering_effective') else row['path']
        groups.setdefault(key, []).append(row)
    result = []
    for selected in groups.values():
        metrics = {k: [] for k in ('received_mbps', 'min_worker_byte_share', 'min_worker_packet_share',
                    'gso_mean_input_ip_bytes', 'gso_split_tail_per_input', 'tayga_cpu_seconds_per_received_application_gb',
                    'system_busy_cores', 'system_softirq_cores')}
        for row in selected:
            values = {k: row.get(k) for k in metrics}
            values['min_worker_byte_share'] = (row.get('byte_distribution') or {}).get('min_share')
            values['min_worker_packet_share'] = (row.get('packet_distribution') or {}).get('min_share')
            for k in ('mean_input_ip_bytes', 'split_tail_per_input'):
                values['gso_'+k] = row.get('gso', {}).get(k)
            for k, v in values.items():
                if v is not None: metrics[k].append(number(v))
        result.append(dict(identity=selected[0].get('identity'), n=len(selected),
            interpretable=all(not r['errors'] and r.get('capture_valid') and r.get('workload_valid') for r in selected),
            evidence_errors=sum(bool(r['errors']) for r in selected),
            invalid_captures=sum(not r.get('capture_valid') or not r.get('workload_valid') for r in selected),
            paths=[r['path'] for r in selected],
            metrics={k: dict(n=len(v), median=statistics.median(v), min=min(v), max=max(v))
                     for k, v in metrics.items() if v}))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs', nargs='+', type=Path, help='result.json, session directory, or acceptance JSON')
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    paths = set()
    for root in args.inputs:
        if root.is_dir():
            paths.update(root.rglob('result.json'))
        elif root.name == 'result.json':
            paths.add(root)
        else:
            doc = json.loads(root.read_text())
            paths.update(Path(s['path']) for ss in doc['samples'].values() for s in ss)
    if not paths:
        p.error('no saved results found')
    rows = [inspect(path) for path in sorted(paths)]
    args.output.write_text(json.dumps(dict(schema_version=1, purpose='diagnostic-only',
        product_accepted=False, analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        runs=rows, groups=grouped(rows)), indent=2) + '\n')
    print(f"{len(rows)} windows; {sum(bool(r['errors']) for r in rows)} evidence errors; {args.output}")
    return int(any(r['errors'] for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
