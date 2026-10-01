#!/usr/bin/env python3
"""Repeated maximum-load CPU-placement study; never pools profiled capacity."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stamp', required=True)
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--protocol', choices=('tcp', 'udp'), nargs='+', default=['tcp', 'udp'])
    parser.add_argument('--profiles-only', action='store_true')
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if args.pairs < 1 or args.duration < 1 or not args.stamp or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in args.stamp):
        parser.error('positive pairs/duration and an alphanumeric stamp are required')
    repo = args.repo.resolve()
    output = repo / 'perf-sessions' / args.stamp
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for protocol in args.protocol:
        # Reverse ordering on alternating pairs to limit time/order confounding.
        runs = [(pair, arm, 'none') for pair in range(1, args.pairs + 1)
                for arm in (('scheduler', 'separate') if pair % 2 else ('separate', 'scheduler'))]
        if args.profiles_only:
            runs = []
        runs += [(0, arm, 'record') for arm in ('scheduler', 'separate')]
        for pair, arm, mode in runs:
            stamp = f'{args.stamp}-{protocol}-{arm}-pair{pair}-{mode}'
            session = repo / 'perf-sessions' / f'{stamp}-lima-debian13-arm64'
            if session.exists():
                raise RuntimeError(f'refusing to overwrite {session}')
            env = dict(os.environ, REPO=str(repo), SESSION_STAMP=stamp,
                       CLIENTS='2', FLOWS='1', WORKERS='1', RATE='0', WARMUP='0',
                       DURATION=str(args.duration if mode == 'none' else 15),
                       DIRECTIONS='upload download', PROTOCOL=protocol, PERF_MODES=mode,
                       CLAT_OFFLOAD='auto', FORWARDING_GRO='on', PERF_SCOPE='process',
                       TAYGA_CPUSET='all' if arm == 'scheduler' else '0',
                       CLIENT_CPUSET='all' if arm == 'scheduler' else '1',
                       SERVER_CPUSET='all' if arm == 'scheduler' else '2,3',
                       SOCKET_BUFFER_BYTES='0', TUN_TXQLEN='1000', CLAT_OFFLINK_MTU='1280',
                       DATAGRAM_SIZE='1200', SENDER_FQ='off', FQ_RATE='0',
                       VETH_QUEUES='0', PACING_TIMER_US='1000', RECEIVER_DRAIN_SECONDS='0.5',
                       MAX_UDP_LOSS_PERCENT='0', MAX_TUN_DROPS='0', MAX_PING_LOSS_PERCENT='0',
                       SOCKET_SAMPLE_INTERVAL='1', BLOCK_SIZE='')
            print(f'Running {stamp}', flush=True)
            with (output / f'{stamp}.log').open('w') as log:
                status = subprocess.run(['bash', str(repo / 'tools/lima-perf/run-host.sh')],
                                        env=env, stdout=log, stderr=subprocess.STDOUT).returncode
            for direction in ('upload', 'download'):
                path = session / mode / direction / 'result.json'
                result = json.loads(path.read_text()) if path.exists() else {}
                rows.append(dict(protocol=protocol, pair=pair, arm=arm, mode=mode,
                                 direction=direction, command_exit=status, path=str(path), result=result))
            (output / 'ledger.json').write_text(json.dumps(rows, indent=2) + '\n')
            # UDP loss acceptance may make the command nonzero; missing or partial
            # workloads are separate errors and must not disappear from results.
            latest = rows[-2:]
            if any(not r['result'].get('capture_valid') or not r['result'].get('workload_valid') for r in latest):
                raise RuntimeError(f'invalid workload in {stamp}; retained logs/ledger, stop study')
    if args.profiles_only:
        return
    hashes = {row['result']['tayga_sha256'] for row in rows}
    if len(hashes) != 1:
        raise RuntimeError('executable changed during study; retained ledger, refuse summary')
    lines = ['# CPU placement study', '', '| Protocol/direction | Scheduler median Mbit/s | Separate median Mbit/s | Median paired change |', '|---|---:|---:|---:|']
    for protocol in args.protocol:
        key = 'received_active_window_mbps' if protocol == 'udp' else 'received_mbps'
        for direction in ('upload', 'download'):
            groups = {arm: {r['pair']: r['result'][key] for r in rows if r['protocol'] == protocol and r['direction'] == direction and r['mode'] == 'none' and r['arm'] == arm} for arm in ('scheduler', 'separate')}
            a, b = groups['scheduler'], groups['separate']
            change = statistics.median((b[p] / a[p] - 1) * 100 for p in a)
            lines.append(f'| {protocol}/{direction} | {statistics.median(a.values()):.3f} | {statistics.median(b.values()):.3f} | {change:+.2f}% |')
    lines += ['', 'Only unprofiled, valid complete workloads enter this table. Zero-loss acceptance remains separate; see ledger. Affinity is an experimental deployment treatment, not a translator code speedup.', '']
    (output / 'summary.md').write_text('\n'.join(lines))


if __name__ == '__main__':
    main()
