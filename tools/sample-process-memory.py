#!/usr/bin/env python3
"""Read Linux TAYGA resident memory during a diagnostic workload.

No allocation hooks are installed. Run separately from capacity measurements.
Records process start identity so PID reuse cannot join unrelated lifetimes.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True)
parser.add_argument('--seconds', type=float, default=300)
parser.add_argument('--interval', type=float, default=2)
args = parser.parse_args()
if args.seconds <= 0 or args.interval <= 0:
    parser.error('seconds and interval must be positive')
start = time.monotonic()
with open(args.output, 'w') as out:
    while time.monotonic() - start < args.seconds:
        pids = subprocess.run(['pgrep', '-x', 'tayga'], capture_output=True, text=True).stdout.split()
        for pid in pids:
            proc = Path('/proc') / pid
            try:
                stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                values = {}
                for name in ('status', 'smaps_rollup'):
                    for line in (proc / name).read_text().splitlines():
                        key, sep, value = line.partition(':')
                        if sep and key in ('VmSize', 'VmRSS', 'VmHWM', 'Threads', 'Rss', 'Pss', 'Anonymous', 'Private_Dirty'):
                            values[key] = int(value.split()[0])
                values.update(pid=int(pid), start_ticks=int(stat[19]),
                              elapsed_seconds=time.monotonic() - start,
                              fd_count=len(list((proc / 'fd').iterdir())))
            except (OSError, ValueError, IndexError):
                continue
            out.write(json.dumps(values) + '\n')
            out.flush()
        time.sleep(args.interval)
