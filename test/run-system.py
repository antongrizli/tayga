#!/usr/bin/env python3
"""Run the self-contained kernel gates against a selected executable."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux root is required')
    root = Path(__file__).resolve().parent / 'system'
    binary = str(args.binary.resolve())
    if args.output.exists():
        shutil.rmtree(args.output, ignore_errors=True)
    args.output.mkdir(parents=True, exist_ok=True)
    # Individual suites take the same lock while owning their namespaces.
    lock_file = Path('/tmp/tayga-perf-workflow.lock')
    try:
        if lock_file.exists() and lock_file.stat().st_uid != os.geteuid():
            lock_file.unlink()
    except OSError:
        pass
    lock_file.touch(exist_ok=True)
    for name in ('auto_negotiation', 'auto_persistent', 'startup_rollback',
                 'worker_burst', 'napi_initialization', 'udp_gso_kernel'):
        subprocess.run([sys.executable, str(root / f'test_{name}.py'), '--binary', binary,
                        '--output', str(args.output.resolve() / name)], check=True)
    subprocess.run([sys.executable, str(root / 'test_tun_steering_lifecycle.py'),
                    binary, '--dispatch=kernel', '--packet-io=sync'], check=True)


if __name__ == '__main__':
    main()
