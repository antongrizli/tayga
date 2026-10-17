#!/usr/bin/env python3
"""Run packet suites in a private network namespace and always remove it."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--big-endian', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux root is required for network namespaces')
    root = Path(__file__).resolve().parents[1]
    namespace = f'tayga-test-{os.getpid()}'
    ip = os.environ.get('IP', 'ip')
    subprocess.run([ip, 'netns', 'add', namespace], check=True)
    try:
        names = ['mapfile', 'addressing', 'mapping', 'translate', 'segment']
        if args.big_endian:
            names.append('bigendian')
        for name in names:
            subprocess.run([ip, 'netns', 'exec', namespace, sys.executable,
                            str(root / 'test/integration' / f'{name}.py')], check=True)
    finally:
        subprocess.run([ip, 'netns', 'del', namespace], check=True)


if __name__ == '__main__':
    main()
