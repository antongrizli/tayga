#!/usr/bin/env python3
"""Record native FreeBSD static binaries with source identity and smoke evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    machine = {'amd64': 'amd64', 'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if platform.system() != 'FreeBSD' or machine != args.arch:
        raise ValueError('native FreeBSD architecture does not match candidate')
    version = Path('VERSION').read_text().strip()
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    help_text = subprocess.check_output(['./tayga', '--help'], text=True)
    if help_text.splitlines()[0] != f'TAYGA version {version}':
        raise ValueError('binary version mismatch')
    prefix = subprocess.check_output(['./pref64-discover', '--check', '64:ff9b::192.0.0.170'], text=True).strip()
    if prefix != '64:ff9b::/96':
        raise ValueError('prefix smoke check failed')
    args.output.mkdir(parents=True, exist_ok=True)
    files = {}
    for binary in ('tayga', 'pref64-discover'):
        headers = subprocess.check_output(['readelf', '-l', binary], text=True)
        if 'INTERP' in headers:
            raise ValueError(f'{binary} has a dynamic interpreter')
        name = f'{binary}-freebsd-{args.arch}'
        path = args.output / name
        shutil.copy2(binary, path)
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (args.output / 'manifest.json').write_text(json.dumps(
        {'version': version, 'sha': sha, 'platform': f'freebsd-{args.arch}',
         'smoke': 'pass', 'files': files}, indent=2) + '\n')


if __name__ == '__main__':
    main()
