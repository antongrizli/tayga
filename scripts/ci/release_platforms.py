#!/usr/bin/env python3
"""The enabled release inventory; pending targets are never advertised as built."""
import argparse
import json
from pathlib import Path

CONTRACT_PATH = Path(__file__).resolve().parents[2] / 'packaging/release-platforms.json'
CONTRACT = json.loads(CONTRACT_PATH.read_text())
LINUX_ARCHES = tuple(item['arch'] for item in CONTRACT['linux'])
CONTAINER_ARCHES = tuple(CONTRACT['container_arches'])
FREEBSD_ARCHES = tuple(CONTRACT['freebsd'])
NATIVE_FORMATS = tuple(CONTRACT['native_formats'])
PROFILES = tuple(CONTRACT['container_profiles'])
if CONTRACT['schema'] != 1 or len(set(LINUX_ARCHES)) != len(LINUX_ARCHES):
    raise ValueError('Invalid release platform contract')


def required_assets(native):
    """Return mandatory unsigned bundle members, using verified native filenames."""
    names = {'release-manifest.json', 'release-notes.md',
             'tayga-installer-linux-universal.sh', 'tayga-installer-universal.sh',
             'tayga-routeros-scripts.zip'}
    names.update(CONTRACT['routeros_scripts'])
    for system, arches in (('linux', LINUX_ARCHES), ('freebsd', FREEBSD_ARCHES)):
        for arch in arches:
            names.update({f'tayga-{system}-{arch}', f'pref64-discover-{system}-{arch}',
                          f'tayga-installer-{system}-{arch}.sh'})
    for arch in LINUX_ARCHES:
        if arch not in native:
            raise ValueError(f'Missing native package manifest: {arch}')
        packages = native[arch].get('artifacts', {})
        for fmt in NATIVE_FORMATS:
            if not any(Path(name).suffix == f'.{fmt}' for name in packages):
                raise ValueError(f'Missing native format {fmt} for {arch}')
        if len(packages) != len(NATIVE_FORMATS):
            raise ValueError(f'Expected exactly one native package per format for {arch}')
        names.update(packages)
        for profile in (PROFILES if arch in CONTAINER_ARCHES else ()):
            names.add(f'tayga-{arch}.tar' if profile == 'production' else f'tayga-{profile}-{arch}.tar')
    return names


def required_signed_assets(manifest):
    names = required_assets(manifest.get('native', {}))
    from openwrt_release import ROLES
    for spec in CONTRACT['openwrt']:
        data = manifest.get('openwrt', {}).get(spec['release'])
        if not data or data.get('platform') != spec or set(data.get('packages', {})) != set(ROLES):
            raise ValueError(f'Missing or incomplete OpenWrt release {spec["release"]}')
        for package in data['packages'].values():
            name = package['name']
            if Path(name).name != name or not name.endswith('.' + spec['format']):
                raise ValueError('Invalid OpenWrt archive in signed manifest')
            names.add(name)
    return names


def verify_assets(directory, native, openwrt=None):
    expected = (required_assets(native) if openwrt is None else
                required_signed_assets({'native': native, 'openwrt': openwrt}))
    actual = {p.name for p in directory.iterdir() if p.is_file()}
    missing = expected - actual
    if missing:
        raise ValueError(f'Release bundle missing required assets: {sorted(missing)}')
    extra = actual - expected
    if extra:
        raise ValueError(f'Release bundle contains unexpected assets: {sorted(extra)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', choices=('matrix', 'linux-arches'))
    args = parser.parse_args()
    print(json.dumps({'include': CONTRACT['linux']}) if args.output == 'matrix' else ' '.join(LINUX_ARCHES))
