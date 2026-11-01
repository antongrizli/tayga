#!/usr/bin/env python3
"""Export original-version SDK packages before upgrade fixtures rebuild them."""
import argparse
import hashlib
import io
import tarfile
import json
from pathlib import Path
import re
import shutil
import subprocess

ROLES = ('base', 'procd', 'network', 'upgrader')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_ipk_identity(path):
    def member(archive, name):
        matches = [m for m in archive if m.name.removeprefix('./') == name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 1024 * 1024:
            raise ValueError('Invalid IPK control metadata')
        return archive.extractfile(matches[0]).read()
    with tarfile.open(path) as archive:
        control = member(archive, 'control.tar.gz')
    with tarfile.open(fileobj=io.BytesIO(control)) as archive:
        text = member(archive, 'control').decode()
    fields = dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line and not line.startswith(' '))
    return fields['Package'], fields['Version'], fields['Architecture']


def read_apk_identity(path, apk_tool):
    result = subprocess.run([str(apk_tool), 'adbdump', '--format', 'json', str(path)],
                            check=True, capture_output=True, text=True, timeout=60)
    info = json.loads(result.stdout)['info']
    return info['name'], info['version'], info['arch']


def export(sdk, output, spec, source):
    if output.exists():
        raise ValueError('OpenWrt candidate output already exists')
    metadata = json.loads((sdk / 'package/tayga-managed-openwrt/source-manifest.json').read_text())
    if (metadata['version'] != source['version'] or metadata['target'] != 'armsr'
            or metadata['subtarget'] != 'armv8' or metadata['architecture'] != 'aarch64_generic'):
        raise ValueError('OpenWrt SDK source identity mismatch')
    packages = {}
    selected = {}
    for role in ROLES:
        name = 'tayga-managed-openwrt' + {'base': '', 'upgrader': '-upgrade'}.get(role, '-' + role)
        separator = '_' if spec['format'] == 'ipk' else '-'
        pattern = re.compile(re.escape(name + separator + source['version']) + r'-r[^/]+\.' + spec['format'])
        matches = [p for p in (sdk / 'bin/packages').rglob('*') if p.is_file() and pattern.fullmatch(p.name)]
        if len(matches) != 1:
            raise ValueError(f'Expected exactly one original-version OpenWrt archive for {role}')
        selected[role] = matches[0]
    output.mkdir(parents=True)
    for role, path in selected.items():
        name = f'openwrt-{spec["release"]}-armsr-armv8-{path.name}'
        shutil.copyfile(path, output / name)
        identity = (read_apk_identity(output / name, sdk / 'staging_dir/host/bin/apk')
                    if spec['format'] == 'apk' else read_ipk_identity(output / name))
        packages[role] = {'name': name, 'sha256': digest(output / name), 'identity': list(identity)}
    manifest = {'source': source, 'platform': spec, 'sdk_source': metadata, 'packages': packages}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    verify(output, spec, source)


def verify(directory, spec, source):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if any(manifest['source'].get(k) != source[k] for k in ('sha', 'version')) or manifest['platform'] != spec:
        raise ValueError('OpenWrt release/source mismatch')
    metadata = manifest.get('sdk_source', {})
    if (metadata.get('version') != source['version'] or metadata.get('target') != 'armsr'
            or metadata.get('subtarget') != 'armv8' or metadata.get('architecture') != 'aarch64_generic'):
        raise ValueError('OpenWrt SDK source identity mismatch')
    if set(manifest['packages']) != set(ROLES):
        raise ValueError('Incomplete OpenWrt subpackage set')
    names = set()
    revisions = set()
    for role, package in manifest['packages'].items():
        name = package['name']
        if (Path(name).name != name or not name.startswith(f'openwrt-{spec["release"]}-armsr-armv8-')
                or not name.endswith('.' + spec['format']) or name in names):
            raise ValueError('Invalid OpenWrt release archive name')
        names.add(name)
        if digest(directory / name) != package['sha256']:
            raise ValueError('OpenWrt release archive checksum mismatch')
        if spec['format'] == 'apk' and (directory / name).read_bytes()[:4] != b'ADBd':
            raise ValueError('Pinned OpenWrt APK branch requires APK3 ADB archives, not Alpine APK')
        identity = (read_ipk_identity(directory / name) if spec['format'] == 'ipk'
                    else package.get('identity'))
        expected_name = 'tayga-managed-openwrt' + {'base': '', 'upgrader': '-upgrade'}.get(role, '-' + role)
        if (not isinstance(identity, (tuple, list)) or len(identity) != 3
                or identity[0] != expected_name or identity[2] != 'aarch64_generic'
                or not re.fullmatch(re.escape(source['version']) + r'-r[1-9][0-9]*', identity[1])):
            raise ValueError(f'OpenWrt {spec["format"].upper()} package identity mismatch')
        revisions.add(identity[1])
    if len(revisions) > 1:
        raise ValueError('Mixed OpenWrt package revisions')
    if {p.name for p in directory.iterdir()} != names | {'manifest.json'}:
        raise ValueError('Unexpected OpenWrt candidate files')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--source-sha', help='Explicit source identity for staged source archives without .git')
    args = parser.parse_args()
    from release_platforms import CONTRACT
    spec = next(s for s in CONTRACT['openwrt'] if s['release'] == args.release)
    sha = args.source_sha or subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        parser.error('Invalid source SHA')
    source = {'sha': sha, 'version': Path('VERSION').read_text().strip()}
    export(args.sdk, args.output, spec, source)
