#!/usr/bin/env python3
"""Smoke-test exact release images, hash artifacts, and assemble verified assets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

ARCHES = ('amd64', 'arm64', 'armv7')
FREEBSD_ARCHES = ('amd64', 'arm64')
PROFILES = ('production', 'clat', 'nat64')


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def archive_name(profile, arch):
    return f'tayga-{arch}.tar' if profile == 'production' else f'tayga-{profile}-{arch}.tar'


def smoke(image, profile, source, arch):
    metadata = json.loads(run('docker', 'image', 'inspect', image))[0]
    expected_arch = {'amd64': 'amd64', 'arm64': 'arm64', 'armv7': 'arm'}[arch]
    if metadata['Os'] != 'linux' or metadata['Architecture'] != expected_arch:
        raise ValueError('wrong image platform')
    if arch == 'armv7' and metadata.get('Variant') != 'v7':
        raise ValueError('wrong ARM variant')
    environment = metadata['Config']['Env']
    if f'MODE={"nat64" if profile == "nat64" else "clat"}' not in environment:
        raise ValueError('wrong default image mode')
    labels = metadata['Config']['Labels']
    if labels['org.opencontainers.image.version'] != source['version']:
        raise ValueError('image version mismatch')
    if labels['org.opencontainers.image.revision'] != source['sha']:
        raise ValueError('image source mismatch')
    help_text = run('docker', 'run', '--rm', '--entrypoint', '/usr/sbin/tayga', image, '--help')
    if help_text.splitlines()[0] != f"TAYGA version {source['version']}":
        raise ValueError('binary version mismatch')
    if run('docker', 'run', '--rm', '--entrypoint', '/usr/local/sbin/pref64-discover',
           image, '--check', '64:ff9b::192.0.0.170') != '64:ff9b::/96':
        raise ValueError('prefix helper returned wrong prefix')
    diagnostic = run('docker', 'run', '--rm', '-e', 'MODE=diagnose', image)
    if 'Diagnostics complete.' not in diagnostic:
        raise ValueError('diagnose did not complete')
    modes = ('clat', 'nat64') if profile == 'production' else (profile,)
    for mode in modes:
        # Explicit profiles exercise their baked-in MODE; production exercises both overrides.
        env = ['-e', f'MODE={mode}'] if profile == 'production' else []
        cid = run('docker', 'run', '-d', '--cap-add=NET_ADMIN', '--device=/dev/net/tun',
                  '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv6.conf.all.forwarding=1',
                  '-e', 'PREF64=64:ff9b::/96', '-e', 'ROUTER4=172.17.0.1', *env, image)
        try:
            ready = False
            for _ in range(30):
                state = json.loads(run('docker', 'inspect', cid))[0]['State']
                if not state['Running']:
                    break
                command = f'ip link show {mode} >/dev/null && pidof tayga >/dev/null'
                if mode == 'nat64':
                    command += ' && pidof unbound >/dev/null'
                if subprocess.run(['docker', 'exec', cid, 'sh', '-ec', command],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    ready = True
                    break
                time.sleep(1)
            logs = run('docker', 'logs', cid, stderr=subprocess.STDOUT)
            print(logs)
            if not ready:
                raise ValueError(f'{profile}/{mode} failed readiness')
            if f'TAYGA Unified {mode.upper()}' not in logs:
                raise ValueError('wrong startup mode')
        finally:
            subprocess.run(['docker', 'rm', '-f', cid], check=True, stdout=subprocess.DEVNULL)
    return metadata['Id']


def record(directory, arch, source):
    images = {}
    for profile in PROFILES:
        image = f'tayga-release-{profile}:{arch}'
        image_id = smoke(image, profile, source, arch)
        archive = archive_name(profile, arch)
        subprocess.run(['docker', 'save', '-o', str(directory / archive), image], check=True)
        images[profile] = {'reference': image, 'id': image_id, 'archive': archive, 'smoke': 'pass'}
    names = [archive_name(p, arch) for p in PROFILES] + [f'tayga-linux-{arch}',
             f'pref64-discover-linux-{arch}', 'binary-help.txt', 'install-files.txt']
    data = {'source': source, 'arch': arch, 'images': images,
            'files': {name: sha256(directory / name) for name in names}}
    (directory / 'manifest.json').write_text(json.dumps(data, indent=2) + '\n')


def verify(directory, arch, source):
    data = json.loads((directory / 'manifest.json').read_text())
    if data['source'] != source or data['arch'] != arch:
        raise ValueError(f'{arch}: source/architecture mismatch')
    expected = {archive_name(p, arch) for p in PROFILES} | {f'tayga-linux-{arch}',
                f'pref64-discover-linux-{arch}', 'binary-help.txt', 'install-files.txt'}
    if set(data['files']) != expected or set(data['images']) != set(PROFILES):
        raise ValueError(f'{arch}: incomplete artifact set')
    for name, digest in data['files'].items():
        if not re.fullmatch('[0-9a-f]{64}', digest) or sha256(directory / name) != digest:
            raise ValueError(f'{arch}: artifact hash mismatch: {name}')
    for profile, image in data['images'].items():
        if (image['reference'] != f'tayga-release-{profile}:{arch}' or
                image['archive'] != archive_name(profile, arch) or image['smoke'] != 'pass' or
                not re.fullmatch('sha256:[0-9a-f]{64}', image['id'])):
            raise ValueError(f'{arch}: invalid image evidence')
    return data


def verify_freebsd(directory, arch, source):
    data = json.loads((directory / 'manifest.json').read_text())
    expected = {f'tayga-freebsd-{arch}', f'pref64-discover-freebsd-{arch}'}
    if (data.get('version') != source['version'] or data.get('sha') != source['sha'] or
            data.get('platform') != f'freebsd-{arch}' or data.get('smoke') != 'pass' or
            set(data.get('files', {})) != expected):
        raise ValueError(f'FreeBSD {arch}: invalid source or smoke evidence')
    for name, digest in data['files'].items():
        if not re.fullmatch('[0-9a-f]{64}', digest) or sha256(directory / name) != digest:
            raise ValueError(f'FreeBSD {arch}: hash mismatch: {name}')
    return data


def assemble(root, inputs, output, source, require_signature=False):
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError('asset output must be empty')
    manifests = {}
    for arch in ARCHES:
        directory = inputs / f'candidate-{arch}'
        manifests[arch] = verify(directory, arch, source)
        for name in manifests[arch]['files']:
            if name.endswith('.tar') or '-linux-' in name:
                shutil.copy2(directory / name, output / name)
    builder = root / 'scripts/build-installer.py'
    platforms = []
    for arch in ARCHES:
        directory = inputs / f'candidate-{arch}'
        args = ['--platform', f'linux-{arch}', str(directory / f'tayga-linux-{arch}'),
                str(directory / f'pref64-discover-linux-{arch}')]
        subprocess.run(['python3', str(builder), '--version', source['version'],
                        '--output', str(output / f'tayga-installer-linux-{arch}.sh'), *args], check=True)
        platforms.extend(args)
    subprocess.run(['python3', str(builder), '--version', source['version'],
                    '--output', str(output / 'tayga-installer-linux-universal.sh'), *platforms], check=True)
    freebsd = {}
    for arch in FREEBSD_ARCHES:
        directory = inputs / f'candidate-freebsd-{arch}'
        freebsd[arch] = verify_freebsd(directory, arch, source)
        for name in freebsd[arch]['files']:
            shutil.copy2(directory / name, output / name)
        args = ['--platform', f'freebsd-{arch}', str(directory / f'tayga-freebsd-{arch}'),
                str(directory / f'pref64-discover-freebsd-{arch}')]
        subprocess.run(['python3', str(builder), '--version', source['version'],
                        '--output', str(output / f'tayga-installer-freebsd-{arch}.sh'), *args], check=True)
        platforms.extend(args)
    subprocess.run(['python3', str(builder), '--version', source['version'],
                    '--output', str(output / 'tayga-installer-universal.sh'), *platforms], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        for path in (root / 'deploy/mikrotik').iterdir():
            if path.suffix in ('.rsc', '.md'):
                shutil.copy2(path, staging / path.name)
        subprocess.run(['bash', str(root / 'scripts/update-image-tags.sh'), source['tag'],
                        source['repository'], str(staging)], check=True)
        required = {'routeros-install-clat.rsc': 'clat', 'routeros-install-nat64.rsc': 'nat64',
                    'routeros-upgrade.rsc': 'clat'}
        for name, profile in required.items():
            text = (staging / name).read_text()
            if f"ghcr.io/{source['repository']}-{profile}:{source['tag']}" not in text:
                raise ValueError(f'unpinned RouterOS image: {name}')
        for path in staging.glob('*.rsc'):
            if ':latest' in path.read_text():
                raise ValueError(f'latest image in {path.name}')
            shutil.copy2(path, output / path.name)
        with zipfile.ZipFile(output / 'tayga-routeros-scripts.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(staging.iterdir()):
                archive.write(path, path.name)
    native_manifests = {}
    native_dir = inputs / 'candidate-native'
    if native_dir.is_dir():
        for arch in ARCHES:
            manifest_candidates = list(native_dir.glob(f'tayga-managed-{source["version"]}-*-{arch}.json'))
            if not manifest_candidates:
                raise ValueError(f'candidate-native: missing manifest for arch {arch}')
            manifest_path = manifest_candidates[0]
            data = json.loads(manifest_path.read_text())
            if data.get('version') != source['version']:
                raise ValueError(f'native package manifest version mismatch for {arch}')
            if data.get('source_commit') != source['sha']:
                raise ValueError(f'native package source commit mismatch for {arch}')
            if data.get('arch') != arch:
                raise ValueError(f'native package architecture mismatch for {arch}')
            expected_tayga = manifests[arch]['files'][f'tayga-linux-{arch}']
            expected_helper = manifests[arch]['files'][f'pref64-discover-linux-{arch}']
            if data.get('inputs', {}).get('tayga') != expected_tayga:
                raise ValueError(f'native package input tayga binary hash mismatch for {arch}')
            if data.get('inputs', {}).get('pref64-discover') != expected_helper:
                raise ValueError(f'native package input helper hash mismatch for {arch}')
            for pkg_name, expected_digest in data.get('artifacts', {}).items():
                pkg_file = native_dir / pkg_name
                if not pkg_file.is_file():
                    raise ValueError(f'native package file missing: {pkg_name}')
                if sha256(pkg_file) != expected_digest:
                    raise ValueError(f'native package digest mismatch: {pkg_name}')
                blob = pkg_file.read_bytes()[:16]
                if pkg_name.endswith('.deb') and not blob.startswith(b'!<arch>\n'):
                    raise ValueError(f'invalid deb package format: {pkg_name}')
                elif pkg_name.endswith('.rpm') and not blob.startswith(b'\xed\xab\xee\xdb'):
                    raise ValueError(f'invalid rpm package format: {pkg_name}')
                elif pkg_name.endswith('.apk') and not blob.startswith(b'\x1f\x8b'):
                    raise ValueError(f'invalid apk package format: {pkg_name}')
                shutil.copy2(pkg_file, output / pkg_name)
            native_manifests[arch] = data
        expected_files = {p for m in native_manifests.values() for p in m.get('artifacts', {})}
        for f in native_dir.iterdir():
            if f.is_file() and not f.name.endswith('.json') and f.name not in expected_files:
                raise ValueError(f'candidate-native contains unmanifested file: {f.name}')
    (output / 'release-manifest.json').write_text(json.dumps(
        {'source': source, 'architectures': manifests, 'freebsd': freebsd, 'native': native_manifests}, indent=2) + '\n')
    changelog = (root / 'CHANGELOG.md').read_text()
    notes = re.search(rf"^## \[{re.escape(source['version'])}\].*?\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
    if not notes or not notes.group(1).strip():
        raise ValueError('release notes missing')
    (output / 'release-notes.md').write_text(
        f"# TAYGA {source['tag']}\n\nSource commit: `{source['sha']}`\n\n" + notes.group(1).strip() + '\n')
    sign_manifest(output, require_signature=require_signature)


def checksums(directory):
    (directory / 'SHA256SUMS').write_text(''.join(
        f'{sha256(path)}  {path.name}\n' for path in sorted(directory.iterdir())
        if path.is_file() and path.name != 'SHA256SUMS' and not path.name.endswith('.minisig') and not path.name.endswith('.sig')))


def sign_manifest(directory, require_signature=False):
    checksums(directory)
    sha_file = directory / 'SHA256SUMS'
    if not sha_file.is_file():
        return
    require_signature = (require_signature or
                         os.environ.get('REQUIRE_RELEASE_SIGNATURE', '').lower() in ('1', 'true', 'yes'))
    minisign_key = os.environ.get('MINISIGN_KEY_FILE')
    minisign_key_data = os.environ.get('MINISIGN_KEY_DATA')
    minisign_bin = shutil.which('minisign')

    if require_signature:
        if not minisign_bin:
            raise ValueError('Release signing is required but minisign binary is not found')
        if not minisign_key and not minisign_key_data:
            raise ValueError('Release signing is required but MINISIGN_KEY_FILE / MINISIGN_KEY_DATA is not configured')

    if not minisign_bin or (not minisign_key and not minisign_key_data):
        return

    temp_key_file = None
    key_path = minisign_key
    if not key_path and minisign_key_data:
        t = tempfile.NamedTemporaryFile(mode='w', delete=False)
        t.write(minisign_key_data.strip() + '\n')
        t.close()
        os.chmod(t.name, 0o600)
        temp_key_file = t.name
        key_path = temp_key_file

    try:
        if not Path(key_path).is_file():
            if require_signature:
                raise ValueError(f'Minisign key file not found: {key_path}')
            return
        pw = os.environ.get('MINISIGN_PASSWORD', '')
        sig_file = directory / 'SHA256SUMS.minisig'
        subprocess.run(['minisign', '-S', '-s', key_path, '-m', str(sha_file),
                        '-x', str(sig_file), '-t', 'TAYGA Release Verification'],
                       input=(pw + '\n').encode(), check=True)
        pubkey_file = os.environ.get('MINISIGN_PUBKEY_FILE')
        if not pubkey_file:
            cand = Path(key_path).with_suffix('.pub')
            if cand.is_file():
                pubkey_file = str(cand)
        pubkey = os.environ.get('MINISIGN_PUBKEY')
        if pubkey_file and Path(pubkey_file).is_file():
            subprocess.run(['minisign', '-V', '-p', pubkey_file, '-m', str(sha_file), '-x', str(sig_file)], check=True)
        elif pubkey:
            subprocess.run(['minisign', '-V', '-P', pubkey, '-m', str(sha_file), '-x', str(sig_file)], check=True)
        elif require_signature:
            raise ValueError('Release signature verification requires MINISIGN_PUBKEY or MINISIGN_PUBKEY_FILE')
    finally:
        if temp_key_file and os.path.exists(temp_key_file):
            os.unlink(temp_key_file)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('record', 'verify', 'assemble'))
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--arch', choices=ARCHES)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path)
    parser.add_argument('--require-signature', action='store_true')
    args = parser.parse_args()
    source = json.loads(args.source.read_text())
    if args.action == 'assemble':
        if not args.output:
            parser.error('--output is required for assemble')
        assemble(args.root, args.directory, args.output, source, require_signature=args.require_signature)
    else:
        if not args.arch:
            parser.error('--arch is required')
        if args.action == 'record':
            record(args.directory, args.arch, source)
        verify(args.directory, args.arch, source)


if __name__ == '__main__':
    main()
