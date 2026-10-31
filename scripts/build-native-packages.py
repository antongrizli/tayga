#!/usr/bin/env python3
"""Build binary-only native packages with nFPM; never activates network profiles."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ('tayga-net-ctl.sh', 'tayga-verify.sh', 'tayga-dns64.sh', 'tayga-host-dns.sh',
           'configure.sh', 'wizard.sh', 'tayga-lifecycle.sh', 'tayga-files.sh',
           'tayga-watchdog.sh', 'tayga-recover.sh', 'tayga-boot-recover.sh',
           'tayga-package-upgrade.sh',
           'tayga-managed@.service', 'tayga-managed.openrc', 'tayga-recovery.service',
           'tayga-recovery.openrc', 'freebsd-rc.in', 'freebsd-recovery-rc.in')


def verify_static(path, arch):
    blob = path.read_bytes()
    if len(blob) < 64 or blob[:4] != b'\x7fELF' or blob[5] not in (1, 2):
        raise ValueError(f'not an ELF binary: {path}')
    if blob[4] != (1 if arch in ('armv7', 'armv6') else 2) or blob[5] not in (1, 2) or blob[7] not in (0, 3):
        raise ValueError('unsupported ELF ABI for Linux package')
    endian = '>' if arch == 's390x' else '<'
    if struct.unpack_from(endian + 'H', blob, 16)[0] not in (2, 3):
        raise ValueError('ELF must be executable')
    machines = {
        'amd64': 62,
        'arm64': 183,
        'armv7': 40,
        'armv6': 40,
        'riscv64': 243,
        'ppc64le': 21,
        's390x': 22,
    }
    if struct.unpack_from(endian + 'H', blob, 18)[0] != machines[arch]:
        raise ValueError('ELF architecture mismatch')
    if blob[4] == 2:
        offset = struct.unpack_from(endian + 'Q', blob, 32)[0]
        size, count = struct.unpack_from(endian + 'HH', blob, 54)
        minimum = 56
    elif blob[4] == 1:
        offset = struct.unpack_from(endian + 'I', blob, 28)[0]
        size, count = struct.unpack_from(endian + 'HH', blob, 42)
        minimum = 32
    else:
        raise ValueError('invalid ELF class')
    if not count or size < minimum or offset + size * count > len(blob):
        raise ValueError('invalid ELF program headers')
    if any(struct.unpack_from(endian + 'I', blob, offset + index * size)[0] == 3 for index in range(count)):
        raise ValueError('native release packages require static binaries')


def build(output, version, release, arch, daemon, helper, maintainer, formats, nfpm, source_commit=None):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?', version) or not re.fullmatch(r'[1-9][0-9]*', release):
        raise ValueError('use a semantic x.y.z version and positive package release')
    if any(ord(c) < 32 for c in maintainer) or not re.fullmatch(r'[^<>]+ <[^<>\s]+@[^<>\s]+>', maintainer):
        raise ValueError('maintainer must be Name <email>')
    if source_commit is not None and not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('invalid source commit')
    for path in (daemon, helper):
        verify_static(path, arch)
    output.mkdir(parents=True, exist_ok=True)
    manifest = output / f'tayga-managed-{version}-{release}-{arch}.json'
    if manifest.exists() or manifest.is_symlink():
        raise ValueError(f'refusing to replace {manifest}')
    artifacts = {}
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        for kind in formats:
            contents = []
            def add(target, data, mode=0o644, config=False):
                source = work / kind / target.lstrip('/')
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(data)
                source.chmod(mode)
                item = {'src': str(source), 'dst': target, 'file_info': {'mode': mode}}
                if config:
                    item['type'] = 'config|noreplace'
                contents.append(item)
            add('/usr/sbin/tayga', daemon.read_bytes(), 0o755)
            add('/usr/sbin/pref64-discover', helper.read_bytes(), 0o755)
            add('/usr/sbin/tayga-ctl', (ROOT / 'packaging/installer/tayga-ctl.sh').read_text().replace('/usr/local', '/usr').encode(), 0o755)
            for name in HELPERS:
                target = name.removesuffix('.sh') if name in ('tayga-net-ctl.sh', 'tayga-verify.sh', 'tayga-dns64.sh', 'tayga-host-dns.sh', 'tayga-package-upgrade.sh') else name
                data = (ROOT / 'packaging/installer' / name).read_text().replace('/usr/local', '/usr').encode()
                if name == 'tayga-managed@.service' and kind in ('deb', 'rpm'):
                    data = data.replace(b'Requires=tayga-recovery.service',
                                        b'Requires=tayga-recovery.service tayga-package-recovery.service')
                    data = data.replace(b'After=tayga-recovery.service network-online.target',
                                        b'After=tayga-recovery.service tayga-package-recovery.service network-online.target')
                add('/usr/libexec/tayga/' + target, data, 0o644 if name.endswith('.service') else 0o755)
            add('/usr/libexec/tayga/package-owner', (kind + '\n').encode())
            if kind in ('deb', 'rpm'):
                add('/usr/lib/systemd/system/tayga-package-recovery.service',
                    (ROOT / 'packaging/native/tayga-package-recovery.service').read_bytes())
                contents.append({'src': '../tayga-package-recovery.service',
                                 'dst': '/usr/lib/systemd/system/multi-user.target.wants/tayga-package-recovery.service',
                                 'type': 'symlink'})


            if kind == 'apk':
                add('/usr/libexec/tayga/package-lock.sh', (ROOT / 'packaging/native/package-lock.sh').read_bytes(), 0o755)
            for name, section in (('tayga.8', '8'), ('tayga.conf.5', '5')):
                add('/usr/share/man/man' + section + '/' + name, (ROOT / 'docs/man' / name).read_bytes())
            add('/usr/share/doc/tayga-managed/LICENSE', (ROOT / 'LICENSE').read_bytes())
            add('/etc/tayga/tayga.conf.example', (ROOT / 'packaging/tayga.conf.example').read_bytes(), config=True)
            nfpm_arch = {'armv7': 'arm7', 'armv6': 'arm6'}.get(arch, arch)
            config = {'name': 'tayga-managed', 'arch': nfpm_arch, 'platform': 'linux', 'version': version,
                      'release': release, 'maintainer': maintainer, 'description': 'TAYGA binary tools and explicit managed profile activation',
                      'license': 'GPL-2.0-or-later', 'contents': contents, 'conflicts': ['tayga'],
                      'scripts': {'preinstall': str(ROOT / 'packaging/native/preinstall.sh'),
                                  'preremove': str(ROOT / 'packaging/native/preremove.sh')},
                      'overrides': {'deb': {'depends': ['iproute2', 'curl', 'procps', 'util-linux', 'coreutils', 'diffutils', 'nftables']},
                                    'rpm': {'depends': ['iproute', 'curl', 'procps-ng', 'util-linux', 'coreutils', 'diffutils', 'nftables']},
                                    'apk': {'depends': ['iproute2', 'curl', 'flock', 'coreutils', 'diffutils', 'nftables']}},
                      'apk': {'scripts': {'preupgrade': str(ROOT / 'packaging/native/preinstall.sh')}}}
            config_path = work / f'{kind}.json'
            config_path.write_text(json.dumps(config))
            target = output / f'tayga-managed-{version}-{release}-{arch}.{kind}'
            if target.exists() or target.is_symlink():
                raise ValueError(f'refusing to replace {target}')
            subprocess.run([nfpm, 'package', '--packager', kind, '--config', str(config_path), '--target', str(target)], check=True)
            artifacts[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = output / f'tayga-managed-{version}-{release}-{arch}.json'
    manifest.write_text(json.dumps({'version': version, 'release': release, 'arch': arch,
                                   'inputs': {'tayga': hashlib.sha256(daemon.read_bytes()).hexdigest(), 'pref64-discover': hashlib.sha256(helper.read_bytes()).hexdigest()},
                                   'artifacts': artifacts, 'signed': False, 'source_commit': source_commit}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--release', default='1')
    parser.add_argument('--arch', choices=('amd64', 'arm64', 'armv7', 'armv6', 'riscv64', 'ppc64le', 's390x'), required=True)
    parser.add_argument('--tayga', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--maintainer', required=True)
    parser.add_argument('--format', choices=('deb', 'rpm', 'apk'), action='append')
    parser.add_argument('--nfpm', default='nfpm')
    parser.add_argument('--source-commit')
    args = parser.parse_args()
    build(args.output.resolve(), args.version, args.release, args.arch, args.tayga, args.helper,
          args.maintainer, args.format or ['deb', 'rpm', 'apk'], args.nfpm, args.source_commit)
