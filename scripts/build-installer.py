#!/usr/bin/env python3
"""Build a text-only self-extracting binary package from prepared binaries."""
import argparse
import base64
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def build(output, version, platforms):
    if not re.fullmatch(r'[A-Za-z0-9._+-]+', version):
        raise ValueError('invalid version')
    entries = {}
    for platform, tayga, helper in platforms:
        if not re.fullmatch(r'(linux-(amd64|arm64|armv7|armv6|riscv64|ppc64le|s390x)|freebsd-(amd64|arm64))', platform):
            raise ValueError(f'unsupported platform: {platform}')
        for name, path in [('tayga', tayga), ('pref64-discover', helper)]:
            key = f'bin/{platform}/{name}'
            if key in entries:
                raise ValueError(f'duplicate platform: {platform}')
            entries[key] = (Path(path).read_bytes(), 0o755)
    if not entries:
        raise ValueError('at least one platform is required')
    for name in ('tayga.8', 'tayga.conf.5'):
        entries[f'man/{name}'] = ((ROOT / 'docs/man' / name).read_bytes(), 0o644)
    for name in ('systemd/tayga@.service', 'openrc/tayga.initd', 'openrc/tayga.confd'):
        entries[f'packaging/{name}'] = ((ROOT / 'packaging' / name).read_bytes(), 0o644)
    entries['installer/configure.sh'] = ((ROOT / 'packaging/installer/configure.sh').read_bytes(), 0o755)
    entries['installer/tayga-net-ctl.sh'] = ((ROOT / 'packaging/installer/tayga-net-ctl.sh').read_bytes(), 0o755)
    for name in ('tayga-ctl.sh', 'tayga-verify.sh', 'tayga-dns64.sh', 'tayga-host-dns.sh', 'tayga-managed@.service', 'tayga-managed.openrc', 'wizard.sh', 'tayga-lifecycle.sh', 'tayga-files.sh', 'tayga-watchdog.sh', 'tayga-recover.sh', 'tayga-boot-recover.sh', 'tayga-recovery.service', 'tayga-recovery.openrc', 'freebsd-rc.in', 'freebsd-recovery-rc.in'):
        entries[f'installer/{name}'] = ((ROOT / 'packaging/installer' / name).read_bytes(), 0o755 if (name.endswith('.sh') or name.endswith('.in')) else 0o644)
    entries['installer/fallback.sh'] = ((ROOT / 'packaging/installer/fallback.sh').read_bytes(), 0o755)
    entries['installer/dependencies.sh'] = ((ROOT / 'packaging/installer/dependencies.sh').read_bytes(), 0o755)
    # Sources share the SFX payload's integrity check; no remote tar is extracted.
    sources = [ROOT / 'Makefile', ROOT / 'VERSION', ROOT / 'LICENSE']
    sources += sorted((ROOT / 'mk').glob('*.mk'))
    sources += sorted(path for path in (ROOT / 'src').rglob('*') if path.suffix in ('.c', '.h'))
    for path in sources:
        entries[f'source/{path.relative_to(ROOT).as_posix()}'] = (path.read_bytes(), 0o644)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, (data, mode) in sorted(entries.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            archive.addfile(info, io.BytesIO(data))
    payload = gzip.compress(raw.getvalue(), mtime=0)
    header = (ROOT / 'packaging/installer/install-header.sh').read_text()
    header = header.replace('@VERSION@', version).replace('@CHECKSUM@', hashlib.sha256(payload).hexdigest())
    header = header.replace('@PAYLOAD@', base64.encodebytes(payload).decode().rstrip('\n'))
    output.write_text(header)
    output.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--platform', nargs=3, action='append', metavar=('OS-ARCH', 'TAYGA', 'HELPER'), required=True)
    args = parser.parse_args()
    build(args.output, args.version, args.platform)


if __name__ == '__main__':
    main()
