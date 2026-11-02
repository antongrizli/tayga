"""Read native package identity without running maintainer scripts or extracting files."""
import io
import struct
import tarfile

ALIASES = {
    'deb': {'amd64': 'amd64', 'arm64': 'arm64', 'armv7': 'armhf', 'armv6': 'armhf',
            'riscv64': 'riscv64', 'ppc64le': 'ppc64el', 's390x': 's390x'},
    'rpm': {'amd64': 'x86_64', 'arm64': 'aarch64', 'armv7': 'armv7hl', 'armv6': 'armv6hl',
            'riscv64': 'riscv64', 'ppc64le': 'ppc64le', 's390x': 's390x'},
    'apk': {'amd64': 'x86_64', 'arm64': 'aarch64', 'armv7': 'armv7', 'armv6': 'armhf',
            'riscv64': 'riscv64', 'ppc64le': 'ppc64le', 's390x': 's390x'}}


def tar_text(blob, name):
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:*') as archive:
        matches = [m for m in archive if m.name.removeprefix('./') == name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 1024 * 1024:
            raise ValueError('Missing or invalid package metadata member')
        return archive.extractfile(matches[0]).read().decode()


def read_identity(path):
    blob = path.read_bytes()
    kind = path.suffix[1:]
    if kind == 'deb':
        if not blob.startswith(b'!<arch>\n'):
            raise ValueError('Invalid DEB archive')
        offset, controls = 8, []
        while offset < len(blob):
            header = blob[offset:offset + 60]
            if len(header) != 60 or header[58:60] != b'`\n':
                raise ValueError('Malformed DEB member')
            size = int(header[48:58])
            data = blob[offset + 60:offset + 60 + size]
            if len(data) != size:
                raise ValueError('Truncated DEB member')
            if header[:16].decode().strip().rstrip('/').startswith('control.tar'):
                controls.append(data)
            offset += 60 + size + size % 2
        if len(controls) != 1:
            raise ValueError('DEB requires one control archive')
        fields = dict(line.split(': ', 1) for line in tar_text(controls[0], 'control').splitlines() if ': ' in line and not line.startswith(' '))
        return fields['Package'], fields['Version'], fields['Architecture']
    if kind == 'apk':
        fields = dict(line.split(' = ', 1) for line in tar_text(blob, '.PKGINFO').splitlines() if ' = ' in line)
        return fields['pkgname'], fields['pkgver'], fields['arch']
    if kind == 'rpm':
        if blob[:4] != b'\xed\xab\xee\xdb':
            raise ValueError('Invalid RPM lead')
        def header(offset, identity=True):
            if blob[offset:offset + 4] != b'\x8e\xad\xe8\x01':
                raise ValueError('Invalid RPM header')
            count, size = struct.unpack_from('>II', blob, offset + 8)
            start = offset + 16 + count * 16
            if start + size > len(blob):
                raise ValueError('Truncated RPM header')
            values = {}
            for i in range(count):
                tag, typ, pos, length = struct.unpack_from('>IIII', blob, offset + 16 + i * 16)
                if identity and tag in (1000, 1001, 1002, 1022):
                    if typ != 6 or length != 1 or pos >= size:
                        raise ValueError('Invalid RPM identity field')
                    values[tag] = blob[start + pos:start + size].split(b'\0', 1)[0].decode()
            return values, start + size
        _, end = header(96, identity=False)
        fields, _ = header((end + 7) & ~7)
        return fields[1000], fields[1001] + '-' + fields[1002], fields[1022]
    raise ValueError('Unsupported native package format')


def verify_identity(path, version, revision, arch):
    kind = path.suffix[1:]
    expected_version = version + ('-r' if kind == 'apk' else '-') + str(revision)
    expected = ('tayga-managed', expected_version, ALIASES[kind][arch])
    actual = read_identity(path)
    if actual != expected:
        raise ValueError(f'Native package metadata mismatch: {path.name}: {actual!r} != {expected!r}')


def verify_manifest(path):
    """Check the exact native archives emitted by the builder, before CI upload."""
    import hashlib
    import json
    from pathlib import Path
    data = json.loads(path.read_text())
    artifacts = data.get('artifacts', {})
    if len(artifacts) != 3 or {Path(name).suffix for name in artifacts} != {'.deb', '.rpm', '.apk'}:
        raise ValueError('Native manifest requires DEB, RPM and APK archives')
    for name, expected in artifacts.items():
        if Path(name).name != name:
            raise ValueError('Invalid native archive path')
        archive = path.parent / name
        with archive.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError(f'Native archive hash mismatch: {name}')
        verify_identity(archive, data['version'], data['release'], data['arch'])


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    verify_manifest(args.manifest)
    print(f'PASS: native archive hashes and metadata: {args.manifest.name}')
