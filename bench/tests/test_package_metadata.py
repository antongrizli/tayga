"""Native identity validation using archive structures, without mocked query tools."""
import io
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/ci'))
from package_metadata import ALIASES, read_identity, verify_identity, verify_manifest


def package_bytes(kind, arch, version='1.2.3', revision='1'):
    identity = ALIASES[kind][arch]
    def tar(name, text):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as archive:
            item = tarfile.TarInfo(name)
            body = text.encode(); item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
        return out.getvalue()
    if kind == 'apk':
        return tar('.PKGINFO', f'pkgname = tayga-managed\npkgver = {version}-r{revision}\narch = {identity}\n')
    if kind == 'deb':
        body = tar('control', f'Package: tayga-managed\nVersion: {version}-{revision}\nArchitecture: {identity}\n')
        header = f'{"control.tar.gz/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(body):<10}`\n'.encode()
        return b'!<arch>\n' + header + body + (b'\n' if len(body) % 2 else b'')
    def rpm_header(fields):
        store = b''; entries = b''
        for tag, value in fields.items():
            entries += struct.pack('>IIII', tag, 6, len(store), 1)
            store += value.encode() + b'\0'
        return b'\x8e\xad\xe8\x01' + b'\0' * 4 + struct.pack('>II', len(fields), len(store)) + entries + store
    # RPM signature tag 1000 is an integer size, not the main-header name.
    signature = (b'\x8e\xad\xe8\x01' + b'\0' * 4 + struct.pack('>II', 1, 4)
                 + struct.pack('>IIII', 1000, 4, 0, 1) + struct.pack('>I', 123))
    signature += b'\0' * (-len(signature) % 8)
    return b'\xed\xab\xee\xdb' + b'\0' * 92 + signature + rpm_header({
        1000: 'tayga-managed', 1001: version, 1002: revision, 1022: identity})


class PackageIdentityTests(unittest.TestCase):
    def test_all_formats_and_architectures(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kind, arches in ALIASES.items():
                for arch in arches:
                    with self.subTest(kind=kind, arch=arch):
                        path = Path(tmp) / ('arbitrary-name.' + kind)
                        path.write_bytes(package_bytes(kind, arch))
                        verify_identity(path, '1.2.3', '1', arch)
                        for version, revision, expected_arch in [('1.2.4', '1', arch), ('1.2.3', '2', arch), ('1.2.3', '1', 'amd64' if arch != 'amd64' else 'arm64')]:
                            with self.assertRaisesRegex(ValueError, 'metadata mismatch'):
                                verify_identity(path, version, revision, expected_arch)

    def test_manifest_binds_hashes_and_complete_format_set(self):
        import json
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {}
            for kind in ALIASES:
                path = root / ('package.' + kind)
                path.write_bytes(package_bytes(kind, 'arm64'))
                files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = root / 'manifest.json'
            data = {'version': '1.2.3', 'release': '1', 'arch': 'arm64', 'artifacts': files}
            manifest.write_text(json.dumps(data))
            verify_manifest(manifest)
            (root / 'package.rpm').write_bytes(b'corruption')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                verify_manifest(manifest)
            del files['package.rpm']
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'requires DEB, RPM and APK'):
                verify_manifest(manifest)

    def test_magic_only_is_not_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kind, blob in [('deb', b'!<arch>\n'), ('rpm', b'\xed\xab\xee\xdb'), ('apk', b'\x1f\x8b')]:
                path = Path(tmp) / ('invalid.' + kind); path.write_bytes(blob)
                with self.assertRaises((ValueError, struct.error, tarfile.ReadError, EOFError)):
                    read_identity(path)
