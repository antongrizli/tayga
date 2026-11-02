"""Release export must retain the tested version and require every subpackage."""
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/ci'))
release = importlib.import_module('openwrt_release')
platforms = importlib.import_module('release_platforms')


def ipk_bytes(role, version='1.2.3'):
    import io
    import tarfile
    def tar(name, body):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            item = tarfile.TarInfo(name); item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
        return stream.getvalue()
    name = 'tayga-managed-openwrt' + {'base': '', 'upgrader': '-upgrade'}.get(role, '-' + role)
    return tar('control.tar.gz', tar('control', f'Package: {name}\nVersion: {version}-r1\nArchitecture: aarch64_generic\n'.encode()))


class OpenWrtReleaseTests(unittest.TestCase):
    def test_export_verify_and_reject_incomplete_corrupt_or_mixed_candidates(self):
        for spec in platforms.CONTRACT['openwrt']:
            with self.subTest(spec=spec), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = root / 'sdk'
                metadata = sdk / 'package/tayga-managed-openwrt/source-manifest.json'
                metadata.parent.mkdir(parents=True)
                metadata.write_text(json.dumps({'version': '1.2.3', 'target': 'armsr',
                    'subtarget': 'armv8', 'architecture': 'aarch64_generic'}))
                binary = sdk / 'bin/packages/arch/feed'
                binary.mkdir(parents=True)
                for role in release.ROLES:
                    suffix = {'base': '', 'upgrader': '-upgrade'}.get(role, '-' + role)
                    sep = '_' if spec['format'] == 'ipk' else '-'
                    for version in ('1.2.3', '1.2.4'):
                        name = f'tayga-managed-openwrt{suffix}{sep}{version}-r1'
                        if spec['format'] == 'ipk':
                            name += '_aarch64_generic'
                        (binary / (name + '.' + spec['format'])).write_bytes(ipk_bytes(role, version) if spec['format'] == 'ipk' else b'ADBd' + version.encode())
                source = {'sha': 'a' * 40, 'version': '1.2.3'}
                out = root / 'candidate'
                def apk_identity(path, tool):
                    name = path.name.split('armsr-armv8-')[1].split('-1.2.3-r1.apk')[0]
                    return name, '1.2.3-r1', 'aarch64_generic'
                with patch.object(release, 'read_apk_identity', side_effect=apk_identity):
                    release.export(sdk, out, spec, source)
                manifest = release.verify(out, spec, source)
                self.assertEqual(len(manifest['packages']), 4)
                with self.assertRaisesRegex(ValueError, 'source mismatch'):
                    release.verify(out, spec, {**source, 'sha': 'b' * 40})
                with self.assertRaisesRegex(ValueError, 'source mismatch'):
                    release.verify(out, spec, {**source, 'version': '1.2.4'})
                for package in manifest['packages'].values():
                    path = out / package['name']
                    original = path.read_bytes()
                    if spec['format'] == 'apk':
                        self.assertEqual(original, b'ADBd1.2.3')
                    path.write_bytes(b'corrupt')
                    with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                        release.verify(out, spec, source)
                    path.write_bytes(original)
                if spec['format'] == 'ipk':
                    base = manifest['packages']['base']
                    path = out / base['name']; original = path.read_bytes()
                    path.write_bytes(ipk_bytes('procd', '1.2.3'))
                    base['sha256'] = release.digest(path)
                    (out / 'manifest.json').write_text(json.dumps(manifest))
                    with self.assertRaisesRegex(ValueError, 'IPK package identity'):
                        release.verify(out, spec, source)
                    path.write_bytes(original); base['sha256'] = release.digest(path)
                if spec['format'] == 'apk':
                    base = manifest['packages']['base']
                    path = out / base['name']; original = path.read_bytes()
                    path.write_bytes(b'\x1f\x8bAlpine package')
                    base['sha256'] = release.digest(path)
                    (out / 'manifest.json').write_text(json.dumps(manifest))
                    with self.assertRaisesRegex(ValueError, 'APK3 ADB'):
                        release.verify(out, spec, source)
                    path.write_bytes(original); base['sha256'] = release.digest(path)
                    original_identity = base['identity']
                    for identity in (None, ['tayga-managed-openwrt-procd', '1.2.3-r1', 'aarch64_generic'],
                                     ['tayga-managed-openwrt', '1.2.4-r1', 'aarch64_generic'],
                                     ['tayga-managed-openwrt', '1.2.3-r1', 'x86_64']):
                        if identity is None:
                            base.pop('identity', None)
                        else:
                            base['identity'] = identity
                        (out / 'manifest.json').write_text(json.dumps(manifest))
                        with self.assertRaisesRegex(ValueError, 'APK package identity'):
                            release.verify(out, spec, source)
                    base['identity'] = original_identity
                del manifest['packages']['network']
                (out / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, 'Incomplete'):
                    release.verify(out, spec, source)
