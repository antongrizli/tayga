"""Native package ABI validation and staged contents; real archives have VM coverage."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_packages', ROOT / 'scripts/build-native-packages.py')
packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'binary'
        blob = bytearray(120)
        blob[:8] = b'\x7fELF\x02\x01\x01\x00'
        struct.pack_into('<HH', blob, 16, 2, 183)
        struct.pack_into('<Q', blob, 32, 64)
        struct.pack_into('<HH', blob, 54, 56, 1)
        struct.pack_into('<I', blob, 64, 1)
        self.binary.write_bytes(blob)

    def test_wrong_arch_and_dynamic_interpreter_are_rejected(self):
        packages.verify_static(self.binary, 'arm64')
        with self.assertRaises(ValueError):
            packages.verify_static(self.binary, 'amd64')
        blob = bytearray(self.binary.read_bytes())
        struct.pack_into('<I', blob, 64, 3)
        self.binary.write_bytes(blob)
        with self.assertRaisesRegex(ValueError, 'static'):
            packages.verify_static(self.binary, 'arm64')

    def test_linux_package_rejects_freebsd_abi(self):
        blob = bytearray(self.binary.read_bytes())
        blob[7] = 9
        self.binary.write_bytes(blob)
        with self.assertRaisesRegex(ValueError, 'ABI'):
            packages.verify_static(self.binary, 'arm64')

    def test_staged_paths_config_and_package_manifest(self):
        tool = self.root / 'nfpm'
        tool.write_text('#!' + sys.executable + '\n' + '''import json, pathlib, sys
args=sys.argv[1:]
config=json.loads(pathlib.Path(args[args.index('--config')+1]).read_text())
for item in config['contents']:
    if item['dst']=='/usr/sbin/tayga-ctl': config['ctl']=pathlib.Path(item['src']).read_text()
pathlib.Path(args[args.index('--target')+1]).write_text(json.dumps(config))
''')
        tool.chmod(0o755)
        output = self.root / 'output'
        args = (output, '0.9.14', '1', 'arm64', self.binary, self.binary,
                'Local test <test@example.invalid>', ['deb'], str(tool))
        packages.build(*args)
        data = json.loads((output / 'tayga-managed-0.9.14-1-arm64.deb').read_text())
        self.assertNotIn('/usr/local', data['ctl'])
        config = next(item for item in data['contents'] if item['dst']=='/etc/tayga/tayga.conf.example')
        self.assertEqual(config['type'], 'config|noreplace')
        self.assertIn('preremove', data['scripts'])
        manifest = json.loads((output / 'tayga-managed-0.9.14-1-arm64.json').read_text())
        self.assertFalse(manifest['signed'])
        with self.assertRaises(ValueError):
            packages.build(*args)
