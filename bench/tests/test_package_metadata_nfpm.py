"""Opt-in real nFPM metadata tests; these empty packages do not certify runtime."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/ci'))
from package_metadata import ALIASES, verify_identity


@unittest.skipUnless(os.environ.get('NFPM_TEST_BINARY'), 'Set NFPM_TEST_BINARY to verified nFPM 2.48.0')
class RealNfpmMetadataTests(unittest.TestCase):
    def test_real_architecture_and_format_matrix(self):
        tool = str(Path(os.environ['NFPM_TEST_BINARY']).resolve())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for arch in ALIASES['deb']:
                config = root / f'{arch}.json'
                config.write_text(json.dumps({'name': 'tayga-managed',
                    'arch': {'armv6': 'arm6', 'armv7': 'arm7'}.get(arch, arch),
                    'platform': 'linux', 'version': '0.9.14', 'release': '101',
                    'maintainer': 'TAYGA Tests <tests@example.invalid>',
                    'description': 'Metadata-only fixture, no executable payload'}))
                for kind in ALIASES:
                    with self.subTest(arch=arch, kind=kind):
                        target = root / f'{arch}.{kind}'
                        subprocess.run([tool, 'package', '--packager', kind, '--config', str(config),
                                        '--target', str(target)], check=True, capture_output=True)
                        verify_identity(target, '0.9.14', '101', arch)
