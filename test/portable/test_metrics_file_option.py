#!/usr/bin/env python3
"""--metrics-file start-up validation, reachable without root through --check-config."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('TAYGA_BIN', ROOT / 'build/tayga'))


@unittest.skipUnless(BINARY.exists(), f'{BINARY} is not built (the daemon builds on Linux only)')
class MetricsFileOptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        temp = Path(self.temp.name)
        (temp / 'data').mkdir()
        self.config = temp / 'tayga.conf'
        self.config.write_text(f'tun-device metrics0\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\n'
                               f'dynamic-pool 192.0.2.128/25\ndata-dir {temp}/data\n')

    def run_tayga(self, *args, env=None):
        environment = {k: v for k, v in os.environ.items() if not k.startswith('TAYGA_')}
        environment.update(env or {})
        return subprocess.run([str(BINARY), '--check-config', '-c', str(self.config), *args],
                              capture_output=True, text=True, env=environment)

    def test_relative_path_is_rejected(self):
        result = self.run_tayga('--metrics-file', 'm.prom')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('metrics-file must be an absolute path', result.stderr)

    def test_overlong_path_is_rejected(self):
        result = self.run_tayga('--metrics-file', '/' + 'a' * 767)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('metrics-file must be an absolute path of at most 767 bytes', result.stderr)

    def test_longest_path_is_accepted(self):
        self.assertEqual(self.run_tayga('--metrics-file', '/' + 'a' * 766).returncode, 0)

    def test_status_path_is_rejected(self):
        for candidate in ('/tmp/a', '/tmp//a', '/tmp/./a'):
            result = self.run_tayga('--status-file', '/tmp/a', '--metrics-file', candidate)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('metrics-file must differ from status-file', result.stderr)

    def test_distinct_absolute_path_is_accepted(self):
        result = self.run_tayga('--status-file', '/tmp/a', '--metrics-file', '/tmp/b.prom')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_environment_variable_is_validated_and_option_wins(self):
        result = self.run_tayga(env={'TAYGA_METRICS_FILE': 'relative.prom'})
        self.assertIn('metrics-file must be an absolute path', result.stderr)
        result = self.run_tayga('--metrics-file', '/tmp/b.prom', env={'TAYGA_METRICS_FILE': 'relative.prom'})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_documents_the_option(self):
        result = subprocess.run([str(BINARY), '--help'], capture_output=True, text=True)
        self.assertIn('--metrics-file', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
