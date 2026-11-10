#!/usr/bin/env python3
"""The RA supervisor's published prefix reaches the readiness probe, status and unit files."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / 'packaging/installer'


class ActivePrefixTests(unittest.TestCase):
    def verify_synthesis_argument(self, active_text):
        """Run tayga-verify against a stubbed toolchain; return the prefix it synthesized from."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            seen = root / 'seen'
            for name in ('ip', 'ifconfig'):	# Linux and FreeBSD interface checks
                (bin_dir / name).write_text('#!/bin/sh\nexit 0\n')
            # Stand-in helper: record the prefix, then fail so the probe stops there.
            (bin_dir / 'pref64-discover').write_text(f'#!/bin/sh\necho "$2" > {seen}\nexit 1\n')
            for stub in bin_dir.iterdir():
                stub.chmod(0o755)
            runtime = root / 'runtime'
            runtime.mkdir()
            if active_text is not None:
                (runtime / 'active-prefix').write_text(active_text)
            config = root / 'nat64.conf'
            config.write_text('# installer-mode nat64\ntun-device nat64\nprefix 64:ff9b::/96\n')
            env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', TAYGA_VERIFY_RUNTIME=str(runtime))
            subprocess.run(['sh', str(INSTALLER / 'tayga-verify.sh'), str(config)], env=env,
                           capture_output=True, text=True)
            return seen.read_text().strip() if seen.exists() else None

    def test_probe_uses_the_published_prefix(self):
        self.assertEqual(self.verify_synthesis_argument('2001:db8:64::/96 rfc8781\n'), '2001:db8:64::/96')

    def test_probe_falls_back_to_the_profile_prefix(self):
        self.assertEqual(self.verify_synthesis_argument(None), '64:ff9b::/96')

    def test_malformed_published_value_is_ignored(self):
        self.assertEqual(self.verify_synthesis_argument('$(touch pwned)/96 rfc8781\n'), '64:ff9b::/96')

    def test_every_service_template_hands_the_runtime_directory_to_the_supervisor(self):
        for name, token in (('tayga-managed@.service', '--runtime-dir /run/tayga-managed-%i --'),
                            ('tayga-managed.openrc', '--runtime-dir /run/tayga-managed-$profile --'),
                            ('freebsd-rc.in', '--runtime-dir "/var/run/tayga-managed-${profile}" --')):
            self.assertIn(token, (INSTALLER / name).read_text(), name)

    def test_status_reports_the_published_prefix(self):
        text = (INSTALLER / 'tayga-ctl.sh').read_text()
        self.assertIn('active-prefix', text)
        subprocess.run(['sh', '-n', str(INSTALLER / 'tayga-ctl.sh')], check=True)


if __name__ == '__main__':
    unittest.main()
