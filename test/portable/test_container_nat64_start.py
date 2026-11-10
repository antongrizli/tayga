"""Config-generation checks for container/rootfs/usr/local/sbin/nat64-start.sh.

The script is run with a stub `unbound-checkconf` that records the generated
configuration and aborts (exit 77) before any network or process setup.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / 'container/rootfs/usr/local/sbin/nat64-start.sh'
STOP = 77


class Nat64StartConfigTests(unittest.TestCase):
    def run_script(self, **env):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bin_dir = tmp / 'bin'
            bin_dir.mkdir()
            stub = bin_dir / 'unbound-checkconf'
            stub.write_text(f'#!/bin/sh\nexit {STOP}\n')
            stub.chmod(0o755)
            runtime = tmp / 'run'
            runtime.mkdir()
            full = {
                'PATH': f'{bin_dir}:/usr/bin:/bin',
                'TAYGA_RUNTIME_DIR': str(runtime),
                'TAYGA_DATA_DIR': str(tmp / 'data'),
                'DNS64_DNSSEC': 'off',
            }
            full.update(env)
            proc = subprocess.run(['/bin/sh', str(SCRIPT)], env=full, capture_output=True,
                                  text=True, timeout=30)
            conf = runtime / 'unbound.conf'
            return proc, conf.read_text() if conf.exists() else ''

    def test_default_access_control_is_not_open_recursion(self):
        proc, conf = self.run_script()
        self.assertEqual(proc.returncode, STOP, proc.stderr)
        self.assertNotIn('0.0.0.0/0', conf)
        self.assertNotIn('::0/0', conf)
        for cidr in ('127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16', 'fc00::/7'):
            self.assertIn(f'access-control: {cidr} allow', conf)

    def test_custom_allow_list(self):
        proc, conf = self.run_script(DNS64_ALLOW_CIDRS='203.0.113.0/24,2001:db8::/32')
        self.assertEqual(proc.returncode, STOP, proc.stderr)
        self.assertIn('access-control: 203.0.113.0/24 allow', conf)
        self.assertIn('access-control: 2001:db8::/32 allow', conf)
        self.assertNotIn('10.0.0.0/8', conf)

    def test_invalid_allow_entries_are_rejected(self):
        for bad in ('10.0.0.0/8\n    control-enable: yes', '10.0.0.0/8;rm', '/8', '10.0.0.0/', '$(id)'):
            proc, _ = self.run_script(DNS64_ALLOW_CIDRS=bad)
            self.assertEqual(proc.returncode, 64, (bad, proc.stderr))

    def test_upstream_injection_is_rejected(self):
        for bad in ('1.1.1.1\ncontrol-enable: yes', '1.1.1.1 ; do', '"quoted"', '1.1.1.1/../x'):
            proc, conf = self.run_script(DNS64_UPSTREAM=bad)
            self.assertEqual(proc.returncode, 64, (bad, proc.stderr))
            self.assertNotIn('control-enable', conf)

    def test_valid_upstreams_are_written(self):
        proc, conf = self.run_script(DNS64_UPSTREAM='1.1.1.1, 2606:4700:4700::1111, 9.9.9.9@853#dns.quad9.net')
        self.assertEqual(proc.returncode, STOP, proc.stderr)
        self.assertIn('forward-addr: 1.1.1.1', conf)
        self.assertIn('forward-addr: 2606:4700:4700::1111', conf)
        self.assertIn('forward-addr: 9.9.9.9@853#dns.quad9.net', conf)

    def test_offload_udp_accepted_and_garbage_rejected(self):
        for mode in ('off', 'tcp', 'udp', 'auto'):
            proc, _ = self.run_script(TAYGA_OFFLOAD=mode)
            self.assertEqual(proc.returncode, STOP, (mode, proc.stderr))
        proc, _ = self.run_script(TAYGA_OFFLOAD='bogus')
        self.assertEqual(proc.returncode, 64)


if __name__ == '__main__':
    unittest.main()
