"""DNS64 config validation and owned-process cleanup without a live resolver."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'packaging/installer'


class DNS64Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'nat64.conf'
        self.output = self.root / 'unbound.conf'
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'id').write_text('#!/bin/sh\necho 0\n')
        (self.bin / 'id').chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'TAYGA_DNS64_RUNTIME': str(self.runtime), 'TAYGA_DNS64_CONFIG_DIR': str(self.root / 'dns64-config')}

    def generate(self, *extra):
        return subprocess.run(['sh', str(HELPERS / 'configure.sh'), '--mode=nat64', '--dns64=yes',
                               '--pref64=2001:db8:64::/96', '--output=' + str(self.config), *extra],
                              env=self.env, capture_output=True, text=True)

    def test_defaults_validate_dnssec_and_render_off_requires_explicit_selection(self):
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('# installer-dns64-dnssec validate', self.config.read_text())
        self.config.unlink()
        result = self.generate('--dns64-dnssec=off', '--dns64-listen=2001:db8::53',
                               '--dns64-allow=2001:db8:1::/64', '--dns64-upstream=127.0.0.1@5300')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['sh', str(HELPERS / 'tayga-dns64.sh'), 'render', str(self.config), str(self.output)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.output.read_text()
        for expected in ('module-config: "dns64 iterator"', 'dns64-prefix: 2001:db8:64::/96',
                         'edns-buffer-size: 1232', 'username: "unbound"', 'forward-addr: 127.0.0.1@5300',
                         'access-control: 2001:db8:1::/64 allow'):
            self.assertIn(expected, text)
        self.assertNotIn('trust-anchor-file', text)

    def test_invalid_dns_tokens_and_non_nat64_provisioning_are_rejected(self):
        for extra in (['--mode=clat', '--clat-ipv6=2001:db8::464'],
                      ['--dns64-upstream=1.1.1.1\nserver:'], ['--dns64-dnssec=permissive']):
            result = self.generate(*extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.config.exists())

    def test_stale_pid_identity_is_removed_without_signalling_any_process(self):
        self.config.write_text('tun-device nat64\n')
        identity = self.runtime / 'dns64.identity'
        identity.write_text('999999999 12345\n')
        result = subprocess.run(['sh', str(HELPERS / 'tayga-dns64.sh'), 'down', str(self.config)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(identity.exists())

    def test_prepare_preserves_unmanaged_configuration_directory(self):
        self.assertEqual(self.generate('--dns64-dnssec=off').returncode, 0)
        for name in ('unbound', 'unbound-checkconf', 'pref64-discover'):
            path = self.bin / name
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o755)
        directory = self.root / 'dns64-config'
        directory.mkdir()
        existing = directory / 'unbound.conf'
        existing.write_text('administrator configuration\n')
        result = subprocess.run(['sh', str(HELPERS / 'tayga-dns64.sh'), 'prepare', str(self.config)],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(existing.read_text(), 'administrator configuration\n')

    def test_successful_prepare_returns_zero_without_launching_a_resolver(self):
        self.assertEqual(self.generate('--dns64-dnssec=off').returncode, 0)
        for name in ('unbound', 'unbound-checkconf', 'pref64-discover'):
            path = self.bin / name
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o755)
        result = subprocess.run(['sh', str(HELPERS / 'tayga-dns64.sh'), 'prepare', str(self.config)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'dns64-config/unbound.conf').exists())
        self.assertFalse((self.runtime / 'dns64.identity').exists())


class HostDNSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'log'
        self.config = self.root / 'clat.conf'
        self.config.write_text('tun-device clat\n# installer-host-dns public\n')
        self.resolv = self.root / 'resolv.conf'
        self.resolv.write_text('nameserver 127.0.0.53\n')
        self.runtime = self.root / 'runtime'
        for name, body in {
            'id': 'echo 0',
            'ip': 'exit 0',
            'resolvectl': 'echo "$*" >> "$TEST_LOG"; case "$*" in *query*) [ "${TEST_DNS_FAIL:-no}" != yes ];; esac',
        }.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + body + '\n')
            path.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'TAYGA_HOST_DNS_RUNTIME': str(self.runtime), 'TAYGA_TEST_RESOLV_CONF': str(self.resolv),
                    'TEST_LOG': str(self.log)}

    def run_helper(self, action, **env):
        return subprocess.run(['sh', str(HELPERS / 'tayga-host-dns.sh'), action, str(self.config)],
                              env={**self.env, **env}, stdin=subprocess.DEVNULL, capture_output=True, text=True)

    def test_public_dns_is_link_scoped_and_reverted_on_stop_or_failure(self):
        before = self.resolv.read_bytes()
        self.assertEqual(self.run_helper('prepare').returncode, 0)
        self.assertFalse(self.runtime.exists())
        result = self.run_helper('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dns clat 1.1.1.1 8.8.8.8', self.log.read_text())
        self.assertIn('domain clat ~.', self.log.read_text())
        self.assertEqual(self.run_helper('down').returncode, 0)
        self.assertFalse((self.runtime / 'host-dns').exists())
        result = self.run_helper('up', TEST_DNS_FAIL='yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.runtime / 'host-dns').exists())
        self.assertEqual(self.log.read_text().count('revert clat'), 2)
        self.assertEqual(self.resolv.read_bytes(), before)

    def test_non_stub_system_dns_is_preserved_without_mutations(self):
        self.resolv.write_text('nameserver 9.9.9.9\n')
        result = self.run_helper('up')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())
        self.assertFalse(self.runtime.exists())
        self.assertEqual(self.resolv.read_text(), 'nameserver 9.9.9.9\n')

    def test_explicit_file_backend_restores_after_runtime_loss_and_preserves_edits(self):
        self.config.write_text('tun-device clat\n# installer-host-dns public-file\n')
        state = self.root / 'persistent'
        self.env['TAYGA_HOST_DNS_STATE'] = str(state)
        original = self.resolv.read_bytes()
        result = self.run_helper('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('1.1.1.1', self.resolv.read_text())
        self.assertEqual(self.run_helper('prepare').returncode, 0)
        (self.runtime / 'host-dns').unlink()
        self.resolv.write_text('administrator change\n')
        self.assertNotEqual(self.run_helper('down').returncode, 0)
        self.assertTrue((state / 'original').exists())
        self.resolv.write_bytes((state / 'expected').read_bytes())
        self.assertEqual(self.run_helper('down').returncode, 0)
        self.assertEqual(self.resolv.read_bytes(), original)
        self.assertFalse(state.exists())

    def test_explicit_resolvconf_backend_registers_and_removes_only_owned_record(self):
        self.config.write_text('tun-device clat\n# installer-host-dns public-resolvconf\n')
        command = self.bin / 'resolvconf'
        command.write_text('#!/bin/sh\necho "$*" >> "$TEST_LOG"\ncat >/dev/null\n')
        command.chmod(0o755)
        self.assertEqual(self.run_helper('up').returncode, 0)
        self.assertEqual(self.run_helper('down').returncode, 0)
        self.assertEqual(self.log.read_text(), '-a clat.tayga\n-d clat.tayga\n')

    def test_nm_checkpoint_is_scoped_and_rolls_back_on_modify_failure(self):
        self.config.write_text('tun-device clat\n# installer-host-dns public-nm\n')
        bus = self.bin / 'busctl'
        bus.write_text('''#!/bin/sh
echo "$*" >> "$TEST_LOG"
case "$*" in
 *status*) [ "${TEST_NM_OWNER_GONE:-no}" != yes ] ;;
 *GetNameOwner*) echo 's ":1.42"' ;;
 *CheckpointCreate*) echo 'o "/org/freedesktop/NetworkManager/Checkpoint/7"' ;;
 *CheckpointRollback*) echo 'a{su} 1 "/org/freedesktop/NetworkManager/Devices/8" 0' ;;
esac
''')
        bus.chmod(0o755)
        nm = self.bin / 'nmcli'
        nm.write_text('''#!/bin/sh
echo "$*" >> "$TEST_LOG"
case "$*" in
 *GENERAL.STATE*) echo '100 (connected)' ;;
 *GENERAL.DBUS-PATH*) echo '/org/freedesktop/NetworkManager/Devices/8' ;;
 *IP4.DNS*) echo '1.1.1.1 | 8.8.8.8' ;;
 *'device modify'*) [ "${TEST_NM_FAIL:-no}" != yes ] ;;
esac
''')
        nm.chmod(0o755)
        result = self.run_helper('up', TEST_NM_FAIL='yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.runtime / 'host-dns').exists())
        log = self.log.read_text()
        self.assertIn('CheckpointCreate aouu 1 /org/freedesktop/NetworkManager/Devices/8 0 0', log)
        self.assertIn('CheckpointRollback o /org/freedesktop/NetworkManager/Checkpoint/7', log)
        self.assertNotIn('connection modify', log)
        self.assertEqual(self.run_helper('up').returncode, 0)
        self.assertEqual(self.run_helper('down').returncode, 0)

        # A checkpoint path must never be sent to a new daemon after restart.
        self.assertEqual(self.run_helper('up').returncode, 0)
        count = self.log.read_text().count('CheckpointRollback')
        self.assertEqual(self.run_helper('down', TEST_NM_OWNER_GONE='yes').returncode, 0)
        self.assertEqual(self.log.read_text().count('CheckpointRollback'), count)
        self.assertFalse((self.runtime / 'host-dns').exists())
