"""Offline tests for the generated self-extracting installer."""
import os
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'mockbin'
        self.bin.mkdir()
        uname = self.bin / 'uname'
        uname.write_text('#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        uname.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH']}
        self.tayga = self.root / 'tayga'
        self.helper = self.root / 'helper'
        self.tayga.write_bytes(b'test tayga binary')
        self.helper.write_bytes(b'test helper binary')
        self.bundle = self.root / 'installer.sh'
        subprocess.run(['python3', str(ROOT / 'scripts/build-installer.py'), '--output', str(self.bundle),
                        '--version', '1.2.3', '--platform', 'linux-amd64', str(self.tayga), str(self.helper)], check=True)

    def test_help_version_and_file_and_pipe_extraction(self):
        subprocess.run(['sh', '-n', str(self.bundle)], check=True)
        self.assertIn('binary-only', subprocess.check_output(['sh', str(self.bundle), '--help'], text=True))
        self.assertEqual(subprocess.check_output(['sh', str(self.bundle), '--version'], text=True).strip(), '1.2.3')
        for pipe in (False, True):
            dest = self.root / ('pipe' if pipe else 'file')
            args = ['sh', '-s', '--', '--extract-only', str(dest)] if pipe else ['sh', str(self.bundle), '--extract-only', str(dest)]
            subprocess.run(args, input=self.bundle.read_bytes() if pipe else None, env={**self.env, 'MODE': 'clat'}, check=True)
            self.assertEqual((dest / 'bin/linux-amd64/tayga').read_bytes(), self.tayga.read_bytes())
            self.assertEqual((dest / 'bin/linux-amd64/pref64-discover').read_bytes(), self.helper.read_bytes())
            self.assertTrue((dest / 'man/tayga.8').is_file())
        result = subprocess.run(['sh', str(self.bundle), '--extract-only', str(self.root / 'file')], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_corruption_and_unsupported_mode_fail_closed(self):
        data = self.bundle.read_text().replace("checksum='", "checksum='0", 1)
        self.bundle.write_text(data)
        dest = self.root / 'bad'
        result = subprocess.run(['sh', str(self.bundle), '--extract-only', str(dest)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum mismatch', result.stderr)
        self.assertFalse(dest.exists())
        result = subprocess.run(['sh', str(self.bundle), '--mode=clat', '--yes'], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_profiles_isolate_state_and_preserve_existing_files(self):
        for mode, extra, directive in (
            ('nat64', [], 'dynamic-pool 192.168.240.0/20'),
            ('clat', ['--clat-ipv6=2001:db8:1::464'], 'map 192.0.0.1 2001:db8:1::464'),
            ('siit', ['--map-ipv4=192.0.2.1', '--map-ipv6=2001:db8::1'], 'map 192.0.2.1 2001:db8::1'),
        ):
            profile = self.root / (mode + '.conf')
            args = ['sh', str(self.bundle), '--mode=' + mode, '--configure-only=' + str(profile), *extra]
            subprocess.run(args, env=self.env, check=True)
            text = profile.read_text()
            self.assertIn(directive, text)
            self.assertIn('data-dir /var/lib/tayga/' + mode, text)
            self.assertIn('tun-offload auto', text)
            if mode == 'nat64':
                self.assertIn('# installer-source6 fd64::1', text)
            if mode != 'nat64':
                self.assertNotIn('dynamic-pool', text)
            subprocess.run(args, env=self.env, check=True)
            profile.write_text('existing user configuration\n')
            result = subprocess.run(args, env=self.env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(profile.read_text(), 'existing user configuration\n')

    def test_invalid_profiles_create_no_output(self):
        for extra in (['--mode=clat'], ['--mode=siit'], ['--mtu=12'], ['--workers=999'],
                      ['--mode=nat64', '--tun-ipv6=fd64::2'],
                      ['--mode=binary-only'],
                      ['--pref64=64:ff9b::/95'], ['--tayga-ipv6=fd64::2\nworkers 63']):
            profile = self.root / 'invalid.conf'
            result = subprocess.run(['sh', str(self.bundle), '--configure-only=' + str(profile), *extra],
                                    env=self.env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(profile.exists())

    def test_embedded_discovery_uses_returned_prefix_and_fails_without_fallback(self):
        self.helper.write_text('#!/bin/sh\necho "2a00:1098:2c:0:0:5::/96"\n')
        subprocess.run(['python3', str(ROOT / 'scripts/build-installer.py'), '--output', str(self.bundle),
                        '--version', '1.2.3', '--platform', 'linux-amd64', str(self.tayga), str(self.helper)], check=True)
        profile = self.root / 'discovered.conf'
        args = ['sh', str(self.bundle), '--mode=clat', '--configure-only=' + str(profile),
                '--pref64=auto', '--dns64-server=2a00:1098:2c::1', '--clat-ipv6=2001:db8::464']
        subprocess.run(args, env=self.env, check=True)
        self.assertIn('prefix 2a00:1098:2c:0:0:5::/96', profile.read_text())
        self.assertIn('# installer-pref64-source rfc7050', profile.read_text())
        self.helper.write_text('#!/bin/sh\nexit 1\n')
        subprocess.run(['python3', str(ROOT / 'scripts/build-installer.py'), '--output', str(self.bundle),
                        '--version', '1.2.3', '--platform', 'linux-amd64', str(self.tayga), str(self.helper)], check=True)
        profile.unlink()
        result = subprocess.run(args, env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(profile.exists())

    def test_sfx_wizard_generates_profile_without_activation(self):
        output = self.root / 'wizard.conf'
        result = subprocess.run(['sh', str(self.bundle), '--wizard', '--mode=nat64',
                                 '--mtu=1300', '--configure-only=' + str(output)],
                                input='\n' * 7, text=True, capture_output=True,
                                env={**self.env, 'TAYGA_WIZARD_STDIN': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('offlink-mtu 1300', output.read_text())
        self.assertNotIn('workers 0', output.read_text())
        result = subprocess.run(['sh', str(self.bundle), '--extract-only', str(self.root / 'extract'), '--uninstall'],
                                env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'extract').exists())

    def test_freebsd_profiles_use_native_tun_name_and_disable_offload(self):
        (self.bin / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo FreeBSD;; -m) echo amd64;; esac\n')
        subprocess.run(['python3', str(ROOT / 'scripts/build-installer.py'), '--output', str(self.bundle),
                        '--version', '1.2.3', '--platform', 'freebsd-amd64', str(self.tayga), str(self.helper)], check=True)
        output = self.root / 'freebsd.conf'
        subprocess.run(['sh', str(self.bundle), '--mode=clat', '--clat-ipv6=2001:db8::464',
                        '--configure-only=' + str(output)], env=self.env, check=True)
        text = output.read_text()
        self.assertIn('tun-device tun64', text)
        self.assertIn('tun-offload off', text)
        self.assertIn('# installer-firewall pf', text)
        self.assertNotIn('\nworkers ', text)
        explicit = self.root / 'freebsd-explicit.conf'
        subprocess.run(['sh', str(self.bundle), '--mode=nat64', '--firewall=pf',
                        '--configure-only=' + str(explicit)], env=self.env, check=True)
        self.assertIn('# installer-firewall pf', explicit.read_text())

    def test_freebsd_rejects_linux_firewall_backends(self):
        (self.bin / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo FreeBSD;; -m) echo amd64;; esac\n')
        subprocess.run(['python3', str(ROOT / 'scripts/build-installer.py'), '--output', str(self.bundle),
                        '--version', '1.2.3', '--platform', 'freebsd-amd64', str(self.tayga), str(self.helper)], check=True)
        result = subprocess.run(['sh', str(self.bundle), '--mode=nat64', '--firewall=nft',
                                 '--configure-only=' + str(self.root / 'invalid.conf')],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('pf backend', result.stderr)

    def test_missing_architecture_download_is_opt_in_pinned_and_version_checked(self):
        (self.bin / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo riscv64;; esac\n')
        self.tayga.write_text('#!/bin/sh\necho "TAYGA version 1.2.3"\n')
        self.helper.write_text('#!/bin/sh\necho "64:ff9b::/96"\n')
        curl = self.bin / 'curl'
        curl.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
 case "$1" in --output) output=$2; shift ;; https://*) url=$1 ;; esac
 shift
done
case "$url" in */tayga-*) cp "$TEST_DAEMON" "$output" ;; *) cp "$TEST_HELPER" "$output" ;; esac
''')
        curl.chmod(0o755)
        env = {**self.env, 'TEST_DAEMON': str(self.tayga), 'TEST_HELPER': str(self.helper)}
        destination = self.root / 'fallback.conf'
        base = ['sh', str(self.bundle), '--mode=nat64', '--configure-only=' + str(destination)]
        result = subprocess.run(base, env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
        hashes = ['--fallback-tayga-sha256=' + hashlib.sha256(self.tayga.read_bytes()).hexdigest(),
                  '--fallback-helper-sha256=' + hashlib.sha256(self.helper.read_bytes()).hexdigest()]
        args = base + ['--fallback=download', '--fallback-url=https://example.invalid/1.2.3', *hashes]
        refused = subprocess.run([arg.replace('https://example.invalid', 'http://example.invalid') for arg in args], env=env, capture_output=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(b'HTTPS', refused.stderr)
        result = subprocess.run(args, env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        destination.unlink()
        self.tayga.write_text('#!/bin/sh\necho "TAYGA version wrong"\n')
        result = subprocess.run(args, env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum mismatch', result.stderr)
        args[-2] = '--fallback-tayga-sha256=' + hashlib.sha256(self.tayga.read_bytes()).hexdigest()
        result = subprocess.run(args, env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'version mismatch', result.stderr)
        self.assertFalse(destination.exists())

    def test_embedded_sources_are_present_and_armv6_is_not_armv7(self):
        destination = self.root / 'sources'
        subprocess.run(['sh', str(self.bundle), '--extract-only', str(destination)], env=self.env, check=True)
        self.assertEqual((destination / 'source/src/tayga.c').read_bytes(), (ROOT / 'src/tayga.c').read_bytes())
        self.assertTrue((destination / 'source/mk/tayga.mk').is_file())
        (self.bin / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo armv6l;; esac\n')
        result = subprocess.run(['sh', str(self.bundle), '--mode=binary-only', '--yes'], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'linux/armv6', result.stderr)
