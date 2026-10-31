"""Native package ABI validation and staged contents; real archives have VM coverage."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
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

    def test_multiarch_static_verification(self):
        # riscv64 (class 2, little-endian, machine 243)
        blob = bytearray(120)
        blob[:8] = b'\x7fELF\x02\x01\x01\x00'
        struct.pack_into('<HH', blob, 16, 2, 243)
        struct.pack_into('<Q', blob, 32, 64)
        struct.pack_into('<HH', blob, 54, 56, 1)
        struct.pack_into('<I', blob, 64, 1)
        self.binary.write_bytes(blob)
        packages.verify_static(self.binary, 'riscv64')

        # s390x (class 2, big-endian, machine 22)
        blob_s390x = bytearray(120)
        blob_s390x[:8] = b'\x7fELF\x02\x02\x01\x00'
        struct.pack_into('>HH', blob_s390x, 16, 2, 22)
        struct.pack_into('>Q', blob_s390x, 32, 64)
        struct.pack_into('>HH', blob_s390x, 54, 56, 1)
        struct.pack_into('>I', blob_s390x, 64, 1)
        self.binary.write_bytes(blob_s390x)
        packages.verify_static(self.binary, 's390x')

        # armv6 (class 1, little-endian, machine 40)
        blob_armv6 = bytearray(100)
        blob_armv6[:8] = b'\x7fELF\x01\x01\x01\x00'
        struct.pack_into('<HH', blob_armv6, 16, 2, 40)
        struct.pack_into('<I', blob_armv6, 28, 52)
        struct.pack_into('<HH', blob_armv6, 42, 32, 1)
        struct.pack_into('<I', blob_armv6, 52, 1)
        self.binary.write_bytes(blob_armv6)
        packages.verify_static(self.binary, 'armv6')

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


class PackageUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.state = self.root / 'var/lib/tayga-installer'
        self.lib = self.root / 'usr/libexec/tayga'
        self.run_dir = self.root / 'var/run/tayga-installer'
        self.sys_bin = self.root / 'usr/sbin'
        for d in (self.bin, self.state, self.lib, self.run_dir, self.sys_bin, self.root / 'run/systemd/system'):
            d.mkdir(parents=True, exist_ok=True)

        for name, script in {
            'dpkg': '''case "$*" in
    *--print-architecture*)
        echo "${TEST_HOST_ARCH:-amd64}"
        exit 0
        ;;
    *--compare-versions*)
        if [ "${TEST_FORCE_DOWNGRADE:-no}" = yes ]; then exit 0; fi
        exit 1
        ;;
    *-i*0.9.15*)
        touch "$TAYGA_TEST_ROOT/upgraded_to_target"
        exit "${TEST_DPKG_RC:-0}"
        ;;
    *-i*old_pkg*)
        if [ "${TEST_ROLLBACK_PKG_FAIL:-no}" != yes ]; then
            rm -f "$TAYGA_TEST_ROOT/upgraded_to_target"
        fi
        exit "${TEST_DPKG_ROLLBACK_RC:-0}"
        ;;
    *) exit "${TEST_DPKG_RC:-0}" ;;
esac''',
            'dpkg-deb': '''case "$*" in
    *Package*) echo "${TEST_PKG_NAME:-tayga-managed}" ;;
    *Version*)
        case "$*" in
            *0.9.14*) echo "${TEST_OLD_PKG_VER:-0.9.14-1}" ;;
            *) echo "${TEST_PKG_VER:-0.9.15-1}" ;;
        esac
        ;;
    *Architecture*) echo "amd64" ;;
    *) echo "ok" ;;
esac''',
            'dpkg-query': '''case "$*" in
    *tayga-managed*)
        if [ -f "$TAYGA_TEST_ROOT/pkg_version_override" ]; then
            cat "$TAYGA_TEST_ROOT/pkg_version_override"
        elif [ -f "$TAYGA_TEST_ROOT/upgraded_to_target" ]; then
            echo "${TEST_PKG_VER:-0.9.15-1}"
        else
            echo "${TEST_INST_VER:-0.9.14-1}"
        fi
        ;;
esac''',
            'systemctl': '''echo "systemctl $*" >> "$TEST_LOG"
case "$*" in
    *is-active*)
        if [ -f "$TAYGA_TEST_ROOT/service_stopped" ]; then exit 3; fi
        exit "${TEST_SYSCTL_RC:-0}"
        ;;
    *stop*)
        touch "$TAYGA_TEST_ROOT/service_stopped"
        exit "${TEST_SYSCTL_RC:-0}"
        ;;
    *start*|*restart*)
        rm -f "$TAYGA_TEST_ROOT/service_stopped"
        exit "${TEST_SYSCTL_RC:-0}"
        ;;
    *) exit "${TEST_SYSCTL_RC:-0}" ;;
esac''',
            'pidof': 'exit 1',
        }.items():
            p = self.bin / name
            p.write_text('#!/bin/sh\n' + script + '\n')
            p.chmod(0o755)

        self.verify_helper = self.lib / 'tayga-verify.sh'
        self.verify_helper.write_text('''#!/bin/sh
st="$TAYGA_TEST_ROOT/var/lib/tayga-installer/package-upgrade/status"
if [ -f "$st" ] && [ "$(cat "$st")" = "rolling-back" ]; then
    exit "${TEST_ROLLBACK_VERIFY_RC:-0}"
fi
exit "${TEST_VERIFY_RC:-0}"
''')
        self.verify_helper.chmod(0o755)

        (self.sys_bin / 'tayga').write_text('binary-v1\n')
        (self.sys_bin / 'tayga').chmod(0o755)

        self.upgrader = ROOT / 'packaging/installer/tayga-package-upgrade.sh'
        self.log = self.root / 'log'
        self.env = {
            **os.environ,
            'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
            'TAYGA_TESTING': '1',
            'TAYGA_TEST_ROOT': str(self.root),
            'TEST_LOG': str(self.log),
        }
        self.pkg = self.root / 'tayga-managed-0.9.15-1-amd64.deb'
        self.pkg.write_text('deb archive content')
        self.old_pkg = self.root / 'tayga-managed-0.9.14-1-amd64.deb'
        self.old_pkg.write_text('deb archive content old')

    def test_upgrade_requires_valid_package_and_format(self):
        res = subprocess.run(['sh', str(self.upgrader)], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        bad_pkg = self.root / 'test.zip'
        bad_pkg.write_text('zip')
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(bad_pkg)], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('Unsupported package format', res.stderr)

    def test_upgrade_respects_operation_lock(self):
        lock_dir = self.state / 'operation.lock'
        lock_dir.mkdir(parents=True, exist_ok=True)
        (lock_dir / 'pid').write_text(str(os.getpid()))
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip() if Path('/proc/sys/kernel/random/boot_id').is_file() else 'boot-unknown'
        (lock_dir / 'boot_id').write_text(boot_id)
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg)], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('Another operation is currently in progress', res.stderr)

    def test_upgrade_preflight_validates_package_identity(self):
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg)],
                             env={**self.env, 'TEST_PKG_NAME': 'foreign-pkg'}, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('Invalid package identity', res.stderr)
        self.assertFalse((self.state / 'package-upgrade').exists())

    def test_upgrade_apk_package_inspection(self):
        apk_path = self.root / 'tayga-managed-0.9.15-r2.apk'
        pkginfo = b'pkgname = tayga-managed\npkgver = 0.9.15-r2\narch = x86_64\n'
        import tarfile, io
        with tarfile.open(apk_path, 'w:gz') as tar:
            ti = tarfile.TarInfo(name='.PKGINFO')
            ti.size = len(pkginfo)
            tar.addfile(ti, io.BytesIO(pkginfo))
        (self.bin / 'apk').write_text('#!/bin/sh\ncase "$*" in *--print-arch*) echo "x86_64"; exit 0 ;; *) exit 0 ;; esac\n')
        (self.bin / 'apk').chmod(0o755)
        # When no package is previously installed (TEST_INST_VER empty), upgrade proceeds without old-package
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(apk_path)],
                             env={**self.env, 'TEST_INST_VER': ''}, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('PASS: Coordinated live package upgrade successful', res.stdout)

    def test_upgrade_fails_without_old_package_for_installed_version(self):
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg)],
                             env=self.env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('Old package archive for installed version', res.stderr)
        self.assertFalse((self.state / 'package-upgrade').exists())

    def test_upgrade_active_profile_and_successful_verification(self):
        (self.state / 'nat64.conf').write_text('tun-device tun64\n')
        (self.state / 'current').write_text('nat64\n')
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg), '--old-package', str(self.old_pkg)],
                             env=self.env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('PASS: Coordinated live package upgrade successful', res.stdout)
        self.assertFalse((self.state / 'package-upgrade').exists())

    def test_upgrade_rollback_failure_preserves_journal(self):
        (self.state / 'nat64.conf').write_text('original-config\n')
        (self.state / 'current').write_text('nat64\n')
        (self.sys_bin / 'tayga').write_text('original-binary\n')

        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg), '--old-package', str(self.old_pkg)],
                             env={**self.env, 'TEST_VERIFY_RC': '1', 'TEST_ROLLBACK_VERIFY_RC': '1'},
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('CRITICAL', res.stderr)
        self.assertTrue((self.state / 'package-upgrade').exists())
        self.assertEqual((self.state / 'package-upgrade/status').read_text().strip(), 'rollback-failed')
        self.assertFalse((self.state / 'operation.lock').exists())

    def test_rollback_fails_if_package_db_still_reports_target_version(self):
        (self.state / 'nat64.conf').write_text('original-config\n')
        (self.state / 'current').write_text('nat64\n')
        (self.sys_bin / 'tayga').write_text('original-binary\n')

        # TEST_ROLLBACK_PKG_FAIL prevents dpkg mock from removing target version
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg), '--old-package', str(self.old_pkg)],
                             env={**self.env, 'TEST_VERIFY_RC': '1', 'TEST_ROLLBACK_PKG_FAIL': 'yes'},
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('CRITICAL', res.stderr)
        self.assertIn('Package rollback verification failed', res.stderr)
        self.assertTrue((self.state / 'package-upgrade').exists())
        self.assertEqual((self.state / 'package-upgrade/status').read_text().strip(), 'rollback-failed')

    def test_upgrade_readiness_failure_triggers_automatic_rollback(self):
        (self.state / 'nat64.conf').write_text('original-config\n')
        (self.state / 'current').write_text('nat64\n')
        (self.sys_bin / 'tayga').write_text('original-binary\n')

        # When verify helper fails, upgrader must rollback to original binary and config
        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg), '--old-package', str(self.old_pkg)],
                             env={**self.env, 'TEST_VERIFY_RC': '1'}, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('rolling back', res.stderr)
        self.assertEqual((self.sys_bin / 'tayga').read_text(), 'original-binary\n')
        self.assertEqual((self.state / 'nat64.conf').read_text(), 'original-config\n')
        self.assertFalse((self.state / 'package-upgrade').exists())

    def test_exact_data_snapshot_restoration_purges_new_files(self):
        data_dir = self.root / 'var/lib/tayga'
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / 'retained.data').write_text('original-data\n')
        (data_dir / '.retained-dotfile').write_text('original-dotfile\n')

        # Custom verify helper that injects new files before failing readiness
        inject_helper = self.lib / 'tayga-verify.sh'
        inject_helper.write_text('''#!/bin/sh
st="$TAYGA_TEST_ROOT/var/lib/tayga-installer/package-upgrade/status"
if [ -f "$st" ] && [ "$(cat "$st")" = "verifying" ]; then
    echo "polluted-file" > "$TAYGA_TEST_ROOT/var/lib/tayga/polluted.tmp"
    exit 1
fi
exit 0
''')
        inject_helper.chmod(0o755)

        (self.state / 'nat64.conf').write_text('original-config\n')
        (self.state / 'current').write_text('nat64\n')

        res = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg), '--old-package', str(self.old_pkg)],
                             env=self.env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('rolling back', res.stderr)
        # Verify original data and dotfiles were preserved
        self.assertTrue((data_dir / 'retained.data').exists())
        self.assertTrue((data_dir / '.retained-dotfile').exists())
        # Verify new files created by upgraded target version were purged
        self.assertFalse((data_dir / 'polluted.tmp').exists())

    def test_recovery_fails_closed_on_incomplete_journal(self):
        journal = self.state / 'package-upgrade'
        journal.mkdir(parents=True, exist_ok=True)
        (journal / 'status').write_text('installing\n')

        res = subprocess.run(['sh', str(self.upgrader), 'recover'], env=self.env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('journal at ' + str(journal) + ' is corrupt or incomplete', res.stderr)
        self.assertTrue(journal.exists())
        self.assertEqual((journal / 'status').read_text().strip(), 'recovery-failed')

    def test_upgrade_recovery_action_restores_from_journal(self):
        (self.state / 'nat64.conf').write_text('corrupt-config\n')
        journal = self.state / 'package-upgrade'
        (journal / 'backup').mkdir(parents=True)
        (journal / 'backup/tayga').write_text('restored-binary\n')
        (journal / 'accepted.conf').write_text('restored-config\n')
        (journal / 'old_pkg.archive').write_text('old-deb-archive')
        (journal / 'kind').write_text('deb\n')
        (journal / 'inst_ver').write_text('0.9.14-1\n')
        (journal / 'target_ver').write_text('0.9.15-1\n')
        (journal / 'status').write_text('installing\n')
        (journal / 'active_profile').write_text('nat64\n')
        (journal / 'was_active').write_text('yes\n')
        (journal / 'init_type').write_text('systemd\n')
        (self.state / 'operation.lock').mkdir(parents=True)

        res = subprocess.run(['sh', str(self.upgrader), 'recover'], env=self.env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('PASS: Package upgrade recovery complete', res.stdout)
        self.assertEqual((self.sys_bin / 'tayga').read_text(), 'restored-binary\n')
        self.assertEqual((self.state / 'nat64.conf').read_text(), 'restored-config\n')
        self.assertFalse(journal.exists())
        self.assertFalse((self.state / 'operation.lock').exists())


if __name__ == '__main__':
    unittest.main()

