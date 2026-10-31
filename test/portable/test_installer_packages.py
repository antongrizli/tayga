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
    if item['dst']=='/usr/libexec/tayga/tayga-managed@.service': config['managed']=pathlib.Path(item['src']).read_text()
pathlib.Path(args[args.index('--target')+1]).write_text(json.dumps(config))
''')
        tool.chmod(0o755)
        output = self.root / 'output'
        args = (output, '0.9.14', '1', 'arm64', self.binary, self.binary,
                'Local test <test@example.invalid>', ['deb'], str(tool))
        packages.build(*args)
        data = json.loads((output / 'tayga-managed-0.9.14-1-arm64.deb').read_text())
        self.assertNotIn('/usr/local', data['ctl'])
        self.assertIn('Requires=tayga-recovery.service tayga-package-recovery.service', data['managed'])
        self.assertIn('After=tayga-recovery.service tayga-package-recovery.service', data['managed'])
        self.assertIn('/usr/lib/systemd/system/tayga-package-recovery.service',
                      [item['dst'] for item in data['contents']])
        config = next(item for item in data['contents'] if item['dst']=='/etc/tayga/tayga.conf.example')
        self.assertEqual(config['type'], 'config|noreplace')
        self.assertIn('preremove', data['scripts'])
        recovery_link = next(item for item in data['contents'] if item['dst'] ==
                             '/usr/lib/systemd/system/multi-user.target.wants/tayga-package-recovery.service')
        self.assertEqual(recovery_link['type'], 'symlink')
        self.assertEqual(recovery_link['src'], '../tayga-package-recovery.service')

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

    def seal_journal(self, journal):
        import hashlib
        entries = []
        for path in sorted(journal.rglob('*')):
            if path.is_file() and str(path.relative_to(journal)) not in ('status', 'data.ready', 'SHA256SUMS'):
                entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(journal)}\n")
        (journal / 'SHA256SUMS').write_text(''.join(entries))

    def test_upgrade_preserves_initializing_operation_gate(self):
        gate = self.state / 'operation.lock'
        gate.mkdir()
        result = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg)],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(gate.exists())
        self.assertIn('initializing', result.stderr)

    def test_kernel_mutex_excludes_concurrent_operation(self):
        import fcntl
        with (self.state / 'package-upgrade.mutex').open('a') as mutex:
            fcntl.flock(mutex, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg)],
                                    env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / 'operation.lock').exists())

    def test_explicit_rpm_downgrade_reaches_manager(self):
        package = self.root / 'tayga-managed-0.9.15.rpm'
        old = self.root / 'tayga-managed-0.9.14.rpm'
        package.write_text('target')
        old.write_text('old')
        rpm = self.bin / 'rpm'
        rpm.write_text('#!/bin/sh\ncase "$*" in\n    *--eval*) echo "${TEST_RPM_ORDER:--1}" ;;\n    *NAME*) echo tayga-managed ;;\n    *ARCH*|*-E*) echo x86_64 ;;\n    *-qp*VERSION*) case "$*" in *0.9.14*) echo 0.9.14-1 ;; *) echo 0.9.15-1 ;; esac ;;\n    *-q*VERSION*) echo 0.9.14-1 ;;\nesac\nexit 0\n')
        rpm.chmod(0o755)
        dnf = self.bin / 'dnf'
        dnf.write_text('#!/bin/sh\necho "dnf $*" >> "$TEST_LOG"\nexit 0\n')
        dnf.chmod(0o755)
        result = subprocess.run(['sh', str(self.upgrader), 'apply', str(package),
                                 '--old-package', str(old), '--allow-downgrade'],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dnf downgrade -y ', self.log.read_text())
        self.log.write_text('')
        result = subprocess.run(['sh', str(self.upgrader), 'apply', str(package),
                                 '--old-package', str(old), '--allow-downgrade'],
                                env={**self.env, 'TEST_RPM_ORDER': '1'},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dnf install -y ', self.log.read_text())
        self.assertNotIn('dnf downgrade ', self.log.read_text())


    def test_early_boot_defers_native_package_journal_to_late_unit(self):
        unit = self.root / 'usr/lib/systemd/system/tayga-package-recovery.service'
        unit.parent.mkdir(parents=True)
        unit.write_text('late unit')
        journal = self.state / 'package-upgrade'
        journal.mkdir()
        result = subprocess.run(['sh', str(ROOT / 'packaging/installer/tayga-boot-recover.sh')],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(journal.exists())
        self.assertFalse((self.state / 'operation.lock').exists())

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

    def test_recovery_preserves_live_data_when_snapshot_was_interrupted(self):
        data = self.root / 'var/lib/tayga'
        data.mkdir(parents=True)
        (data / 'valuable').write_text('accepted data')
        journal = self.state / 'package-upgrade'
        (journal / 'backup').mkdir(parents=True)
        (journal / 'data').mkdir()
        (journal / 'data/partial').write_text('incomplete copy')
        for name, value in {'status': 'staged', 'kind': 'deb',
                            'inst_ver': '0.9.14-1', 'target_ver': '0.9.15-1',
                            'old_pkg.archive': 'old package'}.items():
            (journal / name).write_text(value)
        self.seal_journal(journal)
        result = subprocess.run(['sh', str(self.upgrader), 'recover'],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((data / 'valuable').read_text(), 'accepted data')
        self.assertFalse((data / 'partial').exists())

    def test_recovery_rejects_installing_without_completed_snapshot(self):
        journal = self.state / 'package-upgrade'
        (journal / 'backup').mkdir(parents=True)
        for name, value in {'status': 'installing', 'kind': 'deb',
                            'inst_ver': '0.9.14-1', 'target_ver': '0.9.15-1',
                            'old_pkg.archive': 'old package'}.items():
            (journal / name).write_text(value)
        self.seal_journal(journal)
        result = subprocess.run(['sh', str(self.upgrader), 'recover'],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no completed data snapshot', result.stderr)
        self.assertTrue(journal.exists())

    def test_recovery_rejects_tampered_old_archive(self):
        (self.state / 'nat64.conf').write_text('original-config\n')
        (self.state / 'current').write_text('nat64\n')
        result = subprocess.run(['sh', str(self.upgrader), 'apply', str(self.pkg),
                                 '--old-package', str(self.old_pkg)],
                                env={**self.env, 'TEST_VERIFY_RC': '1',
                                     'TEST_ROLLBACK_VERIFY_RC': '1'},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        journal = self.state / 'package-upgrade'
        (journal / 'old_pkg.archive').write_text('damaged archive')
        before = self.log.read_text()
        result = subprocess.run(['sh', str(self.upgrader), 'recover'],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('integrity verification failed', result.stderr)
        self.assertTrue(journal.exists())
        self.assertEqual(self.log.read_text(), before)

    def test_upgrade_recovery_action_restores_from_journal(self):
        self.recover_journal()

    def test_boot_recovery_queues_service_without_waiting_on_own_dependency(self):
        self.env.update(TAYGA_BOOT_RECOVERY='1', TEST_VERIFY_RC='1')
        self.recover_journal()
        log = self.log.read_text()
        self.assertIn('systemctl --no-block start tayga-managed@nat64', log)
        self.assertNotIn('systemctl start tayga-managed@nat64', log)

    def test_openrc_boot_recovery_defers_dependent_service_start(self):
        self.env.update(TAYGA_BOOT_RECOVERY='1', TEST_VERIFY_RC='1')
        mock = self.bin / 'rc-service'
        mock.write_text('#!/bin/sh\necho "rc-service $*" >> "$TEST_LOG"\nexit 0\n')
        mock.chmod(0o755)
        self.recover_journal(init_type='openrc')
        self.assertNotIn('rc-service tayga-managed start', self.log.read_text())

    def test_apk_recovery_reads_installed_list_not_package_description(self):
        mock = self.bin / 'apk'
        mock.write_text('#!/bin/sh\ncase "$*" in\n"info -v") echo tayga-managed-0.9.14-1 ;;\n"info -v tayga-managed") echo "tayga-managed-0.9.14-1 description:" ;;\nesac\nexit 0\n')
        mock.chmod(0o755)
        self.recover_journal(init_type='none', kind='apk')

    def recover_journal(self, init_type='systemd', kind='deb'):
        (self.state / 'nat64.conf').write_text('corrupt-config\n')
        journal = self.state / 'package-upgrade'
        (journal / 'backup').mkdir(parents=True)
        (journal / 'backup/tayga').write_text('restored-binary\n')
        (journal / 'accepted.conf').write_text('restored-config\n')
        (journal / 'old_pkg.archive').write_text('old-deb-archive')
        (journal / 'kind').write_text(kind + '\n')
        (journal / 'inst_ver').write_text('0.9.14-1\n')
        (journal / 'target_ver').write_text('0.9.15-1\n')
        (journal / 'status').write_text('installing\n')
        (journal / 'data.ready').write_text('complete\n')
        (journal / 'active_profile').write_text('nat64\n')
        (journal / 'was_active').write_text('yes\n')
        (journal / 'init_type').write_text(init_type + '\n')
        self.seal_journal(journal)

        res = subprocess.run(['sh', str(self.upgrader), 'recover'], env=self.env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('PASS: Package upgrade recovery complete', res.stdout)
        self.assertEqual((self.sys_bin / 'tayga').read_text(), 'restored-binary\n')
        self.assertEqual((self.state / 'nat64.conf').read_text(), 'restored-config\n')
        self.assertFalse(journal.exists())
        self.assertFalse((self.state / 'operation.lock').exists())


if __name__ == '__main__':
    unittest.main()

