"""Profile activation transactions against an isolated filesystem and fake init."""
import os
import shutil
import sys
import time
import signal
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'packaging/installer'


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('run/systemd/system', 'usr/local/libexec/tayga', 'bin'):
            (self.root / directory).mkdir(parents=True)
        (self.root / 'usr/local/libexec/tayga/tayga-managed@.service').write_text('test unit\n')
        lib = self.root / 'usr/local/libexec/tayga'
        (self.root / 'etc').mkdir(exist_ok=True)
        (self.root / 'etc/machine-id').write_text('test-machine\n')
        for name in ('tayga-watchdog.sh', 'tayga-recover.sh', 'tayga-files.sh', 'tayga-boot-recover.sh', 'tayga-recovery.service', 'tayga-recovery.openrc', 'freebsd-rc.in', 'freebsd-recovery-rc.in'):
            shutil.copy2(HELPERS / name, lib / name)
        for name in ('tayga-net-ctl', 'tayga-dns64', 'tayga-host-dns'):
            (lib / name).write_text('#!/bin/sh\nexit 0\n')
        # Production uses the Linux utilities. Keep portable transaction tests
        # runnable on macOS without adding a Python dependency to the installer.
        if not shutil.which('setsid'):
            path = self.root / 'bin/setsid'
            path.write_text('#!' + sys.executable + '\nimport os,sys\nos.setsid()\nos.execvp(sys.argv[1],sys.argv[1:])\n')
            path.chmod(0o755)
        if not shutil.which('timeout'):
            path = self.root / 'bin/timeout'
            path.write_text('#!' + sys.executable + '\nimport subprocess,sys\na=sys.argv[1:]\nif a[0]=="-k": a=a[2:]\nt=float(a.pop(0))\nsys.exit(subprocess.run(a,timeout=t).returncode)\n')
            path.chmod(0o755)
        if not shutil.which('flock'):
            path = self.root / 'bin/flock'
            path.write_text('#!' + sys.executable + '\nimport fcntl,os,sys\na=sys.argv[1:]\nassert a.pop(0)=="-n"\nfd=os.open(a.pop(0),os.O_CREAT|os.O_RDWR,0o600)\ntry: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(1)\nos.set_inheritable(fd,True)\nos.execvp(a[0],a)\n')
            path.chmod(0o755)
        if not Path('/proc/self').exists():
            path = self.root / 'bin/ps'
            path.write_text('#!' + sys.executable + '''
import os, sys
args = sys.argv[1:]
pid = None
pgid_mode = False
lstart_mode = False
while args:
    a = args.pop(0)
    if a == '-p' and args:
        pid = int(args.pop(0))
    elif 'pgid' in a:
        pgid_mode = True
    elif 'lstart' in a:
        lstart_mode = True
if pid is not None:
    try:
        os.kill(pid, 0)
    except OSError:
        sys.exit(1)
    if pgid_mode:
        try:
            print(os.getpgid(pid))
        except OSError:
            print(pid)
    elif lstart_mode:
        print("Thu Oct 29 00:00:00 2026")
    else:
        print(pid)
''')
            path.chmod(0o755)
        self.log = self.root / 'log'
        self.env = {**os.environ, 'TAYGA_TEST_ROOT': str(self.root), 'TAYGA_TESTING': '1',
                    'PATH': str(self.root / 'bin') + os.pathsep + os.environ['PATH'], 'TEST_LOG': str(self.log)}
        for name in ('id', 'ip', 'iptables', 'ip6tables', 'sysctl', 'curl', 'systemctl'):
            script = 'exit 0'
            if name == 'id': script = 'echo 0'
            if name == 'systemctl':
                script = '''echo "$*" >> "$TEST_LOG"
case "$1" in
    is-active|is-enabled) exit 0 ;;
    start)
        if [ "$2" = "${TEST_BLOCK_UNIT:-}" ]; then
            : > "$TEST_STARTED"
            trap '' TERM
            if [ "${TEST_NEW_GROUP:-no}" = yes ]; then
                python3 -c 'import os,signal,time,ctypes; os.setpgrp(); cdll=ctypes.CDLL(None); getattr(cdll,"prctl",lambda *a:0)(15,bytes([99,104,105,108,100,10,41,32,120]),0,0,0); signal.signal(signal.SIGTERM,signal.SIG_IGN); open(os.environ["TEST_CHILD_PID"],"w").write(str(os.getpid())); time.sleep(60)' &
            else sleep 60 &
            fi
            wait
        fi
        if [ "$2" = "${TEST_GATE_UNIT:-}" ]; then
            : > "$TEST_STARTED"
            while [ ! -f "$TEST_RELEASE" ]; do sleep 0.05; done
        fi
        [ "$2" != "${TEST_FAIL_UNIT:-}" ]
        ;;
esac'''
            path = self.root / 'bin' / name
            path.write_text('#!/bin/sh\n' + script + '\n')
            path.chmod(0o755)

    def candidate(self, mode, comment=''):
        path = self.root / ('candidate-' + mode)
        path.write_text('tun-device ' + mode + '\n# ' + comment + '\n')
        return path

    def run_lifecycle(self, action, argument, **env):
        return subprocess.run(['sh', str(HELPERS / 'tayga-lifecycle.sh'), action, str(argument)],
                              env={**self.env, **env}, capture_output=True, text=True)

    def test_failed_switch_restores_old_service_and_files(self):
        old = self.candidate('clat')
        result = self.run_lifecycle('apply', old)
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = self.root / 'etc/systemd/system/tayga-managed@.service'
        before = unit.read_bytes()
        result = self.run_lifecycle('apply', self.candidate('nat64'), TEST_FAIL_UNIT='tayga-managed@nat64.service')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text(), 'clat\n')
        self.assertEqual(unit.read_bytes(), before)
        self.assertFalse((self.root / 'etc/tayga/nat64.conf').exists())
        self.assertIn('start tayga-managed@clat.service', self.log.read_text())
        self.assertFalse((self.root / 'var/lib/tayga-installer/operation.lock').exists())

    def test_modified_config_is_preserved_and_owned_uninstall_is_idempotent_at_service_layer(self):
        result = self.run_lifecycle('apply', self.candidate('nat64'))
        self.assertEqual(result.returncode, 0, result.stderr)
        config = self.root / 'etc/tayga/nat64.conf'
        original = config.read_text()
        config.write_text('user changes\n')
        self.assertNotEqual(self.run_lifecycle('uninstall', 'nat64').returncode, 0)
        self.assertEqual(config.read_text(), 'user changes\n')
        config.write_text(original)
        result = self.run_lifecycle('uninstall', 'nat64')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(config.exists())
        self.assertFalse((self.root / 'etc/systemd/system/tayga-managed@.service').exists())

    def test_wizard_generates_reviewable_profile_and_cancels_on_eof(self):
        path = self.root / 'wizard.conf'
        result = subprocess.run(['sh', str(HELPERS / 'wizard.sh'), str(path)],
                                input='\n' * 7, text=True, capture_output=True,
                                env={**self.env, 'TAYGA_WIZARD_STDIN': '1', 'MODE': 'nat64'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dynamic-pool', path.read_text())
        path.unlink()
        result = subprocess.run(['sh', str(HELPERS / 'wizard.sh'), str(path)],
                                input='', text=True, capture_output=True,
                                env={**self.env, 'TAYGA_WIZARD_STDIN': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(path.exists())

    def test_native_apk_pin_is_snapshotted_before_service_changes_and_released_on_failure(self):
        lib = self.root / 'usr/local/libexec/tayga'
        (lib / 'package-owner').write_text('apk\n')
        (lib / 'package-lock.sh').write_text('#!/bin/sh\necho "package-pin:$1" >> "$TEST_LOG"\n')
        result = self.run_lifecycle('apply', self.candidate('nat64'), TEST_FAIL_UNIT='tayga-managed@nat64.service')
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text()
        self.assertLess(log.index('package-pin:lock'), log.index('start tayga-managed@nat64.service'))
        self.assertIn('package-pin:unlock', log)
        self.assertFalse((self.root / 'var/lib/tayga-installer/operation.lock').exists())

    def test_file_install_refuses_package_owned_files_before_staging(self):
        binary = self.root / 'usr/local/sbin/tayga'
        binary.parent.mkdir(parents=True)
        binary.write_text('package-owned binary\n')
        query = self.root / 'bin/dpkg-query'
        query.write_text('#!/bin/sh\nexit 0\n')
        query.chmod(0o755)
        payload = self.root / 'package-payload'
        payload.mkdir()
        result = subprocess.run(['sh', str(HELPERS / 'tayga-files.sh'), 'stage', str(payload), 'linux-amd64'],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Package-managed file preserved', result.stderr)
        self.assertEqual(binary.read_text(), 'package-owned binary\n')
        self.assertFalse((self.root / 'var/lib/tayga-installer/files-transaction').exists())

    def test_file_install_refuses_opkg_owned_file(self):
        binary = self.root / 'usr/local/sbin/tayga'
        binary.parent.mkdir(parents=True)
        binary.write_text('OpenWrt package binary\n')
        for name in ('apk', 'dpkg-query', 'rpm'):
            query = self.root / 'bin' / name
            query.write_text('#!/bin/sh\nexit 1\n')
            query.chmod(0o755)
        query = self.root / 'bin/opkg'
        query.write_text('#!/bin/sh\necho "tayga - $2"\n')
        query.chmod(0o755)
        result = subprocess.run(['sh', str(HELPERS / 'tayga-files.sh'), 'stage', str(self.root), 'linux-arm64'],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Package-managed file preserved', result.stderr)
        self.assertEqual(binary.read_text(), 'OpenWrt package binary\n')
        self.assertFalse((self.root / 'var/lib/tayga-installer/files-transaction').exists())

    def test_file_install_rollback_and_uninstall_restore_originals(self):
        import shutil
        payload = self.root / 'payload'
        (payload / 'bin/linux-amd64').mkdir(parents=True)
        for name in ('tayga', 'pref64-discover'):
            (payload / 'bin/linux-amd64' / name).write_text('new ' + name)
        shutil.copytree(HELPERS, payload / 'installer')
        shutil.copytree(ROOT / 'docs/man', payload / 'man')
        original = self.root / 'usr/local/sbin/tayga'
        original.parent.mkdir(parents=True)
        original.write_text('previous administrator binary')
        files = HELPERS / 'tayga-files.sh'
        def run(*args):
            return subprocess.run(['sh', str(files), *map(str, args)], env=self.env, capture_output=True, text=True)
        result = run('stage', payload, 'linux-amd64')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(original.read_text(), 'new tayga')
        file_id = result.stdout.strip()
        self.assertTrue(file_id.startswith('token.'))
        self.assertEqual(run('rollback', 'another-transaction').returncode, 0)
        self.assertEqual(run('commit', 'another-transaction').returncode, 0)
        self.assertTrue((self.root / 'var/lib/tayga-installer/files-transaction').exists())
        self.assertEqual(original.read_text(), 'new tayga')
        self.assertEqual(run('rollback', file_id).returncode, 0)
        self.assertEqual(original.read_text(), 'previous administrator binary')
        self.assertEqual(run('stage', payload, 'linux-amd64').returncode, 0)
        self.assertEqual(run('commit').returncode, 0)
        original.write_text('user edit')
        self.assertNotEqual(run('uninstall').returncode, 0)
        self.assertEqual(original.read_text(), 'user edit')
        original.write_text('new tayga')
        result = run('uninstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(original.read_text(), 'previous administrator binary')
        self.assertFalse((self.root / 'usr/local/sbin/pref64-discover').exists())

    def test_openrc_switch_keeps_shared_service_enabled(self):
        (self.root / 'run/systemd/system').rmdir()
        (self.root / 'run/openrc').mkdir()
        (self.root / 'usr/local/libexec/tayga/tayga-managed.openrc').write_text('#!/sbin/openrc-run\n')
        for name in ('rc-service', 'rc-update'):
            path = self.root / 'bin' / name
            path.write_text('#!/bin/sh\necho "' + name + ' $*" >> "$TEST_LOG"\nif [ "$1" = show ]; then echo "tayga-managed | default"; fi\n')
            path.chmod(0o755)
        self.assertEqual(self.run_lifecycle('apply', self.candidate('clat')).returncode, 0)
        result = self.run_lifecycle('apply', self.candidate('nat64'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'etc/conf.d/tayga-managed').read_text(), 'profile=nat64\n')
        self.assertNotIn('rc-update del', self.log.read_text())
        self.assertTrue((self.root / 'etc/init.d/tayga-managed').stat().st_mode & 0o100)

    def test_freebsd_rc_switch_and_uninstall(self):
        (self.root / 'run/systemd/system').rmdir()
        (self.root / 'etc/rc.d').mkdir(parents=True)
        (self.root / 'usr/local/etc/rc.d').mkdir(parents=True)
        (self.root / 'etc/rc.conf.d').mkdir(parents=True)
        (self.root / 'etc/hostid').write_text('test-freebsd-hostid\n')
        for name in ('service', 'sysrc', 'pfctl'):
            path = self.root / 'bin' / name
            path.write_text('#!/bin/sh\necho "' + name + ' $*" >> "$TEST_LOG"\nif [ "$1" = -f ] && [ "$3" = -n ]; then echo YES; fi\n')
            path.chmod(0o755)
        path = self.root / 'bin/uname'
        path.write_text('#!/bin/sh\ncase "$1" in -s) echo FreeBSD;; -m) echo amd64;; *) echo FreeBSD;; esac\n')
        path.chmod(0o755)
        candidate = self.root / 'candidate-clat'
        candidate.write_text('tun-device tun64\n# installer-mode clat\n')
        self.assertEqual(self.run_lifecycle('apply', candidate).returncode, 0)
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text().strip(), 'clat')
        self.assertIn('tayga_managed_profile="clat"', (self.root / 'etc/rc.conf.d/tayga_managed').read_text())
        candidate_nat = self.root / 'candidate-nat64'
        candidate_nat.write_text('tun-device tun64\n# installer-mode nat64\n')
        self.assertEqual(self.run_lifecycle('apply', candidate_nat).returncode, 0)
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text().strip(), 'nat64')
        self.assertIn('tayga_managed_profile="nat64"', (self.root / 'etc/rc.conf.d/tayga_managed').read_text())
        self.assertEqual(self.run_lifecycle('uninstall', 'nat64').returncode, 0)
        self.assertTrue((self.root / 'etc/rc.conf.d/tayga_managed').exists())
        self.assertEqual(self.run_lifecycle('uninstall', 'clat').returncode, 0)
        self.assertFalse((self.root / 'etc/rc.conf.d/tayga_managed').exists())
        self.assertFalse((self.root / 'usr/local/etc/rc.d/tayga-managed').exists())
        self.assertFalse((self.root / 'usr/local/etc/rc.d/tayga-recovery').exists())

    def test_siit_activation_and_uninstall_select_correct_unit(self):
        result = self.run_lifecycle('apply', self.candidate('siit'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text(), 'siit\n')
        self.assertIn('start tayga-managed@siit.service', self.log.read_text())
        self.assertEqual(self.run_lifecycle('uninstall', 'siit').returncode, 0)

    def wait_for(self, predicate, description, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail('Timed out waiting for ' + description)

    def start_blocked_switch(self, stage_files=False, **extra):
        self.assertEqual(self.run_lifecycle('apply', self.candidate('clat')).returncode, 0)
        file_transaction = None
        if stage_files:
            payload = self.root / 'guard-payload'
            (payload / 'bin/linux-amd64').mkdir(parents=True)
            for name in ('tayga', 'pref64-discover'):
                (payload / 'bin/linux-amd64' / name).write_text('new binary')
            shutil.copytree(HELPERS, payload / 'installer')
            shutil.copytree(ROOT / 'docs/man', payload / 'man')
            # No network operations in the portable suite; kernel restoration
            # is covered by the disposable-container test instead.
            for name in ('tayga-net-ctl.sh', 'tayga-dns64.sh', 'tayga-host-dns.sh'):
                (payload / 'installer' / name).write_text('#!/bin/sh\nexit 0\n')
            original = self.root / 'usr/local/sbin/tayga'
            original.parent.mkdir(parents=True)
            original.write_text('original binary')
            result = subprocess.run(['sh', str(HELPERS / 'tayga-files.sh'), 'stage', str(payload), 'linux-amd64'],
                                    env=self.env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            file_transaction = result.stdout.strip()
        started = self.root / 'start.reached'
        env = {**self.env, 'TAYGA_WATCHDOG_SECONDS': '3',
               'TEST_BLOCK_UNIT': 'tayga-managed@nat64.service', 'TEST_STARTED': str(started), **extra}
        if file_transaction:
            env['TAYGA_FILES_TRANSACTION'] = file_transaction
        proc = subprocess.Popen(['sh', str(HELPERS / 'tayga-lifecycle.sh'), 'apply', str(self.candidate('nat64'))],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lock = self.root / 'var/lib/tayga-installer/operation.lock'
        self.wait_for(started.exists, 'blocked service start')
        lock = lock / (lock / 'transaction').read_text().strip()
        runner = int((lock / 'runner.pid').read_text())
        def cleanup_processes():
            try:
                os.killpg(runner, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=5)
        self.addCleanup(cleanup_processes)
        return proc, runner, lock

    def assert_recovered_clat(self, lock):
        self.wait_for(lambda: not lock.exists(), 'independent rollback completion')
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text(), 'clat\n')
        self.assertFalse((self.root / 'etc/tayga/nat64.conf').exists())
        self.assertGreaterEqual(self.log.read_text().count('start tayga-managed@clat.service'), 2)
        self.assertIn('deadline expired', (self.root / 'var/lib/tayga-installer/watchdog.log').read_text())

    def test_watchdog_recovers_hung_start_and_terminates_its_process_group(self):
        proc, runner, lock = self.start_blocked_switch()
        _, stderr = proc.communicate(timeout=12)
        self.assertNotEqual(proc.returncode, 0, stderr)
        self.assert_recovered_clat(lock)
        # The fake start ignored SIGTERM and its sleep inherited that setting.
        # Completion demonstrates that the guard's SIGKILL stopped them too.
        with self.assertRaises(ProcessLookupError):
            os.kill(runner, 0)

    def test_watchdog_recovers_after_runner_sigkill_with_orphaned_children(self):
        proc, runner, lock = self.start_blocked_switch()
        os.kill(runner, signal.SIGKILL)
        proc.communicate(timeout=12)
        self.assertNotEqual(proc.returncode, 0)
        self.assert_recovered_clat(lock)

    def test_watchdog_survives_installer_sigkill_and_restores_staged_files(self):
        proc, _, lock = self.start_blocked_switch(stage_files=True)
        proc.kill()
        proc.communicate(timeout=12)
        self.assert_recovered_clat(lock)
        self.assertEqual((self.root / 'usr/local/sbin/tayga').read_text(), 'original binary')
        self.assertFalse((self.root / 'var/lib/tayga-installer/files-transaction').exists())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux activation-session recovery')
    def test_watchdog_stops_orphaned_child_process_groups_in_the_owned_session(self):
        child_file = self.root / 'child.pid'
        proc, runner, lock = self.start_blocked_switch(TEST_NEW_GROUP='yes', TEST_CHILD_PID=str(child_file))
        self.wait_for(child_file.exists, 'child process group')
        child = int(child_file.read_text())
        def cleanup_child():
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(cleanup_child)
        self.assertEqual(os.getpgid(child), child)
        os.killpg(runner, signal.SIGKILL)
        proc.communicate(timeout=12)
        self.assert_recovered_clat(lock)
        stat = Path(f'/proc/{child}/stat')
        if stat.exists():
            self.assertEqual(stat.read_text().rsplit(') ', 1)[1].split()[0], 'Z')

    def test_successful_commit_cancels_guard_and_cannot_be_rolled_back_later(self):
        started = self.root / 'gate.reached'
        release = self.root / 'gate.release'
        env = {**self.env, 'TAYGA_WATCHDOG_SECONDS': '4',
               'TEST_GATE_UNIT': 'tayga-managed@nat64.service', 'TEST_STARTED': str(started),
               'TEST_RELEASE': str(release)}
        proc = subprocess.Popen(['sh', str(HELPERS / 'tayga-lifecycle.sh'), 'apply', str(self.candidate('nat64'))],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: proc.poll() is not None or proc.kill())
        self.wait_for(started.exists, 'service gate')
        release.touch()
        _, stderr = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 0, stderr)
        time.sleep(4.2)
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text(), 'nat64\n')
        self.assertFalse((self.root / 'var/lib/tayga-installer/operation.lock').exists())
        self.assertNotIn('deadline expired', (self.root / 'var/lib/tayga-installer/watchdog.log').read_text())

    def test_stale_guard_cannot_claim_a_new_transaction(self):
        lock = self.root / 'var/lib/tayga-installer/operation.lock'
        lock.mkdir(parents=True)
        (lock / 'id').write_text('new-transaction\n')
        result = subprocess.run(['sh', str(HELPERS / 'tayga-watchdog.sh'), str(lock),
                                 'old-transaction', '0', str(os.getpid()), 'old-start'],
                                env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((lock / 'decision').exists())

    def boot_snapshot(self, decision=''):
        state = self.root / 'var/lib/tayga-installer'
        lock = state / 'operation.lock/session.token.boot'
        (lock / 'metadata').mkdir(parents=True)
        (lock.parent / 'transaction').write_text(lock.name + '\n')
        for name, value in {'id': 'token.boot', 'boot.id': 'previous-boot',
                            'machine.id': 'test-machine', 'profile': 'nat64', 'old': 'clat',
                            'init': 'systemd', 'was_enabled': 'yes', 'was_active': 'yes',
                            'recovery.enabled': 'no', 'mutating': '', 'decision': decision}.items():
            (lock / name).write_text(value + '\n')
        (lock / 'metadata/current').write_text('clat\n')
        (lock / 'unit.old').write_text('previous unit\n')
        (self.root / 'etc/systemd/system').mkdir(parents=True)
        (self.root / 'etc/tayga').mkdir(parents=True)
        (self.root / 'etc/tayga/nat64.conf').write_text('unconfirmed candidate\n')
        shutil.copy2(HELPERS / 'tayga-recover.sh', lock / 'recover.sh')
        for helper in ('net', 'dns64', 'host-dns'):
            (lock / (helper + '.sh')).write_text('exit 99\n')
        return lock

    def test_boot_recovery_restores_files_without_old_kernel_cleanup_or_sync_start(self):
        self.boot_snapshot()
        result = subprocess.run(['sh', str(HELPERS / 'tayga-boot-recover.sh')],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'etc/tayga/nat64.conf').exists())
        self.assertEqual((self.root / 'var/lib/tayga-installer/current').read_text(), 'clat\n')
        self.assertFalse((self.root / 'var/lib/tayga-installer/operation.lock').exists())
        calls = self.log.read_text()
        self.assertIn('--no-block start tayga-managed@clat.service', calls)
        self.assertNotIn('\nstart tayga-managed@clat.service', calls)

    def test_boot_recovery_rejects_foreign_identity_and_retains_snapshot(self):
        lock = self.boot_snapshot()
        (lock / 'machine.id').write_text('foreign-machine\n')
        result = subprocess.run(['sh', str(HELPERS / 'tayga-boot-recover.sh')],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(lock.exists())
        self.assertFalse(self.log.exists())

    def test_boot_recovery_keeps_committed_profile_and_only_retires_snapshot(self):
        lock = self.boot_snapshot('commit')
        result = subprocess.run(['sh', str(HELPERS / 'tayga-boot-recover.sh')],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'etc/tayga/nat64.conf').exists())
        self.assertFalse(lock.exists())
        self.assertFalse(self.log.exists())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux boot/namespace identity')
    def test_old_boot_snapshot_is_rejected_before_any_signalling(self):
        lock = self.root / 'var/lib/tayga-installer/operation.lock/session.token.old'
        lock.mkdir(parents=True)
        (lock / 'id').write_text('token.old\n')
        (lock / 'boot.id').write_text('different-boot\n')
        (lock / 'pid.namespace').write_text('old\n')
        (lock / 'net.namespace').write_text('old\n')
        result = subprocess.run(['sh', str(HELPERS / 'tayga-watchdog.sh'), str(lock),
                                 'token.old', '0', str(os.getpid()), 'not-this-process'],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r'another (boot|namespace)')
        self.assertFalse((lock / 'armed').exists())
        self.assertFalse((lock / 'decision').exists())
