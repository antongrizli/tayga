"""OpenWrt SDK identity and binary-only staging, without touching a host SDK."""
import importlib.util
import hashlib
from types import SimpleNamespace
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('openwrt_package', ROOT / 'scripts/prepare-openwrt-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class OpenWrtPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sdk = Path(self.temp.name)
        (self.sdk / 'include').mkdir()
        (self.sdk / 'include/package.mk').touch()
        (self.sdk / 'staging_dir').mkdir()
        self.config = 'CONFIG_TARGET_BOARD="armsr"\nCONFIG_TARGET_SUBTARGET="armv8"\nCONFIG_TARGET_ARCH_PACKAGES="aarch64_generic"\nCONFIG_USE_MUSL=y\n'
        (self.sdk / '.config').write_text(self.config)

    def prepare(self, target='armsr', subtarget='armv8', arch='aarch64_generic'):
        return package.prepare(self.sdk, target, subtarget, arch, '0.9.14')

    def test_reject_mismatched_target_subtarget_abi_and_libc(self):
        for args in (('x86', 'armv8', 'aarch64_generic'), ('armsr', 'armv7', 'aarch64_generic'),
                     ('armsr', 'armv8', 'aarch64_cortex-a53')):
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                self.prepare(*args)
        (self.sdk / '.config').write_text(self.config.replace('CONFIG_USE_MUSL=y', 'CONFIG_USE_GLIBC=y'))
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            self.prepare()
        self.assertFalse((self.sdk / 'package').exists())


    def test_source_snapshot_and_refuse_overwrite(self):
        result = self.prepare()
        manifest = json.loads((result / 'source-manifest.json').read_text())
        self.assertIn('src/tayga.c', manifest['sources'])
        self.assertNotIn('build/tayga', manifest['sources'])
        self.assertTrue(manifest['binary_only'])
        self.assertIn('PKG_VERSION:=0.9.14', (result / 'Makefile').read_text())
        self.assertEqual((result / 'package-owner').read_text(), 'openwrt-sdk\n')
        with self.assertRaisesRegex(ValueError, 'refusing'):
            self.prepare()

    def test_network_down_waits_for_object_removal(self):
        net = self.sdk / 'network'
        net.mkdir()
        (net / 'token').write_text('owner.test')
        counter = self.sdk / 'calls'
        counter.write_text('0')
        script = self.sdk / 'down.sh'
        script.write_text('TAYGA_NETWORK_LIBRARY=1 . "$HELPER"\nnet="$TEST_NET"\nnet_cleanup() { :; }\nsleep() { :; }\nubus() {\n    case "$*" in\n        *status)\n            n=$(cat "$COUNTER"); n=$((n+1)); echo "$n" > "$COUNTER"\n            [ "$n" -lt 6 ] || return 1\n            echo \'{"proto":"tayga_managed","up":false,"pending":false}\' ;;\n        *) : ;;\n    esac\n}\njsonfilter() { echo tayga_managed; }\nnet_down\n')
        result = subprocess.run(['sh', str(script)], env={**os.environ,
            'HELPER': str(ROOT / 'packaging/openwrt/openwrt-network.sh'),
            'TEST_NET': str(net), 'COUNTER': str(counter)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(int(counter.read_text()), 6)
        self.assertFalse(net.exists())

    def test_network_down_tolerates_failed_down_when_already_inactive(self):
        net = self.sdk / 'network-down-fail'
        net.mkdir()
        (net / 'token').write_text('owner.test')
        script = self.sdk / 'down-fail.sh'
        script.write_text('''TAYGA_NETWORK_LIBRARY=1 . "$HELPER"
net="$TEST_NET"
net_cleanup() { :; }
sleep() { :; }
call_count=0
ubus() {
    case "$*" in
        *down) return 1 ;;
        *status)
            call_count=$((call_count + 1))
            if [ "$call_count" -ge 4 ]; then return 1; fi
            echo '{"proto":"tayga_managed","up":false,"pending":false}'
            ;;
        *) : ;;
    esac
}
jsonfilter() {
    case "$*" in
        *proto*) echo tayga_managed ;;
        *up*) echo false ;;
        *) echo "" ;;
    esac
}
net_down
''')
        result = subprocess.run(['sh', str(script)], env={**os.environ,
            'HELPER': str(ROOT / 'packaging/openwrt/openwrt-network.sh'),
            'TEST_NET': str(net)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(net.exists())

    def test_vm_rejects_mixed_package_format_before_boot(self):
        spec = importlib.util.spec_from_file_location('openwrt_vm', ROOT / 'test/system/run-openwrt-vm.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        kernel = self.sdk / 'kernel.bin'
        kernel.write_bytes(b'test kernel')
        wrong = self.sdk / 'base.ipk'
        wrong.write_bytes(b'test package')
        args = SimpleNamespace(release='25.12.6', work=self.sdk / 'vm', port=0,
                               kernel=kernel, image=kernel, base=wrong, procd=wrong,
                               tun=wrong, flock=wrong, network=None, extra_package=[])
        vm = runner.VM(args)
        self.addCleanup(vm.close)
        # Isolate the format guard from the separately pinned image validation.
        vm.release = {**vm.release, 'pins': {'kernel': hashlib.sha256(kernel.read_bytes()).hexdigest(),
                                           'image': hashlib.sha256(kernel.read_bytes()).hexdigest()}}
        with self.assertRaisesRegex(ValueError, 'Wrong package format'):
            vm.execute()
        self.assertIsNone(vm.process)
        self.assertFalse((args.work / 'disk.raw').exists())

    def test_dhcp_wait_tolerates_temporarily_absent_procd_pid(self):
        source = (ROOT / 'test/system/installer-openwrt-procd-smoke.sh').read_text()
        body = source.split('wait_dhcp_owner() {', 1)[1].split('\nstopped() {', 1)[0]
        body = body.replace('/usr/libexec/tayga/openwrt-uplink', '"$TEST_UPLINK"')
        helper = self.sdk / 'uplink'
        helper.write_text('#!/bin/sh\necho "eth2 stable-facts"\n')
        helper.chmod(0o755)
        counter = self.sdk / 'pid-calls'
        counter.write_text('0')
        script = self.sdk / 'wait.sh'
        script.write_text('set -eu\nwait_dhcp_owner() {' + body +
            '\npid() { n=$(cat "$TEST_COUNTER"); n=$((n+1)); echo "$n" > "$TEST_COUNTER"; '
            '[ "$n" -gt 1 ] || return 1; echo 42; }\n'
            'running() { :; }\none_owner() { :; }\nsleep() { :; }\nubus() { :; }\nwait_dhcp_owner\n')
        result = subprocess.run(['sh', str(script)], capture_output=True, text=True,
            env={**os.environ, 'TEST_UPLINK': str(helper), 'TEST_COUNTER': str(counter)}, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(int(counter.read_text()), 7)

    def test_vm_peer_resources_close_even_before_boot(self):
        spec = importlib.util.spec_from_file_location('openwrt_vm', ROOT / 'test/system/run-openwrt-vm.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        vm = runner.VM(SimpleNamespace(release='24.10.8', work=self.sdk / 'client', port=0))
        peer = runner.VM(SimpleNamespace(release='24.10.8', work=self.sdk / 'server', port=0))
        vm.lease_server = peer
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        vm.lease_socket, peer.lease_socket = left, right
        vm.close()
        self.assertEqual(left.fileno(), -1)
        self.assertEqual(right.fileno(), -1)
        for instance in (vm, peer):
            self.assertTrue(instance.serial.closed)
            self.assertFalse(json.loads((instance.work / 'report.json').read_text())['passed'])

    def test_fresh_sdk_requires_defconfig_before_staging(self):
        (self.sdk / '.config').unlink()
        with self.assertRaisesRegex(ValueError, 'defconfig'):
            self.prepare()
        self.assertFalse((self.sdk / 'package').exists())


class OpenWrtServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        for directory in ('bin', 'etc/tayga', 'sys/class/net/tun64', 'var/lock'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / 'sys/class/net/tun64/tun_flags').write_text('0x1001\n')
        for name, script in {
            'id': 'echo 0',
            'tayga': 'case "$*" in *--check-config*) ;; *) exit 2;; esac\nfor last; do :; done\n! grep -q invalid "$last"',
            'logger': ':',
            'uplink': 'printf "%s\\n" "$TEST_UPLINK_INFO"\nexit "${TEST_UPLINK_RESULT:-0}"',
        }.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + script + '\n')
            path.chmod(0o755)
        if not shutil.which('flock'):
            tool = self.bin / 'flock'
            tool.write_text('#!' + sys.executable + '\nimport fcntl; fcntl.flock(9,fcntl.LOCK_EX|fcntl.LOCK_NB)\n')
            tool.chmod(0o755)
        self.candidate = self.root / 'etc/tayga/candidate.conf'
        self.candidate.write_text('tun-device tun64\nipv4-addr 192.0.2.1\nipv6-addr fd64::1\nprefix 64:ff9b::/96\ndata-dir /var/lib/tayga\n')
        self.state = self.root / 'etc/tayga-managed'
        self.helper = ROOT / 'packaging/openwrt/openwrt-state.sh'
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'TAYGA_TESTING': '1', 'TAYGA_TEST_ROOT': str(self.root)}

    def run_helper(self, *args):
        return subprocess.run(['sh', str(self.helper), *map(str, args)], env=self.env, capture_output=True, text=True)

    def prepare(self):
        result = self.run_helper('prepare', self.candidate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.state / 'active.conf'))
        return (self.state / 'active.conf').read_text()

    def test_persistent_snapshot_validation_and_noop_does_not_rewrite(self):
        text = self.prepare()
        self.assertIn('data-dir ' + str(self.state / 'data'), text)
        before = (self.state / 'active.conf').stat().st_mtime_ns
        self.prepare()
        self.assertEqual(before, (self.state / 'active.conf').stat().st_mtime_ns)
        self.assertFalse((self.state / 'pending').exists())

    def test_bad_candidate_missing_tun_and_external_map_cannot_replace_snapshot(self):
        original = self.prepare()
        for extra in ('invalid\n', 'map-file /tmp/maps\n', 'data-dir /another\n'):
            self.candidate.write_text(original + extra)
            self.assertNotEqual(self.run_helper('prepare', self.candidate).returncode, 0)
            self.assertEqual((self.state / 'active.conf').read_text(), original)
        self.candidate.write_text(original)
        (self.root / 'sys/class/net/tun64/tun_flags').unlink()
        self.assertNotEqual(self.run_helper('prepare', self.candidate).returncode, 0)
        self.assertEqual((self.state / 'active.conf').read_text(), original)

    def test_interrupted_publication_restores_previous_without_kernel_commands(self):
        previous = self.prepare()
        pending = self.state / 'pending'
        pending.mkdir()
        (pending / 'ready').write_text('v1\n')
        (pending / 'previous').write_text('yes\n')
        (pending / 'old.conf').write_text(previous)
        (self.state / 'active.conf').write_text('interrupted candidate\n')
        result = self.run_helper('recover')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.state / 'active.conf').read_text(), previous)
        self.assertFalse(pending.exists())

    def test_interrupted_first_install_and_invalid_recovery_metadata(self):
        self.prepare()
        pending = self.state / 'pending'
        pending.mkdir()
        (pending / 'ready').write_text('v1\n')
        (pending / 'previous').write_text('bad\n')
        self.assertNotEqual(self.run_helper('recover').returncode, 0)
        self.assertTrue((self.state / 'active.conf').exists())
        (pending / 'previous').write_text('no\n')
        self.assertEqual(self.run_helper('recover').returncode, 0)
        self.assertFalse((self.state / 'active.conf').exists())

    def test_candidate_outside_owned_config_directory_is_rejected(self):
        outside = self.root / 'outside.conf'
        shutil.copyfile(self.candidate, outside)
        self.assertNotEqual(self.run_helper('prepare', outside).returncode, 0)
        link = self.root / 'etc/tayga/link.conf'
        link.symlink_to(outside)
        self.assertNotEqual(self.run_helper('prepare', link).returncode, 0)

    def test_managed_snapshot_normalizes_tun_and_fences_live_reconfiguration(self):
        lib = self.root / 'usr/libexec/tayga'
        lib.mkdir(parents=True)
        checker = lib / 'openwrt-network'
        checker.write_text('#!/bin/sh\n[ "$1" = check ] && grep -qx "tun-device tmg0" "$2"\n')
        result = self.run_helper('prepare', self.candidate, 'managed')
        self.assertEqual(result.returncode, 0, result.stderr)
        accepted = (self.state / 'active.conf').read_text()
        self.assertIn('tun-device tmg0', accepted)
        (self.root / 'var/run/tayga-managed/network').mkdir(parents=True)
        self.candidate.write_text(self.candidate.read_text() + '# changed profile\n')
        result = self.run_helper('prepare', self.candidate, 'managed')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Stop the managed service', result.stderr)
        self.assertEqual((self.state / 'active.conf').read_text(), accepted)

    def service(self, action, enabled='1', boot=False, uplink='', uplink_result='0'):
        script = (ROOT / 'packaging/openwrt/tayga-managed.init').read_text()
        script = script.replace('/usr/libexec/tayga/openwrt-state', 'sh ' + str(self.helper))
        script = script.replace('/usr/libexec/tayga/openwrt-uplink', str(self.bin / 'uplink'))
        script = script.replace('/etc/tayga-managed/package-upgrade', str(self.state / 'package-upgrade'))
        script = script.replace('/var/run/tayga-managed', str(self.root / 'run/tayga-managed'))
        harness = self.root / 'service.sh'
        harness.write_text('extra_command() { :; }\n' + script + '''
config_load() { :; }
config_get_bool() { eval "$1=\\\"$TEST_ENABLED\\\""; }
config_get() {
    case "$3" in network_mode) eval "$1=external";; config) eval "$1=\\\"$TEST_CANDIDATE\\\"";; uplink) eval "$1=\\\"$TEST_UPLINK\\\"";; esac
}
procd_open_instance() { echo "open:$*"; }
procd_set_param() { echo "param:$*"; }
procd_close_instance() { echo close; }
start() { start_service; }
''' + action + '\n')
        return subprocess.run(['sh', str(harness)], env={**self.env, 'TEST_ENABLED': enabled,
                              'TEST_CANDIDATE': str(self.candidate), 'TEST_UPLINK': uplink,
                              'TEST_UPLINK_RESULT': uplink_result,
                              'TEST_UPLINK_INFO': 'wan0 0123456789abcdef'}, capture_output=True, text=True)

    def test_pending_package_upgrade_fences_normal_start(self):
        previous = self.prepare()
        marker = self.state / 'package-upgrade'
        for kind in ('directory', 'file', 'symlink'):
            with self.subTest(kind=kind):
                if kind == 'directory': marker.mkdir()
                elif kind == 'file': marker.write_text('broken journal')
                else: marker.symlink_to(self.state / 'missing')
                result = self.service('start_service')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('open:', result.stdout)
                self.assertEqual((self.state / 'active.conf').read_text(), previous)
                if kind == 'directory': marker.rmdir()
                else: marker.unlink()

    def test_profile_publication_is_fenced_by_package_journal(self):
        previous = self.prepare()
        (self.state / 'package-upgrade').mkdir()
        self.candidate.write_text(self.candidate.read_text() + '# changed candidate\n')
        result = self.run_helper('prepare', self.candidate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Package upgrade pending', result.stderr)
        self.assertEqual((self.state / 'active.conf').read_text(), previous)
        result = self.service('reload_service')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('open:', result.stdout)
        self.assertEqual((self.state / 'active.conf').read_text(), previous)

    def test_procd_disabled_and_enabled_command_contract(self):
        result = self.service('start_service', enabled='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('open:', result.stdout)
        result = self.service('start_service')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('param:command /usr/sbin/tayga --config ' + str(self.state / 'active.conf'), result.stdout)
        self.assertIn('param:respawn 3600 5 3', result.stdout)

    def test_reload_failure_preserves_service_and_boot_uses_accepted_snapshot(self):
        previous = self.prepare()
        self.candidate.write_text('invalid candidate\n')
        result = self.service('reload_service')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('open:', result.stdout)
        self.assertEqual((self.state / 'active.conf').read_text(), previous)

        result = self.service('start_service')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('open:main', result.stdout)
        self.assertIn('param:command /usr/sbin/tayga --config ' + str(self.state / 'active.conf'), result.stdout)
        self.assertEqual((self.state / 'active.conf').read_text(), previous)
        result = self.service('boot')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('open:main', result.stdout)
        self.assertEqual((self.state / 'active.conf').read_text(), previous)


    def test_wan_suspend_resume_uses_snapshot_and_manual_stop_disarms_events(self):
        result = self.service('start_service', uplink='wan6', uplink_result='3')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('open:', result.stdout)
        armed = self.root / 'run/tayga-managed/armed'
        self.assertTrue(armed.exists())
        accepted = (self.state / 'active.conf').read_text()
        self.candidate.write_text('invalid candidate\n')
        result = self.service('uplink_changed unrelated', uplink='wan6')
        self.assertNotIn('open:', result.stdout)
        result = self.service('uplink_changed wan6', uplink='wan6')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('param:netdev wan0', result.stdout)
        self.assertIn('param:data uplink=wan6 uplink_state=0123456789abcdef', result.stdout)
        self.assertIn('param:env TAYGA_UPLINK=wan6 TAYGA_UPLINK_STATE=0123456789abcdef', result.stdout)
        self.assertEqual((self.state / 'active.conf').read_text(), accepted)
        self.service('stop_service', uplink='wan6')
        self.assertFalse(armed.exists())
        result = self.service('uplink_changed wan6', uplink='wan6')
        self.assertNotIn('open:', result.stdout)
        result = self.service('TAYGA_OPENWRT_EVENT=1 start_service', uplink='wan6')
        self.assertNotIn('open:', result.stdout)

    def test_hotplug_filters_interface_and_does_not_exit_dispatcher(self):
        uci = self.bin / 'uci'
        uci.write_text('#!/bin/sh\necho wan6\n')
        uci.chmod(0o755)
        service = self.bin / 'mock-service'
        service.write_text('#!/bin/sh\necho "service:$*"\n')
        service.chmod(0o755)
        hook = self.root / 'hotplug'
        hook.write_text((ROOT / 'packaging/openwrt/tayga-managed.hotplug').read_text().replace('/etc/init.d/tayga-managed', str(service)))
        for action, interface, selected in (('ifup', 'wan6', True), ('ifupdate', 'wan6', True),
                                             ('ifdown', 'other', False), ('free', 'wan6', False)):
            result = subprocess.run(['sh', '-c', '. "$1"; echo dispatcher-alive', 'sh', str(hook)],
                                    env={**self.env, 'ACTION': action, 'INTERFACE': interface}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('dispatcher-alive', result.stdout)
            self.assertEqual('service:uplink_changed wan6' in result.stdout, selected)

    def test_managed_clat_nat64_siit_rules_and_proto(self):
        net_dir = self.root / 'run/tayga-managed/network'
        net_dir.mkdir(parents=True)
        (net_dir / 'wan').write_text('eth1\n')
        (net_dir / 'inside').write_text('br-lan\n')
        (net_dir / 'token').write_text('owner.12345678\n')
        clat_cfg = self.root / 'etc/tayga/clat.conf'
        clat_cfg.write_text(
            '# installer-mode clat\n'
            '# installer-clat-address-mode nat66\n'
            '# installer-nat66-address 2001:db8:1::9\n'
            '# installer-host-dns public\n'
            'tun-device tmg0\n'
            'ipv4-addr 192.0.0.2\n'
            'ipv6-addr fd64:100::2\n'
            'prefix fd64:100::/96\n'
            'map 192.0.0.1 fd64:100::1\n'
        )
        shutil.copyfile(clat_cfg, net_dir / 'config')
        net_script = (ROOT / 'packaging/openwrt/openwrt-network.sh').read_text().replace(
            '/var/run/tayga-managed', str(self.root / 'run/tayga-managed')
        )
        net_file = self.root / 'openwrt-network.sh'
        net_file.write_text(net_script)
        chk = subprocess.run(['sh', str(net_file), 'check', str(clat_cfg)], env=self.env, capture_output=True, text=True)
        self.assertEqual(chk.returncode, 0, chk.stderr)
        rules_run = subprocess.run(
            ['sh', '-c', 'TAYGA_NETWORK_LIBRARY=1 . "$1"; net_parse "$2" && net_rules', 'sh', str(net_file), str(clat_cfg)],
            env=self.env, capture_output=True, text=True
        )
        self.assertEqual(rules_run.returncode, 0, rules_run.stderr)
        self.assertIn('tayga-managed CLAT LAN', (net_dir / 'forward.rules.nft').read_text())
        self.assertIn('tayga-managed local CLAT', (net_dir / 'output.rules.nft').read_text())
        srcnat_text = (net_dir / 'srcnat.rules.nft').read_text()
        self.assertIn('tayga-managed CLAT LAN masq', srcnat_text)
        self.assertIn('snat ip6 to 2001:db8:1::9', srcnat_text)

    def test_managed_readiness_verify_and_automatic_rollback(self):
        lib = self.root / 'usr/libexec/tayga'
        lib.mkdir(parents=True)
        net_dir = self.root / 'run/tayga-managed/network'
        net_dir.mkdir(parents=True)
        (net_dir / 'token').write_text('owner.abcdef12\n')
        net_helper = lib / 'openwrt-network'
        net_helper.write_text(
            '#!/bin/sh\n'
            'case "$1" in\n'
            '  check) exit 0;;\n'
            '  up) echo "net-up:$2"; exit 0;;\n'
            '  down) echo "net-down"; exit 0;;\n'
            '  verify) echo "net-verify:$2:$3"; ! grep -q fail_verify "$2";;\n'
            'esac\n'
        )
        net_helper.chmod(0o755)
        script = (ROOT / 'packaging/openwrt/tayga-managed.init').read_text()
        script = script.replace('/usr/libexec/tayga/openwrt-state', 'sh ' + str(self.helper))
        script = script.replace('/usr/libexec/tayga/openwrt-uplink', str(self.bin / 'uplink'))
        script = script.replace('/usr/libexec/tayga/openwrt-network', str(net_helper))
        script = script.replace('/etc/tayga-managed/package-upgrade', str(self.state / 'package-upgrade'))
        script = script.replace('/var/run/tayga-managed', str(self.root / 'run/tayga-managed'))
        harness = self.root / 'managed-service.sh'
        harness.write_text('extra_command() { :; }\n' + script + '''
config_load() { :; }
config_get_bool() { eval "$1=1"; }
config_get() {
    case "$3" in
        network_mode) eval "$1=managed";;
        config) eval "$1=\\\"$TEST_CANDIDATE\\\"";;
        uplink) eval "$1=wan6";;
        inside) eval "$1=lan";;
        verify_target) eval "$1=198.51.100.1";;
    esac
}
procd_open_instance() { echo "open:$*"; }
procd_set_param() { echo "param:$*"; }
procd_close_instance() { echo close; }
stop() { stop_service; }
start() { start_service && service_started; }
start
''')
        res1 = subprocess.run(['sh', str(harness)], env={
            **self.env, 'TEST_CANDIDATE': str(self.candidate), 'TEST_UPLINK_RESULT': '0', 'TEST_UPLINK_INFO': 'eth1 state1'
        }, capture_output=True, text=True)
        self.assertEqual(res1.returncode, 0, res1.stderr)
        good_snapshot = (self.state / 'active.conf').read_text()
        self.assertFalse((self.state / 'previous.conf').exists())

        self.candidate.write_text(self.candidate.read_text() + '# fail_verify\n')
        res2 = subprocess.run(['sh', str(harness)], env={
            **self.env, 'TEST_CANDIDATE': str(self.candidate), 'TEST_UPLINK_RESULT': '0', 'TEST_UPLINK_INFO': 'eth1 state1'
        }, capture_output=True, text=True)
        self.assertNotEqual(res2.returncode, 0)
        self.assertEqual((self.state / 'active.conf').read_text(), good_snapshot)
