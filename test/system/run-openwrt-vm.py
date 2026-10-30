#!/usr/bin/env python3
"""Boot a pinned disposable OpenWrt VM and test real procd/overlay lifecycle.

No shared host folders, external guest networking or non-loopback listeners.
Every run requires a new work directory and retains its disk/logs/report.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import subprocess
import tarfile
import time
import zlib

RELEASES = {
    '24.10.8': {
        'manager': 'opkg', 'suffix': '.ipk', 'pins': {
            'kernel': 'ccc97f1598224e73a5f75fb1612c284db037f02fa050d1a18b5b2ee93631e37e',
            'image': '9013deabf64ddd93bd2039b1b469a595c48201d611a9885afffd050053d063a5',
            'tun': '9bbbf77e4762077d8bd49602ccb1fff1767c0e540de9f24507dcc5355f150caa',
            'flock': 'a0718db1870b45db97dbfe79f0a53ed6fe784a92520be08024a1da7a84edfa17',
        }},
    '25.12.6': {
        'manager': 'apk', 'suffix': '.apk', 'pins': {
            'kernel': '2b9ce48df5536e993ee691339057828488e4a31be9c2bb5d3f6120f1135fcbb0',
            'image': 'da639ebe2205532dce3ffacd2e91657c15d0ac77234c26bda1f63efbbd8efba1',
            'tun': 'cf50e6c6a97f086810871daefae92cf18b0f3bc0da89550abd9c6e9887eab7ab',
            'flock': '8d02f35efa78b15aa380a2028fabc10ef1b8e65b30289b5c0d0a91b223651fc0',
        }},
}


class VM:
    def __init__(self, args):
        self.args = args
        self.release = RELEASES[args.release]
        self.work = args.work.resolve()
        self.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.process = None
        self.lease_socket = None
        self.lease_server = None
        self.serial = (self.work / 'serial.log').open('wb')
        self.report = {'openwrt': args.release, 'package_manager': self.release['manager'], 'target': 'armsr/armv8', 'passed': False,
                       'inputs': {}, 'phases': [], 'supervised_instances': {}}
        self.port = args.port
        if not self.port:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                self.port = listener.getsockname()[1]
        self.key = self.work / 'test-key'
        self.ssh = ['ssh', '-F', os.devnull, '-i', str(self.key), '-p', str(self.port), '-o', 'BatchMode=yes',
                    '-o', 'IdentitiesOnly=yes', '-o', 'LogLevel=ERROR',
                    '-o', 'StrictHostKeyChecking=accept-new',
                    '-o', 'UserKnownHostsFile=' + str(self.work / 'known_hosts'),
                    '-o', 'ConnectTimeout=2', 'root@127.0.0.1']

    def run_ssh(self, command, timeout=120, check=True, stdin=None):
        result = subprocess.run(self.ssh + [command], stdin=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f'SSH command failed ({result.returncode}): {command}\n' + result.stdout.decode(errors='replace'))
        return result

    def start(self):
        accel = self.args.accel
        if accel == 'auto':
            if platform.system() == 'Darwin' and platform.machine() == 'arm64':
                accel = 'hvf'
            elif platform.machine() in ('aarch64', 'arm64') and os.access('/dev/kvm', os.R_OK | os.W_OK):
                accel = 'kvm'
            else:
                accel = 'tcg'
        command = [self.args.qemu, '-machine', 'virt', '-accel', accel,
                   '-cpu', 'host' if accel in ('hvf', 'kvm') else 'cortex-a72',
                   '-smp', '2', '-m', '512', '-kernel', str(self.args.kernel.resolve()),
                   '-append', 'root=/dev/vda2 rootwait console=ttyAMA0',
                   '-drive', f'file={self.work / "disk.raw"},format=raw,if=virtio',
                   '-netdev', f'user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{self.port}-:22',
                   '-device', 'virtio-net-pci,netdev=net0', '-device', 'virtio-rng-pci',
                   '-display', 'none', '-serial', 'stdio', '-monitor', 'none']
        if self.args.network:
            command += ['-netdev', 'user,id=net1,restrict=on,net=10.0.3.0/24,ipv6-net=fd42:3::/64,ipv6-host=fd42:3::2',
                        '-device', 'virtio-net-pci,netdev=net1']
        if self.lease_socket is not None:
            command += ['-netdev', f'dgram,id=lease,local.type=fd,local.str={self.lease_socket.fileno()}',
                        '-device', 'virtio-net-pci,netdev=lease,mac=52:54:00:64:00:' +
                        ('01' if self.args.network else '02')]
        self.report['qemu_command'] = command
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=self.serial, stderr=subprocess.STDOUT,
                                        pass_fds=() if self.lease_socket is None else (self.lease_socket.fileno(),))

    def alive(self):
        if self.process.poll() is not None:
            raise RuntimeError('QEMU exited; inspect serial.log')

    def console(self, command):
        self.alive()
        self.process.stdin.write((command + '\n').encode())
        self.process.stdin.flush()

    def wait_serial(self, needle, timeout=120, activate=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.alive()
            if needle in (self.work / 'serial.log').read_text(errors='replace'):
                return
            if activate:
                self.console('')
            time.sleep(0.5)
        raise TimeoutError('Boot console timed out; inspect serial.log')

    def wait_ssh(self, previous=None, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.alive()
            try:
                result = self.run_ssh('cat /proc/sys/kernel/random/boot_id', timeout=5, check=False)
            except subprocess.TimeoutExpired:
                time.sleep(1)
                continue
            boot_id = result.stdout.decode(errors='replace').strip()
            if result.returncode == 0 and boot_id and boot_id != previous:
                return boot_id
            time.sleep(1)
        raise TimeoutError('SSH/new boot timed out; inspect serial.log')

    def phase(self, name, command=None):
        print('Running ' + name, flush=True)
        command = command or ('TAYGA_ISOLATED_TEST=yes sh -x /etc/tayga-procd-test/test.sh ' + name)
        try:
            result = self.run_ssh(command, timeout=480 if name == 'managed' or 'upgrade' in name or 'dhcpv6' in name else 120, check=False)
        except subprocess.TimeoutExpired as error:
            (self.work / (name + '.log')).write_bytes(error.output or b'')
            diagnostics = self.run_ssh('logread; ubus call service list; ip addr; ip route; ip -6 route', check=False)
            (self.work / (name + '-diagnostics.log')).write_bytes(diagnostics.stdout)
            raise
        output = result.stdout.decode(errors='replace')
        (self.work / (name + '.log')).write_text(output)
        if result.returncode:
            diagnostics = self.run_ssh('logread; ubus call network.interface.tayga_managed status; '
                                       'ip addr; ip route; ip -6 route; nft list ruleset', check=False)
            (self.work / (name + '-diagnostics.log')).write_bytes(diagnostics.stdout)
            raise RuntimeError(f'{name} failed ({result.returncode}):\n{output}')
        self.report['phases'].append(name)
        for line in output.splitlines():
            if line.startswith('PASS:'):
                print(line, flush=True)

    def instance(self, label):
        result = self.run_ssh('ubus call service list \'{"name":"tayga-managed"}\'')
        data = json.loads(result.stdout)['tayga-managed']['instances']
        assert list(data) == ['main'] and data['main']['running']
        self.report['supervised_instances'][label] = data['main']

    def bootstrap(self):
        # OpenWrt gzip images have a firmware metadata trailer. Validate the
        # gzip member's CRC/length; its complete input is pinned above.
        decompressor = zlib.decompressobj(31)
        with self.args.image.open('rb') as source, (self.work / 'disk.raw').open('wb') as disk:
            while chunk := source.read(1024 * 1024):
                disk.write(decompressor.decompress(chunk))
            disk.write(decompressor.flush())
        if not decompressor.eof:
            raise ValueError('Truncated gzip image')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True)
        self.start()
        self.wait_serial('Please press Enter to activate this console.')
        self.console('')
        self.wait_serial('root@OpenWrt:', activate=True)
        public_key = ' '.join(self.key.with_suffix('.pub').read_text().split()[:2])
        self.console("mkdir -p /etc/dropbear; echo " + shlex.quote(public_key) + " > /etc/dropbear/authorized_keys; "
                     "chmod 600 /etc/dropbear/authorized_keys; uci set network.lan.ipaddr='10.0.2.15'; "
                     "uci set network.lan.netmask='255.255.255.0'; uci commit network; /etc/init.d/network restart")
        initial_boot = self.wait_ssh()
        self.report['initial_boot'] = initial_boot
        self.run_ssh('. /etc/openwrt_release; test "$DISTRIB_RELEASE" = ' +
                     shlex.quote(self.args.release) + ' && command -v ' + self.release['manager'])
        return initial_boot

    def execute(self):
        for name, path in (('runner', Path(__file__)), ('guest_test', Path(__file__).with_name('installer-openwrt-procd-smoke.sh'))):
            self.report['inputs'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        names = ['kernel', 'image', 'base', 'procd', 'tun', 'flock']
        if self.args.network:
            names.append('network')
        if getattr(self.args, 'upgrader', None):
            names.append('upgrader')
        if getattr(self.args, 'upgrade_base', None):
            names.extend(['upgrade_base', 'upgrade_procd', 'upgrade_network'])
        for name in names:
            path = getattr(self.args, name)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if name not in ('kernel', 'image') and path.suffix != self.release['suffix']:
                raise ValueError('Wrong package format for selected release: ' + name)
            if name in self.release['pins'] and digest != self.release['pins'][name]:
                raise ValueError('Wrong pinned OpenWrt input: ' + name)
            self.report['inputs'][name] = digest
        for index, path in enumerate(self.args.extra_package):
            if path.suffix != self.release['suffix']:
                raise ValueError('Wrong extra package format for selected release')
            self.report['inputs'][f'extra_package_{index}'] = hashlib.sha256(path.read_bytes()).hexdigest()
        initial_boot = self.bootstrap()
        archive = self.work / 'inputs.tar'
        with tarfile.open(archive, 'w') as bundle:
            for name in ['base', 'procd', 'tun', 'flock'] + (['network'] if self.args.network else []) + (['upgrader'] if self.args.upgrader else []):
                bundle.add(getattr(self.args, name), arcname=('kmod-tun' if name == 'tun' else name) + self.release['suffix'])
            if self.args.upgrade_base:
                for role in ('base', 'procd', 'network'):
                    bundle.add(getattr(self.args, 'upgrade_' + role), arcname='next-' + role + self.release['suffix'])
            bundle.add(Path(__file__).with_name('installer-openwrt-procd-smoke.sh'), arcname='test.sh')
            for index, path in enumerate(self.args.extra_package):
                bundle.add(path, arcname=f'extra-{index}' + self.release['suffix'])
        with archive.open('rb') as source:
            self.run_ssh('mkdir -p /tmp/tayga-procd-inputs; tar -xf - -C /tmp/tayga-procd-inputs', stdin=source)
        self.phase('install', 'TAYGA_ISOLATED_TEST=yes sh -x /tmp/tayga-procd-inputs/test.sh install /tmp/tayga-procd-inputs')
        self.instance('initial')
        self.phase('lifecycle')
        self.instance('after_respawn')
        self.phase('uplink-facts')
        self.phase('wan')
        self.instance('after_wan_handover')
        if self.args.network_only:
            # netifd loads protocol handlers on startup, not network reload.
            self.phase('arm-reboot')
            self.run_ssh('reboot', timeout=10, check=False)
            network_boot = self.wait_ssh(previous=initial_boot)
            self.phase('check-reboot', 'TAYGA_ISOLATED_TEST=yes sh -x /etc/tayga-procd-test/test.sh check-boot')
            self.instance('after_network_reboot')
            if self.args.dhcpv6_server:
                self.test_dhcpv6()
            self.phase('managed')
            self.phase('remove')
            self.run_ssh('poweroff', timeout=10, check=False)
            self.process.wait(timeout=30)
            self.report.update(passed=True, suite='managed-network-only', reboot_boot=network_boot)
            return
        self.phase('arm-reboot')
        self.run_ssh('reboot', timeout=10, check=False)
        reboot_id = self.wait_ssh(previous=initial_boot)
        self.phase('check-reboot', 'TAYGA_ISOLATED_TEST=yes sh -x /etc/tayga-procd-test/test.sh check-boot')
        self.instance('after_reboot')
        self.phase('arm-powercut')
        self.process.kill()
        self.process.wait(timeout=10)
        time.sleep(0.5)
        self.start()
        powercut_id = self.wait_ssh(previous=reboot_id)
        self.phase('check-powercut', 'TAYGA_ISOLATED_TEST=yes sh -x /etc/tayga-procd-test/test.sh check-boot')
        self.instance('after_powercut')
        if self.args.upgrade_base:
            self.phase('upgrade-failure')
            self.phase('upgrade-readiness-failure')
            self.phase('arm-upgrade-powercut')
            self.process.kill()
            self.process.wait(timeout=10)
            time.sleep(0.5)
            self.start()
            upgrade_boot = self.wait_ssh(previous=powercut_id)
            self.phase('check-upgrade-recovery')
            self.phase('upgrade-success')
            self.report['upgrade_recovery_boot'] = upgrade_boot
            self.report['upgrade_powercut'] = 'QEMU SIGKILL after target package installation, before upgrade confirmation'
            self.instance('after_upgrade')
        if self.args.dhcpv6_server:
            self.test_dhcpv6()
        if self.args.network:
            self.phase('managed')
        self.phase('remove')
        self.run_ssh('poweroff', timeout=10, check=False)
        self.process.wait(timeout=30)
        self.report.update(passed=True, reboot_boot=reboot_id, powercut_boot=powercut_id,
                           powercut='QEMU SIGKILL after synced pending journal and interrupted active config')

    def test_dhcpv6(self):
        server = self.lease_server
        fixture = Path(__file__).with_name('installer-openwrt-dhcpv6-server.sh')
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        self.report['inputs']['dhcpv6_server_fixture'] = digest
        server.report['inputs'] = {key: self.report['inputs'][key] for key in ('runner', 'kernel', 'image')}
        server.report['inputs']['fixture'] = digest
        server.bootstrap()
        with fixture.open('rb') as source:
            server.run_ssh('cat > /tmp/dhcpv6-server.sh', stdin=source)
        server.phase('server-setup', 'TAYGA_ISOLATED_TEST=yes sh -x /tmp/dhcpv6-server.sh setup')
        self.phase('dhcpv6-start')
        server.phase('server-lease-initial', 'TAYGA_ISOLATED_TEST=yes sh -x /tmp/dhcpv6-server.sh leases fd62:100:')
        self.phase('dhcpv6-renew')
        server.phase('server-renumber', 'TAYGA_ISOLATED_TEST=yes sh -x /tmp/dhcpv6-server.sh renumber')
        self.phase('dhcpv6-renumber')
        server.phase('server-lease-renumbered', 'TAYGA_ISOLATED_TEST=yes sh -x /tmp/dhcpv6-server.sh leases fd62:200:')
        server.phase('server-retire-old', 'TAYGA_ISOLATED_TEST=yes sh -x /tmp/dhcpv6-server.sh retire-old')
        self.phase('dhcpv6-retire')
        self.instance('after_dhcpv6_renumber')
        self.phase('dhcpv6-stop')
        server.report['passed'] = True
        self.report['dhcpv6_server'] = {'release': self.args.release, 'transport': 'private AF_UNIX datagram socketpair',
                                      'slaac': False, 'address': 'IA_NA', 'delegation': 'IA_PD /62',
                                      'prefixes': ['fd62:100::/48', 'fd62:200::/48'], 'renumbering': 'overlap, then retire old prefix',
                                      'report': str(server.work / 'report.json')}

    def close(self):
        if self.lease_server is not None:
            self.lease_server.close()
        if self.lease_socket is not None:
            self.lease_socket.close()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.serial.close()
        self.key.unlink(missing_ok=True)
        (self.work / 'report.json').write_text(json.dumps(self.report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel', 'image', 'base', 'procd', 'tun', 'flock', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--network-only', action='store_true', help='Run install/lifecycle/WAN, one reboot and managed networking without power-cut/package-upgrade phases')
    parser.add_argument('--dhcpv6-server', action='store_true', help='Test IA_NA/IA_PD and renumbering against a second isolated OpenWrt VM')
    parser.add_argument('--release', choices=tuple(RELEASES), default='24.10.8')
    parser.add_argument('--qemu', default='qemu-system-aarch64')
    parser.add_argument('--upgrader', type=Path, help='Independent baseline upgrade coordinator package')
    parser.add_argument('--network', type=Path, help='Optional managed netifd/fw4 package (adds isolated test NIC)')
    parser.add_argument('--extra-package', type=Path, action='append', default=[], help='Offline dependency archive; may be repeated')
    for role in ('base', 'procd', 'network'):
        parser.add_argument('--upgrade-' + role, type=Path, help='Optional target package; supply all three')
    parser.add_argument('--accel', choices=('auto', 'hvf', 'kvm', 'tcg'), default='auto')
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    if args.dhcpv6_server and not args.network:
        parser.error('--dhcpv6-server requires --network')
    if args.upgrader and not args.network:
        parser.error('--upgrader requires --network')
    upgrade_count = sum(getattr(args, 'upgrade_' + role) is not None for role in ('base', 'procd', 'network'))
    if args.network_only and (not args.network or upgrade_count):
        parser.error('--network-only requires --network and excludes --upgrade-* packages')
    if upgrade_count not in (0, 3) or (upgrade_count and (not args.network or not args.upgrader)):
        parser.error('Upgrade tests require --network, --upgrader and all three --upgrade-* packages')
    if not 0 <= args.port <= 65535:
        parser.error('invalid loopback port')
    for command in (args.qemu, 'ssh', 'ssh-keygen'):
        if not shutil.which(command):
            parser.error('Required tool missing: ' + command)
    vm = VM(args)
    try:
        if args.dhcpv6_server:
            peer_args = copy.copy(args)
            peer_args.work = vm.work / 'dhcpv6-server'
            peer_args.port = 0
            peer_args.network = None
            peer_args.dhcpv6_server = False
            vm.lease_server = VM(peer_args)
            vm.lease_socket, vm.lease_server.lease_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        vm.execute()
    except BaseException as error:
        vm.report['error'] = str(error)
        if vm.lease_server is not None and vm.lease_server.process is not None and vm.lease_server.process.poll() is None:
            peer = vm.lease_server
            peer.report['error'] = str(error)
            try:
                diagnostics = peer.run_ssh('logread; ubus call dhcp ipv6leases; '
                                           'ubus call network.interface.lease status; ip -6 addr; ip -6 route; nft list ruleset',
                                           timeout=15, check=False)
                (peer.work / 'failure-diagnostics.log').write_bytes(diagnostics.stdout)
            except (subprocess.SubprocessError, OSError):
                pass
        raise
    finally:
        vm.close()
    print('PASS: OpenWrt VM; report: ' + str(vm.work / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
