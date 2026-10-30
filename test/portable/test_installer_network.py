"""Fault-injection tests for network ownership and rollback (no privileges)."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / 'packaging/installer/tayga-net-ctl.sh'


class NetworkControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'log'
        self.state = self.root / 'state'
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'TAYGA_NET_STATE': str(self.state), 'TEST_LOG': str(self.log), 'SSH_CONNECTION': '198.51.100.7 123 10.0.0.2 22'}
        for name, script in {
            'uname': 'echo Linux', 'id': 'echo 0',
            'tayga': 'echo "tayga $*" >> "$TEST_LOG"',
            'sysctl': 'echo "sysctl $*" >> "$TEST_LOG"; if [ "$1" = -n ]; then echo 0; fi',
            'curl': 'echo "curl $*" >> "$TEST_LOG"; [ "${TEST_CURL_FAIL:-no}" != yes ]',
            'iptables': 'echo "iptables $*" >> "$TEST_LOG"; case "$*" in *MASQUERADE*) [ "${TEST_FW_FAIL:-no}" != yes ];; *"-D OUTPUT"*) [ "${TEST_UNDO_FAIL:-no}" != yes ];; esac',
            'ip6tables': 'echo "ip6tables $*" >> "$TEST_LOG"',
            'nft': 'echo "nft $*" >> "$TEST_LOG"; case "$1" in list) exit "${TEST_NFT_EXISTS:-1}";; -f) cat "$2" >> "$TEST_LOG"; [ "${TEST_NFT_FAIL:-no}" != yes ];; esac',
            'ip': '''echo "ip $*" >> "$TEST_LOG"
case "$*" in
    'link show dev '*) exit "${TEST_LINK_EXISTS:-1}" ;;
    '-6 addr show dev eth0') echo 'inet6 2001:db8::5/128 scope global' ;;
    '-6 neigh show proxy dev eth0') [ "${TEST_PROXY_EXISTS:-no}" != yes ] || echo '2001:db8::464 dev eth0' ;;
    '-4 route show default') echo 'default via 10.0.0.1 dev eth0' ;;
    '-6 route show default') echo 'default via fe80::1 dev eth0' ;;
    '-6 route get 2001:db8:20::42') echo "2001:db8:20::42 dev ${TEST_SIIT_NATIVE_DEV:-lan0}" ;;
    '-4 route get 198.51.100.42'|'-6 route get 2001:db8:64::') echo 'route dev siit' ;;
    '-4 route add 128.0.0.0/1 dev clat') [ "${TEST_FAIL:-no}" != yes ] ;;
esac''',
        }.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + script + '\n')
            path.chmod(0o755)
        self.config = self.root / 'clat.conf'
        self.config.write_text('tun-device clat\nprefix 64:ff9b::/96\nipv4-addr 192.0.0.2\nipv6-addr 2001:db8::2\nmap 192.0.0.1 2001:db8::464\n')
        with self.config.open('a') as stream:
            stream.write('offlink-mtu 1400\n')

    def run_controller(self, action, **env):
        return subprocess.run(['sh', str(CONTROLLER), action, str(self.config)],
                              env={**self.env, **env}, capture_output=True, text=True)

    def test_nat66_generation_requires_real_ula_and_explicit_source(self):
        generator = ROOT / 'packaging/installer/configure.sh'
        output = self.root / 'generated.conf'
        base = ['sh', str(generator), '--mode=clat', '--clat-address-mode=nat66',
                '--clat-ipv6=fd64::464', '--tayga-ipv6=fd64::2', '--output=' + str(output)]
        for extra in ([], ['--nat66-address=2001:db8::5', '--clat-ipv6=fd::464']):
            result = subprocess.run(base + extra, env=self.env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
        result = subprocess.run(base + ['--nat66-address=2001:db8::5'], env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('# installer-clat-address-mode nat66', output.read_text())

    def test_proxy_ndp_is_owned_and_restored_on_failure(self):
        with self.config.open('a') as stream:
            stream.write('# installer-clat-address-mode proxy-ndp\n')
        result = self.run_controller('up', TEST_FAIL='yes')
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text()
        self.assertIn('ip -6 neigh add proxy 2001:db8::464 dev eth0', log)
        self.assertIn('ip -6 neigh del proxy 2001:db8::464 dev eth0', log)
        self.assertIn('sysctl -w net.ipv6.conf.eth0.proxy_ndp=0', log)

    def test_proxy_ndp_preserves_existing_entries(self):
        with self.config.open('a') as stream:
            stream.write('# installer-clat-address-mode proxy-ndp\n')
        result = self.run_controller('up', TEST_PROXY_EXISTS='yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('neigh del proxy', self.log.read_text())

    def test_nat66_is_scoped_and_owned(self):
        text = self.config.read_text().replace('2001:db8::2', 'fd64::2').replace('2001:db8::464', 'fd64::464')
        self.config.write_text(text + '# installer-clat-address-mode nat66\n# installer-nat66-address 2001:db8::5\n')
        result = self.run_controller('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-s fd64::464/128 -d 64:ff9b::/96 -o eth0 -j SNAT --to-source 2001:db8::5', self.log.read_text())
        self.assertEqual(self.run_controller('down').returncode, 0)
        self.assertIn('ip6tables -w -t nat -X TAYGA_SFX_clat', self.log.read_text())

    def test_failure_rolls_back_only_successful_mutations(self):
        result = self.run_controller('up', TEST_FAIL='yes')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text()
        self.assertIn('route add 198.51.100.7/32 via 10.0.0.1 dev eth0', log)
        self.assertIn('route del 0.0.0.0/1 dev clat', log)
        self.assertNotIn('route del 128.0.0.0/1', log)
        self.assertTrue(log.rstrip().endswith('ip link delete dev clat'))
        self.assertFalse((self.state / 'clat.undo').exists())
        self.assertFalse((self.state / 'operation.lock').exists())

    def test_up_down_and_existing_interface_protection(self):
        result = self.run_controller('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.state / 'clat.undo').exists())
        self.assertNotEqual(self.run_controller('up').returncode, 0)
        result = self.run_controller('down')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_controller('down').returncode, 0)
        self.log.write_text('')
        self.assertNotEqual(self.run_controller('up', TEST_LINK_EXISTS='0').returncode, 0)
        self.assertNotIn('delete', self.log.read_text())

    def test_nat44_failure_removes_owned_hooks_and_restores_sysctls(self):
        self.config.write_text('tun-device nat64\nprefix 64:ff9b::/96\nipv4-addr 192.168.240.1\nipv6-addr fd64::2\ndynamic-pool 192.168.240.0/20\nofflink-mtu 1400\n')
        result = self.run_controller('up', TEST_FW_FAIL='yes')
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text()
        self.assertIn('-s 192.168.240.0/20 -o eth0 -j MASQUERADE', log)
        self.assertIn('iptables -w -t nat -D POSTROUTING -j TAYGA_SFX_nat64', log)
        self.assertIn('iptables -w -t nat -X TAYGA_SFX_nat64', log)
        self.assertNotIn('iptables -F', log)
        self.assertIn('sysctl -w net.ipv6.conf.all.forwarding=0', log)
        self.assertLess(log.index('net.ipv6.conf.eth0.accept_ra=2'), log.index('net.ipv6.conf.all.forwarding=1'))
        self.assertFalse((self.state / 'nat64.undo').exists())

    def test_clat_clamps_host_output_and_removes_hooks_before_chains(self):
        self.assertEqual(self.run_controller('up').returncode, 0)
        self.assertEqual(self.run_controller('down').returncode, 0)
        log = self.log.read_text()
        self.assertIn('mangle -I OUTPUT 1 -j TAYGA_SFX_clat', log)
        self.assertIn('--clamp-mss-to-pmtu', log)
        self.assertLess(log.index('mangle -D OUTPUT'), log.index('mangle -X TAYGA_SFX_clat'))

    def test_interrupted_cleanup_resumes_without_repeating_completed_routes(self):
        self.assertEqual(self.run_controller('up').returncode, 0)
        self.assertNotEqual(self.run_controller('down', TEST_UNDO_FAIL='yes').returncode, 0)
        result = self.run_controller('down')
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text()
        self.assertEqual(log.count('route del 128.0.0.0/1 dev clat'), 1)

    def test_verification_uses_translation_and_rejects_failed_tcp(self):
        verify = ROOT / 'packaging/installer/tayga-verify.sh'
        for mode, expected in [('clat', 'http://1.1.1.1/'), ('nat64', 'http://[64:ff9b::101:101]/')]:
            self.config.write_text('tun-device ' + mode + '\nprefix 64:ff9b::/96\n')
            result = subprocess.run(['sh', str(verify), str(self.config)],
                                    env={**self.env, 'TEST_LINK_EXISTS': '0'}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(expected, self.log.read_text())
        result = subprocess.run(['sh', str(verify), str(self.config)],
                                env={**self.env, 'TEST_LINK_EXISTS': '0', 'TEST_CURL_FAIL': 'yes'}, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_saved_ssh_peer_survives_service_environment(self):
        with self.config.open('a') as stream:
            stream.write('# installer-management4 203.0.113.55\n')
        result = self.run_controller('up', SSH_CONNECTION='')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('route add 203.0.113.55/32 via 10.0.0.1 dev eth0', self.log.read_text())

    def test_nft_table_ownership_and_atomic_load_failure(self):
        with self.config.open('a') as stream:
            stream.write('# installer-firewall nft\n')
        self.assertNotEqual(self.run_controller('up', TEST_NFT_EXISTS='0').returncode, 0)
        self.assertNotIn('nft delete table', self.log.read_text())
        self.log.write_text('')
        self.assertNotEqual(self.run_controller('up', TEST_NFT_FAIL='yes').returncode, 0)
        self.assertNotIn('nft delete table', self.log.read_text())
        self.assertFalse((self.state / 'operation.lock').exists())
        self.log.write_text('')
        self.assertEqual(self.run_controller('up').returncode, 0)
        self.assertEqual(self.run_controller('down').returncode, 0)
        log = self.log.read_text()
        self.assertIn('tcp option maxseg size set rt mtu', log)
        self.assertIn('nft delete table inet tayga_sfx_clat', log)
        self.assertNotIn('iptables -', log)

    def test_firewalld_lifecycle_and_rules(self):
        fcmd = self.bin / 'firewall-cmd'
        fcmd.write_text('''#!/bin/sh
echo "firewall-cmd $*" >> "$TEST_LOG"
case "$1" in
    --state) exit "${TEST_FIREWALLD_STATE:-0}" ;;
    --get-zone-of-interface=*) echo "${TEST_FIREWALLD_ZONE:-external}" ;;
    --get-default-zone) echo "public" ;;
    --zone=*)
        case "$*" in
            *--add-rich-rule*masquerade*) [ "${TEST_FW_FAIL:-no}" != yes ] || exit 1 ;;
        esac
        ;;
    --direct)
        case "$*" in
            *OUTPUT*) [ "${TEST_UNDO_FAIL:-no}" != yes ] || exit 1 ;;
        esac
        ;;
esac
exit 0
''')
        fcmd.chmod(0o755)
        # 1. Inactive firewalld fails with explicit backend
        with self.config.open('a') as stream:
            stream.write('# installer-firewall firewalld\n')
        self.assertNotEqual(self.run_controller('up', TEST_FIREWALLD_STATE='1').returncode, 0)
        self.assertIn('firewalld is not running', self.run_controller('up', TEST_FIREWALLD_STATE='1').stderr)

        # 2. CLAT mode with active firewalld
        self.log.write_text('')
        self.assertEqual(self.run_controller('up').returncode, 0)
        log = self.log.read_text()
        self.assertIn('firewall-cmd --zone=trusted --add-interface=clat', log)
        self.assertIn('firewall-cmd --direct --add-rule ipv4 mangle FORWARD 0 -o clat', log)
        self.assertIn('firewall-cmd --direct --add-rule ipv4 mangle OUTPUT 0 -o clat', log)
        self.assertIn('firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i clat -o eth0 -s 2001:db8::464 -j ACCEPT', log)
        self.assertIn('firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i eth0 -o clat -d 2001:db8::464', log)
        # Down removes rules
        self.assertEqual(self.run_controller('down').returncode, 0)
        down_log = self.log.read_text()
        self.assertIn('firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i eth0 -o clat -d 2001:db8::464', down_log)
        self.assertIn('firewall-cmd --direct --remove-rule ipv4 mangle OUTPUT 0 -o clat', down_log)
        self.assertIn('firewall-cmd --zone=trusted --remove-interface=clat', down_log)

        # 3. NAT64 mode with active firewalld and fault rollback
        self.config.write_text('tun-device nat64\nprefix 64:ff9b::/96\nipv4-addr 192.168.240.1\nipv6-addr fd64::2\ndynamic-pool 192.168.240.0/20\nofflink-mtu 1400\n# installer-firewall firewalld\n')
        self.log.write_text('')
        result = self.run_controller('up', TEST_FW_FAIL='yes')
        self.assertNotEqual(result.returncode, 0)
        fail_log = self.log.read_text()
        self.assertIn('masquerade', fail_log)
        self.assertIn('--remove-interface=nat64', fail_log)
        self.assertFalse((self.state / 'nat64.undo').exists())

        # Successful NAT64 up and down
        self.log.write_text('')
        self.assertEqual(self.run_controller('up').returncode, 0)
        up_log = self.log.read_text()
        self.assertIn('firewall-cmd --zone=external --add-rich-rule=rule family=\'ipv4\' source address=\'192.168.240.0/20\' masquerade', up_log)
        self.assertIn('firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i nat64 -o eth0 -s 192.168.240.0/20 -j ACCEPT', up_log)
        self.assertEqual(self.run_controller('down').returncode, 0)
        down_log = self.log.read_text()
        self.assertIn('firewall-cmd --zone=external --remove-rich-rule=rule family=\'ipv4\' source address=\'192.168.240.0/20\' masquerade', down_log)
        self.assertIn('firewall-cmd --zone=trusted --remove-interface=nat64', down_log)

        # 4. Auto-detection selects firewalld when active
        self.config.write_text('tun-device clat\nprefix 64:ff9b::/96\nipv4-addr 192.0.0.2\nipv6-addr 2001:db8::2\nmap 192.0.0.1 2001:db8::464\nofflink-mtu 1400\n')
        self.log.write_text('')
        self.assertEqual(self.run_controller('up').returncode, 0)
        self.assertIn('firewall-cmd --zone=trusted --add-interface=clat', self.log.read_text())
        self.assertEqual(self.run_controller('down').returncode, 0)

    def test_siit_routes_bidirectional_rules_and_no_nat44(self):
        for backend in ('iptables', 'nft'):
            self.config.write_text('tun-device siit\nprefix 2001:db8:64::/96\nipv4-addr 192.168.240.1\nipv6-addr fd64::2\nmap 198.51.100.42 2001:db8:20::42\nofflink-mtu 1400\n# installer-firewall ' + backend + '\n')
            self.log.write_text('')
            result = self.run_controller('up')
            self.assertEqual(result.returncode, 0, result.stderr)
            log = self.log.read_text()
            self.assertIn('route add 198.51.100.42 dev siit', log)
            self.assertNotIn('MASQUERADE', log)
            self.assertNotIn('masquerade', log)
            result = subprocess.run(['sh', str(ROOT / 'packaging/installer/tayga-verify.sh'), str(self.config)],
                                    env={**self.env, 'TEST_LINK_EXISTS': '0'}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.run_controller('down').returncode, 0)
        result = self.run_controller('up', TEST_SIIT_NATIVE_DEV='siit')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / 'siit.undo').exists())

    def test_freebsd_network_and_pf_lifecycle(self):
        (self.bin / 'uname').write_text('#!/bin/sh\necho FreeBSD\n')
        for tool, script in {
            'ifconfig': '''echo "ifconfig $*" >> "$TEST_LOG"
case "$*" in
    tun64) exit "${TEST_IF_EXISTS:-1}" ;;
    *) exit 0 ;;
esac''',
            'route': '''echo "route $*" >> "$TEST_LOG"
case "$*" in
    '-n get -inet6 default') echo 'interface: eth0' ;;
    '-n get default') echo 'gateway: 192.168.5.2'; echo 'interface: eth0' ;;
esac''',
            'netstat': 'echo "netstat $*" >> "$TEST_LOG"',
            'pfctl': '''echo "pfctl $*" >> "$TEST_LOG"
case "$1" in
    -s) echo 'Status: Enabled' ;;
    -sr) echo 'anchor "tayga_sfx/*"' ;;
    -a)
        if [ "$3" = -f ]; then
            cat "$4" >> "$TEST_LOG"
        fi
        ;;
esac''',
        }.items():
            path = self.bin / tool
            path.write_text('#!/bin/sh\n' + script + '\n')
            path.chmod(0o755)
        config = self.root / 'freebsd-clat.conf'
        config.write_text('tun-device tun64\n# installer-mode clat\nprefix 64:ff9b::/96\nipv4-addr 192.0.0.2\nipv6-addr 2001:db8::2\nmap 192.0.0.1 2001:db8::464\nofflink-mtu 1400\n# installer-firewall pf\n')
        result = subprocess.run(['sh', str(CONTROLLER), 'up', str(config)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text()
        self.assertIn('ifconfig tun64 mtu 1400 up', log)
        self.assertIn('ifconfig tun64 inet 192.0.0.1 192.0.0.2 up', log)
        self.assertIn('pfctl -a tayga_sfx/tun64 -f', log)
        self.assertIn('scrub on tun64 proto tcp all max-mss 1360', log)
        self.assertIn('route add -net 0.0.0.0/1 -interface tun64', log)
        self.assertIn('route add -net 128.0.0.0/1 -interface tun64', log)
        result = subprocess.run(['sh', str(CONTROLLER), 'down', str(config)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        down_log = self.log.read_text()
        self.assertIn('route del -net 0.0.0.0/1', down_log)
        self.assertIn('pfctl -a tayga_sfx/tun64 -F rules', down_log)
        self.assertIn('ifconfig tun64 destroy', down_log)
