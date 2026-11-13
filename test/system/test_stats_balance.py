#!/usr/bin/env python3
"""Packet accounting invariant: rx == (tx - icmp_sent) + dropped + self.

Every packet read from the TUN must end in exactly one of: translated and
written (tx, excluding ICMP originated by the daemon), dropped/rejected
(dropped, even when an ICMP error was sent for it) or answered locally (self).
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

try:
    from scapy.all import ICMP, ICMPv6EchoRequest, IP, IPv6, Raw, TCP, UDP, conf, raw
except ImportError:
    print('SKIP: scapy is not installed')
    sys.exit(0)

conf.verb = 0
SEND_MODE = len(sys.argv) > 2 and sys.argv[1] == '--send'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', default='/usr/sbin/tayga')
p.add_argument('--output', default=None)
a = p.parse_args([] if SEND_MODE else None)

D = '64:ff9b::808:808'
SRC6 = '2001:db8::2'


def v6(dst, **k):
    return IPv6(src=SRC6, dst=dst, **k)


CASES = {
    'udp_ok': lambda: [v6(D) / UDP(sport=1, dport=2) / Raw(b'x' * 20)] * 10,
    'tcp_ok': lambda: [v6(D) / TCP(sport=1, dport=2) / Raw(b'x' * 20)] * 10,
    'echo_ok': lambda: [v6(D) / ICMPv6EchoRequest()] * 5,
    'hop_limit_1': lambda: [v6(D, hlim=1) / UDP() / Raw(b'x')] * 5,
    'bad_prefix': lambda: [v6('2001:db8:ffff::5') / UDP() / Raw(b'x')] * 5,
    'loopback4': lambda: [v6('64:ff9b::7f00:1') / UDP() / Raw(b'x')] * 5,
    'self_echo6': lambda: [v6('2001:db8::1') / ICMPv6EchoRequest()] * 5,
    'private4': lambda: [v6('64:ff9b::c0a8:1') / UDP() / Raw(b'x')] * 3,
    'unknown_proto': lambda: [v6(D, nh=253) / Raw(b'z' * 8)] * 3,
    'self_proto6': lambda: [v6('2001:db8::1', nh=253) / Raw(b'z' * 8)] * 3,
    'self_echo4': lambda: [IP(src='198.51.100.9', dst='192.0.2.1') / ICMP()] * 4,
    'self_proto4': lambda: [IP(src='198.51.100.9', dst='192.0.2.1', proto=253) / Raw(b'z' * 8)] * 3,
    'v4_unmapped': lambda: [IP(src='198.51.100.9', dst='192.0.2.77') / UDP() / Raw(b'x')] * 4,
    'v4_ttl1': lambda: [IP(src='198.51.100.9', dst='192.0.2.130', ttl=1) / UDP() / Raw(b'x')] * 4,
}


# Used only by the metrics-file case below.
CASES_EXTRA = {'echo10': lambda: [v6(D) / ICMPv6EchoRequest()] * 10}


def sh(cmd):
    return subprocess.run(cmd, shell=True, check=True, text=True, capture_output=True).stdout


def find(d, key):
    if isinstance(d, dict):
        if key in d and not isinstance(d[key], (dict, list)):
            return d[key]
        for v in d.values():
            r = find(v, key)
            if r is not None:
                return r
    return None


def run_case(name, packets, tmp):
    ns = f'statbal{os.getpid()}'
    rt = tmp / name
    rt.mkdir()
    cfg = tmp / f'{name}.conf'
    cfg.write_text('tun-device statbal0\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\n'
                   'prefix 64:ff9b::/96\ndynamic-pool 192.0.2.128/25\nworkers 1\ntun-offload off\n')
    subprocess.run(['ip', 'netns', 'add', ns], check=True)
    try:
        d = subprocess.Popen(['ip', 'netns', 'exec', ns, a.binary, '-d', '-c', str(cfg),
                              '--runtime-dir', str(rt)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        try:
            e = f'ip netns exec {ns} ip'
            sh(f'{e} link set statbal0 up; {e} addr add 192.0.2.254/24 dev statbal0; '
               f'{e} -6 addr add {SRC6}/64 dev statbal0 nodad; {e} -6 route add 64:ff9b::/96 dev statbal0; '
               f'{e} route add 198.51.100.0/24 dev statbal0')
            time.sleep(1)
            # Send from inside the namespace: re-run this file in send mode.
            subprocess.run(['ip', 'netns', 'exec', ns, sys.executable, __file__, '--send', name], check=True)
            time.sleep(.5)
        finally:
            d.terminate()
            d.wait(timeout=5)
        j = json.loads((rt / 'tayga-status.json').read_text())
    finally:
        subprocess.run(['ip', 'netns', 'del', ns], check=False)
    g = lambda k: find(j, k) or 0
    rx = g('rx_packets_v4') + g('rx_packets_v6')
    tx = g('tx_packets_v4') + g('tx_packets_v6')
    return rx, tx, g('icmp_sent_packets'), g('dropped_packets'), g('self_packets')


def run_metrics_case(tmp):
    """--chroot with --metrics-file: SIGUSR2 publishes the Prometheus file outside the chroot."""
    ns = f'statprom{os.getpid()}'
    rt = tmp / 'prom-rt'
    data = tmp / 'prom-data'
    rt.mkdir()
    data.mkdir()
    rt.chmod(0o777)  # the unprivileged daemon user publishes through a descriptor opened before chroot()
    metrics = rt / 'tayga.prom'
    cfg = tmp / 'prom.conf'
    cfg.write_text('tun-device statprom0\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\n'
                   f'prefix 64:ff9b::/96\ndynamic-pool 192.0.2.128/25\ndata-dir {data}\nworkers 1\ntun-offload off\n')
    subprocess.run(['ip', 'netns', 'add', ns], check=True)
    try:
        d = subprocess.Popen(['ip', 'netns', 'exec', ns, a.binary, '-d', '--chroot', '-u', 'nobody', '-c', str(cfg),
                              '--runtime-dir', str(rt), '--metrics-file', str(metrics)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        try:
            e = f'ip netns exec {ns} ip'
            sh(f'{e} link set statprom0 up; {e} addr add 192.0.2.254/24 dev statprom0; '
               f'{e} -6 addr add {SRC6}/64 dev statprom0 nodad; {e} -6 route add 64:ff9b::/96 dev statprom0')
            time.sleep(1)
            subprocess.run(['ip', 'netns', 'exec', ns, sys.executable, __file__, '--send', 'echo10',
                            'statprom0'], check=True)
            time.sleep(.5)
            d.send_signal(signal.SIGUSR2)
            time.sleep(1.5)
            text = metrics.read_text()
            leftovers = [x.name for x in rt.iterdir() if x.name.startswith('.tayga-metrics.')]
        finally:
            d.terminate()
            d.wait(timeout=5)
    finally:
        subprocess.run(['ip', 'netns', 'del', ns], check=False)
    prefix = 'tayga_rx_packets_total{family="ipv6"} '
    line = next(x for x in text.splitlines() if x.startswith(prefix))
    value = int(line[len(prefix):])
    assert value >= 10, f'ipv6 rx {value} < 10 in metrics file'
    assert '# TYPE tayga_rx_packets_total counter' in text and text.endswith('\n')
    assert not leftovers, f'temporary metrics files left behind: {leftovers}'
    print(f'metrics_file   chroot rx_ipv6={value}')


def send_mode(name, dev='statbal0'):
    def mk(proto):
        k = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(proto))
        k.bind((dev, proto))
        return k
    for pkt in {**CASES, **CASES_EXTRA}[name]():
        mk(0x86dd if pkt.version == 6 else 0x0800).send(raw(pkt))


if SEND_MODE:
    send_mode(*sys.argv[2:4])
    sys.exit(0)

if sys.platform != 'linux' or os.geteuid() != 0:
    print('SKIP: Linux root required')
    sys.exit(0)

failed = []
with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    lines = []
    for name, make in CASES.items():
        n = len(make())
        rx, tx, icmp, drop, self_ = run_case(name, make(), tmp)
        # The kernel may add a stray ND/MLD packet on a fresh TUN, which is
        # counted as one rx and one drop, so the invariant still holds.
        balance = rx - ((tx - icmp) + drop + self_)
        lines.append(f'{name:14} sent={n:2} rx={rx:2} tx={tx:2} icmp={icmp:2} drop={drop:2} self={self_:2} balance={balance}')
        print(lines[-1])
        if balance != 0 or rx < n:
            failed.append(name)
    run_metrics_case(tmp)
    if a.output:
        out = Path(a.output)
        out.mkdir(parents=True, exist_ok=True)
        (out / 'balance.txt').write_text('\n'.join(lines) + '\n')
assert not failed, f'accounting imbalance in {failed}'
print('PASS stats balance')
