#!/usr/bin/env python3
"""On-wire ICMP checks through a real TUN: RFC 4884 multi-part extensions in
both directions and the originated-error rate limiter under a TTL=1 flood.

The daemon runs in a private network namespace.  A child process in the same
namespace injects packets with AF_PACKET and sniffs what the daemon writes
back to the TUN (PACKET_HOST), then reports JSON to the parent.
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    from scapy.all import ICMP, ICMPv6TimeExceeded, IP, IPv6, Raw, UDP, conf, raw
except ImportError:
    print('SKIP: scapy is not installed')
    sys.exit(0)

conf.verb = 0
DEV = 'icmpwire0'
MAPPED4, MAPPED6 = '192.0.2.50', '2001:db8:5::50'
FAR4, FAR6 = '8.8.8.8', '64:ff9b::808:808'
# Extension structure: version 2 header, checksum filled in below, one object.
OBJECT = struct.pack('!HBB', 8, 1, 1) + b'\x00\x00\x00\x07'


def ext_struct():
    body = struct.pack('!BBH', 0x20, 0, 0) + OBJECT
    s = sum(struct.unpack('!%dH' % (len(body) // 2), body))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return body[:2] + struct.pack('!H', (~s) & 0xffff) + body[4:]


EXT = ext_struct()


def sniffer():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    s.bind((DEV, 3))
    s.settimeout(0.2)
    return s


def drain(s, seconds):
    got = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[2] == socket.PACKET_HOST:
            got.append(data)
    return got


def sender(proto):
    k = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(proto))
    k.bind((DEV, proto))
    return k


def child():
    res = {}
    snd4, snd6, sn = sender(0x0800), sender(0x86dd), sniffer()
    # --- 4 -> 6: ICMPv4 Time Exceeded carrying a 128-octet original + extension
    inner = raw(IP(src=MAPPED4, dst=FAR4, id=7) / UDP(sport=1000, dport=2000) / Raw(b'abcd'))
    inner += b'\x00' * (128 - len(inner))
    pkt = IP(src=FAR4, dst=MAPPED4) / ICMP(type=11, code=0, length=32) / Raw(inner + EXT)
    snd4.send(raw(pkt))
    res['v6_out'] = [p.hex() for p in drain(sn, 1.0) if p[0] >> 4 == 6]
    # --- 6 -> 4: ICMPv6 Time Exceeded with Length=16 (8-octet units) + extension
    inner6 = raw(IPv6(src=MAPPED6, dst=FAR6, hlim=5) / UDP(sport=1000, dport=2000) / Raw(b'abcd'))
    inner6 += b'\x00' * (128 - len(inner6))
    p6 = IPv6(src=FAR6, dst=MAPPED6) / ICMPv6TimeExceeded(code=0, length=16) / Raw(inner6 + EXT)
    snd6.send(raw(p6))
    res['v4_out'] = [p.hex() for p in drain(sn, 1.0) if p[0] >> 4 == 4]
    # --- TTL=1 flood: originated Time Exceeded must be rate limited
    flood = raw(IPv6(src=MAPPED6, dst=FAR6, hlim=1) / UDP(sport=3, dport=4) / Raw(b'x'))
    for _ in range(3000):
        snd6.send(flood)
    time.sleep(0.5)
    res['flood_errors'] = len([p for p in drain(sn, 1.0) if p[0] >> 4 == 6 and p[6] == 58])
    # --- Packet Too Big has its own bucket: still answered after the flood
    # 1490-octet IPv4 packet fits the 1500 TUN MTU but needs 1510 octets as IPv6.
    big = raw(IP(src=FAR4, dst=MAPPED4, flags='DF') / UDP(sport=5, dport=6) / Raw(b'y' * 1462))
    snd4.send(big)
    res['after_flood'] = [p.hex() for p in drain(sn, 1.0)]
    print(json.dumps(res))


def sh(cmd):
    return subprocess.run(cmd, shell=True, check=True, text=True, capture_output=True).stdout


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', default='/usr/sbin/tayga')
    p.add_argument('--output', default=None)
    a = p.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        print('SKIP: Linux root required')
        return 0
    ns = f'icmpwire{os.getpid()}'
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        (tmp / 'rt').mkdir()
        cfg = tmp / 'tayga.conf'
        cfg.write_text(f'tun-device {DEV}\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\n'
                       f'prefix 64:ff9b::/96\nmap {MAPPED4} {MAPPED6}\nworkers 1\ntun-offload off\n'
                       'icmp-rate-limit 100\n')
        subprocess.run(['ip', 'netns', 'add', ns], check=True)
        try:
            d = subprocess.Popen(['ip', 'netns', 'exec', ns, a.binary, '-d', '-c', str(cfg),
                                  '--runtime-dir', str(tmp / 'rt')],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                time.sleep(1)
                e = f'ip netns exec {ns} ip'
                sh(f'{e} link set {DEV} up; {e} addr add 192.0.2.254/24 dev {DEV}; '
                   f'{e} -6 addr add 2001:db8::2/64 dev {DEV} nodad; '
                   f'{e} -6 route add 64:ff9b::/96 dev {DEV}; {e} route add 8.8.8.0/24 dev {DEV}; '
                   f'{e} -6 route add 2001:db8:5::/64 dev {DEV}')
                time.sleep(1)
                out = subprocess.run(['ip', 'netns', 'exec', ns, sys.executable, __file__, '--child'],
                                     check=True, text=True, capture_output=True).stdout
            finally:
                d.terminate()
                d.wait(timeout=5)
        finally:
            subprocess.run(['ip', 'netns', 'del', ns], check=False)
    res = json.loads(out.strip().splitlines()[-1])
    if a.output:
        Path(a.output).mkdir(parents=True, exist_ok=True)
        (Path(a.output) / 'icmp_wire.json').write_text(json.dumps(res, indent=1))

    # 4->6: expect ICMPv6 Time Exceeded (type 3) with Length=16 and the extension intact
    v6 = [bytes.fromhex(x) for x in res['v6_out'] if bytes.fromhex(x)[6] == 58]
    assert v6, f'no ICMPv6 produced: {res["v6_out"]}'
    pkt = v6[0]
    icmp6 = pkt[40:]
    assert icmp6[0] == 3, f'ICMPv6 type {icmp6[0]}'
    assert icmp6[4] == 16, f'ICMPv6 length attribute {icmp6[4]}, want 16 (128 octets)'
    assert pkt.endswith(EXT), 'extension structure not carried to ICMPv6'
    assert len(pkt) == 40 + 8 + 128 + len(EXT), f'ICMPv6 size {len(pkt)}'
    print('PASS 4->6 multi-part ICMP: type 3, length attribute 16, extension preserved')

    # 6->4: expect ICMPv4 Time Exceeded (type 11) with Length=32 (4-octet units)
    v4 = [bytes.fromhex(x) for x in res['v4_out'] if bytes.fromhex(x)[9] == 1]
    assert v4, f'no ICMPv4 produced: {res["v4_out"]}'
    pkt = v4[0]
    ihl = (pkt[0] & 15) * 4
    icmp4 = pkt[ihl:]
    assert icmp4[0] == 11, f'ICMPv4 type {icmp4[0]}'
    assert icmp4[5] == 32, f'ICMPv4 length attribute {icmp4[5]}, want 32 (128 octets)'
    assert pkt.endswith(EXT), 'extension structure not carried to ICMPv4'
    print('PASS 6->4 multi-part ICMP: type 11, length attribute 32, extension preserved')

    # Rate limit: 100/s with a bounded burst; a 3000-packet flood must be cut hard
    n = res['flood_errors']
    assert 0 < n <= 400, f'flood produced {n} ICMP errors (limit 100/s, burst <= 200)'
    print(f'PASS TTL=1 flood of 3000 -> {n} originated errors')

    # Packet Too Big is a separate bucket
    ptb = [bytes.fromhex(x) for x in res['after_flood'] if bytes.fromhex(x)[9] == 1]
    assert ptb and ptb[0][(ptb[0][0] & 15) * 4] == 3 and ptb[0][(ptb[0][0] & 15) * 4 + 1] == 4, \
        'no Fragmentation Needed after the flood'
    print('PASS Packet Too Big still answered after a TTL=1 flood')
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child()
        sys.exit(0)
    sys.exit(main())
