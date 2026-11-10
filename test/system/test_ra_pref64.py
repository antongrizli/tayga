#!/usr/bin/env python3
"""RFC 8781: pref64-discover -i must learn PREF64 from a Router Advertisement.

Needs root, iproute2 and scapy.  Two network namespaces are joined by a veth
pair; the "router" side answers the Router Solicitation with crafted RAs:
  1. hop limit 64          -> must be ignored (RFC 4861 6.1.2)
  2. non-link-local source -> must be ignored
  3. valid RA with PREF64  -> prefix must be reported
Usage: test_ra_pref64.py path/to/pref64-discover
"""
import os
import subprocess
import sys
import threading
import time

from scapy.all import (Ether, IPv6, ICMPv6ND_RS, ICMPv6ND_RA, Raw, sniff, sendp, get_if_hwaddr,
                       conf)

BIN = os.path.abspath(sys.argv[1])
NS_C, NS_R = f'ra-c{os.getpid()}', f'ra-r{os.getpid()}'


def sh(*a, check=True, **k):
    return subprocess.run(a, check=check, capture_output=True, text=True, **k)


def setup():
    sh('ip', 'netns', 'add', NS_C)
    sh('ip', 'netns', 'add', NS_R)
    sh('ip', 'link', 'add', 'vc', 'netns', NS_C, 'type', 'veth', 'peer', 'name', 'vr', 'netns', NS_R)
    for ns, dev in ((NS_C, 'vc'), (NS_R, 'vr')):
        sh('ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'lo', 'up')
        sh('ip', 'netns', 'exec', ns, 'ip', 'link', 'set', dev, 'up')
        sh('ip', 'netns', 'exec', ns, 'sysctl', '-qw', f'net.ipv6.conf.{dev}.accept_ra=0')
    time.sleep(1.5)	# DAD / link-local addresses


def teardown():
    for ns in (NS_C, NS_R):
        sh('ip', 'netns', 'del', ns, check=False)


def pref64_option(prefix96: bytes, plc=0, lifetime_units=100):
    v = (lifetime_units << 3) | plc
    return bytes([38, 2]) + v.to_bytes(2, 'big') + prefix96


def run_router(frames_to_send, stop):
    """Runs inside NS_R via setns: answers each RS with the given RA variants."""
    libc = __import__('ctypes').CDLL(None, use_errno=True)
    fd = os.open(f'/var/run/netns/{NS_R}', os.O_RDONLY)
    if libc.setns(fd, 0x40000000) != 0:
        raise OSError('setns failed')
    conf.iface = 'vr'
    def reply(pkt):
        if ICMPv6ND_RS in pkt:
            for build in frames_to_send:
                sendp(build(), iface='vr', verbose=False)
    sniff(iface='vr', lfilter=lambda p: ICMPv6ND_RS in p, prn=reply,
          stop_filter=lambda p: stop.is_set(), timeout=8, store=False)


def ra(src_ll, hlim, extra=b''):
    mac = get_if_hwaddr('vr')
    return (Ether(src=mac, dst='33:33:00:00:00:01') / IPv6(src=src_ll, dst='ff02::1', hlim=hlim) /
            ICMPv6ND_RA(routerlifetime=0) / Raw(extra))


def discover(timeout=4):
    p = subprocess.run(['ip', 'netns', 'exec', NS_C, BIN, '-i', 'vc', '--ra-only', '-t', str(timeout), '-v'],
                       capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr


def main():
    setup()
    try:
        ll = sh('ip', 'netns', 'exec', NS_R, 'sh', '-c',
                "ip -6 addr show dev vr scope link | awk '/inet6/ {print $2}' | cut -d/ -f1").stdout.split()[0]
        prefix = bytes.fromhex('20010db8000100020003000400000000')[:12]
        opt = pref64_option(prefix, plc=0)

        for name, builders, expect in (
            ('hop limit 64 is ignored', [lambda: ra(ll, 64, opt)], False),
            ('global source is ignored', [lambda: ra('2001:db8::99', 255, opt)], False),
            ('valid RA is accepted', [lambda: ra(ll, 255, opt)], True),
        ):
            stop = threading.Event()
            t = threading.Thread(target=lambda: run_router(builders, stop), daemon=True)
            # run_router changes this thread's netns only (setns on a thread).
            t.start()
            time.sleep(0.8)
            rc, out, err = discover()
            stop.set(); t.join(10)
            if expect:
                assert rc == 0 and out == '2001:db8:1:2:3:4::/96', (name, rc, out, err)
            else:
                assert rc != 0, (name, rc, out, err)
            print(f'PASS RFC 8781: {name}')
    finally:
        teardown()


if __name__ == '__main__':
    main()
