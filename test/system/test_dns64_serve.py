#!/usr/bin/env python3
"""End-to-end check of pref64-discover --serve-dns64 against a fake upstream.

Usage: test_dns64_serve.py path/to/pref64-discover
Needs no privileges: everything runs on 127.0.0.1.
"""
import socket, struct, subprocess, threading, time, sys
seen = []
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); up.bind(('127.0.0.1', 0)); upport = up.getsockname()[1]
def upstream():
    while True:
        d, a = up.recvfrom(2048)
        seen.append(d)
        qend = 12
        while d[qend]: qend += d[qend] + 1
        qend += 5
        qtype = struct.unpack('>H', d[qend-4:qend-2])[0]
        flags = 0x8180 | (d[3] & 0x10)
        resp = bytearray(d[:2]) + struct.pack('>HHHHH', flags, 1, 1 if qtype == 1 else 0, 0, 0) + d[12:qend]
        if qtype == 1:
            resp += b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        up.sendto(bytes(resp), a)
threading.Thread(target=upstream, daemon=True).start()
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe.bind(('127.0.0.1', 0))
port = probe.getsockname()[1]; probe.close()
srv = subprocess.Popen([sys.argv[1], '--serve-dns64', '127.0.0.1#%d' % port, '64:ff9b::/96', '127.0.0.1#%d' % upport])
time.sleep(0.5)
def query(cd, edns):
    q = struct.pack('>HHHHHH', 0x4242, 0x0100 | (0x10 if cd else 0), 1, 0, 0, 1 if edns else 0)
    q += b'\x07example\x03com\x00' + struct.pack('>HH', 28, 1)
    if edns: q += b'\x00' + struct.pack('>HHIH', 41, 1232, 0x8000, 0)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(3)
    c.sendto(q, ('127.0.0.1', port)); return c.recvfrom(2048)[0]
try:
    r = query(True, True)
    assert r[:2] == b'\x42\x42' and r.endswith(socket.inet_pton(socket.AF_INET6, '64:ff9b::102:304')), r.hex()
    a_q = [s for s in seen if struct.unpack('>H', s[s.index(b'\x00', 12)+1:s.index(b'\x00', 12)+3])[0] == 1][-1]
    assert a_q[3] & 0x10, 'CD lost'
    assert struct.unpack('>H', a_q[10:12])[0] == 1 and b'\x00\x00\x29\x04\xd0\x00\x00\x80\x00' in a_q, 'EDNS0 lost: ' + a_q.hex()
    r = query(False, False)
    assert r.endswith(socket.inet_pton(socket.AF_INET6, '64:ff9b::102:304'))
    print('PASS dns64 e2e: synthesized AAAA, CD and EDNS0 preserved')
finally:
    srv.kill()
