#!/usr/bin/env python3
"""End-to-end check of pref64-discover --serve-dns64 against a fake upstream.

Usage: test_dns64_serve.py path/to/pref64-discover
Needs no privileges: everything runs on 127.0.0.1.
"""
import socket, struct, subprocess, threading, time, sys
seen = []
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); up.bind(('127.0.0.1', 0)); upport = up.getsockname()[1]
def answer(d, a):
    qend = 12
    while d[qend]: qend += d[qend] + 1
    qend += 5
    qtype = struct.unpack('>H', d[qend-4:qend-2])[0]
    label = d[13:13 + d[12]]
    if label == b'slow' and qtype == 28:
        time.sleep(1.5)	# a slow authoritative server must not delay other names
    flags = 0x8180 | (d[3] & 0x10)
    ttl = 300 if label in (b'ttl', b'soa') else 60
    soa = label == b'soa' and qtype == 1
    resp = bytearray(d[:2]) + struct.pack('>HHHHH', flags, 1, 1 if qtype == 1 else 0, 1 if soa else 0, 0) + d[12:qend]
    if qtype == 1:
        resp += b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, ttl, 4) + bytes([1, 2, 3, 4])
    if soa:
        rdata = b'\x02ns\xc0\x0c' + b'\x04host\xc0\x0c' + struct.pack('>IIIII', 1, 7200, 900, 604800, 45)
        resp += b'\xc0\x0c' + struct.pack('>HHIH', 6, 1, 600, len(rdata)) + rdata
    up.sendto(bytes(resp), a)
def upstream():
    while True:
        d, a = up.recvfrom(2048)
        seen.append(d)
        threading.Thread(target=answer, args=(d, a), daemon=True).start()
threading.Thread(target=upstream, daemon=True).start()
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe.bind(('127.0.0.1', 0))
port = probe.getsockname()[1]; probe.close()
srv = subprocess.Popen([sys.argv[1], '--serve-dns64', '127.0.0.1#%d' % port, '64:ff9b::/96', '127.0.0.1#%d' % upport])
time.sleep(0.5)
def query(cd, edns, padding=0, preceding=False, name='example.com'):
    q = struct.pack('>HHHHHH', 0x4242, 0x0100 | (0x10 if cd else 0), 1, 0, 0, (2 if preceding else 1) if edns else 0)
    q += b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\x00' + struct.pack('>HH', 28, 1)
    if preceding:
        q += b'\x00' + struct.pack('>HHIH', 16, 1, 0, 2) + b'\x01x'
    if edns:
        options = struct.pack('>HH', 12, padding) + bytes(padding) if padding else b''
        q += b'\x00' + struct.pack('>HHIH', 41, 1232, 0x8000, len(options)) + options
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(3)
    try:
        c.sendto(q, ('127.0.0.1', port))
        return c.recvfrom(2048)[0]
    finally:
        c.close()
try:
    r = query(True, True)
    assert r[:2] == b'\x42\x42' and r.endswith(socket.inet_pton(socket.AF_INET6, '64:ff9b::102:304')), r.hex()
    a_q = [s for s in seen if struct.unpack('>H', s[s.index(b'\x00', 12)+1:s.index(b'\x00', 12)+3])[0] == 1][-1]
    assert a_q[3] & 0x10, 'CD lost'
    assert struct.unpack('>H', a_q[10:12])[0] == 1 and b'\x00\x00\x29\x04\xd0\x00\x00\x80\x00' in a_q, 'EDNS0 lost: ' + a_q.hex()
    r = query(False, False)
    assert r.endswith(socket.inet_pton(socket.AF_INET6, '64:ff9b::102:304'))
    r = query(True, True, padding=128, preceding=True)
    a_q = [s for s in seen if struct.unpack('>H', s[s.index(b'\x00', 12)+1:s.index(b'\x00', 12)+3])[0] == 1][-1]
    assert a_q[3] & 0x10 and a_q[11] == 1
    assert a_q.endswith(struct.pack('>HH', 12, 128) + bytes(128)), 'large/non-first OPT lost'
    # Synthesized TTL follows the A record (RFC 6147 5.1.7), bounded by an SOA MINIMUM.
    assert struct.unpack('>I', query(False, False)[-22:-18])[0] == 60
    assert struct.unpack('>I', query(False, False, name='ttl.example.com')[-22:-18])[0] == 300
    assert struct.unpack('>I', query(False, False, name='soa.example.com')[-22:-18])[0] == 45
    # One slow upstream name must not hold up the others.
    slow = {}
    def slow_query():
        began = time.monotonic()
        slow['reply'] = query(False, False, name='slow.example.com')
        slow['took'] = time.monotonic() - began
    worker = threading.Thread(target=slow_query)
    worker.start()
    time.sleep(0.2)
    began = time.monotonic()
    fast = query(False, False, name='fast.example.com')
    fast_took = time.monotonic() - began
    worker.join()
    assert fast.endswith(socket.inet_pton(socket.AF_INET6, '64:ff9b::102:304'))
    assert fast_took < 0.5, 'fast name waited for the slow one: %.2fs' % fast_took
    assert slow['took'] >= 1.4 and slow['reply'].endswith(socket.inet_pton(socket.AF_INET6, '64:ff9b::102:304'))
    srv.terminate(); srv.wait(timeout=5)
    # Independently build the RFC 6052 byte layout for every supported PLC.
    for plen in (32, 40, 48, 56, 64, 96):
        prefix = '2001:db8::/%d' % plen
        expected = bytearray(socket.inet_pton(socket.AF_INET6, '2001:db8::'))
        pos = plen // 8
        for byte in (1, 2, 3, 4):
            if pos == 8: pos += 1
            expected[pos] = byte
            pos += 1
        srv = subprocess.Popen([sys.argv[1], '--serve-dns64', '127.0.0.1#%d' % port,
                                prefix, '127.0.0.1#%d' % upport])
        time.sleep(0.5)
        assert query(True, True).endswith(expected), 'RFC 6052 layout mismatch /%d' % plen
        srv.terminate(); srv.wait(timeout=5)
    print('PASS dns64 e2e: all prefix lengths, CD, large/non-first EDNS0, TTL, concurrent upstream')
finally:
    if srv.poll() is None: srv.kill()
    srv.wait(timeout=5)
