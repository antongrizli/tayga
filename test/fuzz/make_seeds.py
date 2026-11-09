#!/usr/bin/env python3
"""Generate valid-looking seed inputs for the libFuzzer packet harnesses.

usage: make_seeds.py OUTDIR   (creates OUTDIR/{fuzz_pkt4,fuzz_pkt6,fuzz_gso,fuzz_flow,fuzz_maps}/*)
Packets use the addresses of fuzz_common.h: 192.0.0.1 <-> fd9b:64:1:ff::10 and
the 64:ff9b::/96 prefix.  Checksums are real for the IPv4 header and TCP/UDP
(complete-checksum variants) so deeper code than the parsers is reached.
"""
import os, socket, struct, sys

def csum(data, init=0):
    if len(data) & 1: data += b"\0"
    s = init + sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

A4, B4 = socket.inet_pton(socket.AF_INET, "192.0.0.1"), socket.inet_pton(socket.AF_INET, "8.8.8.8")
A6 = socket.inet_pton(socket.AF_INET6, "fd9b:64:1:ff::10")
B6 = socket.inet_pton(socket.AF_INET6, "64:ff9b::808:808")

def l4(proto, payload, src, dst, v6, flags=0x10):
    if proto == 6:
        h = struct.pack("!HHIIBBHHH", 40000, 443, 1000, 0, 5 << 4, flags, 65535, 0, 0)
    else:
        h = struct.pack("!HHHH", 40000, 443, 8 + len(payload), 0)
    seg = h + payload
    ph = (src + dst + struct.pack("!IHBB", len(seg), 0, 0, proto)) if v6 else (src + dst + struct.pack("!BBH", 0, proto, len(seg)))
    c = csum(seg, csum(ph) ^ 0xffff) or 0xffff
    off = 16 if proto == 6 else 6
    return seg[:off] + struct.pack("!H", c) + seg[off + 2:]

def ip4(proto, payload, ttl=64, df=True, opts=b""):
    ihl = 5 + len(opts) // 4
    h = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, ihl * 4 + len(payload), 0, 0x4000 if df else 0, ttl, proto, 0, A4, B4) + opts
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + payload

def ip6(proto, payload, hl=64):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), proto, hl, A6, B6) + payload

def vhdr(gso, size, hdr, cstart, coff, needs=True):
    return struct.pack("<BBHHHH", 1 if needs else 0, gso, hdr, size, cstart, coff)

GSO = {"none": 0, "tcp4": 1, "udp": 3, "tcp6": 4}
out = sys.argv[1]
for d in ("fuzz_pkt4", "fuzz_pkt6", "fuzz_gso", "fuzz_flow", "fuzz_maps"):
    os.makedirs(os.path.join(out, d), exist_ok=True)
def save(d, name, data): open(os.path.join(out, d, name), "wb").write(data)

pl = bytes(range(251)) * 12                     # 3012 bytes
small = b"hello"
cases4 = {
    "tcp": (ip4(6, l4(6, small, A4, B4, False)), None),
    "udp": (ip4(17, l4(17, small, A4, B4, False)), None),
    "icmp_echo": (ip4(1, b"\x08\0\0\0\0\1\0\1" + small), None),
    "opts": (ip4(6, l4(6, small, A4, B4, False), opts=b"\x01\x01\x01\x01"), None),
    "ttl1": (ip4(6, l4(6, small, A4, B4, False), ttl=1), None),
    "gso_tcp4": (ip4(6, l4(6, pl, A4, B4, False)), vhdr(GSO["tcp4"], 1400, 40, 20, 16)),
    "gso_udp4": (ip4(17, l4(17, pl, A4, B4, False)), vhdr(GSO["udp"], 1400, 28, 20, 6)),
    "gso_tcp4_opts": (ip4(6, l4(6, pl, A4, B4, False), opts=b"\x01\x01\x01\x01"), vhdr(GSO["tcp4"], 1000, 44, 24, 16)),
}
cases6 = {
    "tcp": (ip6(6, l4(6, small, A6, B6, True)), None),
    "udp": (ip6(17, l4(17, small, A6, B6, True)), None),
    "icmp_echo": (ip6(58, b"\x80\0\0\0\0\1\0\1" + small), None),
    "hl1": (ip6(6, l4(6, small, A6, B6, True), hl=1), None),
    "gso_tcp6": (ip6(6, l4(6, pl, A6, B6, True)), vhdr(GSO["tcp6"], 1400, 60, 40, 16)),
    "gso_udp6": (ip6(17, l4(17, pl, A6, B6, True)), vhdr(GSO["udp"], 1200, 48, 40, 6)),
}
for name, (pkt, vh) in cases4.items():
    mode = (8 if vh and vh[1] == GSO["udp"] else 4) if vh else 0
    save("fuzz_pkt4", name, (bytes([1 | mode]) + vh + pkt) if vh else (bytes([2 if name == "ttl1" else 0]) + pkt))
for name, (pkt, vh) in cases6.items():
    mode = (8 if vh and vh[1] == GSO["udp"] else 4) if vh else 0
    save("fuzz_pkt6", name, (bytes([1 | mode]) + vh + pkt) if vh else bytes([0]) + pkt)
# fuzz_gso: [mtu_sel|offload<<2, function index, vhdr(10), packet]; functions in fuzz_gso.c order
fn = {"translate_tcp_4to6": 0, "translate_tcp_6to4": 1, "translate_udp_4to6": 2, "translate_udp_6to4": 3,
      "sw_4to6": 4, "sw_6to4": 5, "sw_udp_4to6": 6, "sw_udp_6to4": 7}
for name, (pkt, vh) in list(cases4.items()) + list(cases6.items()):
    if not vh: continue
    v6 = pkt[0] >> 4 == 6
    udp = vh[1] == GSO["udp"]
    for mtu in (1, 3):
        f = (3 if udp else 1) if v6 else (2 if udp else 0)
        save("fuzz_gso", f"{name}_{'6' if v6 else '4'}_mtu{mtu}_tr", bytes([mtu, f]) + vh + pkt)
        f = (7 if udp else 5) if v6 else (6 if udp else 4)
        save("fuzz_gso", f"{name}_{'6' if v6 else '4'}_mtu{mtu}_sw", bytes([mtu | 4, f]) + vh + pkt)
# fuzz_flow: the bare IP packet; fuzz_maps: map-file text
for name, (pkt, vh) in list(cases4.items()) + list(cases6.items()):
    save("fuzz_flow", name, pkt)
maps = {
    "basic": "map 192.0.2.9 2001:db8::9\nmap 192.0.2.10 2001:db8::a\n",
    "prefix": "map 198.51.100.0/24 2001:db8:1::/120\nmap 198.51.100.7 2001:db8:2::7\n",
    "nested": "map 10.0.0.0/8 2001:db8:a::/72\nmap 10.1.0.0/16 2001:db8:b::/112\nmap 10.1.2.3 2001:db8:c::3\n",
    "comments": "# comment\n\nmap 192.0.2.1 2001:db8::1 # trailing\n",
    "bad": "map 999.1.1.1 2001:db8::1\nmap 192.0.2.1\nmap 192.0.2.2/33 2001:db8::2\n",
    "many": "".join(f"map 203.0.113.{i} 2001:db8:100::{i:x}\n" for i in range(1, 40)),
}
for name, text in maps.items():
    save("fuzz_maps", name, text.encode())
print("seeds written to", out)
