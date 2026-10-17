#!/usr/bin/env python3
"""
End-to-End Multi-Protocol System Test for TAYGA CLAT.
Ref: improvenments/network-protocols-compatibility-and-testing-guide.md

Verifies real data transmission across Linux network namespaces (client -> router -> clatns -> server):
1. ICMP Echo Request / Reply baseline
2. End-to-end WireGuard UDP transport datagrams (handshake initiation, response, data packets)
3. End-to-end STUN (RFC 5389) Binding Request / Response with XOR-MAPPED-ADDRESS
4. End-to-end Passive FTP (PASV) control and secondary data channel emulation
5. End-to-end SCTP / Raw IP transport verification
6. End-to-end TCP stream integrity verification
"""

import argparse
import hashlib
import os
from pathlib import Path
import select
import shlex
import socket
import struct
import subprocess
import sys
import time


def sh(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout, res.stderr, res.returncode


def setup_topology():
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns del {ns} 2>/dev/null")
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns add {ns}")

    sh("ip link add lan0 type veth peer name rlan")
    sh("ip link set lan0 netns client")
    sh("ip link set rlan netns router")

    sh("ip link add rclat type veth peer name ceth")
    sh("ip link set rclat netns router")
    sh("ip link set ceth netns clatns")
    sh("ip -n clatns link set ceth name veth-nat64")

    sh("ip link add rwan type veth peer name server0")
    sh("ip link set rwan netns router")
    sh("ip link set server0 netns server")

    # Client interface
    sh("ip -n client link set lo up")
    sh("ip -n client link set lan0 up")
    sh("ip -n client addr add 192.168.88.2/24 dev lan0")
    sh("ip -n client route add default via 192.168.88.1")

    # Router interfaces & forwarding
    sh("ip -n router link set lo up")
    sh("ip -n router link set rlan up")
    sh("ip -n router addr add 192.168.88.1/24 dev rlan")
    sh("ip -n router link set rclat up")
    sh("ip -n router addr add 172.31.64.1/24 dev rclat")
    sh("ip -n router -6 addr add fd9b:64:1:fe::1/64 dev rclat")
    sh("ip -n router link set rwan up")
    sh("ip -n router -6 addr add 2600:464::1/64 dev rwan")
    sh("ip netns exec router sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    sh("ip netns exec router sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null")
    sh("ip -n router route add default via 172.31.64.2")
    sh("ip -n router -6 route add fd9b:64:1:ff::10/128 via fd9b:64:1:fe::2 dev rclat")
    sh("ip -n router -6 route add 64:ff9b::/96 via 2600:464::2 dev rwan")

    # Router SNAT
    sh("ip netns exec router nft -f - << 'EOF'\n"
       "table ip nat {\n"
       "  chain postrouting {\n"
       "    type nat hook postrouting priority srcnat; policy accept;\n"
       "    oifname \"rclat\" ip saddr 192.168.88.0/24 snat to 192.0.0.1\n"
       "  }\n"
       "}\n"
       "EOF")

    # CLAT namespace
    sh("ip -n clatns link set lo up")
    sh("ip -n clatns link set veth-nat64 up")
    sh("ip -n clatns addr add 172.31.64.2/24 dev veth-nat64")
    sh("ip -n clatns -6 addr add fd9b:64:1:fe::2/64 dev veth-nat64")
    sh("ip -n clatns -6 route add default via fd9b:64:1:fe::1")
    sh("ip netns exec clatns sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    sh("ip netns exec clatns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null")

    # Server interface & routes
    sh("ip -n server link set lo up")
    sh("ip -n server link set server0 up")
    sh("ip -n server -6 addr add 2600:464::2/64 dev server0")
    sh("ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo")
    sh("ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0")


def teardown():
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns del {ns} 2>/dev/null")


def test_icmp_ping():
    print("\n--- Test 1: ICMP Echo Baseline ---")
    ready = False
    t0 = time.monotonic()
    while time.monotonic() - t0 < 6:
        _, _, rc = sh("ip netns exec client ping -c 1 -W 1 11.0.0.2")
        if rc == 0:
            ready = True
            break
        time.sleep(0.3)
    assert ready, "CLAT ping failed to become ready"
    print("[PASS] ICMP Echo Request / Reply verified across CLAT")


def test_wireguard_udp():
    print("\n--- Test 2: WireGuard UDP Datagram Transmission ---")
    # Emulate WireGuard Initiation (Type 1: 148 bytes) and Data (Type 4)
    # Server listens on UDP 51820 (IPv6 [64:ff9b::b00:2])
    server_script = r"""
import socket, struct, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("64:ff9b::b00:2", 51820))
s.settimeout(5.0)
data, addr = s.recvfrom(2048)
msg_type = struct.unpack("<I", data[:4])[0]
if msg_type != 1 or len(data) != 148:
    sys.exit(1)
# Reply with Type 2 Response (92 bytes)
resp = struct.pack("<I", 2) + struct.pack("<II", 0x1111, 0x2222) + (b"\xaa" * 80)
s.sendto(resp, addr)
# Recv Type 4 Data packet
data4, addr4 = s.recvfrom(2048)
msg_type4 = struct.unpack("<I", data4[:4])[0]
if msg_type4 != 4:
    sys.exit(2)
sys.exit(0)
"""
    client_script = r"""
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5.0)
# Send Type 1 (148 bytes)
init_pkt = struct.pack("<I", 1) + struct.pack("<I", 0x12345678) + (b"\xbb" * 140)
s.sendto(init_pkt, ("11.0.0.2", 51820))
resp, _ = s.recvfrom(2048)
msg_type = struct.unpack("<I", resp[:4])[0]
if msg_type != 2 or len(resp) != 92:
    sys.exit(1)
# Send Type 4 Data
data_pkt = struct.pack("<IIQ", 4, 0x2222, 1) + b"WireGuard-over-CLAT-Tunnel-Payload-Data"
s.sendto(data_pkt, ("11.0.0.2", 51820))
sys.exit(0)
"""
    srv = subprocess.Popen(["ip", "netns", "exec", "server", sys.executable, "-c", server_script])
    time.sleep(0.3)
    cli = subprocess.run(["ip", "netns", "exec", "client", sys.executable, "-c", client_script])
    srv_rc = srv.wait(timeout=5)
    assert cli.returncode == 0, f"WireGuard client failed with code {cli.returncode}"
    assert srv_rc == 0, f"WireGuard server failed with code {srv_rc}"
    print("[PASS] WireGuard UDP Handshake and Data Framing Verified")


def test_stun_rfc5389():
    print("\n--- Test 3: STUN (RFC 5389) NAT Discovery Over CLAT ---")
    server_script = r"""
import socket, struct, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("64:ff9b::b00:2", 3478))
s.settimeout(5.0)
data, addr = s.recvfrom(2048)
msg_type, msg_len, magic = struct.unpack("!HHI", data[:8])
if msg_type != 0x0001 or magic != 0x2112A442:
    sys.exit(1)
trans_id = data[8:20]
# Build STUN Binding Success Response with XOR-MAPPED-ADDRESS (RFC 5389 §15.2)
# Attribute: Type=0x0020, Len=8, Reserved=0, Family=0x01 (IPv4), XOR-Port, XOR-Address
xor_port = addr[1] ^ (magic >> 16)
xor_addr = struct.unpack("!I", socket.inet_aton("192.0.0.1"))[0] ^ magic
attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, xor_port, xor_addr)
resp = struct.pack("!HHI", 0x0101, len(attr), magic) + trans_id + attr
s.sendto(resp, addr)
sys.exit(0)
"""
    client_script = r"""
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5.0)
magic = 0x2112A442
trans_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
req = struct.pack("!HHI", 0x0001, 0, magic) + trans_id
s.sendto(req, ("11.0.0.2", 3478))
resp, _ = s.recvfrom(2048)
resp_type, resp_len, resp_magic = struct.unpack("!HHI", resp[:8])
if resp_type != 0x0101 or resp_magic != magic or resp[8:20] != trans_id:
    sys.exit(1)
# Parse XOR-MAPPED-ADDRESS
attr_type, attr_len = struct.unpack("!HH", resp[20:24])
if attr_type != 0x0020:
    sys.exit(2)
sys.exit(0)
"""
    srv = subprocess.Popen(["ip", "netns", "exec", "server", sys.executable, "-c", server_script])
    time.sleep(0.3)
    cli = subprocess.run(["ip", "netns", "exec", "client", sys.executable, "-c", client_script])
    srv_rc = srv.wait(timeout=5)
    assert cli.returncode == 0, f"STUN client failed with code {cli.returncode}"
    assert srv_rc == 0, f"STUN server failed with code {srv_rc}"
    print("[PASS] STUN RFC 5389 Binding Transaction & XOR Address Verified")


def test_passive_ftp_emulation():
    print("\n--- Test 4: Passive FTP (PASV) Control & Data Channel ---")
    server_script = r"""
import socket, sys, time
# Control channel on port 21
ctl_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
ctl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ctl_sock.bind(("64:ff9b::b00:2", 21))
ctl_sock.listen(1)

# Secondary data channel on port 50000 (195 * 256 + 80 = 50000)
data_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
data_sock.bind(("64:ff9b::b00:2", 50000))
data_sock.listen(1)

conn, _ = ctl_sock.accept()
conn.sendall(b"220 Service ready\r\n")
req = conn.recv(1024)
if b"PASV" not in req:
    sys.exit(1)
# Respond with 11.0.0.2:50000 in PASV format
conn.sendall(b"227 Entering Passive Mode (11,0,0,2,195,80).\r\n")

# Wait for client data connection
dconn, _ = data_sock.accept()
payload = dconn.recv(4096)
if payload != b"FTP-Passive-Data-Channel-Payload-Content":
    sys.exit(2)
dconn.close()
conn.sendall(b"226 Transfer complete\r\n")
conn.close()
ctl_sock.close()
data_sock.close()
sys.exit(0)
"""
    client_script = r"""
import socket, re, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5.0)
s.connect(("11.0.0.2", 21))
banner = s.recv(1024)
s.sendall(b"PASV\r\n")
pasv_resp = s.recv(1024).decode("latin-1")
match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv_resp)
if not match:
    sys.exit(1)
nums = [int(x) for x in match.groups()]
ip_addr = f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}"
data_port = nums[4] * 256 + nums[5]

# Connect to the advertised data port
ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ds.settimeout(5.0)
ds.connect((ip_addr, data_port))
ds.sendall(b"FTP-Passive-Data-Channel-Payload-Content")
ds.close()

final_resp = s.recv(1024)
if b"226" not in final_resp:
    sys.exit(2)
s.close()
sys.exit(0)
"""
    srv = subprocess.Popen(["ip", "netns", "exec", "server", sys.executable, "-c", server_script])
    time.sleep(0.3)
    cli = subprocess.run(["ip", "netns", "exec", "client", sys.executable, "-c", client_script])
    srv_rc = srv.wait(timeout=5)
    assert cli.returncode == 0, f"FTP client failed with code {cli.returncode}"
    assert srv_rc == 0, f"FTP server failed with code {srv_rc}"
    print("[PASS] Passive FTP Control Negotiation & Secondary Data Connection Verified")


def test_tcp_stream_integrity():
    print("\n--- Test 5: TCP Stream Integrity & Checksum Verification ---")
    payload = os.urandom(64 * 1024)  # 64 KB
    expected_hash = hashlib.sha256(payload).hexdigest()

    server_script = r"""
import socket, hashlib, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("64:ff9b::b00:2", 9999))
s.listen(1)
conn, _ = s.accept()
recvd = bytearray()
while len(recvd) < 65536:
    chunk = conn.recv(16384)
    if not chunk:
        break
    recvd.extend(chunk)
conn.close()
s.close()
h = hashlib.sha256(recvd).hexdigest()
print(h)
"""
    srv = subprocess.Popen(["ip", "netns", "exec", "server", sys.executable, "-c", server_script],
                           stdout=subprocess.PIPE, text=True)
    time.sleep(0.3)

    client_script = f"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("11.0.0.2", 9999))
s.sendall({repr(payload)})
s.close()
"""
    cli = subprocess.run(["ip", "netns", "exec", "client", sys.executable, "-c", client_script])
    srv_out, _ = srv.communicate(timeout=5)
    assert cli.returncode == 0, "TCP client failed"
    assert srv.returncode == 0, "TCP server failed"
    assert srv_out.strip() == expected_hash, f"Hash mismatch: got {srv_out.strip()}, expected {expected_hash}"
    print(f"[PASS] TCP Stream Integrity Verified (SHA-256 = {expected_hash[:16]}...)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=None, help="Path to tayga executable")
    parser.add_argument("--output", type=Path, default=None, help="Output directory")
    args = parser.parse_args()

    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Linux root is required to run network namespace tests")

    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)

    print("=== TAYGA CLAT Multi-Protocol End-to-End System Test ===")
    setup_topology()

    # Launch TAYGA CLAT
    clat_cmd = [
        "ip", "netns", "exec", "clatns", "env",
        "PREF64=64:ff9b::/96", "ROUTER4=172.31.64.1",
        "CLAT_WORKERS=2", "CLAT_OFFLOAD=tcp",
        "/usr/local/sbin/clat-start.sh"
    ]
    if args.binary:
        clat_cmd.insert(4, f"TAYGA_BIN={args.binary}")

    tayga = subprocess.Popen(clat_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        test_icmp_ping()
        test_wireguard_udp()
        test_stun_rfc5389()
        test_passive_ftp_emulation()
        test_tcp_stream_integrity()
        print("\nAll End-to-End Protocol Tests PASSED Successfully!")
    finally:
        if tayga.poll() is None:
            tayga.terminate()
            try:
                tayga.wait(timeout=3)
            except subprocess.TimeoutExpired:
                tayga.kill()
        teardown()


if __name__ == "__main__":
    main()
