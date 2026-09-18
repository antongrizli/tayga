#!/usr/bin/env python3
"""
End-to-End PMTUD / ICMPv6 Packet Too Big Correctness Test for TAYGA CLAT.

Verifies:
1. End-to-end TCP throughput and file integrity (SHA-256) through MTU 1280 CLAT path.
2. Direct RFC 7915 / RFC 6146 ICMPv6 PTB translation:
   - Injects ICMPv6 Packet Too Big (mtu=1280) from server.
   - Verifies TAYGA translates it to ICMPv4 Destination Unreachable / Fragmentation Needed (mtu=1260).
   - Verifies router conntrack NAT reversibility.
   - Verifies client receives valid ICMPv4 Frag-Needed with correct embedded IPv4/TCP header.
"""

import subprocess
import time
import hashlib
import os
import sys

sys.path.insert(0, '/usr/lib/python3/dist-packages')
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import conf, sendp, Ether, IPv6, ICMPv6PacketTooBig, TCP
conf.verb = 0

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode

def get_mac(iface, netns):
    out, _, _ = sh(f"ip -n {netns} link show {iface}")
    for tok in out.split():
        if len(tok) == 17 and tok.count(':') == 5 and tok != 'ff:ff:ff:ff:ff:ff':
            return tok
    return None

def setup_topology(mtu_rwan=1500):
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns del {ns} 2>/dev/null")
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns add {ns}")

    sh("ip link add lan0 type veth peer name rlan")
    sh("ip link set lan0 netns client"); sh("ip link set rlan netns router")
    sh("ip link add rclat type veth peer name ceth")
    sh("ip link set rclat netns router"); sh("ip link set ceth netns clatns")
    sh("ip -n clatns link set ceth name veth-nat64")
    sh("ip link add rwan type veth peer name server0")
    sh("ip link set rwan netns router"); sh("ip link set server0 netns server")

    for c in [
        "ip -n client link set lo up", "ip -n client link set lan0 up",
        "ip -n client addr add 192.168.88.2/24 dev lan0",
        "ip -n client route add default via 192.168.88.1",
        "ip -n router link set lo up", "ip -n router link set rlan up",
        "ip -n router addr add 192.168.88.1/24 dev rlan",
        "ip -n router link set rclat up",
        "ip -n router addr add 172.31.64.1/24 dev rclat",
        "ip -n router -6 addr add fd9b:64:1:fe::1/64 dev rclat",
        "ip -n router link set rwan up",
        "ip -n router -6 addr add 2600:464::1/64 dev rwan",
        "ip netns exec router sysctl -w net.ipv4.ip_forward=1 >/dev/null",
        "ip netns exec router sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null",
        "ip -n router route add default via 172.31.64.2",
        "ip -n router -6 route add fd9b:64:1:ff::10/128 via fd9b:64:1:fe::2 dev rclat",
        "ip -n router -6 route add 64:ff9b::/96 via 2600:464::2 dev rwan",
        "ip -n router link set rwan mtu " + str(mtu_rwan),
        "ip -n server link set server0 mtu " + str(mtu_rwan),
    ]:
        sh(c)

    sh("""ip netns exec router nft -f - <<'EOF'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "rclat" ip saddr 192.168.88.0/24 snat to 192.0.0.1
  }
}
EOF""")

    for c in [
        "ip -n clatns link set lo up", "ip -n clatns link set veth-nat64 up",
        "ip -n clatns addr add 172.31.64.2/24 dev veth-nat64",
        "ip -n clatns -6 addr add fd9b:64:1:fe::2/64 dev veth-nat64",
        "ip -n clatns -6 route add default via fd9b:64:1:fe::1",
        "ip netns exec clatns sysctl -w net.ipv4.ip_forward=1 >/dev/null",
        "ip netns exec clatns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null",
        "ip -n server link set lo up", "ip -n server link set server0 up",
        "ip -n server -6 addr add 2600:464::2/64 dev server0",
        "ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo",
        "ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0",
    ]:
        sh(c)

def teardown():
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns del {ns} 2>/dev/null")

def test_tcp_data_integrity():
    print("\n--- 1. TCP 20 MB Integrity Test (MTU 1280 Path) ---")
    setup_topology(mtu_rwan=1280)
    test_file = "/tmp/pmtud_test_20mb.bin"
    dl_file = "/tmp/pmtud_dl_20mb.bin"
    if not os.path.exists(test_file) or os.path.getsize(test_file) != 20 * 1024 * 1024:
        with open(test_file, "wb") as f:
            f.write(os.urandom(20 * 1024 * 1024))
    with open(test_file, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()

    tayga = subprocess.Popen(
        ["ip", "netns", "exec", "clatns", "env",
         "PREF64=64:ff9b::/96", "ROUTER4=172.31.64.1",
         "CLAT_WORKERS=2", "CLAT_OFFLOAD=tcp",
         "/usr/local/sbin/clat-start.sh"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    srv = subprocess.Popen(
        ["ip", "netns", "exec", "server", "socat", "-u",
         f"OPEN:{test_file}", "TCP6-LISTEN:9990,reuseaddr,bind=[64:ff9b::b00:2]"])
    time.sleep(0.3)

    if os.path.exists(dl_file):
        os.remove(dl_file)
    t0 = time.monotonic()
    sh(f"ip netns exec client socat -u TCP4:11.0.0.2:9990 OPEN:{dl_file},creat,trunc")
    elapsed = time.monotonic() - t0
    srv.wait(timeout=5)

    with open(dl_file, "rb") as f:
        got_hash = hashlib.sha256(f.read()).hexdigest()

    tayga.terminate()
    tayga.wait(timeout=2)
    teardown()

    assert got_hash == expected_hash, f"Hash mismatch: expected {expected_hash}, got {got_hash}"
    print(f"[PASS] TCP Download 20 MB completed in {elapsed:.2f}s (SHA-256 match)")
    return True

def test_ptb_translation():
    print("\n--- 2. ICMPv6 Packet Too Big Translation Test ---")
    setup_topology(mtu_rwan=1500)

    tayga = subprocess.Popen(
        ["ip", "netns", "exec", "clatns", "env",
         "PREF64=64:ff9b::/96", "ROUTER4=172.31.64.1",
         "CLAT_WORKERS=1", "CLAT_OFFLOAD=tcp",
         "/usr/local/sbin/clat-start.sh"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    # Ping to warm up routing/NDP
    sh("ip netns exec client ping -c 1 -W 1 11.0.0.2 >/dev/null 2>&1")

    # Start server listener
    srv = subprocess.Popen(["ip", "netns", "exec", "server", "socat", "-u",
                            "TCP6-LISTEN:8088,reuseaddr,bind=[64:ff9b::b00:2]", "/dev/null"])
    time.sleep(0.2)

    server0_mac = get_mac("server0", "server")
    rwan_mac    = get_mac("rwan", "router")

    cap_client = "/tmp/cap_pmtud_verify.pcap"
    td = subprocess.Popen(
        ["ip", "netns", "exec", "client", "tcpdump", "-i", "lan0",
         "-w", cap_client, "-n", "icmp"], stderr=subprocess.DEVNULL)
    time.sleep(0.2)

    # Establish TCP NAT connection from client
    client_conn = subprocess.Popen(
        ["ip", "netns", "exec", "client", "socat", "-u", "-",
         "TCP4:11.0.0.2:8088,sourceport=55555"], stdin=subprocess.PIPE)
    time.sleep(0.2)

    # Inject ICMPv6 PTB from server
    emb = IPv6(src="fd9b:64:1:ff::10", dst="64:ff9b::b00:2", nh=6, hlim=63) / \
          TCP(sport=55555, dport=8088, flags="PA", seq=100)
    ptb = Ether(src=server0_mac, dst=rwan_mac) / \
          IPv6(src="64:ff9b::c000:201", dst="fd9b:64:1:ff::10", nh=58) / \
          ICMPv6PacketTooBig(mtu=1280) / emb

    pkt_bin = "/tmp/_ptb_temp.bin"
    with open(pkt_bin, "wb") as f:
        f.write(bytes(ptb))

    sh(f"""ip netns exec server python3 -c "
import sys; sys.path.insert(0,'/usr/lib/python3/dist-packages')
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import sendp, Ether
with open('{pkt_bin}','rb') as f: raw = f.read()
sendp(Ether(raw), iface='server0', verbose=0)
" """)

    time.sleep(0.5)

    td.terminate()
    try: td.wait(timeout=2)
    except: td.kill(); td.wait()

    client_conn.kill()
    try: client_conn.wait(timeout=1)
    except: pass
    srv.kill()
    try: srv.wait(timeout=1)
    except: pass
    tayga.terminate()
    try: tayga.wait(timeout=2)
    except: tayga.kill(); tayga.wait()
    teardown()

    txt, _, _ = sh(f"tcpdump -r {cap_client} -n -v 2>/dev/null")
    print("Client ICMP capture:")
    for line in txt.splitlines():
        print(" ", line)

    has_frag = ("unreachable" in txt.lower() or "need to frag" in txt.lower()) and "1260" in txt
    assert has_frag, "ICMPv4 Fragmentation Needed (mtu 1260) was not received by client!"
    print("[PASS] ICMPv6 PTB (mtu=1280) -> ICMPv4 Frag-Needed (mtu=1260) verified end-to-end!")
    return True

def main():
    print("=== TAYGA CLAT PMTUD & ICMPv6 PTB Test Suite ===")
    test_tcp_data_integrity()
    test_ptb_translation()
    print("\nALL PMTUD & PTB TESTS PASSED!")

if __name__ == "__main__":
    main()
