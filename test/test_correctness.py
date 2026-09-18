#!/usr/bin/env python3
import subprocess
import time
import hashlib
import os
import sys

def sh(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout, res.stderr, res.returncode

def main():
    print("=== TAYGA CLAT Data Correctness & Integrity Test ===")

    # 1. Prepare 20 MB random payload
    test_file = "/tmp/test_20mb.bin"
    up_received = "/tmp/upload_received.bin"
    dl_received = "/tmp/download_received.bin"

    if not os.path.exists(test_file) or os.path.getsize(test_file) != 20 * 1024 * 1024:
        data = os.urandom(20 * 1024 * 1024)
        with open(test_file, "wb") as f:
            f.write(data)
    
    with open(test_file, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"Test payload: 20 MB, SHA-256 = {expected_hash}")

    # 2. Cleanup & recreate netns
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

    sh("ip -n client link set lo up")
    sh("ip -n client link set lan0 up")
    sh("ip -n client addr add 192.168.88.2/24 dev lan0")
    sh("ip -n client route add default via 192.168.88.1")

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
    sh("ip netns exec router nft -f - << 'EOF'\n"
       "table ip nat {\n"
       "  chain postrouting {\n"
       "    type nat hook postrouting priority srcnat; policy accept;\n"
       "    oifname \"rclat\" ip saddr 192.168.88.0/24 snat to 192.0.0.1\n"
       "  }\n"
       "}\n"
       "EOF")

    sh("ip -n clatns link set lo up")
    sh("ip -n clatns link set veth-nat64 up")
    sh("ip -n clatns addr add 172.31.64.2/24 dev veth-nat64")
    sh("ip -n clatns -6 addr add fd9b:64:1:fe::2/64 dev veth-nat64")
    sh("ip -n clatns -6 route add default via fd9b:64:1:fe::1")
    sh("ip netns exec clatns sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    sh("ip netns exec clatns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null")

    # Start TAYGA with CLAT_OFFLOAD=tcp
    tayga = subprocess.Popen(["ip", "netns", "exec", "clatns", "env",
                             "PREF64=64:ff9b::/96", "ROUTER4=172.31.64.1",
                             "CLAT_WORKERS=2", "CLAT_OFFLOAD=tcp",
                             "/usr/local/sbin/clat-start.sh"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    sh("ip -n server link set lo up")
    sh("ip -n server link set server0 up")
    sh("ip -n server -6 addr add 2600:464::2/64 dev server0")
    sh("ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo")
    sh("ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0")

    # 3. Test ICMP Ping
    ping_out, _, ping_rc = sh("ip netns exec client ping -c 3 -W 1 11.0.0.2")
    assert ping_rc == 0, f"Ping failed: {ping_out}"
    print("[PASS] ICMP Echo Request / Reply verified")

    # 4. Test TCP Upload (20 MB)
    for f in [up_received, dl_received]:
        if os.path.exists(f): os.remove(f)

    # Server receives on port 9999
    srv_nc = subprocess.Popen("ip netns exec server socat -u TCP6-LISTEN:9999,reuseaddr,bind=64:ff9b::b00:2 OPEN:/tmp/upload_received.bin,creat,trunc",
                              shell=True)
    time.sleep(0.5)
    sh("ip netns exec client socat -u OPEN:/tmp/test_20mb.bin TCP4:11.0.0.2:9999")
    srv_nc.wait(timeout=10)

    with open(up_received, "rb") as f:
        up_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"Upload Result:   SHA-256 = {up_hash}")
    assert up_hash == expected_hash, f"Upload hash mismatch! Expected {expected_hash}, got {up_hash}"
    print("[PASS] TCP Upload 20 MB file integrity verified")

    # 5. Test TCP Download (20 MB)
    srv_nc_dl = subprocess.Popen("ip netns exec server socat -u OPEN:/tmp/test_20mb.bin TCP6-LISTEN:9998,reuseaddr,bind=64:ff9b::b00:2",
                                 shell=True)
    time.sleep(0.5)
    sh("ip netns exec client socat -u TCP4:11.0.0.2:9998 OPEN:/tmp/download_received.bin,creat,trunc")
    srv_nc_dl.wait(timeout=10)

    with open(dl_received, "rb") as f:
        dl_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"Download Result: SHA-256 = {dl_hash}")
    assert dl_hash == expected_hash, f"Download hash mismatch! Expected {expected_hash}, got {dl_hash}"
    print("[PASS] TCP Download 20 MB file integrity verified")

    # 6. Test UDP Datagram Echo
    udp_srv = subprocess.Popen("ip netns exec server socat -u UDP6-RECV:9997,bind=64:ff9b::b00:2 SYSTEM:'cat > /tmp/udp_received.txt'",
                               shell=True)
    time.sleep(0.5)
    sh("ip netns exec client sh -c \"printf 'HELLO_UDP_VERIFY_12345' | socat -u - UDP4-DATAGRAM:11.0.0.2:9997\"")
    time.sleep(0.5)
    udp_srv.terminate()
    udp_content = open("/tmp/udp_received.txt").read() if os.path.exists("/tmp/udp_received.txt") else ""
    assert "HELLO_UDP_VERIFY_12345" in udp_content, f"UDP echo failed, got '{udp_content}'"
    print("[PASS] UDP datagram translation verified")

    # Cleanup TAYGA & netns
    tayga.terminate()
    tayga.wait(timeout=2)
    for ns in ["client", "router", "clatns", "server"]:
        sh(f"ip netns del {ns} 2>/dev/null")

    print("\nALL INTEGRITY & CORRECTNESS TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
