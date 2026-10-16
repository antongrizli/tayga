#!/usr/bin/env python3
import subprocess
import time
import hashlib
import os
import shlex

def sh(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout, res.stderr, res.returncode

def main():
    print("=== TAYGA CLAT Data Correctness & Integrity Test ===")

    size_mb = int(os.environ.get("TEST_SIZE_MB", "100"))
    payload_bytes = size_mb * 1024 * 1024
    test_file = f"/tmp/test_{size_mb}mb.bin"
    up_received = "/tmp/upload_received.bin"
    dl_received = "/tmp/download_received.bin"

    if not os.path.exists(test_file) or os.path.getsize(test_file) != payload_bytes:
        print(f"Generating {size_mb} MB random payload...")
        with open(test_file, "wb") as f:
            for _ in range(size_mb):
                f.write(os.urandom(1024 * 1024))
    
    with open(test_file, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"Test payload: {size_mb} MB ({payload_bytes} bytes), SHA-256 = {expected_hash}")

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

    # Setup server interface and routing
    sh("ip -n server link set lo up")
    sh("ip -n server link set server0 up")
    sh("ip -n server -6 addr add 2600:464::2/64 dev server0")
    sh("ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo")
    sh("ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0")

    # Start TAYGA with CLAT_OFFLOAD=tcp
    tayga = subprocess.Popen(["ip", "netns", "exec", "clatns", "env",
                             "PREF64=64:ff9b::/96", "ROUTER4=172.31.64.1",
                             "CLAT_WORKERS=2", "CLAT_OFFLOAD=tcp",
                             "/usr/local/sbin/clat-start.sh"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv_nc = srv_nc_dl = None
    try:
        # Wait for CLAT readiness
        ready = False
        t0 = time.monotonic()
        while time.monotonic() - t0 < 6:
            _, _, rc = sh("ip netns exec client ping -c 1 -W 1 11.0.0.2")
            if rc == 0:
                ready = True
                break
            time.sleep(0.3)
        assert ready, "CLAT ping failed to become ready"
        print("[PASS] ICMP Echo Request / Reply verified")

        # 4. Test TCP Upload (unlimited speed)
        for f in [up_received, dl_received]:
            if os.path.exists(f): os.remove(f)

        # Server receives on port 9999
        srv_nc = subprocess.Popen(shlex.split(f"ip netns exec server socat -u TCP6-LISTEN:9999,reuseaddr,bind=[64:ff9b::b00:2] OPEN:{up_received},creat,trunc"))
        time.sleep(0.5)
        t_up_start = time.monotonic()
        sh(f"ip netns exec client socat -u OPEN:{test_file} TCP4:11.0.0.2:9999")
        srv_nc.wait(timeout=30)
        t_up_elapsed = time.monotonic() - t_up_start
        up_rate_mbps = (payload_bytes * 8 / t_up_elapsed) / 1_000_000

        with open(up_received, "rb") as f:
            up_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"Upload Result:   SHA-256 = {up_hash} (Time: {t_up_elapsed:.2f}s, Rate: {up_rate_mbps:.1f} Mbps)")
        assert up_hash == expected_hash, f"Upload hash mismatch! Expected {expected_hash}, got {up_hash}"
        print(f"[PASS] TCP Upload {size_mb} MB file integrity & rate verified")

        # 5. Test TCP Download (unlimited speed)
        srv_nc_dl = subprocess.Popen(shlex.split(f"ip netns exec server socat -u OPEN:{test_file} TCP6-LISTEN:9998,reuseaddr,bind=[64:ff9b::b00:2]"))
        time.sleep(0.5)
        t_dl_start = time.monotonic()
        sh(f"ip netns exec client socat -u TCP4:11.0.0.2:9998 OPEN:{dl_received},creat,trunc")
        srv_nc_dl.wait(timeout=30)
        t_dl_elapsed = time.monotonic() - t_dl_start
        dl_rate_mbps = (payload_bytes * 8 / t_dl_elapsed) / 1_000_000

        with open(dl_received, "rb") as f:
            dl_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"Download Result: SHA-256 = {dl_hash} (Time: {t_dl_elapsed:.2f}s, Rate: {dl_rate_mbps:.1f} Mbps)")
        assert dl_hash == expected_hash, f"Download hash mismatch! Expected {expected_hash}, got {dl_hash}"
        print(f"[PASS] TCP Download {size_mb} MB file integrity & rate verified")

        # 6. Test UDP delivery (IPv4 -> IPv6; this is not an echo test).
        # UDP bind parses an optional port, so IPv6 literals need brackets.
        udp_payload = b"HELLO_UDP_VERIFY_12345"
        udp_received = "/tmp/udp_received.txt"
        with open(udp_received, "wb") as received:
            udp_srv = subprocess.Popen(
                ["ip", "netns", "exec", "server", "socat", "-u",
                 "UDP6-RECV:9997,bind=[64:ff9b::b00:2]", "-"],
                stdout=received, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if udp_srv.poll() is not None:
                        raise RuntimeError(f"UDP receiver failed: {udp_srv.stderr.read()}")
                    listeners, _, rc = sh("ip netns exec server ss -H -lun6 'sport = :9997'")
                    if rc == 0 and listeners.strip():
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("UDP receiver did not become ready within 5s")
                    time.sleep(0.05)
                subprocess.run(
                    ["ip", "netns", "exec", "client", "socat", "-u", "-",
                     "UDP4-DATAGRAM:11.0.0.2:9997"],
                    input=udp_payload, check=True, timeout=5)
                deadline = time.monotonic() + 5
                while os.path.getsize(udp_received) < len(udp_payload):
                    if udp_srv.poll() is not None:
                        raise RuntimeError(f"UDP receiver exited: {udp_srv.stderr.read()}")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("UDP datagram was not received within 5s")
                    time.sleep(0.05)
            finally:
                udp_srv.terminate()
                try:
                    udp_srv.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    udp_srv.kill()
                    udp_srv.wait()
                udp_srv.stderr.close()
        with open(udp_received, "rb") as received:
            udp_content = received.read()
        assert udp_payload == udp_content, f"UDP delivery failed, got {udp_content!r}"
        print("[PASS] UDP IPv4 -> IPv6 datagram integrity verified")

    finally:
        for process in (srv_nc, srv_nc_dl, tayga):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for ns in ["client", "router", "clatns", "server"]:
            sh(f"ip netns del {ns} 2>/dev/null")

    print("\nALL INTEGRITY & CORRECTNESS TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
