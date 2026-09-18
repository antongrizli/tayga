#!/usr/bin/env python3
"""
Preflight & Auto-detection Test Suite for TAYGA CLAT Offload.

Verifies:
1. CLI flag `tayga --check-offload` exits with code 0 on supported Linux systems
   and prints detailed capability report.
2. `tun-offload auto` initializes offload when supported and logs active status.
3. `tun-offload tcp` explicitly enables offload.
4. `tun-offload off` explicitly disables offload (no vnet header).
5. End-to-end data integrity (SHA-256) under `tun-offload auto`.
"""

import subprocess
import time
import hashlib
import os
import sys

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode

def setup_topology():
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

def wait_for_clat(timeout_sec=5):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_sec:
        out, _, rc = sh("ip netns exec client ping -c 1 -W 1 11.0.0.2")
        if rc == 0:
            return True
        time.sleep(0.3)
    return False

def test_cli_check_offload():
    print("\n--- 1. CLI `tayga --check-offload` Test ---")
    out, err, rc = sh("/usr/local/sbin/tayga --check-offload")
    print(f"Output: {out.strip()}")
    assert rc == 0, f"tayga --check-offload failed with rc={rc}: {err}"
    assert "OFFLOAD_CHECK: OK" in out, f"Unexpected output: {out}"
    print("[PASS] CLI --check-offload verified successfully")

def test_mode_startup(mode, expect_offload_active):
    print(f"\n--- 2. Mode Startup Test: CLAT_OFFLOAD={mode} ---")
    setup_topology()
    log_file = f"/tmp/tayga_test_{mode}.log"
    tayga = subprocess.Popen(
        f"ip netns exec clatns env PREF64=64:ff9b::/96 ROUTER4=172.31.64.1 "
        f"CLAT_WORKERS=1 CLAT_OFFLOAD={mode} /usr/local/sbin/clat-start.sh > {log_file} 2>&1",
        shell=True)

    ready = wait_for_clat(timeout_sec=6)
    with open(log_file, "r") as f:
        log_content = f.read()

    tayga.terminate()
    try: tayga.wait(timeout=2)
    except: sh("killall -9 tayga 2>/dev/null || true")
    teardown()

    assert ready, f"Ping readiness timed out in mode {mode}. Log:\n{log_content}"
    if expect_offload_active:
        assert "TUN offload active" in log_content, f"Expected 'TUN offload active' in log, got:\n{log_content}"
        print(f"[PASS] Mode {mode} active offload verified ('TUN offload active')")
    else:
        assert "TUN offload active" not in log_content, f"Expected no offload in log, got:\n{log_content}"
        print(f"[PASS] Mode {mode} disabled offload verified (clean standard tun)")

def test_auto_data_transfer():
    print("\n--- 3. End-to-End Data Transfer with CLAT_OFFLOAD=auto ---")
    setup_topology()
    test_file = "/tmp/preflight_test_10mb.bin"
    dl_file = "/tmp/preflight_dl_10mb.bin"
    if not os.path.exists(test_file) or os.path.getsize(test_file) != 10 * 1024 * 1024:
        with open(test_file, "wb") as f:
            f.write(os.urandom(10 * 1024 * 1024))
    with open(test_file, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()

    log_file = "/tmp/tayga_auto_transfer.log"
    tayga = subprocess.Popen(
        f"ip netns exec clatns env PREF64=64:ff9b::/96 ROUTER4=172.31.64.1 "
        f"CLAT_WORKERS=2 CLAT_OFFLOAD=auto /usr/local/sbin/clat-start.sh > {log_file} 2>&1",
        shell=True)

    ready = wait_for_clat(timeout_sec=6)
    assert ready, "CLAT failed to become ready under auto mode"

    srv = subprocess.Popen(
        ["ip", "netns", "exec", "server", "socat", "-u",
         f"OPEN:{test_file}", "TCP6-LISTEN:9988,reuseaddr,bind=[64:ff9b::b00:2]"])
    time.sleep(0.3)

    if os.path.exists(dl_file): os.remove(dl_file)
    t0 = time.monotonic()
    sh(f"ip netns exec client socat -u TCP4:11.0.0.2:9988 OPEN:{dl_file},creat,trunc")
    elapsed = time.monotonic() - t0
    srv.wait(timeout=5)

    with open(dl_file, "rb") as f:
        got_hash = hashlib.sha256(f.read()).hexdigest()

    tayga.terminate()
    try: tayga.wait(timeout=2)
    except: sh("killall -9 tayga 2>/dev/null || true")
    teardown()

    assert got_hash == expected_hash, f"Hash mismatch: expected {expected_hash}, got {got_hash}"
    print(f"[PASS] 10 MB transfer under `auto` mode verified in {elapsed:.2f}s (SHA-256 match)")

def main():
    print("=== TAYGA CLAT Preflight & Auto-detection Test Suite ===")
    test_cli_check_offload()
    test_mode_startup("auto", expect_offload_active=True)
    test_mode_startup("tcp", expect_offload_active=True)
    test_mode_startup("off", expect_offload_active=False)
    test_auto_data_transfer()
    print("\nALL PREFLIGHT & AUTO-DETECTION TESTS PASSED!")

if __name__ == "__main__":
    main()
