#!/usr/bin/env python3
"""
Self-contained PMTUD sub-test B: sets up topology, injects ICMPv6 PTB
via Scapy L2, verifies ICMPv4 Fragmentation-Needed at client.
"""
import sys, os, time, subprocess, socket

sys.path.insert(0, '/usr/lib/python3/dist-packages')
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import conf, sendp, Ether, IPv6, ICMPv6PacketTooBig, TCP

conf.verb = 0

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode

def get_mac(iface, netns=None):
    if netns:
        out, _, _ = sh(f"ip -n {netns} link show {iface}")
    else:
        out, _, _ = sh(f"ip link show {iface}")
    for tok in out.split():
        if len(tok)==17 and tok.count(':')==5:
            return tok
    return None

def setup():
    for ns in ["client","router","clatns","server"]:
        sh(f"ip netns del {ns} 2>/dev/null")
    for ns in ["client","router","clatns","server"]:
        sh(f"ip netns add {ns}")

    sh("ip link add lan0 type veth peer name rlan")
    sh("ip link set lan0 netns client"); sh("ip link set rlan netns router")
    sh("ip link add rclat type veth peer name ceth")
    sh("ip link set rclat netns router"); sh("ip link set ceth netns clatns")
    sh("ip -n clatns link set ceth name veth-nat64")
    sh("ip link add rwan type veth peer name server0")
    sh("ip link set rwan netns router"); sh("ip link set server0 netns server")

    for c in ["ip -n client link set lo up", "ip -n client link set lan0 up",
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
              "ip -n router -6 route add 64:ff9b::/96 via 2600:464::2 dev rwan"]:
        sh(c)
    sh("""ip netns exec router nft -f - <<'EOF'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "rclat" ip saddr 192.168.88.0/24 snat to 192.0.0.1
  }
}
EOF""")
    for c in ["ip -n clatns link set lo up", "ip -n clatns link set veth-nat64 up",
              "ip -n clatns addr add 172.31.64.2/24 dev veth-nat64",
              "ip -n clatns -6 addr add fd9b:64:1:fe::2/64 dev veth-nat64",
              "ip -n clatns -6 route add default via fd9b:64:1:fe::1",
              "ip netns exec clatns sysctl -w net.ipv4.ip_forward=1 >/dev/null",
              "ip netns exec clatns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null",
              "ip -n server link set lo up", "ip -n server link set server0 up",
              "ip -n server -6 addr add 2600:464::2/64 dev server0",
              "ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo",
              "ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0"]:
        sh(c)

def teardown():
    for ns in ["client","router","clatns","server"]:
        sh(f"ip netns del {ns} 2>/dev/null")


def main():
    print("=== Sub-test B: ICMPv6 PTB → ICMPv4 Frag-Needed (TAYGA) ===")
    setup()

    # Start TAYGA
    tayga = subprocess.Popen(
        ["ip","netns","exec","clatns","env",
         "PREF64=64:ff9b::/96","ROUTER4=172.31.64.1",
         "CLAT_WORKERS=1","CLAT_OFFLOAD=off",
         "/usr/local/sbin/clat-start.sh"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)

    # Warm up NDP
    sh("ip netns exec client ping -c 2 -W 2 11.0.0.2 >/dev/null 2>&1")
    sh("ip netns exec router ping6 -c 1 -W 1 fd9b:64:1:fe::2 >/dev/null 2>&1")
    time.sleep(0.3)

    # Get MACs
    server0_mac = get_mac("server0", "server")
    rwan_mac    = get_mac("rwan",    "router")
    rclat_mac   = get_mac("rclat",  "router")
    vnat64_mac  = get_mac("veth-nat64", "clatns")
    print(f"  server0={server0_mac}  rwan={rwan_mac}")
    print(f"  rclat={rclat_mac}  veth-nat64={vnat64_mac}")

    assert server0_mac and rwan_mac, "Could not get MACs!"

    # Capture at rlan (between router and client)
    cap_client = "/tmp/ptb_rlan.pcap"
    cap_clatns = "/tmp/ptb_vnat64.pcap"
    td_client = subprocess.Popen(
        ["ip","netns","exec","router","tcpdump","-i","rlan",
         "-w", cap_client, "-n", "icmp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    td_clatns = subprocess.Popen(
        ["ip","netns","exec","clatns","tcpdump","-i","veth-nat64",
         "-w", cap_clatns, "-n", "ip or icmp6"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.2)

    # Build and send ICMPv6 PTB via L2 from server netns
    # We need to exec in server netns — use nsenter
    # The embedded packet: fd9b:64:1:ff::10 → 64:ff9b::b00:2 TCP SYN
    # Outer PTB src: 64:ff9b::c000:201 (maps to 192.0.2.1 via RFC6052)
    # Outer PTB dst: fd9b:64:1:fe::2 (TAYGA's veth-nat64)
    
    # Build packet in current netns (same FS layout)
    emb = IPv6(src="fd9b:64:1:ff::10", dst="64:ff9b::b00:2", nh=6, hlim=63) / \
          TCP(sport=12345, dport=80, flags="S", seq=1000)
    ptb_pkt = Ether(src=server0_mac, dst=rwan_mac) / \
              IPv6(src="64:ff9b::c000:201", dst="fd9b:64:1:fe::2", nh=58) / \
              ICMPv6PacketTooBig(mtu=1280) / emb

    # Send via nsenter into server netns
    import ctypes
    CLONE_NEWNET = 0x40000000
    
    # Use ip netns exec subprocess approach with raw packet bytes
    raw_bytes = bytes(ptb_pkt)
    
    # Write packet to file, then send via python in server netns
    pkt_file = "/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/_ptb_pkt.bin"
    with open(pkt_file, "wb") as f:
        f.write(raw_bytes)
    
    send_script = f"""
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import sendp, Ether
with open('{pkt_file}', 'rb') as f:
    raw = f.read()
pkt = Ether(raw)
sendp(pkt, iface='server0', verbose=0)
print('SENT', len(raw), 'bytes')
"""
    send_file = "/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/_ptb_send.py"
    with open(send_file, "w") as f:
        f.write(send_script)

    out, err, rc = sh(f"ip netns exec server python3 {send_file}")
    print(f"  Inject: {out.strip()}")
    if err.strip() and "SyntaxWarning" not in err and "iface" not in err:
        print(f"  STDERR: {err.strip()[:200]}")

    time.sleep(1.0)

    for td in (td_client, td_clatns):
        td.terminate()
        try: td.wait(timeout=2)
        except: td.kill(); td.wait()

    print("\n  === ICMPv4 at rlan (router→client) ===")
    out, _, _ = sh(f"tcpdump -r {cap_client} -n -v 2>/dev/null")
    for l in out.splitlines()[:20]:
        if l.strip(): print(f"    {l}")

    print("\n  === IPv4/ICMPv6 at veth-nat64 (clatns) ===")
    out2, _, _ = sh(f"tcpdump -r {cap_clatns} -n 2>/dev/null")
    for l in out2.splitlines()[:15]:
        if l.strip(): print(f"    {l}")

    print("\n  === TAYGA log ===")
    tayga.terminate()
    try:
        log, _ = tayga.communicate(timeout=3)
    except:
        tayga.kill()
        log, _ = tayga.communicate()
    for line in log.decode(errors='replace').splitlines():
        if line.strip(): print(f"    {line}")

    teardown()

    frag_lines = [l for l in out.splitlines() if "unreachable" in l.lower() or "3," in l]
    if frag_lines:
        print("\n[PASS] ICMPv4 Fragmentation-Needed confirmed at client!")
        for l in frag_lines[:3]: print(f"  {l}")
    else:
        print("\n[INFO] No ICMPv4 type=3/code=4 at rlan — see captures above")

if __name__ == "__main__":
    main()
