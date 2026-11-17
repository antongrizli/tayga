#!/bin/sh
# End-to-end kernel verification for contrib/tc-bpf cls_bpf dataplane.
# Creates an isolated network/mount namespace with a veth pair, loads
# tayga_tc_fastpath.o onto clsact egress with LIBBPF_PIN_BY_NAME maps,
# provisions host & subnet EAM rules via tayga-tc-ctl --sync-maps, and
# sends live IPv4/IPv6 UDP & TCP packets with Scapy to verify translation
# and per-CPU statistics counters.

set -eu

DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: test_kernel_e2e.sh must be run as root" >&2
	exit 1
fi

for cmd in unshare ip tc mount python3; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "ERROR: required command not found: $cmd" >&2
		exit 1
	fi
done

if ! python3 -c 'import scapy.all' 2>/dev/null; then
	echo "ERROR: python3 scapy module is required" >&2
	exit 1
fi

if [ ! -f "$DIR/tayga_tc_fastpath.o" ] || [ ! -x "$DIR/tayga-tc-ctl" ]; then
	echo "ERROR: build tayga_tc_fastpath.o and tayga-tc-ctl first" >&2
	exit 1
fi

WORKDIR=$(mktemp -d)
cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

CONF="$WORKDIR/tayga.conf"
cat > "$CONF" <<'EOF'
tun-device nat64
prefix 64:ff9b::/96
map 192.0.2.1 2001:db8:1::1
map 198.51.100.0/24 2001:db8:2::/120
map 10.10.0.0/24 2001:db8:3:0:cafe::/80
EOF

unshare --net --mount -- env DIR="$DIR" CONF="$CONF" sh -eu <<'INNER'
mount --make-rprivate /
mount -t sysfs sysfs /sys
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf

ip link set lo up
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up

tc qdisc add dev veth1 clsact
tc filter add dev veth1 egress bpf da obj "$DIR/tayga_tc_fastpath.o" sec tc

PIN_DIR="/sys/fs/bpf/tc/globals"
for m in tayga_cfg_map tayga_eam4_map tayga_eam6_map tayga_stats_map; do
	if [ ! -e "$PIN_DIR/$m" ]; then
		echo "ERROR: missing pinned BPF map: $PIN_DIR/$m" >&2
		exit 1
	fi
done

"$DIR/tayga-tc-ctl" --sync-maps "$CONF" "$PIN_DIR"

python3 - <<'PY'
import threading
import time
from scapy.all import AsyncSniffer, Ether, IP, IPv6, TCP, UDP, Raw, raw, sendp

def read_mac(iface):
    with open(f"/sys/class/net/{iface}/address", "r", encoding="utf-8") as f:
        return f.read().strip()

src_mac = read_mac("veth1")
dst_mac = read_mac("veth0")

def send_and_expect(pkt, count=1):
    ready = threading.Event()
    sniffer = AsyncSniffer(
        iface="veth0",
        lfilter=lambda p: Ether in p and p[Ether].src == src_mac and p[Ether].dst == dst_mac,
        count=count,
        timeout=3.0,
        started_callback=ready.set,
    )
    sniffer.start()
    assert ready.wait(timeout=2.0), "AsyncSniffer failed to start"
    time.sleep(0.05)
    sendp(pkt, iface="veth1", verbose=False)
    sniffer.join(timeout=3.5)
    pkts = sniffer.results or []
    assert len(pkts) == count, f"Expected {count} packet(s) on veth0, got {len(pkts)}"
    return pkts

def verify_udp6(pkt, expected_src, expected_dst, payload):
    assert IPv6 in pkt, f"Expected IPv6 packet, got {pkt.summary()}"
    ip6 = pkt[IPv6]
    assert ip6.src == expected_src, f"src mismatch: {ip6.src} != {expected_src}"
    assert ip6.dst == expected_dst, f"dst mismatch: {ip6.dst} != {expected_dst}"
    assert ip6.hlim == 63, f"expected hlim 63, got {ip6.hlim}"
    assert UDP in pkt, f"Expected UDP, got {pkt.summary()}"
    assert bytes(pkt[UDP].payload) == payload
    orig_csum = pkt[UDP].chksum
    rebuilt = IPv6(raw(ip6))
    del rebuilt[UDP].chksum
    rebuilt = IPv6(raw(rebuilt))
    assert rebuilt[UDP].chksum == orig_csum, f"UDP6 checksum mismatch: {orig_csum:#x} != {rebuilt[UDP].chksum:#x}"

def verify_udp4(pkt, expected_src, expected_dst, payload):
    assert IP in pkt, f"Expected IPv4 packet, got {pkt.summary()}"
    ip4 = pkt[IP]
    assert ip4.src == expected_src, f"src mismatch: {ip4.src} != {expected_src}"
    assert ip4.dst == expected_dst, f"dst mismatch: {ip4.dst} != {expected_dst}"
    assert ip4.ttl == 63, f"expected ttl 63, got {ip4.ttl}"
    assert UDP in pkt, f"Expected UDP, got {pkt.summary()}"
    assert bytes(pkt[UDP].payload) == payload
    orig_ip_csum = ip4.chksum
    orig_udp_csum = pkt[UDP].chksum
    rebuilt = IP(raw(ip4))
    del rebuilt[IP].chksum
    del rebuilt[UDP].chksum
    rebuilt = IP(raw(rebuilt))
    assert rebuilt[IP].chksum == orig_ip_csum, f"IPv4 checksum mismatch: {orig_ip_csum:#x} != {rebuilt[IP].chksum:#x}"
    assert rebuilt[UDP].chksum == orig_udp_csum, f"UDP4 checksum mismatch: {orig_udp_csum:#x} != {rebuilt[UDP].chksum:#x}"

# 1. Host EAM /32 -> /128 (UDP)
p1 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IP(src="192.0.2.1", dst="203.0.113.5", ttl=64)
    / UDP(sport=12345, dport=5353)
    / Raw(b"host-eam-4to6")
)[0]
verify_udp6(p1, "2001:db8:1::1", "64:ff9b::cb00:7105", b"host-eam-4to6")

# 2. Subnet EAM /24 -> /120 (UDP)
p2 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IP(src="198.51.100.42", dst="203.0.113.9", ttl=64)
    / UDP(sport=22345, dport=8080)
    / Raw(b"sub120-4to6")
)[0]
verify_udp6(p2, "2001:db8:2::2a", "64:ff9b::cb00:7109", b"sub120-4to6")

# 3. Subnet EAM /24 -> /80 (TCP)
p3 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IP(src="10.10.0.7", dst="203.0.113.10", ttl=64)
    / TCP(sport=40001, dport=443, flags="S", seq=100)
    / Raw(b"tcp80")
)[0]
assert IPv6 in p3 and TCP in p3
assert p3[IPv6].src == "2001:db8:3:0:cafe:700::"
assert p3[IPv6].dst == "64:ff9b::cb00:710a"
assert p3[IPv6].hlim == 63
orig_tcp_csum = p3[TCP].chksum
rebuilt_tcp = IPv6(raw(p3[IPv6]))
del rebuilt_tcp[TCP].chksum
rebuilt_tcp = IPv6(raw(rebuilt_tcp))
assert rebuilt_tcp[TCP].chksum == orig_tcp_csum, f"TCP6 checksum mismatch"

# 4. Return /128 -> /32 (UDP)
p4 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IPv6(src="64:ff9b::cb00:7105", dst="2001:db8:1::1", hlim=64)
    / UDP(sport=5353, dport=12345)
    / Raw(b"host-eam-6to4")
)[0]
verify_udp4(p4, "203.0.113.5", "192.0.2.1", b"host-eam-6to4")

# 5. Return /120 -> /24 (UDP)
p5 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IPv6(src="64:ff9b::cb00:7109", dst="2001:db8:2::2a", hlim=64)
    / UDP(sport=8080, dport=22345)
    / Raw(b"sub120-6to4")
)[0]
verify_udp4(p5, "203.0.113.9", "198.51.100.42", b"sub120-6to4")

# 6. Return /80 -> /24 (TCP)
p6 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IPv6(src="64:ff9b::cb00:710a", dst="2001:db8:3:0:cafe:700::", hlim=64)
    / TCP(sport=443, dport=40001, flags="SA", seq=200, ack=101)
    / Raw(b"tcp6to4")
)[0]
assert IP in p6 and TCP in p6
assert p6[IP].src == "203.0.113.10"
assert p6[IP].dst == "10.10.0.7"
assert p6[IP].ttl == 63
orig_ip4_csum = p6[IP].chksum
orig_tcp4_csum = p6[TCP].chksum
rebuilt_tcp4 = IP(raw(p6[IP]))
del rebuilt_tcp4[IP].chksum
del rebuilt_tcp4[TCP].chksum
rebuilt_tcp4 = IP(raw(rebuilt_tcp4))
assert rebuilt_tcp4[IP].chksum == orig_ip4_csum
assert rebuilt_tcp4[TCP].chksum == orig_tcp4_csum

# 7. Slow fallback: unmapped IPv4 source passes through unmodified
p7 = send_and_expect(
    Ether(src=src_mac, dst=dst_mac)
    / IP(src="172.16.0.1", dst="203.0.113.5", ttl=64)
    / UDP(sport=1111, dport=2222)
    / Raw(b"fallback")
)[0]
assert IP in p7 and IPv6 not in p7
assert p7[IP].src == "172.16.0.1"
print("PASS: all 7 Scapy live cls_bpf translations & checksums verified")
PY

STATS_JSON=$("$DIR/tayga-tc-ctl" --read-stats "$PIN_DIR" --json)
python3 - "$STATS_JSON" <<'PY'
import json
import sys

st = json.loads(sys.argv[1])
assert st["fast_4to6"] == 3, f"expected fast_4to6=3, got {st}"
assert st["fast_6to4"] == 3, f"expected fast_6to4=3, got {st}"
assert st["slow_fallback"] >= 1, f"expected slow_fallback>=1, got {st}"
print(f"PASS: tc-bpf per-CPU stats verified: {st}")
PY
INNER
