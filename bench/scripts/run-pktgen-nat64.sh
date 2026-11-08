#!/usr/bin/env bash
# Small-packet NAT64 saturation test: kernel pktgen (IPv6/UDP) -> tayga -> sink.
# Topology (all disposable namespaces):  c6 --veth-- nt[tayga, nat64 TUN] --veth-- s4
# usage: run-pktgen-nat64.sh TAYGA_BIN [SECONDS] [PKT_SIZE] [GEN_THREADS] [WORKERS] [SOURCES]
# PORT_MIN/PORT_MAX narrow the UDP source-port range (few flows per generator thread).
# Needs root, pktgen module, nft. Prints received Mpps on the IPv4 sink and tayga CPU.
set -euo pipefail
BIN=$(readlink -f "$1"); SECS=${2:-8}; SIZE=${3:-90}; GEN=${4:-3}; WORKERS=${5:-3}; SRCS=${6:-64}
GEN_CPUS=${GEN_CPUS:-0-3}; TAYGA_CPUS=${TAYGA_CPUS:-4-7}
D=$(mktemp -d); tp=
cleanup() {
  [ -w /proc/net/pktgen/pgctrl ] && echo reset > /proc/net/pktgen/pgctrl 2>/dev/null || true
  [ -n "$tp" ] && kill "$tp" 2>/dev/null || true; sleep 0.3
  for n in c6 nt s4; do ip netns del $n 2>/dev/null || true; done; ip link del c0 2>/dev/null || true; sleep 1; rm -rf "$D"
}
trap cleanup EXIT
modprobe pktgen
ip link del c0 2>/dev/null || true
for n in c6 nt s4; do ip netns add $n; done
ip link add c0 type veth peer name n0; ip link set c0 netns c6; ip link set n0 netns nt
ip link add n1 type veth peer name s0; ip link set n1 netns nt; ip link set s0 netns s4
for p in c6:c0 nt:n0 nt:n1 s4:s0; do ip -n ${p%:*} link set ${p#*:} up; ethtool_q=$(ip netns exec ${p%:*} ethtool -L ${p#*:} rx ${VETH_Q:-4} tx ${VETH_Q:-4} 2>&1 || true); done
ip -n c6 link set lo up; ip -n nt link set lo up; ip -n s4 link set lo up
ip -n c6 -6 addr add 2001:db8:1::2/64 dev c0 nodad
ip -n c6 -6 route add default via 2001:db8:1::1
ip -n nt -6 addr add 2001:db8:1::1/64 dev n0 nodad
ip -n nt addr add 8.8.8.1/24 dev n1
ip -n s4 addr add 8.8.8.2/24 dev s0
ip -n s4 route add default via 8.8.8.1
for n in nt; do ip netns exec $n sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1; done
cat > $D/t.conf <<EOF
tun-device nat64
ipv4-addr 192.168.255.1
ipv6-addr 2001:db8:255::1
prefix 64:ff9b::/96
dynamic-pool 192.168.255.128/25
data-dir $D
workers $WORKERS
udp-cksum-mode calc
EOF
[ "${MODE:-pktgen}" = tcp ] || ip netns exec s4 nft -f - <<'EOF'
table ip t {
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    iifname "s0" counter drop
  }
}
EOF
ip netns exec nt taskset -c "$TAYGA_CPUS" "$BIN" -c $D/t.conf ${TAYGA_ARGS:-} --nodetach --stdout --status-file $D/s.json >$D/log 2>&1 &
tp=$!
for i in $(seq 40); do ip -n nt link show nat64 >/dev/null 2>&1 && break; sleep 0.25; done
kill -0 $tp 2>/dev/null || { cat $D/log >&2; echo "tayga exited" >&2; exit 1; }
ip -n nt link set nat64 up
ip -n nt addr add 192.168.255.254/32 dev nat64 2>/dev/null || true
ip -n nt route add 192.168.255.0/24 dev nat64
ip -n nt -6 route add 64:ff9b::/96 dev nat64
ip -n nt route replace 8.8.8.0/24 dev n1
sleep 1
ip netns exec c6 ping -6 -c2 -W2 64:ff9b::808:802 >$D/ping.txt 2>&1 || true; [ -n "${DEBUG:-}" ] && { cat $D/ping.txt; ip -n nt -s link show nat64 | tr "\n" " "; ip netns exec nt sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.n1.rp_filter; ip netns exec c6 ip -6 route; tail -3 $D/log; } || true   # prime dynamic mapping
if [ "${MODE:-pktgen}" = tcp ]; then
  # TCP variant: PAR parallel streams through the same topology, report goodput and retransmits.
  ip netns exec s4 iperf3 -s -1 -B 8.8.8.2 >/dev/null 2>&1 &
  sleep 1
  if [ -n "${CAPTURE:-}" ]; then
    ip netns exec nt tcpdump -i n0 -s 80 -B 65536 -w $CAPTURE.n0.pcap "ip6 and tcp and dst port 5201" >/dev/null 2>&1 &
    ip netns exec nt tcpdump -i n1 -s 80 -B 65536 -w $CAPTURE.n1.pcap "tcp and dst port 5201" >/dev/null 2>&1 &
    sleep 1
  fi
  ip netns exec c6 iperf3 -6 -c 64:ff9b::808:802 -P "${PAR:-4}" -t "$SECS" -O 2 -J > $D/iperf.json 2>$D/iperf.err || true
  echo "tun_tx_dropped=$(ip -n nt -s -j link show nat64 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["stats64"]["tx"]["dropped"])') tun_rx_dropped=$(ip -n nt -s -j link show nat64 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["stats64"]["rx"]["dropped"])') n1_tx_dropped=$(ip -n nt -s -j link show n1 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["stats64"]["tx"]["dropped"])') n0_tx_dropped=$(ip -n nt -s -j link show n0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["stats64"]["tx"]["dropped"])')"
  for h in c6 s4; do echo "$h: $(ip netns exec $h nstat -az 2>/dev/null | awk '/TcpRetransSegs|SACKReorder|TSReorder|RenoReorder|TCPDSACKRecv|TCPDSACKOldSent|TCPSpuriousRTOs|TCPLossProbes |TCPFastRetrans|TCPTimeouts|TCPSackRecovery |TCPLostRetransmit/ {printf "%s=%s ", $1, $2}')"; done
  [ -n "${CAPTURE:-}" ] && { sleep 1; pkill tcpdump || true; sleep 1; }
  cp $D/iperf.json /tmp/iperf-last.json 2>/dev/null; python3 - "$D/iperf.json" <<'P3'
import json,sys
try:
    j=json.load(open(sys.argv[1])); e=j["end"]
    r=sum(s["sender"].get("retransmits",0) for s in e["streams"])
    print("tcp_gbps=%.2f retransmits=%d"%(e["sum_received"]["bits_per_second"]/1e9,r))
except Exception as ex: print("iperf failed:",ex)
P3
  exit 0
fi
dmac=$(ip -n nt -o link show n0 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
PG=/proc/net/pktgen
pg() { echo "$2" > "$PG/$1"; }
echo reset > $PG/pgctrl
IFS=- read -r lo hi <<<"$GEN_CPUS"
# pktgen can only use devices of its own netns, so move c0 out of c6
ip -n c6 link set c0 netns 1; ip link set c0 up
ip addr add 2001:db8:1::2/64 dev c0 nodad 2>/dev/null || true
for i in $(seq 0 $((GEN-1))); do
  cpu=$((lo+i)); dev="c0@$i"
  pg kpktgend_$cpu "rem_device_all"; pg kpktgend_$cpu "add_device $dev"
done
for i in $(seq 0 $((GEN-1))); do
  cpu=$((lo+i)); dev="c0@$i"
  pg $dev "count 0"; pg $dev "pkt_size $SIZE"; pg $dev "delay 0"; pg $dev "clone_skb 0"
  pg $dev "dst_mac $dmac"; pg $dev "dst6 64:ff9b::808:802"
  pg $dev "src6 2001:db8:1::$(printf %x $((0x10+i)))"   # one source per generator thread
  pg $dev "udp_src_min ${PORT_MIN:-1024}"; pg $dev "udp_src_max ${PORT_MAX:-60000}"; pg $dev "udp_dst_min 9"; pg $dev "udp_dst_max 9"
  pg $dev "flag UDPSRC_RND"; pg $dev "flag QUEUE_MAP_CPU"
done
rx() { ip netns exec s4 cat /sys/class/net/s0/statistics/rx_packets; }
cpu_ticks() { awk '{print $14+$15}' /proc/$tp/stat; }
echo start > $PG/pgctrl & pgp=$!
sleep 2; r0=$(rx); c0t=$(cpu_ticks); sleep "$SECS"; r1=$(rx); c1t=$(cpu_ticks)
echo stop > $PG/pgctrl 2>/dev/null || true; kill $pgp 2>/dev/null || true
[ -n "${DEBUG:-}" ] && { cat $PG/c0@0 | head -30; for l in "nt n0" "nt nat64" "nt n1" "s4 s0"; do set -- $l; ip -n $1 -s link show $2 | tr "\n" " "; echo; done; tail -5 $D/log; sleep 5.5; grep -E "dropped|error|rx_packets_v6|tx_packets_v4|icmp" $D/s.json | head -20; ip -6 neigh show dev c0; } || true
sent=0; for i in $(seq 0 $((GEN-1))); do sent=$((sent + $(sed -n 's/.*pkts-sofar: \([0-9]*\).*/\1/p' $PG/c0@$i | head -1))); done
sleep 5.5   # let the exporter publish final per-worker counters
python3 - "$D/s.json" <<'P2'
import json,sys
try:
    j=json.load(open(sys.argv[1])); w=[x["rx_packets_v6"] for x in j["workers"] if x["slot"]>0 or True]
    t=sum(w) or 1
    print("worker_rx_share=%s"%[round(x/t,3) for x in w])
except Exception as e: print("no worker stats:",e)
P2
python3 - "$r0" "$r1" "$c0t" "$c1t" "$SECS" "$sent" <<'P'
import sys,os
r0,r1,c0,c1,s,sent=map(int,sys.argv[1:7]); hz=os.sysconf('SC_CLK_TCK')
print("rx_mpps=%.3f tayga_cpu=%.2f sent_total=%d"%((r1-r0)/s/1e6,(c1-c0)/hz/s,sent))
P
