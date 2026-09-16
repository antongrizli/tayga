#!/bin/sh
# Benchmark the static-map CLAT path.  Unlike the NAT64 benchmark, this
# exercises the exact map + RFC 6052 configuration used on Chateau stage 3.
set -eu

DURATION=${DURATION:-20}
FLOWS=${FLOWS:-20}
OMIT=${OMIT:-3}
DIRECTIONS=${DIRECTIONS:-"upload download"}

cleanup() {
  kill "${clat_pid:-}" "${iperf_pid:-}" 2>/dev/null || true
  for ns in client router clatns server; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM HUP

for ns in client router clatns server; do ip netns add "$ns"; done

ip link add lan0 type veth peer name rlan
ip link set lan0 netns client
ip link set rlan netns router
ip link add rclat type veth peer name ceth
ip link set rclat netns router
ip link set ceth netns clatns
ip -n clatns link set ceth name veth-nat64
ip link add rwan type veth peer name server0
ip link set rwan netns router
ip link set server0 netns server

ip -n client link set lo up
ip -n client link set lan0 up
ip -n client addr add 192.168.88.2/24 dev lan0
ip -n client route add default via 192.168.88.1

ip -n router link set lo up
ip -n router link set rlan up
ip -n router addr add 192.168.88.1/24 dev rlan
ip -n router link set rclat up
ip -n router addr add 172.31.64.1/24 dev rclat
ip -n router -6 addr add fd9b:64:1:fe::1/64 dev rclat
ip -n router link set rwan up
ip -n router -6 addr add 2600:464::1/64 dev rwan
ip netns exec router sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec router sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip -n router route add default via 172.31.64.2
ip -n router -6 route add fd9b:64:1:ff::10/128 via fd9b:64:1:fe::2 dev rclat
ip -n router -6 route add 64:ff9b::/96 via 2600:464::2 dev rwan
ip netns exec router nft -f - <<'EOF'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "rclat" ip saddr 192.168.88.0/24 snat to 192.0.0.1
  }
}
EOF

ip -n clatns link set lo up
ip -n clatns link set veth-nat64 up
ip -n clatns addr add 172.31.64.2/24 dev veth-nat64
ip -n clatns -6 addr add fd9b:64:1:fe::2/64 dev veth-nat64
ip -n clatns -6 route add default via fd9b:64:1:fe::1
ip netns exec clatns sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec clatns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec clatns env PREF64=64:ff9b::/96 ROUTER4=172.31.64.1 \
  CLAT_WORKERS=3 /usr/local/sbin/clat-start.sh >/tmp/clat-benchmark.log 2>&1 &
clat_pid=$!

ip -n server link set lo up
ip -n server link set server0 up
ip -n server -6 addr add 2600:464::2/64 dev server0
ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo
ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0
ip netns exec server iperf3 -s -6 -B 64:ff9b::b00:2 >/tmp/clat-iperf.log 2>&1 &
iperf_pid=$!

tries=0
until ip netns exec clatns pgrep -x tayga >/dev/null 2>&1 || [ "$tries" -ge 10 ]; do
  sleep 1
  tries=$((tries + 1))
done
ip netns exec clatns pgrep -x tayga >/dev/null
tayga_pid=$(ip netns exec clatns pgrep -x tayga)
threads=$(ip netns exec clatns /bin/sh -ec 'pid=$(pgrep -x tayga); find /proc/$pid/task -mindepth 1 -maxdepth 1 -type d | wc -l')
echo "CLAT_THREADS=${threads} FLOWS=${FLOWS} DURATION=${DURATION} OMIT=${OMIT}"

ticks() {
  ip netns exec clatns /bin/sh -ec "awk '{ticks += \$14 + \$15} END {print ticks + 0}' /proc/${tayga_pid}/task/*/stat"
}
uptime_seconds() { ip netns exec clatns awk '{print $1}' /proc/uptime; }

run_iperf() {
  direction=$1
  reverse=$2
  ticks_before=$(ticks)
  uptime_before=$(uptime_seconds)
  if [ "$reverse" = yes ]; then
    output=$(ip netns exec client iperf3 -c 11.0.0.2 -P "$FLOWS" -t "$DURATION" -O "$OMIT" -R -J)
  else
    output=$(ip netns exec client iperf3 -c 11.0.0.2 -P "$FLOWS" -t "$DURATION" -O "$OMIT" -J)
  fi
  ticks_after=$(ticks)
  uptime_after=$(uptime_seconds)
  printf '%s' "$output" | python3 -c '
import json, os, sys
r = json.load(sys.stdin)["end"]
sent = r["sum_sent"]["bits_per_second"] / 1_000_000
received = r["sum_received"]["bits_per_second"] / 1_000_000
elapsed = float(sys.argv[4]) - float(sys.argv[3])
cores = (int(sys.argv[2]) - int(sys.argv[1])) / os.sysconf("SC_CLK_TCK") / elapsed
print(f"RESULT direction={sys.argv[5]} sent_mbps={sent:.2f} received_mbps={received:.2f} tayga_cpu_cores={cores:.3f} tayga_core_per_gbps={cores/(received/1000):.3f}")
' "$ticks_before" "$ticks_after" "$uptime_before" "$uptime_after" "$direction"
}

for direction in $DIRECTIONS; do
  case "$direction" in
    upload) run_iperf upload no ;;
    download) run_iperf download yes ;;
    *) echo 'DIRECTIONS accepts only upload and download' >&2; exit 64 ;;
  esac
done
