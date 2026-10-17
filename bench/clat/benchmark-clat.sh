#!/bin/sh
# Reproducible static-map CLAT benchmark. It exercises LAN NAT44, the real
# clat-start.sh entrypoint and an IPv6-only upstream server.
set -eu
TAYGA_RUNTIME_DIR="${TAYGA_RUNTIME_DIR:-/run}"
TAYGA_STATUS_FILE="${TAYGA_STATUS_FILE:-$TAYGA_RUNTIME_DIR/tayga-status.json}"
export TAYGA_RUNTIME_DIR TAYGA_STATUS_FILE

DURATION=${DURATION:-60}
WARMUP=${WARMUP:-10}
FLOWS=${FLOWS:-1}
CLIENTS=${CLIENTS:-20}
WORKERS=${WORKERS:-3}
DIRECTIONS=${DIRECTIONS:-"upload download"}
PROTOCOL=${PROTOCOL:-tcp}
RATE=${RATE:-0}
DATAGRAM_SIZE=${DATAGRAM_SIZE:-1200}
BLOCK_SIZE=${BLOCK_SIZE:-}
ARTIFACT_DIR=${ARTIFACT_DIR:-/tmp/tayga-clat-results}
PERF_MODE=${PERF_MODE:-none}
PERF_SCOPE=${PERF_SCOPE:-process}
export PERF_SCOPE
MAX_UDP_LOSS_PERCENT=${MAX_UDP_LOSS_PERCENT:-0}
MAX_TUN_DROPS=${MAX_TUN_DROPS:-0}
MAX_PING_LOSS_PERCENT=${MAX_PING_LOSS_PERCENT:-0}
TUN_TXQLEN=${TUN_TXQLEN:-1000}
CLAT_OFFLOAD=${CLAT_OFFLOAD:-auto}
CLAT_STEERING=${CLAT_STEERING:-}
CLAT_OFFLINK_MTU=${CLAT_OFFLINK_MTU:-1280}
FORWARDING_GRO=${FORWARDING_GRO:-off}
PACING_TIMER_US=${PACING_TIMER_US:-1000}
FQ_RATE=${FQ_RATE:-0}
SOCKET_BUFFER_BYTES=${SOCKET_BUFFER_BYTES:-0}
SENDER_FQ=${SENDER_FQ:-off}
SENDER_FQ_FLOW_LIMIT=${SENDER_FQ_FLOW_LIMIT:-100}
SENDER_FQ_LIMIT=${SENDER_FQ_LIMIT:-10000}
VETH_QUEUES=${VETH_QUEUES:-0}
SENDER_FQ_TOPOLOGY=${SENDER_FQ_TOPOLOGY:-auto}
TAYGA_CPUSET=${TAYGA_CPUSET:-all}
CLIENT_CPUSET=${CLIENT_CPUSET:-all}
SERVER_CPUSET=${SERVER_CPUSET:-all}
SOCKET_SAMPLE_INTERVAL=${SOCKET_SAMPLE_INTERVAL:-1}
RECEIVER_DRAIN_SECONDS=${RECEIVER_DRAIN_SECONDS:-0.5}
IPERF_START_GATE=${IPERF_START_GATE:-on}
export IPERF_START_GATE
export FORWARDING_GRO PACING_TIMER_US FQ_RATE SOCKET_BUFFER_BYTES SENDER_FQ SENDER_FQ_FLOW_LIMIT SENDER_FQ_LIMIT VETH_QUEUES SENDER_FQ_TOPOLOGY TAYGA_CPUSET CLIENT_CPUSET SERVER_CPUSET SOCKET_SAMPLE_INTERVAL RECEIVER_DRAIN_SECONDS
GIT_REVISION=${GIT_REVISION:-unknown}
SOURCE_TREE_SHA256=${SOURCE_TREE_SHA256:-unknown}

case "$IPERF_START_GATE" in on|off) ;; *) echo 'IPERF_START_GATE must be on or off' >&2; exit 64;; esac
case "$PROTOCOL" in tcp|udp) ;; *) echo 'PROTOCOL must be tcp or udp' >&2; exit 64;; esac
case "$CLAT_OFFLOAD" in off|tcp|udp|auto) ;; *) echo 'CLAT_OFFLOAD must be off, tcp, udp or auto' >&2; exit 64;; esac
case "$CLAT_STEERING" in ''|kernel|groups|flows) ;; *) echo 'CLAT_STEERING must be kernel, groups or flows' >&2; exit 64;; esac
case "$PERF_SCOPE" in process|system) ;; *) echo 'PERF_SCOPE must be process or system' >&2; exit 64;; esac
case "$PERF_MODE" in none|stat|record) ;; *) echo 'PERF_MODE must be none, stat or record' >&2; exit 64;; esac
case "$FORWARDING_GRO" in off|on) ;; *) echo 'FORWARDING_GRO must be off or on' >&2; exit 64;; esac
case "$SENDER_FQ_TOPOLOGY" in auto|single|mq) ;; *) echo 'SENDER_FQ_TOPOLOGY must be auto, single or mq' >&2; exit 64;; esac
for cpuset in "$TAYGA_CPUSET" "$CLIENT_CPUSET" "$SERVER_CPUSET"; do
  [ "$cpuset" != all ] || continue
  printf '%s\n' "$cpuset" | grep -Eq '^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$' || {
    echo 'CPU sets must be all or a CPU list such as 0,2-3' >&2; exit 64;
  }
  taskset -c "$cpuset" true || { echo "CPU set unavailable: $cpuset" >&2; exit 64; }
done
# Only used for background child launches; exec preserves PID ownership for
# readiness, profiling and cleanup, including the gated client wrapper.
BENCH_LIB_DIR="${BENCH_LIB_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib}"
. "$BENCH_LIB_DIR/netns.sh"
. "$BENCH_LIB_DIR/offload.sh"
. "$BENCH_LIB_DIR/collect.sh"
. "$BENCH_LIB_DIR/iperf.sh"

case "$SENDER_FQ" in off|on) ;; *) echo 'SENDER_FQ must be off or on' >&2; exit 64;; esac
for numeric in "$PACING_TIMER_US" "$SOCKET_BUFFER_BYTES" "$SOCKET_SAMPLE_INTERVAL" "$SENDER_FQ_FLOW_LIMIT" "$SENDER_FQ_LIMIT" "$VETH_QUEUES"; do
  case "$numeric" in ''|*[!0-9]*) echo 'pacing/buffer/sampling values must be non-negative integers' >&2; exit 64;; esac
done
[ "$SENDER_FQ_FLOW_LIMIT" -gt 0 ] && [ "$SENDER_FQ_FLOW_LIMIT" -le 10000 ] || { echo 'SENDER_FQ_FLOW_LIMIT must be between 1 and 10000' >&2; exit 64; }
[ "$SENDER_FQ_LIMIT" -gt 0 ] && [ "$SENDER_FQ_LIMIT" -le 1000000 ] || { echo 'SENDER_FQ_LIMIT must be between 1 and 1000000' >&2; exit 64; }
[ "$SENDER_FQ_FLOW_LIMIT" -le "$SENDER_FQ_LIMIT" ] || { echo 'SENDER_FQ_FLOW_LIMIT cannot exceed SENDER_FQ_LIMIT' >&2; exit 64; }
[ "$VETH_QUEUES" -le 64 ] || { echo 'VETH_QUEUES must be between 0 (unchanged) and 64' >&2; exit 64; }
[ "$PACING_TIMER_US" -gt 0 ] || { echo 'PACING_TIMER_US must be positive' >&2; exit 64; }
awk -v d="$RECEIVER_DRAIN_SECONDS" 'BEGIN { exit !(d ~ /^[0-9]+([.][0-9]+)?$/ && d >= 0) }' || {
  echo 'RECEIVER_DRAIN_SECONDS must be a finite non-negative number' >&2; exit 64;
}
awk -v rate="$FQ_RATE" 'BEGIN { exit !(rate ~ /^[0-9]+([.][0-9]+)?[KMGTkmgt]?$/) }' || { echo 'invalid FQ_RATE' >&2; exit 64; }
if [ "$PROTOCOL" = udp ] && [ -n "$BLOCK_SIZE" ] && [ "$BLOCK_SIZE" != "$DATAGRAM_SIZE" ]; then
  echo 'UDP BLOCK_SIZE must equal DATAGRAM_SIZE for packet accounting' >&2; exit 64
fi
[ "$FQ_RATE" = 0 ] || [ "$SENDER_FQ" = on ] || { echo 'FQ_RATE requires SENDER_FQ=on' >&2; exit 64; }
case "$DURATION:$WARMUP" in *[!0-9:]*|:) echo 'DURATION and WARMUP must be integers' >&2; exit 64;; esac
case "$MAX_TUN_DROPS" in ''|*[!0-9]*) echo 'MAX_TUN_DROPS must be a non-negative integer' >&2; exit 64;; esac
case "$MAX_UDP_LOSS_PERCENT:$MAX_PING_LOSS_PERCENT" in
  *[!0-9.:]*|:*|*:) echo 'loss thresholds must be non-negative numbers' >&2; exit 64;;
esac
awk -v x="$MAX_UDP_LOSS_PERCENT" -v y="$MAX_PING_LOSS_PERCENT" \
  'BEGIN { exit !((x ~ /^[0-9]+([.][0-9]+)?$/) && (y ~ /^[0-9]+([.][0-9]+)?$/) && x >= 0 && y >= 0) }' || {
  echo 'loss thresholds must be finite non-negative numbers' >&2; exit 64;
}
case "$TUN_TXQLEN" in
  '') ;;
  *[!0-9]*) echo 'TUN_TXQLEN must be a non-negative integer' >&2; exit 64;;
esac
[ "$DURATION" -gt 0 ] || { echo 'DURATION must be positive' >&2; exit 64; }
mkdir -p "$ARTIFACT_DIR"

# The topology uses fixed namespace and link names. Serialize benchmark runs
# and refuse to remove namespaces that may belong to another test.
LOCK_DIR=${BENCHMARK_LOCK_DIR:-/tmp/tayga-clat-benchmark.lock}
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "another benchmark holds $LOCK_DIR" >&2
  exit 1
fi
owned_namespaces=
clat_pid=
iperf_pids=
client_pids=
release_pids=
socket_sampler_pid=
saved_rmem_max=
saved_wmem_max=
for ns in client router clatns server; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "network namespace '$ns' already exists; refusing to alter it" >&2
    cleanup
    exit 1
  fi
done
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

for ns in client router clatns server; do
  if ip netns add "$ns"; then
    owned_namespaces="$owned_namespaces $ns"
  else
    echo "failed to create namespace '$ns'" >&2
    exit 1
  fi
done

# Linux 6.12 exposes these limits read-only in child network namespaces.
# Raise the initial-namespace limits only for this serialized experiment and
# restore them on every exit; socket defaults remain unchanged.
if [ "$SOCKET_BUFFER_BYTES" -gt 0 ]; then
  saved_rmem_max=$(sysctl -n net.core.rmem_max) || exit 1
  saved_wmem_max=$(sysctl -n net.core.wmem_max) || exit 1
  printf '%s\n%s\n' "$saved_rmem_max" "$saved_wmem_max" > "$ARTIFACT_DIR/buffer-limits.original"
  for setting in rmem_max wmem_max; do
    current_limit=$(sysctl -n "net.core.$setting") || exit 1
    if [ "$SOCKET_BUFFER_BYTES" -gt "$current_limit" ]; then
      sysctl -qw "net.core.$setting=$SOCKET_BUFFER_BYTES" || exit 1
    fi
  done
fi

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

# Change both sides of each disposable pair, before traffic starts. Unsupported
# channel counts fail setup; never silently label a single-queue run multiqueue.
for veth_endpoint in client:lan0 router:rlan router:rclat clatns:veth-nat64 router:rwan server:server0; do
  veth_ns=${veth_endpoint%:*}
  veth_dev=${veth_endpoint#*:}
  ip netns exec "$veth_ns" ethtool -l "$veth_dev" > "$ARTIFACT_DIR/channels-$veth_ns-$veth_dev.before.txt"
  if [ "$VETH_QUEUES" -gt 0 ]; then
    ip netns exec "$veth_ns" ethtool -L "$veth_dev" rx "$VETH_QUEUES" tx "$VETH_QUEUES"
  fi
  ip netns exec "$veth_ns" ethtool -l "$veth_dev" > "$ARTIFACT_DIR/channels-$veth_ns-$veth_dev.after.txt"
  if [ "$VETH_QUEUES" -gt 0 ]; then
    awk -v expected="$VETH_QUEUES" '
      /Current hardware settings:/ { current=1; next }
      current && /^RX:/ { rx=$2 }
      current && /^TX:/ { tx=$2 }
      END { exit !(rx == expected && tx == expected) }
    ' "$ARTIFACT_DIR/channels-$veth_ns-$veth_dev.after.txt" || {
      echo "requested channels were not applied to $veth_ns/$veth_dev" >&2; exit 1;
    }
  fi
done

ip -n client link set lo up
ip -n client link set lan0 up
for client_no in $(seq 1 "$CLIENTS"); do
  ip -n client addr add "192.168.88.$((client_no + 1))/24" dev lan0
done
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
if [ "$FORWARDING_GRO" = on ]; then
  # Only disposable benchmark ingress links are changed. Namespace cleanup
  # removes them; no host or physical-interface features are modified.
  for ingress in router:rlan router:rwan router:rclat clatns:veth-nat64; do
    ingress_ns=${ingress%:*}
    ingress_dev=${ingress#*:}
    ip netns exec "$ingress_ns" ethtool -k "$ingress_dev" \
      > "$ARTIFACT_DIR/gro-$ingress_ns-$ingress_dev.before.txt"
    ip netns exec "$ingress_ns" ethtool -K "$ingress_dev" gro on \
      rx-udp-gro-forwarding on rx-gro-list off
    ip netns exec "$ingress_ns" ethtool -k "$ingress_dev" \
      > "$ARTIFACT_DIR/gro-$ingress_ns-$ingress_dev.after.txt"
    feature_file="$ARTIFACT_DIR/gro-$ingress_ns-$ingress_dev.after.txt"
    grep -q '^generic-receive-offload: on' "$feature_file"
    grep -q '^[[:space:]]*rx-udp-gro-forwarding: on' "$feature_file"
    grep -q '^[[:space:]]*rx-gro-list: off' "$feature_file"
  done
fi
exec_with_affinity "$TAYGA_CPUSET" ip netns exec clatns env PREF64=64:ff9b::/96 ROUTER4=172.31.64.1 \
  CLAT_WORKERS="$WORKERS" CLAT_OFFLOAD="$CLAT_OFFLOAD" \
  CLAT_OFFLINK_MTU="$CLAT_OFFLINK_MTU" ${CLAT_STEERING:+CLAT_STEERING="$CLAT_STEERING"} /usr/local/sbin/clat-start.sh \
  >"$ARTIFACT_DIR/clat.log" 2>&1 &
clat_pid=$!

ip -n server link set lo up
ip -n server link set server0 up
ip -n server -6 addr add 2600:464::2/64 dev server0
ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo
ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0
if [ "$SENDER_FQ" = on ]; then
  configure_sender_fq client lan0
  configure_sender_fq server server0
fi







for attempt in $(seq 1 20); do
  if test "$(cat "/proc/$clat_pid/comm" 2>/dev/null || true)" = tayga \
     && ip -n clatns route get 192.0.0.1 2>/dev/null | grep -q 'via 172.31.64.1' \
     && ip netns exec client ping -c 1 -W 1 11.0.0.2 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
test "$(cat "/proc/$clat_pid/comm" 2>/dev/null || true)" = tayga || {
  echo 'TAYGA did not become ready' >&2; exit 1;
}
offload_active=no
if grep -q 'TUN offload active:' "$ARTIFACT_DIR/clat.log"; then
  offload_active=yes
fi
if { test "$CLAT_OFFLOAD" = tcp || test "$CLAT_OFFLOAD" = udp; } && test "$offload_active" != yes; then
  echo "requested CLAT_OFFLOAD=tcp but TUN offload was not confirmed" >&2
  cat "$ARTIFACT_DIR/clat.log" >&2
  exit 1
fi
if test "$CLAT_OFFLOAD" = udp && ! grep -q 'experimental UDP USO' "$ARTIFACT_DIR/clat.log"; then
  echo "requested CLAT_OFFLOAD=udp but UDP USO was not confirmed" >&2
  cat "$ARTIFACT_DIR/clat.log" >&2
  exit 1
fi
if test "$CLAT_OFFLOAD" = auto && test "$offload_active" != yes \
   && ! grep -Eqi 'fallback.*offload=off|fallback to offload=off|re-opening clean tun without offload' "$ARTIFACT_DIR/clat.log"; then
  echo "CLAT_OFFLOAD=auto outcome could not be determined" >&2
  cat "$ARTIFACT_DIR/clat.log" >&2
  exit 1
fi
if test -n "$TUN_TXQLEN"; then
  ip -n clatns link set clat txqueuelen "$TUN_TXQLEN"
fi
printf '%s\n' "$clat_pid" > "$ARTIFACT_DIR/tayga.pid"
readlink "/proc/$clat_pid/exe" > "$ARTIFACT_DIR/tayga.exe"
readlink "/proc/$clat_pid/ns/net" > "$ARTIFACT_DIR/tayga.netns"
sha256sum "/proc/$clat_pid/exe" > "$ARTIFACT_DIR/tayga.sha256"
cat "/proc/$clat_pid/status" > "$ARTIFACT_DIR/tayga.status.before"
uname -a > "$ARTIFACT_DIR/kernel.txt"
cat /proc/cpuinfo > "$ARTIFACT_DIR/cpuinfo.txt"
iperf3 --version > "$ARTIFACT_DIR/iperf-version.txt" 2>&1
ip netns exec clatns cat "$TAYGA_RUNTIME_DIR/clat.conf" > "$ARTIFACT_DIR/clat.conf"
sha256sum /usr/local/sbin/clat-start.sh > "$ARTIFACT_DIR/clat-start.sha256"
ip -n clatns -j link show dev clat > "$ARTIFACT_DIR/clat.link.json"
ip netns exec clatns sh -c 'command -v ethtool >/dev/null && ethtool -k veth-nat64 || true' \
  > "$ARTIFACT_DIR/uplink-offloads.txt" 2>&1
ip netns exec clatns tc -s qdisc show dev clat > "$ARTIFACT_DIR/clat.qdisc.before" 2>&1 || true
ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,comm > "$ARTIFACT_DIR/tayga.threads.before"
ip -n clatns route show > "$ARTIFACT_DIR/clat.routes"
ip netns exec router nft list ruleset > "$ARTIFACT_DIR/router.nft"
ip -n clatns -s link show > "$ARTIFACT_DIR/clat.links.before"
ip -n clatns -j -s link show > "$ARTIFACT_DIR/clat.links.before.json"
ip -j -s link show > "$ARTIFACT_DIR/host.links.before.json"
ip -n router -j -s link show > "$ARTIFACT_DIR/router.links.before.json"
cat /proc/softirqs > "$ARTIFACT_DIR/softirqs.before"
cat /proc/net/softnet_stat > "$ARTIFACT_DIR/softnet.before"

uptime_seconds() { awk '{print $1}' /proc/uptime; }
# BusyBox date does not implement %N. Python is already a benchmark dependency.
monotonic_ns() { python3 -c 'import time; print(time.monotonic_ns())'; }






printf 'pid=%s workers=%s clients=%s flows-per-client=%s protocol=%s rate-per-flow=%s requested-total-rate=%s duration=%s warmup=%s\n' \
  "$clat_pid" "$WORKERS" "$CLIENTS" "$FLOWS" "$PROTOCOL" "${RATE:-unlimited}" "${RATE:+$((CLIENTS * FLOWS))x$RATE}" "$DURATION" "$WARMUP" \
  | tee "$ARTIFACT_DIR/session.txt"

status=0
for direction in $DIRECTIONS; do
  case "$direction" in
    upload|download|bidir) run_iperf "$direction" || { status=1; break; };;
    *) echo "unknown direction: $direction" >&2; status=1;;
  esac
done
ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,comm > "$ARTIFACT_DIR/tayga.threads.after"
cat "/proc/$clat_pid/status" > "$ARTIFACT_DIR/tayga.status.after"
ip -j -s link show > "$ARTIFACT_DIR/host.links.after.json"
ip -n router -j -s link show > "$ARTIFACT_DIR/router.links.after.json"
ip -n clatns -j -s link show > "$ARTIFACT_DIR/clat.links.after.json"
cat /proc/softirqs > "$ARTIFACT_DIR/softirqs.after"
cat /proc/net/softnet_stat > "$ARTIFACT_DIR/softnet.after"
exit "$status"
