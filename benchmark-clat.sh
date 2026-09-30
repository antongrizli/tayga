#!/bin/sh
# Reproducible static-map CLAT benchmark. It exercises LAN NAT44, the real
# clat-start.sh entrypoint and an IPv6-only upstream server.
set -eu

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
MAX_UDP_LOSS_PERCENT=${MAX_UDP_LOSS_PERCENT:-0}
MAX_TUN_DROPS=${MAX_TUN_DROPS:-0}
MAX_PING_LOSS_PERCENT=${MAX_PING_LOSS_PERCENT:-0}
TUN_TXQLEN=${TUN_TXQLEN:-1000}
CLAT_OFFLOAD=${CLAT_OFFLOAD:-auto}
CLAT_OFFLINK_MTU=${CLAT_OFFLINK_MTU:-1280}
FORWARDING_GRO=${FORWARDING_GRO:-off}
export FORWARDING_GRO
GIT_REVISION=${GIT_REVISION:-unknown}
SOURCE_TREE_SHA256=${SOURCE_TREE_SHA256:-unknown}

case "$PROTOCOL" in tcp|udp) ;; *) echo 'PROTOCOL must be tcp or udp' >&2; exit 64;; esac
case "$CLAT_OFFLOAD" in off|tcp|udp|auto) ;; *) echo 'CLAT_OFFLOAD must be off, tcp, udp or auto' >&2; exit 64;; esac
case "$PERF_MODE" in none|stat|record) ;; *) echo 'PERF_MODE must be none, stat or record' >&2; exit 64;; esac
case "$FORWARDING_GRO" in off|on) ;; *) echo 'FORWARDING_GRO must be off or on' >&2; exit 64;; esac
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
cleanup() {
  test -n "$clat_pid" && kill "$clat_pid" 2>/dev/null || true
  for iperf_pid in $iperf_pids; do kill "$iperf_pid" 2>/dev/null || true; done
  for client_pid in $client_pids; do kill "$client_pid" 2>/dev/null || true; done
  for release_pid in $release_pids; do kill "$release_pid" 2>/dev/null || true; done
  for owned_ns in $owned_namespaces; do ip netns del "$owned_ns" 2>/dev/null || true; done
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
clat_pid=
iperf_pids=
client_pids=
release_pids=
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
ip netns exec clatns env PREF64=64:ff9b::/96 ROUTER4=172.31.64.1 \
  CLAT_WORKERS="$WORKERS" CLAT_OFFLOAD="$CLAT_OFFLOAD" \
  CLAT_OFFLINK_MTU="$CLAT_OFFLINK_MTU" /usr/local/sbin/clat-start.sh \
  >"$ARTIFACT_DIR/clat.log" 2>&1 &
clat_pid=$!

ip -n server link set lo up
ip -n server link set server0 up
ip -n server -6 addr add 2600:464::2/64 dev server0
ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo
ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0
cleanup_iperf_servers() {
  for old_iperf_pid in $iperf_pids; do
    kill "$old_iperf_pid" 2>/dev/null || true
  done
  for old_iperf_pid in $iperf_pids; do
    wait "$old_iperf_pid" 2>/dev/null || true
  done
  iperf_pids=
}

start_iperf_servers() {
  cleanup_iperf_servers
  for client_no in $(seq 1 "$CLIENTS"); do
    ip netns exec server iperf3 -s -6 -B 64:ff9b::b00:2 -p "$((5200 + client_no))" \
      >"$ARTIFACT_DIR/iperf-server-$client_no.log" 2>&1 &
    iperf_pids="$iperf_pids $!"
  done
  # iperf3 binds each port asynchronously. Wait for every listener instead of
  # relying on a fixed sleep, which can race under VM CPU contention.
  for readiness_attempt in $(seq 1 50); do
    ready_servers=0
    for client_no in $(seq 1 "$CLIENTS"); do
      port=$((5200 + client_no))
      if ip netns exec server ss -H -l -t -n -6 2>/dev/null | \
              awk -v port="$port" '$4 ~ (":" port "$" ) { found=1 } END { exit(found ? 0 : 1) }'; then
        ready_servers=$((ready_servers + 1))
      fi
    done
    test "$ready_servers" -eq "$CLIENTS" && return 0
    sleep 0.1
  done
  echo "iperf3 servers did not all become ready" >&2
  return 1
}

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
ip netns exec clatns cat /run/clat.conf > "$ARTIFACT_DIR/clat.conf"
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

ticks() {
  awk '{ticks += $14 + $15} END {print ticks + 0}' /proc/"$clat_pid"/task/*/stat
}
uptime_seconds() { awk '{print $1}' /proc/uptime; }
# BusyBox date does not implement %N. Python is already a benchmark dependency.
monotonic_ns() { python3 -c 'import time; print(time.monotonic_ns())'; }

start_clients() {
  local run_dir=$1
  local direction=$2
  local duration=$3
  local gated=$4
  : > "$run_dir/pids"
  : > "$run_dir/gates"
  local client_no client_addr gate
  for client_no in $(seq 1 "$CLIENTS"); do
    client_addr="192.168.88.$((client_no + 1))"
    set -- -c 11.0.0.2 -p "$((5200 + client_no))" -B "$client_addr" -P "$FLOWS" -t "$duration" --connect-timeout 5000 -J
    test "$direction" = download && set -- "$@" -R
    test "$direction" = bidir && set -- "$@" --bidir
    test "$PROTOCOL" = udp && set -- "$@" -u -l "$DATAGRAM_SIZE"
    test -n "$BLOCK_SIZE" && set -- "$@" -l "$BLOCK_SIZE"
    test -n "$RATE" && set -- "$@" -b "$RATE"
    if test "$gated" = yes; then
      gate="$run_dir/gate-$client_no"
      rm -f "$gate"
      mkfifo "$gate"
      printf '%s\n' "$gate" >> "$run_dir/gates"
      ip netns exec client sh -c 'read -r _ < "$1"; shift; exec "$@"' sh "$gate" iperf3 "$@" \
        >"$run_dir/client-$client_no.json" 2>"$run_dir/client-$client_no.stderr" &
    else
      ip netns exec client iperf3 "$@" >"$run_dir/client-$client_no.json" \
        2>"$run_dir/client-$client_no.stderr" &
    fi
    printf '%s\n' "$!" >> "$run_dir/pids"
    client_pids="$client_pids $!"
  done
}

wait_clients() {
  local run_dir=$1
  local timeout_limit=${2:-$((DURATION + 15))}
  local deadline=$(( $(uptime_seconds | cut -d. -f1) + timeout_limit ))
  local running=1
  while [ "$running" -gt 0 ] && [ "$(uptime_seconds | cut -d. -f1)" -lt "$deadline" ]; do
    running=0
    while read -r child_pid; do
      if kill -0 "$child_pid" 2>/dev/null; then
        running=$((running + 1))
      fi
    done < "$run_dir/pids"
    [ "$running" -gt 0 ] && sleep 0.5
  done

  if [ "$running" -gt 0 ]; then
    echo "Clients timed out after ${timeout_limit}s! Capturing diagnostic state..." >&2
    printf '%s\n' "timed_out" > "$run_dir/timeout.marker"
    ip -n clatns -s link show > "$run_dir/clat.timeout.links" 2>&1 || true
    ip -n clatns tc -s qdisc show dev clat > "$run_dir/clat.timeout.qdisc" 2>&1 || true
    cat /proc/"$clat_pid"/status > "$run_dir/clat.timeout.status" 2>&1 || true
    ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,stat,wchan:20,comm > "$run_dir/clat.timeout.threads" 2>&1 || true
    ps aux > "$run_dir/system.timeout.ps" 2>&1 || true
    ip netns exec client ss -tuna > "$run_dir/client.timeout.sockets" 2>&1 || true
    while read -r child_pid; do
      if [ -d "/proc/$child_pid" ]; then
        cat "/proc/$child_pid/wchan" > "$run_dir/client-$child_pid.wchan" 2>/dev/null || true
        cat "/proc/$child_pid/status" > "$run_dir/client-$child_pid.status" 2>/dev/null || true
      fi
    done < "$run_dir/pids"
    # Graceful TERM first
    while read -r child_pid; do
      kill -TERM "$child_pid" 2>/dev/null || true
    done < "$run_dir/pids"
    sleep 1
    # Force KILL and REAP every child
    while read -r child_pid; do
      kill -9 "$child_pid" 2>/dev/null || true
      wait "$child_pid" 2>/dev/null || true
    done < "$run_dir/pids"
    return 1
  fi

  local status=0 child_pid
  while read -r child_pid; do wait "$child_pid" || status=1; done < "$run_dir/pids"
  return "$status"
}

run_warmup() {
  local warmup_dir
  test "$WARMUP" -gt 0 || return 0
  warmup_dir="$ARTIFACT_DIR/warmup-$1"
  mkdir -p "$warmup_dir"
  start_iperf_servers || { echo "warmup server startup failed for $1" >&2; return 1; }
  start_clients "$warmup_dir" "$1" "$WARMUP" no
  local w_status=0
  wait_clients "$warmup_dir" "$((WARMUP + 15))" || w_status=$?
  client_pids=
  cleanup_iperf_servers
  if [ "$w_status" -ne 0 ]; then
    echo "warmup failed for $1 (status $w_status)" >&2
    printf '%s\n' "warmup_failed" > "$warmup_dir/failed.marker"
    return 1
  fi
  return 0
}

run_iperf() {
  local direction=$1
  local run_dir="$ARTIFACT_DIR/$direction"
  mkdir -p "$run_dir"
  if ! run_warmup "$direction"; then
    echo "Warmup failed for $direction; marking run as degraded" >&2
    printf '%s\n' "warmup_failed" > "$run_dir/warmup-failed.marker"
  fi
  start_iperf_servers || return 1
  start_clients "$run_dir" "$direction" "$DURATION" yes
  # Give every wrapper time to block on its FIFO before a common release.
  sleep 1
  ticks_before=$(ticks)
  uptime_before=$(uptime_seconds)
  monotonic_before=$(monotonic_ns)
  ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,stat,comm > "$run_dir/tayga.threads.before"
  cat "/proc/$clat_pid/status" > "$run_dir/tayga.status.before"
  if test "$offload_active" = yes; then
    kill -USR2 "$clat_pid"
    sleep 0.1
    grep 'GSO Stats:' "$ARTIFACT_DIR/clat.log" | tail -n 1 > "$run_dir/gso-stats.before" || true
  fi
  ip -n clatns -s link show > "$run_dir/clat.links.before"
  ip -n clatns -j -s link show > "$run_dir/clat.links.before.json"
  ip netns exec clatns tc -s qdisc show dev clat > "$run_dir/clat.qdisc.before" 2>&1 || true
  ip -n router -j -s link show > "$run_dir/router.links.before.json"
  cat /proc/softirqs > "$run_dir/softirqs.before"
  cat /proc/net/softnet_stat > "$run_dir/softnet.before"
  cat /proc/stat > "$run_dir/proc_stat.before"
  local perf_pid=
  local perf_status=0
  if test "$PERF_MODE" != none && command -v perf >/dev/null 2>&1; then
    perf --version > "$run_dir/perf-version.txt" 2>&1 || true
    if test "$PERF_MODE" = stat; then
      perf stat -x ';' -o "$run_dir/perf-stat.csv" \
        -e task-clock,context-switches,cpu-migrations,page-faults,raw_syscalls:sys_enter,syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_writev \
        -p "$clat_pid" -- sleep "$DURATION" \
        >"$run_dir/perf-stat.stdout" 2>"$run_dir/perf-stat.stderr" &
    else
      perf record -o "$run_dir/perf.data" -e cpu-clock -F 99 --call-graph fp -p "$clat_pid" -- sleep "$DURATION" \
        >"$run_dir/perf-record.stdout" 2>"$run_dir/perf-record.stderr" &
    fi
    perf_pid=$!
  elif test "$PERF_MODE" != none; then
    printf '%s\n' 'perf is unavailable in this runtime' > "$run_dir/perf-unavailable.txt"
  fi
  local ping_pid=
  ip netns exec client ping -c "$((DURATION * 5))" -i 0.2 -W 1 11.0.0.2 > "$run_dir/ping.txt" 2>&1 &
  ping_pid=$!
  release_pids=
  while read -r gate; do printf 'go\n' > "$gate" & release_pids="$release_pids $!"; done < "$run_dir/gates"
  for release_pid in $release_pids; do wait "$release_pid" || true; done
  release_pids=
  if wait_clients "$run_dir"; then status=0; else status=$?; fi
  client_pids=
  cleanup_iperf_servers
  if test -n "$ping_pid"; then
    wait "$ping_pid" || true
  fi
  if test -n "$perf_pid"; then
    wait "$perf_pid" || perf_status=$?
    printf '%s\n' "$perf_status" > "$run_dir/perf-exit-status"
    if test "$perf_status" -ne 0; then
      printf 'perf %s failed with exit status %s\n' "$PERF_MODE" "$perf_status" > "$run_dir/perf-failed.txt"
    fi
  fi
  ticks_after=$(ticks)
  uptime_after=$(uptime_seconds)
  monotonic_after=$(monotonic_ns)
  printf '%s\n%s\n' "$monotonic_before" "$monotonic_after" > "$run_dir/measurement.monotonic-ns"
  ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,stat,comm > "$run_dir/tayga.threads.after"
  cat "/proc/$clat_pid/status" > "$run_dir/tayga.status.after"
  if test "$offload_active" = yes; then
    kill -USR2 "$clat_pid"
    sleep 0.1
    grep 'GSO Stats:' "$ARTIFACT_DIR/clat.log" | tail -n 1 > "$run_dir/gso-stats.after" || true
  fi
  ip -n clatns -s link show > "$run_dir/clat.links.after"
  ip -n clatns -j -s link show > "$run_dir/clat.links.after.json"
  ip netns exec clatns tc -s qdisc show dev clat > "$run_dir/clat.qdisc.after" 2>&1 || true
  ip -n router -j -s link show > "$run_dir/router.links.after.json"
  cat /proc/softirqs > "$run_dir/softirqs.after"
  cat /proc/net/softnet_stat > "$run_dir/softnet.after"
  cat /proc/stat > "$run_dir/proc_stat.after"
  printf '%s\n' "$status" > "$run_dir/exit-status"
  python3 - "$run_dir" "$direction" "$ticks_before" "$ticks_after" "$uptime_before" "$uptime_after" "$monotonic_before" "$monotonic_after" "$PROTOCOL" "$MAX_UDP_LOSS_PERCENT" "$MAX_TUN_DROPS" "$MAX_PING_LOSS_PERCENT" "$CLAT_OFFLOAD" "$offload_active" "$TUN_TXQLEN" "$GIT_REVISION" "$SOURCE_TREE_SHA256" "$WORKERS" "$FLOWS" "$RATE" "$DURATION" "$WARMUP" "$DATAGRAM_SIZE" "$BLOCK_SIZE" "$CLAT_OFFLINK_MTU" <<'PY'
import glob, json, os, re, sys
run_dir, direction, before, after, up_before, up_after, mono_before, mono_after, protocol, max_udp_loss, max_tun_drops, max_ping_loss, offload_requested, offload_active, txqlen, revision, source_tree_sha256, workers, flows, rate, duration, warmup, datagram_size, block_size, offlink_mtu = sys.argv[1:]
reports = []
capture_errors = []
workload_errors = []
def udp_packet_accounting(sent, received, payload_size):
    """iperf3 packets is the receiver's expected sequence count, not receipts."""
    expected = received["packets"]
    lost = received["lost_packets"]
    byte_count = received["bytes"]
    size = int(payload_size)
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 0
           for v in (expected, lost, byte_count)) or lost > expected or size <= 0:
        raise ValueError("invalid UDP packet/byte counters")
    if byte_count % size:
        raise ValueError("UDP received bytes do not contain whole fixed-size datagrams")
    return dict(packets=byte_count // size, receiver_expected_packets=expected,
                lost_packets=lost, sent_packets=sent.get("packets"))

for path in sorted(glob.glob(os.path.join(run_dir, "client-*.json"))):
    try:
        with open(path) as f:
            doc = json.load(f)
        if doc.get("error"):
            raise ValueError(doc["error"])
        end = doc.get("end")
        if not end:
            raise ValueError("missing 'end' section in iperf report")
        sent = end.get("sum_sent", {})
        received = end.get("sum_received", {})
        required = ("bits_per_second", "bytes", "seconds")
        if any(key not in received for key in required):
            raise ValueError("receiver summary is missing throughput/byte/duration fields")
        report = dict(sent_bps=sent.get("bits_per_second"), received_bps=received["bits_per_second"],
                      sent_bytes=sent.get("bytes"), received_bytes=received["bytes"],
                      sent_packets=sent.get("packets"), retransmits=sent.get("retransmits", 0),
                      seconds=received["seconds"])
        if protocol == "udp":
            if "packets" not in received or "lost_packets" not in received:
                raise ValueError("UDP receiver summary is missing packet/loss counters")
            report.update(udp_packet_accounting(sent, received, datagram_size))
            stream_ooo = [s.get("udp", {}).get("out_of_order") for s in end.get("streams", [])]
            report.update(
                          lost_percent=received.get("lost_percent"),
                          jitter_ms=received.get("jitter_ms"),
                          out_of_order=(sum(stream_ooo) if stream_ooo and all(v is not None for v in stream_ooo) else None))
        reports.append(report)
    except Exception as exc:
        print(f"ERROR direction={direction} file={os.path.basename(path)} reason={exc}", file=sys.stderr)
        workload_errors.append(f"client report {os.path.basename(path)} error: {exc}")

if not reports:
    workload_errors.append("no valid iperf client reports found")
if str(revision).strip().lower() in ("", "unknown", "n/a"):
    capture_errors.append("source Git revision is unknown")
if str(source_tree_sha256).strip().lower() in ("", "unknown", "n/a"):
    capture_errors.append("source snapshot hash is unknown")

elapsed = (int(mono_after) - int(mono_before)) / 1_000_000_000
if elapsed <= 0:
    elapsed = float(up_after) - float(up_before)
elapsed = max(elapsed, 0.001)

cores = (int(after) - int(before)) / os.sysconf("SC_CLK_TCK") / elapsed
sent = sum(x["sent_bps"] for x in reports) / 1_000_000 if reports else 0.0
received = sum(x["received_bps"] for x in reports) / 1_000_000 if reports else 0.0
retransmits = sum(x["retransmits"] for x in reports) if reports else 0
received_bytes = sum(x["received_bytes"] for x in reports) if reports else 0

def counters(path, ifname):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            links = json.load(f)
        for link in links:
            if link.get("ifname") == ifname:
                stats = link.get("stats64", link.get("stats", {}))
                return {side: {field: (int(stats[side][field]) if field in stats.get(side, {}) else None)
                               for field in ("bytes", "packets", "errors", "dropped")}
                        for side in ("rx", "tx")}
    except Exception as exc:
        capture_errors.append(f"failed reading {ifname} stats from {os.path.basename(path)}: {exc}")
    return None

def delta(before_path, after_path, ifname):
    before_stats, after_stats = counters(before_path, ifname), counters(after_path, ifname)
    if before_stats is None or after_stats is None:
        capture_errors.append(f"missing {ifname} interface counters in benchmark window")
        return None
    if any(before_stats[side][field] is None or after_stats[side][field] is None
           for side in before_stats for field in before_stats[side]):
        capture_errors.append(f"incomplete {ifname} interface counters in benchmark window")
        return None
    result = {side: {field: after_stats[side][field] - before_stats[side][field]
                   for field in before_stats[side]}
            for side in before_stats}
    if any(value < 0 for side in result.values() for value in side.values()):
        capture_errors.append(f"{ifname} interface counters decreased or reset during measurement")
        return None
    return result

router_delta = delta(os.path.join(run_dir, "router.links.before.json"),
                     os.path.join(run_dir, "router.links.after.json"), "rclat")
clat_delta = delta(os.path.join(run_dir, "clat.links.before.json"),
                   os.path.join(run_dir, "clat.links.after.json"), "clat")
router_packets = (router_delta["rx"]["packets"] + router_delta["tx"]["packets"]) if router_delta else None
tun_drops = (clat_delta["rx"]["dropped"] + clat_delta["tx"]["dropped"]) if clat_delta else None
tun_total_tx = (clat_delta["tx"]["packets"] + clat_delta["tx"]["dropped"]) if clat_delta else None
tun_tx_drop_pct = (100.0 * clat_delta["tx"]["dropped"] / tun_total_tx
                   if clat_delta and tun_total_tx else None)

sys_busy_cores = None
sys_softirq_cores = None
stat_before_path = os.path.join(run_dir, "proc_stat.before")
stat_after_path = os.path.join(run_dir, "proc_stat.after")
if os.path.exists(stat_before_path) and os.path.exists(stat_after_path):
    try:
        def read_cpu_line(path):
            for l in open(path):
                if l.startswith("cpu "):
                    return [int(x) for x in l.split()[1:]]
            return None
        c_b = read_cpu_line(stat_before_path)
        c_a = read_cpu_line(stat_after_path)
        if c_b and c_a:
            total_delta = sum(c_a) - sum(c_b)
            idle_delta = (c_a[3] + c_a[4]) - (c_b[3] + c_b[4])
            softirq_delta = c_a[6] - c_b[6]
            busy_delta = total_delta - idle_delta
            clk_tck = os.sysconf("SC_CLK_TCK")
            sys_busy_cores = busy_delta / clk_tck / elapsed
            sys_softirq_cores = softirq_delta / clk_tck / elapsed
    except Exception:
        pass

perf_stat_metrics = {}
perf_csv_path = os.path.join(run_dir, "perf-stat.csv")
if os.path.exists(perf_csv_path):
    try:
        for line in open(perf_csv_path):
            parts = [p.strip() for p in line.split(";")]
            if len(parts) >= 3 and parts[0] != "<not counted>":
                try:
                    val = float(parts[0].replace(",", ""))
                    event = parts[2]
                    perf_stat_metrics[event] = val
                except ValueError:
                    pass
    except Exception:
        pass

expected_clients = int(os.environ.get("CLIENTS", len(reports) or 1))
if len(reports) != expected_clients:
    workload_errors.append(f"received {len(reports)} client reports; expected {expected_clients}")
client_status_path = os.path.join(run_dir, "exit-status")
client_status = open(client_status_path).read().strip() if os.path.exists(client_status_path) else "missing"
if client_status != "0":
    workload_errors.append(f"client workload exit status is {client_status}")
if os.path.exists(os.path.join(run_dir, "warmup-failed.marker")):
    workload_errors.append("warmup failed")
if os.path.exists(os.path.join(run_dir, "timeout.marker")):
    workload_errors.append("one or more clients timed out")
perf_mode = os.environ.get("PERF_MODE", "none")
perf_status_path = os.path.join(run_dir, "perf-exit-status")
perf_status = open(perf_status_path).read().strip() if os.path.exists(perf_status_path) else "missing"
if perf_mode != "none" and perf_status != "0":
    capture_errors.append(f"perf {perf_mode} exit status is {perf_status}")
if perf_mode != "none" and not os.path.exists(os.path.join(run_dir, "perf-stat.csv" if perf_mode == "stat" else "perf.data")):
    capture_errors.append(f"perf {perf_mode} output is missing")
offload_log_path = os.path.join(os.path.dirname(run_dir), "clat.log")
offload_log = open(offload_log_path).read().lower() if os.path.exists(offload_log_path) else ""
offload_fell_back = any(marker in offload_log for marker in ("fallback", "without offload"))
effective_offload = ("udp" if offload_requested == "udp" and "experimental udp uso" in offload_log else
                     "tcp" if offload_active == "yes" else
                     "off" if offload_requested == "off" or offload_fell_back else "unknown")
if effective_offload == "unknown":
    capture_errors.append("effective TUN offload mode could not be determined")

def parse_gso_stats(name):
    path = os.path.join(run_dir, name)
    if not os.path.exists(path):
        return None
    line = open(path).read().strip()
    return {key: int(value) for key, value in re.findall(r"([a-z_]+)=(\d+)", line)}

gso_before = parse_gso_stats("gso-stats.before")
gso_after = parse_gso_stats("gso-stats.after")
gso_delta = ({key: gso_after[key] - gso_before.get(key, 0) for key in gso_after}
             if gso_before is not None and gso_after is not None else None)
if (effective_offload == "tcp" and protocol == "tcp" and
        (not gso_delta or gso_delta.get("rx_pkts", 0) + gso_delta.get("tx_pkts", 0) <= 0)):
    capture_errors.append("TUN offload active but no GSO packets were observed")
udp_aggregate_count = ((gso_delta or {}).get("udp_rx_aggregates", 0) +
                       (gso_delta or {}).get("udp_tx_aggregates", 0))

result = dict(direction=direction, clients=len(reports), expected_clients=expected_clients,
              capture_valid=not capture_errors, workload_valid=True, acceptance_pass=True,
              schema_version=3,
              degraded_reasons=list(capture_errors),
              perf_mode=perf_mode,
              git_revision=revision,
              source_tree_sha256=source_tree_sha256,
              tayga_sha256=open(os.path.join(os.path.dirname(run_dir), "tayga.sha256")).read().split()[0]
                  if os.path.exists(os.path.join(os.path.dirname(run_dir), "tayga.sha256")) else "unknown",
              clat_start_sha256=open(os.path.join(os.path.dirname(run_dir), "clat-start.sha256")).read().split()[0]
                  if os.path.exists(os.path.join(os.path.dirname(run_dir), "clat-start.sha256")) else "unknown",
              kernel=open(os.path.join(os.path.dirname(run_dir), "kernel.txt")).read().strip()
                  if os.path.exists(os.path.join(os.path.dirname(run_dir), "kernel.txt")) else "unknown",
              offload_requested=offload_requested,
              offload_effective=effective_offload,
              gso_stats_before=gso_before, gso_stats_after=gso_after, gso_stats_delta=gso_delta,
              udp_gso_input_aggregates=(gso_delta or {}).get("udp_rx_aggregates") if gso_delta else None,
              udp_gso_output_aggregates=(gso_delta or {}).get("udp_tx_aggregates") if gso_delta else None,
              udp_gso_software_fallbacks=(gso_delta or {}).get("udp_sw_fallbacks") if gso_delta else None,
              udp_gso_software_segments=(gso_delta or {}).get("udp_sw_segments") if gso_delta else None,
              udp_gso_aggregate_path_observed=(udp_aggregate_count > 0),
              workers=int(workers), flows_per_client=int(flows), tun_txqlen=(int(txqlen) if txqlen else None),
              offlink_mtu=int(offlink_mtu),
              forwarding_gro=os.environ.get("FORWARDING_GRO", "off"),
              rate_per_flow=(rate or "unlimited"), duration_seconds=int(duration), warmup_seconds=int(warmup),
              datagram_size=int(datagram_size) if protocol == "udp" else None,
              block_size=(block_size or None),
              sent_mbps=sent, received_mbps=received,
              client_duration_seconds_min=(min(x["seconds"] for x in reports) if reports else None),
              client_duration_seconds_max=(max(x["seconds"] for x in reports) if reports else None),
              client_duration_seconds_median=(sorted(x["seconds"] for x in reports)[len(reports)//2] if reports else None),
              retransmits=retransmits, tayga_cpu_cores=cores,
              tayga_core_per_gbps=cores / (received / 1000) if received else None,
              system_busy_cores=sys_busy_cores,
              system_softirq_cores=sys_softirq_cores,
              perf_stat_metrics=perf_stat_metrics,
              received_application_MBps=received_bytes / elapsed / 1_000_000,
              received_udp_packets_per_second=None,
              router_interface_packets_per_second=(router_packets / elapsed if router_packets is not None else None),
              router_rclat_delta=router_delta, clat_tun_delta=clat_delta, tun_drops=tun_drops,
              tun_tx_drop_percent=tun_tx_drop_pct,
              retransmits_per_gbyte=(retransmits / (received_bytes / 1_000_000_000) if received_bytes else None),
              elapsed_s=elapsed, workload_protocol=protocol,
              measurement_window=dict(monotonic_start_ns=int(mono_before), monotonic_end_ns=int(mono_after),
                                     elapsed_seconds=elapsed, intended_duration_seconds=int(duration)))

if protocol == "udp":
    packets = sum(x.get("packets", 0) for x in reports)
    lost = sum(x.get("lost_packets", 0) for x in reports)
    receiver_expected = sum(x["receiver_expected_packets"] for x in reports)
    sender_packets = [x.get("sent_packets") for x in reports]
    total_sent = sum(sender_packets) if sender_packets and all(p is not None for p in sender_packets) else None
    loss_pct = (100.0 * lost / receiver_expected) if receiver_expected > 0 else None
    if receiver_expected <= 0:
        workload_errors.append("UDP receiver reported no datagrams; loss rate is undefined")
    jitter_samples = [x["jitter_ms"] for x in reports if x.get("jitter_ms") is not None]
    jitter_max = max(jitter_samples, default=None)
    ooo_counts = [x.get("out_of_order") for x in reports]
    ooo = sum(ooo_counts) if ooo_counts and all(v is not None for v in ooo_counts) else None
    result.update(udp_received_packets=packets, udp_lost_packets=lost,
                  udp_accounting_version=2,
                  udp_counter_definitions=dict(received="receiver bytes divided by configured fixed datagram size",
                                               receiver_expected="iperf receiver highest-sequence packet count; includes lost packets",
                                               sent="iperf sender packet count, independently reported"),
                  udp_sent_packets=total_sent,
                  udp_receiver_expected_packets=receiver_expected,
                  received_udp_packets_per_second=sum(x.get("packets", 0) / max(x.get("seconds", 0), 0.001) for x in reports),
                  udp_loss_percent=loss_pct,
                  udp_jitter_ms_max=jitter_max,
                  udp_out_of_order=ooo)
    if loss_pct is not None and loss_pct > float(max_udp_loss):
        result["acceptance_pass"] = False
        result["degraded_reasons"].append(f"UDP loss {loss_pct:.3f}% exceeds {max_udp_loss}% threshold")

ping_file = os.path.join(run_dir, "ping.txt")
if not os.path.exists(ping_file):
    capture_errors.append("ping output is missing")
if os.path.exists(ping_file):
    try:
        ping_rtts = []
        ping_transmitted = None
        ping_received = None
        ping_loss_percent = None
        for line in open(ping_file):
            if "packets transmitted" in line:
                m = re.search(r"(\d+)\s+(?:packets\s+)?transmitted,\s+(\d+)\s+(?:packets\s+)?received.*?(?:([0-9.]+)%\s+packet loss)?", line)
                if m:
                    ping_transmitted = int(m.group(1))
                    ping_received = int(m.group(2))
                    if m.group(3) is not None:
                        ping_loss_percent = float(m.group(3))
                    elif ping_transmitted > 0:
                        ping_loss_percent = 100.0 * (ping_transmitted - ping_received) / ping_transmitted
            if "rtt min/avg/max/mdev" in line:
                parts = line.split("=")[1].strip().split()[0].split("/")
                result.update(ping_min_ms=float(parts[0]), ping_avg_ms=float(parts[1]),
                              ping_max_ms=float(parts[2]), ping_mdev_ms=float(parts[3]))
            match = re.search(r"time[=<]([0-9.]+)\s*ms", line)
            if match:
                ping_rtts.append(float(match.group(1)))
        if ping_loss_percent is not None:
            result.update(ping_transmitted=ping_transmitted,
                          ping_received=ping_received,
                          ping_loss_percent=ping_loss_percent)
            if ping_loss_percent > float(max_ping_loss):
                result["acceptance_pass"] = False
                result["degraded_reasons"].append(f"ping loss {ping_loss_percent:.1f}% exceeds {max_ping_loss}% threshold")
        if ping_rtts:
            ping_rtts.sort()
            def percentile(values, p):
                return values[min(len(values) - 1, max(0, int((len(values) - 1) * p + 0.5)))]
            result.update(ping_samples=len(ping_rtts),
                          ping_p50_ms=percentile(ping_rtts, 0.50),
                          ping_p95_ms=percentile(ping_rtts, 0.95),
                          ping_p99_ms=percentile(ping_rtts, 0.99))
    except Exception as exc:
        capture_errors.append(f"failed parsing ping.txt: {exc}")

if tun_drops is not None and tun_drops > int(max_tun_drops):
    result["acceptance_pass"] = False
    result["degraded_reasons"].append(f"TUN drops {tun_drops} exceeds {max_tun_drops} threshold")
if capture_errors:
    result["capture_valid"] = False
    result["acceptance_pass"] = False
    for err in capture_errors:
        if err not in result["degraded_reasons"]:
            result["degraded_reasons"].append(err)
if workload_errors:
    result["workload_valid"] = False
    result["acceptance_pass"] = False
    for err in workload_errors:
        if err not in result["degraded_reasons"]:
            result["degraded_reasons"].append(err)
with open(os.path.join(run_dir, "result.json"), "w") as out:
    json.dump(result, out, indent=2, sort_keys=True)
print("RESULT " + " ".join(f"{key}={value:.3f}" if isinstance(value, float) else f"{key}={value}" for key, value in result.items()))
PY
}

printf 'pid=%s workers=%s clients=%s flows-per-client=%s protocol=%s rate-per-flow=%s requested-total-rate=%s duration=%s warmup=%s\n' \
  "$clat_pid" "$WORKERS" "$CLIENTS" "$FLOWS" "$PROTOCOL" "${RATE:-unlimited}" "${RATE:+$((CLIENTS * FLOWS))x$RATE}" "$DURATION" "$WARMUP" \
  | tee "$ARTIFACT_DIR/session.txt"

status=0
for direction in $DIRECTIONS; do
  case "$direction" in
    upload|download|bidir) run_iperf "$direction" || status=1;;
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
