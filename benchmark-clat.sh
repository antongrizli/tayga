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
PERF_SCOPE=${PERF_SCOPE:-process}
export PERF_SCOPE
MAX_UDP_LOSS_PERCENT=${MAX_UDP_LOSS_PERCENT:-0}
MAX_TUN_DROPS=${MAX_TUN_DROPS:-0}
MAX_PING_LOSS_PERCENT=${MAX_PING_LOSS_PERCENT:-0}
TUN_TXQLEN=${TUN_TXQLEN:-1000}
CLAT_OFFLOAD=${CLAT_OFFLOAD:-auto}
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
exec_with_affinity() {
  local child_cpuset=$1
  shift
  if [ "$child_cpuset" = all ]; then exec "$@"; else exec taskset -c "$child_cpuset" "$@"; fi
}

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
cleanup() {
  test -n "$socket_sampler_pid" && kill "$socket_sampler_pid" 2>/dev/null || true
  test -n "$clat_pid" && kill "$clat_pid" 2>/dev/null || true
  for iperf_pid in $iperf_pids; do kill "$iperf_pid" 2>/dev/null || true; done
  for client_pid in $client_pids; do kill "$client_pid" 2>/dev/null || true; done
  for release_pid in $release_pids; do kill "$release_pid" 2>/dev/null || true; done
  # Reap owned children before releasing namespaces/locks or starting the next
  # allocator/throughput arm. A slow shutdown must not overlap that next arm.
  python3 - $clat_pid $iperf_pids $client_pids $release_pids $socket_sampler_pid <<'PY'
import os, signal, sys, time
from pathlib import Path
parent = os.getppid()
def identity(pid):
    try:
        fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        return (int(fields[1]), int(fields[19]), fields[0])
    except (OSError, ValueError, IndexError):
        return None
owned = {}
for pid in map(int, sys.argv[1:]):
    state = identity(pid)
    if state and state[0] == parent:
        owned[pid] = state[:2]
deadline = time.monotonic() + 3
while owned:
    owned = {pid: start for pid, start in owned.items()
             if (state := identity(pid)) and state[:2] == start and state[2] != 'Z'}
    if time.monotonic() >= deadline:
        for pid in owned:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        break
    if owned: time.sleep(.025)
PY
  for owned_pid in $clat_pid $iperf_pids $client_pids $release_pids $socket_sampler_pid; do
    wait "$owned_pid" 2>/dev/null || true
  done
  for owned_ns in $owned_namespaces; do ip netns del "$owned_ns" 2>/dev/null || true; done
  if test -n "$saved_rmem_max"; then
    sysctl -qw "net.core.rmem_max=$saved_rmem_max" "net.core.wmem_max=$saved_wmem_max" || {
      echo 'ERROR: could not restore socket buffer limits' >&2; return 1;
    }
  fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
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
  CLAT_OFFLINK_MTU="$CLAT_OFFLINK_MTU" /usr/local/sbin/clat-start.sh \
  >"$ARTIFACT_DIR/clat.log" 2>&1 &
clat_pid=$!

ip -n server link set lo up
ip -n server link set server0 up
ip -n server -6 addr add 2600:464::2/64 dev server0
ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo
ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0
configure_sender_fq() {
  local sender_ns=$1 sender_dev=$2 tx_count topology queue_no queue_limit flow_limit
  tx_count=$(awk '/Current hardware settings:/ { current=1; next } current && /^TX:/ { print $2; exit }'     "$ARTIFACT_DIR/channels-$sender_ns-$sender_dev.after.txt")
  case "$tx_count" in ''|*[!0-9]*|0) echo 'could not determine active TX channels' >&2; exit 1;; esac
  topology=$SENDER_FQ_TOPOLOGY
  if [ "$topology" = auto ]; then
    topology=single
    [ "$tx_count" -le 1 ] || topology=mq
  fi
  printf '%s/%s topology=%s tx_channels=%s total_limit=%s flow_limit=%s fq_rate=%s\n'     "$sender_ns" "$sender_dev" "$topology" "$tx_count" "$SENDER_FQ_LIMIT" "$SENDER_FQ_FLOW_LIMIT" "$FQ_RATE"     >> "$ARTIFACT_DIR/sender-qdisc-settings.txt"
  if [ "$topology" = single ]; then
    ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" root fq       limit "$SENDER_FQ_LIMIT" flow_limit "$SENDER_FQ_FLOW_LIMIT"
  else
    [ "$SENDER_FQ_LIMIT" -ge "$tx_count" ] || { echo 'total fq limit must cover all TX queues' >&2; exit 64; }
    # Each hardware TX queue gets its own scheduler. Partition the total budget
    # exactly; adding channels must not silently multiply buffered memory.
    ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" root handle 1: mq
    for queue_no in $(seq 1 "$tx_count"); do
      queue_limit=$((SENDER_FQ_LIMIT / tx_count))
      if [ "$queue_no" -le "$((SENDER_FQ_LIMIT % tx_count))" ]; then queue_limit=$((queue_limit + 1)); fi
      flow_limit=$SENDER_FQ_FLOW_LIMIT
      [ "$flow_limit" -le "$queue_limit" ] || flow_limit=$queue_limit
      ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" parent "1:$queue_no" fq         limit "$queue_limit" flow_limit "$flow_limit"
    done
  fi
}
if [ "$SENDER_FQ" = on ]; then
  configure_sender_fq client lan0
  configure_sender_fq server server0
fi


snapshot_thread_counters() {
  python3 - "$clat_pid" "$1" <<'PY_THREADS'
import json, os, pathlib, re, sys, time
pid, target = int(sys.argv[1]), pathlib.Path(sys.argv[2])
rows = []
for task in sorted(pathlib.Path(f"/proc/{pid}/task").iterdir()):
    stat = (task / "stat").read_text().rsplit(")", 1)[1].split()
    status = dict(line.split(":", 1) for line in (task / "status").read_text().splitlines() if ":" in line)
    def optional(path):
        try:
            return path.read_text()
        except OSError:
            return None
    sched, schedstat = optional(task / "sched"), optional(task / "schedstat")
    migration = re.search(r"se.nr_migrations\s*:\s*(\d+)", sched or "")
    times = [int(value) for value in schedstat.split()] if schedstat else None
    rows.append(dict(tid=int(task.name), start_ticks=int(stat[19]), comm=(task / "comm").read_text().strip(),
                     cpu_ticks=int(stat[11]) + int(stat[12]),
                     cpus_allowed_list=status["Cpus_allowed_list"].strip(),
                     voluntary_context_switches=int(status["voluntary_ctxt_switches"]),
                     involuntary_context_switches=int(status["nonvoluntary_ctxt_switches"]),
                     migrations=int(migration.group(1)) if migration else None,
                     scheduler_running_ns=times[0] if times else None,
                     runqueue_wait_ns=times[1] if times else None))
target.write_text(json.dumps(dict(pid=pid, monotonic_ns=time.monotonic_ns(),
                                 clock_ticks=os.sysconf("SC_CLK_TCK"), threads=rows), indent=2) + "\n")
PY_THREADS
}

collect_network_counters() {
  local counter_dir=$1 counter_phase=$2 counter_ns
  uptime_seconds > "$counter_dir/network-counters.$counter_phase.uptime"
  sysctl -n net.core.rmem_max net.core.wmem_max > "$counter_dir/buffer-limits.$counter_phase"
  for counter_ns in client router clatns server; do
    ip netns exec "$counter_ns" cat /proc/net/snmp > "$counter_dir/$counter_ns.snmp.$counter_phase"
    ip netns exec "$counter_ns" cat /proc/net/snmp6 > "$counter_dir/$counter_ns.snmp6.$counter_phase"
    ip -n "$counter_ns" -j -s link show > "$counter_dir/$counter_ns.links.$counter_phase.json"
    ip netns exec "$counter_ns" tc -s qdisc show > "$counter_dir/$counter_ns.qdisc.$counter_phase"
    ip netns exec "$counter_ns" tc -j -s qdisc show > "$counter_dir/$counter_ns.qdisc.$counter_phase.json"
    ip netns exec "$counter_ns" sysctl -n net.core.rmem_max net.core.wmem_max > "$counter_dir/$counter_ns.buffer-limits.$counter_phase"
    case "$counter_ns" in
      client) counter_devs=lan0;;
      router) counter_devs="rlan rclat rwan";;
      clatns) counter_devs=veth-nat64;;
      server) counter_devs=server0;;
    esac
    for counter_dev in $counter_devs; do
      ip netns exec "$counter_ns" ethtool -S "$counter_dev" > "$counter_dir/$counter_ns.$counter_dev.driver.$counter_phase"
    done
  done
}

sample_udp_sockets() {
  local sample_dir=$1 sample_ns
  while :; do
    for sample_ns in client server; do
      printf 'uptime=%s namespace=%s\n' "$(uptime_seconds)" "$sample_ns" >> "$sample_dir/socket-samples.txt"
      ip netns exec "$sample_ns" ss -u -a -n -m -i >> "$sample_dir/socket-samples.txt" 2>> "$sample_dir/socket-samples.stderr"
    done
    sleep "$SOCKET_SAMPLE_INTERVAL"
  done
}
tayga_snapshot() {
  local target_path=$1
  local cur_seq=0
  if [ -s /run/tayga-status.json ]; then
    cur_seq=$(python3 -c 'import json, sys; d=json.load(open("/run/tayga-status.json")); print(d.get("snapshot_sequence", 0) if d.get("pid") == int(sys.argv[1]) else 0)' "$clat_pid" 2>/dev/null || echo 0)
  fi
  kill -USR2 "$clat_pid" 2>/dev/null || true
  local fresh=0
  for _ in $(seq 1 50); do
    test "$(( _ % 10 ))" -ne 0 || kill -USR2 "$clat_pid" 2>/dev/null || true
    sleep 0.02
    if [ -s /run/tayga-status.json ]; then
      fresh=$(python3 -c '
import json, sys
try:
    d = json.load(open("/run/tayga-status.json"))
    pid = int(sys.argv[1])
    cur_seq = int(sys.argv[2])
    if (d.get("pid") == pid and
        d.get("snapshot_sequence", 0) > cur_seq and
        d.get("workers_synced") is True and
        not d.get("unacknowledged_worker_slots")):
        with open(sys.argv[3], "w") as output:
            json.dump(d, output)
        print(1)
    else:
        print(0)
except Exception:
    print(0)
' "$clat_pid" "$cur_seq" "$target_path" 2>/dev/null || echo 0)
      if [ "$fresh" = 1 ]; then
        return 0
      fi
    fi
  done
  echo "Failed to obtain fresh TAYGA status snapshot for PID $clat_pid (old seq $cur_seq)" >&2
  return 1
}

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
    exec_with_affinity "$SERVER_CPUSET" ip netns exec server env "LD_PRELOAD=${iperf_start_library:+$iperf_start_library:}${udp_drain_guard:-}" "TAYGA_IPERF_START_CONTROL=${iperf_start_control:-}" "TAYGA_UDP_DRAIN_CONTROL=${udp_drain_control:-}" iperf3 -s -6 -B 64:ff9b::b00:2 -p "$((5200 + client_no))" \
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
    test "$PROTOCOL" = udp && set -- "$@" --pacing-timer "$PACING_TIMER_US"
    set -- "$@" --fq-rate "$FQ_RATE"
    test "$SOCKET_BUFFER_BYTES" -gt 0 && set -- "$@" -w "$SOCKET_BUFFER_BYTES"
    test -n "$BLOCK_SIZE" && set -- "$@" -l "$BLOCK_SIZE"
    test -n "$RATE" && set -- "$@" -b "$RATE"
    if test "$gated" = yes; then
      gate="$run_dir/gate-$client_no"
      rm -f "$gate"
      mkfifo "$gate"
      printf '%s\n' "$gate" >> "$run_dir/gates"
      exec_with_affinity "$CLIENT_CPUSET" ip netns exec client sh -c 'read -r _ < "$1"; shift; exec "$@"' sh "$gate" env "LD_PRELOAD=${iperf_start_library:+$iperf_start_library:}${udp_drain_guard:-}" "TAYGA_IPERF_START_CONTROL=${iperf_start_control:-}" "TAYGA_UDP_DRAIN_CONTROL=${udp_drain_control:-}" iperf3 "$@" \
        >"$run_dir/client-$client_no.json" 2>"$run_dir/client-$client_no.stderr" &
    else
      exec_with_affinity "$CLIENT_CPUSET" ip netns exec client env "LD_PRELOAD=${iperf_start_library:+$iperf_start_library:}${udp_drain_guard:-}" "TAYGA_IPERF_START_CONTROL=${iperf_start_control:-}" "TAYGA_UDP_DRAIN_CONTROL=${udp_drain_control:-}" iperf3 "$@" >"$run_dir/client-$client_no.json" \
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

prepare_iperf_start_gate() {
  local run_dir=$1
  iperf_start_control=
  iperf_start_library=
  if [ "$PROTOCOL" = udp ] && [ "$IPERF_START_GATE" = on ]; then
    if ! test -r /usr/local/lib/tayga-perf/iperf-start-gate.so || ! test -x /usr/local/libexec/tayga-perf/iperf-start-control; then
      echo 'iperf start helpers are missing; build/install make iperf-start-tools' >&2
      return 1
    fi
    iperf_start_control="$run_dir/iperf-start.control"
    iperf_start_library=/usr/local/lib/tayga-perf/iperf-start-gate.so
    /usr/local/libexec/tayga-perf/iperf-start-control init "$iperf_start_control" "$((CLIENTS * 2))" || return 1
    sha256sum "$iperf_start_library" > "$run_dir/iperf-start-gate.sha256"
  fi
}

run_warmup() {
  local warmup_dir
  test "$WARMUP" -gt 0 || return 0
  warmup_dir="$ARTIFACT_DIR/warmup-$1"
  mkdir -p "$warmup_dir"
  prepare_iperf_start_gate "$warmup_dir" || return 2
  start_iperf_servers || { echo "warmup server startup failed for $1" >&2; return 1; }
  start_clients "$warmup_dir" "$1" "$WARMUP" no
  if test -n "$iperf_start_control"; then
    /usr/local/libexec/tayga-perf/iperf-start-control wait-ready "$iperf_start_control" > "$warmup_dir/iperf-start.ready.json" || return 2
    /usr/local/libexec/tayga-perf/iperf-start-control release "$iperf_start_control" > "$warmup_dir/iperf-start.released.json" || return 2
  fi
  local w_status=0
  wait_clients "$warmup_dir" "$((WARMUP + 15))" || w_status=$?
  client_pids=
  cleanup_iperf_servers
  iperf_start_control=
  iperf_start_library=
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
  if run_warmup "$direction"; then :; else
    warmup_status=$?
    echo "Warmup failed for $direction; marking run as degraded" >&2
    printf '%s\n' "warmup_failed" > "$run_dir/warmup-failed.marker"
    test "$warmup_status" -ne 2 || return 1
  fi
  drain_s=${RECEIVER_DRAIN_SECONDS:-0.5}
  drain_int=0
  if [ "$PROTOCOL" = udp ] && [ "$(awk -v d="$drain_s" 'BEGIN { print (d > 0) }')" = 1 ]; then
    drain_int=$(awk -v d="$drain_s" 'BEGIN { print int(d + 0.999) }')
  fi
  udp_drain_control=
  udp_drain_guard=
  if test "$drain_int" -gt 0; then
    test -r /usr/local/lib/tayga-perf/udp-drain-guard.so || return 1
    udp_drain_control="$run_dir/udp-drain.control"
    /usr/local/libexec/tayga-perf/udp-drain-control init "$udp_drain_control" || return 1
    udp_drain_guard=/usr/local/lib/tayga-perf/udp-drain-guard.so
    sha256sum /usr/local/lib/tayga-perf/udp-drain-guard.so > "$run_dir/udp-drain-guard.sha256"
  fi
  prepare_iperf_start_gate "$run_dir" || return 1
  start_iperf_servers || return 1
  client_duration=$(( DURATION + drain_int ))
  start_clients "$run_dir" "$direction" "$client_duration" yes
  # Give every wrapper time to block on its FIFO before a common release.
  sleep 1
  if test -n "$iperf_start_control"; then
    release_pids=
    while read -r gate; do printf 'go\n' > "$gate" & release_pids="$release_pids $!"; done < "$run_dir/gates"
    for release_pid in $release_pids; do wait "$release_pid" || true; done
    release_pids=
    /usr/local/libexec/tayga-perf/iperf-start-control wait-ready "$iperf_start_control" > "$run_dir/iperf-start.ready.json" || return 1
  fi
  : > "$run_dir/endpoint-affinity.before"
  for endpoint_pid in $client_pids $iperf_pids; do
    printf 'pid=%s\n' "$endpoint_pid" >> "$run_dir/endpoint-affinity.before"
    awk '/^(Name|Cpus_allowed_list):/' "/proc/$endpoint_pid/status" >> "$run_dir/endpoint-affinity.before"
  done
  ticks_before=$(ticks)
  uptime_before=$(uptime_seconds)
  monotonic_before=$(monotonic_ns)
  ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,stat,comm > "$run_dir/tayga.threads.before"
  cat "/proc/$clat_pid/status" > "$run_dir/tayga.status.before"
  tayga_snapshot "$run_dir/tayga-status.before.json" || {
    echo "failed to capture valid synchronized before status snapshot" >&2
    printf 'failed to capture valid synchronized before status snapshot\n' >> "$run_dir/capture_errors.txt"
  }
  if test "$offload_active" = yes; then
    grep 'GSO Stats:' "$ARTIFACT_DIR/clat.log" | tail -n 1 > "$run_dir/gso-stats.before" || true
  fi
  grep 'Stats: Worker' "$ARTIFACT_DIR/clat.log" | tail -n "$((WORKERS + 1))" > "$run_dir/worker-stats.before.txt" 2>/dev/null || true
  ip -n clatns -s link show > "$run_dir/clat.links.before"
  ip -n clatns -j -s link show > "$run_dir/clat.links.before.json"
  ip netns exec clatns tc -s qdisc show dev clat > "$run_dir/clat.qdisc.before" 2>&1 || true
  ip -n router -j -s link show > "$run_dir/router.links.before.json"
  cat /proc/softirqs > "$run_dir/softirqs.before"
  cat /proc/net/softnet_stat > "$run_dir/softnet.before"
  cat /proc/stat > "$run_dir/proc_stat.before"
  snapshot_thread_counters "$run_dir/thread-counters.before.json"
  collect_network_counters "$run_dir" before
  if [ "$PROTOCOL" = udp ] && [ "$SOCKET_SAMPLE_INTERVAL" -gt 0 ]; then
    sample_udp_sockets "$run_dir" &
    socket_sampler_pid=$!
  fi
  local perf_pid=
  local perf_status=0
  if test "$PERF_MODE" != none && command -v perf >/dev/null 2>&1; then
    perf --version > "$run_dir/perf-version.txt" 2>&1 || true
    set -- -p "$clat_pid"
    test "$PERF_SCOPE" = system && set -- -a
    if test "$PERF_MODE" = stat; then
      perf stat -x ';' -o "$run_dir/perf-stat.csv" \
        -e task-clock,context-switches,cpu-migrations,page-faults,raw_syscalls:sys_enter,syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_writev \
        "$@" -- sleep "$DURATION" \
        >"$run_dir/perf-stat.stdout" 2>"$run_dir/perf-stat.stderr" &
    else
      perf record -o "$run_dir/perf.data" -e cpu-clock -F 99 --call-graph fp "$@" -- sleep "$DURATION" \
        >"$run_dir/perf-record.stdout" 2>"$run_dir/perf-record.stderr" &
    fi
    perf_pid=$!
  elif test "$PERF_MODE" != none; then
    printf '%s\n' 'perf is unavailable in this runtime' > "$run_dir/perf-unavailable.txt"
  fi
  local ping_pid=
  ip netns exec client ping -c "$((DURATION * 5))" -i 0.2 -W 1 11.0.0.2 > "$run_dir/ping.txt" 2>&1 &
  ping_pid=$!
  monotonic_traffic_start=$(monotonic_ns)
  if test -n "$iperf_start_control"; then
    /usr/local/libexec/tayga-perf/iperf-start-control release "$iperf_start_control" > "$run_dir/iperf-start.released.json" || return 1
  else
    release_pids=
    while read -r gate; do printf 'go\n' > "$gate" & release_pids="$release_pids $!"; done < "$run_dir/gates"
    for release_pid in $release_pids; do wait "$release_pid" || true; done
    release_pids=
  fi
  if [ "$drain_int" -gt 0 ]; then
    sleep "$DURATION"
    if ! /usr/local/libexec/tayga-perf/udp-drain-control stop "$udp_drain_control" > "$run_dir/udp-drain.stop.json"; then
      echo "failed to suppress UDP sender during drain" >&2
      printf 'failed to suppress UDP sender during drain\n' >> "$run_dir/capture_errors.txt"
    fi
    monotonic_traffic_end=$(monotonic_ns)
    sleep "$drain_s"
    if wait_clients "$run_dir"; then status=0; else status=$?; fi
    monotonic_drain_end=$(monotonic_ns)
  else
    if wait_clients "$run_dir"; then status=0; else status=$?; fi
    monotonic_traffic_end=$(monotonic_ns)
    monotonic_drain_end=$monotonic_traffic_end
  fi
  client_pids=
  if test -n "$socket_sampler_pid"; then
    kill "$socket_sampler_pid" 2>/dev/null || true
    wait "$socket_sampler_pid" 2>/dev/null || true
    socket_sampler_pid=
  fi
  if test -n "$udp_drain_control"; then
    /usr/local/libexec/tayga-perf/udp-drain-control status "$udp_drain_control" > "$run_dir/udp-drain.status.json" || printf "drain status failed\n" >> "$run_dir/capture_errors.txt"
  fi
  collect_network_counters "$run_dir" after
  cleanup_iperf_servers
  udp_drain_control=
  udp_drain_guard=
  iperf_start_control=
  iperf_start_library=
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
  snapshot_thread_counters "$run_dir/thread-counters.after.json"
  ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,stat,comm > "$run_dir/tayga.threads.after"
  cat "/proc/$clat_pid/status" > "$run_dir/tayga.status.after"
  tayga_snapshot "$run_dir/tayga-status.after.json" || {
    echo "failed to capture valid synchronized after status snapshot" >&2
    printf 'failed to capture valid synchronized after status snapshot\n' >> "$run_dir/capture_errors.txt"
  }
  if test "$offload_active" = yes; then
    grep 'GSO Stats:' "$ARTIFACT_DIR/clat.log" | tail -n 1 > "$run_dir/gso-stats.after" || true
  fi
  grep 'Stats: Worker' "$ARTIFACT_DIR/clat.log" | tail -n "$((WORKERS + 1))" > "$run_dir/worker-stats.after.txt" 2>/dev/null || true
  ip -n clatns -s link show > "$run_dir/clat.links.after"
  ip -n clatns -j -s link show > "$run_dir/clat.links.after.json"
  ip netns exec clatns tc -s qdisc show dev clat > "$run_dir/clat.qdisc.after" 2>&1 || true
  ip -n router -j -s link show > "$run_dir/router.links.after.json"
  cat /proc/softirqs > "$run_dir/softirqs.after"
  cat /proc/net/softnet_stat > "$run_dir/softnet.after"
  cat /proc/stat > "$run_dir/proc_stat.after"
  printf '%s\n' "$status" > "$run_dir/exit-status"
  python3 - "$run_dir" "$direction" "$ticks_before" "$ticks_after" "$uptime_before" "$uptime_after" "$monotonic_before" "$monotonic_after" "$PROTOCOL" "$MAX_UDP_LOSS_PERCENT" "$MAX_TUN_DROPS" "$MAX_PING_LOSS_PERCENT" "$CLAT_OFFLOAD" "$offload_active" "$TUN_TXQLEN" "$GIT_REVISION" "$SOURCE_TREE_SHA256" "$WORKERS" "$FLOWS" "$RATE" "$DURATION" "$WARMUP" "$DATAGRAM_SIZE" "$BLOCK_SIZE" "$CLAT_OFFLINK_MTU" "$monotonic_traffic_end" "$monotonic_drain_end" "$monotonic_traffic_start" <<'PY'
import glob, json, os, re, sys
run_dir, direction, before, after, up_before, up_after, mono_before, mono_after, protocol, max_udp_loss, max_tun_drops, max_ping_loss, offload_requested, offload_active, txqlen, revision, source_tree_sha256, workers, flows, rate, duration, warmup, datagram_size, block_size, offlink_mtu, mono_traffic_end, mono_drain_end, mono_traffic_start = sys.argv[1:]
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
    sent_packets = sent.get("packets")
    if "bytes" in sent:
        sent_bytes = sent["bytes"]
        if not isinstance(sent_bytes, int) or isinstance(sent_bytes, bool) or sent_bytes < 0 or sent_bytes % size:
            raise ValueError("UDP sent bytes do not contain whole fixed-size datagrams")
        # iperf increments its sequence before Nwrite and rolls it back after
        # EAGAIN; a concurrent final report can observe the unsent attempt.
        sent_packets = sent_bytes // size
    return dict(packets=byte_count // size, receiver_expected_packets=expected,
                lost_packets=lost, sent_packets=sent_packets)


def parse_udp_snmp(text, ipv6=False):
    """Return available UDP counters; missing fields never become zero."""
    if ipv6:
        return {key: int(value) for key, value in (line.split() for line in text.splitlines())
                if key.startswith("Udp6")}
    lines = text.splitlines()
    for pos, line in enumerate(lines[:-1]):
        if line.startswith("Udp:"):
            keys, values = line.split()[1:], lines[pos + 1].split()[1:]
            if not lines[pos + 1].startswith("Udp:") or len(keys) != len(values):
                raise ValueError("malformed UDP SNMP header/value pair")
            return {"Udp" + key: int(value) for key, value in zip(keys, values)}
    return {}


def udp_snmp_delta(before, after):
    if not before or before.keys() != after.keys():
        raise ValueError("UDP SNMP fields missing or changed")
    delta = {key: after[key] - before[key] for key in before}
    if any(value < 0 for value in delta.values()):
        raise ValueError("UDP SNMP counter reset")
    return delta


def qdisc_counter_delta(before, after):
    """Keep each qdisc separate: parent and child counters can overlap."""
    def indexed(rows):
        return {(row["dev"], row["handle"], row.get("parent"), row.get("root", False)): row for row in rows}
    old, new = indexed(before), indexed(after)
    if old.keys() != new.keys():
        raise ValueError("qdisc topology changed during measurement")
    result = []
    for key, row in new.items():
        if old[key]["kind"] != row["kind"] or old[key].get("options") != row.get("options"):
            raise ValueError("qdisc settings changed during measurement")
        counters = {name: row[name] - old[key][name] for name in ("bytes", "packets", "drops", "overlimits", "requeues")}
        if any(value < 0 for value in counters.values()):
            raise ValueError("qdisc counter reset")
        result.append(dict(dev=row["dev"], handle=row["handle"], kind=row["kind"],
                           parent=row.get("parent"), root=row.get("root", False),
                           options=row.get("options"), counters=counters,
                           backlog_before=old[key].get("backlog"), backlog_after=row.get("backlog"),
                           qlen_before=old[key].get("qlen"), qlen_after=row.get("qlen")))
    return result


def interface_counter_delta(before, after):
    """Interface counters are distinct from qdisc counters and datagram counts."""
    def indexed(rows):
        if not rows:
            raise ValueError("interface counters unavailable")
        out = {row["ifname"]: row for row in rows}
        if len(out) != len(rows):
            raise ValueError("duplicate interface identity")
        return out
    old, new = indexed(before), indexed(after)
    if old.keys() != new.keys():
        raise ValueError("interface topology changed during measurement")
    result = {}
    for name, row in new.items():
        if old[name]["ifindex"] != row["ifindex"]:
            raise ValueError("interface identity changed during measurement")
        counters = {}
        for direction in ("rx", "tx"):
            counters[direction] = {}
            for field in ("bytes", "packets", "dropped", "errors"):
                previous, current = old[name]["stats64"][direction][field], row["stats64"][direction][field]
                if any(not isinstance(value, int) or isinstance(value, bool) or value < 0
                       for value in (previous, current)) or current < previous:
                    raise ValueError("invalid or reset interface counter")
                counters[direction][field] = current - previous
        result[name] = counters
    return result


def udp_delivery_reconciliation(reports):
    """Sequence-gap loss misses trailing packets; reconcile each client too."""
    counts = [row.get("sent_packets") for row in reports]
    if not counts or any(not isinstance(count, int) or isinstance(count, bool) or count < 0 for count in counts):
        return dict(udp_delivery_accounting_match=False, udp_sender_receiver_packet_gap=None,
                    udp_sender_receiver_gap_percent=None, udp_sender_unobserved_tail_packets=None,
                    udp_client_packet_gaps=None, udp_sequence_ledger=None)
    gaps = [row["sent_packets"] - row["packets"] for row in reports]
    tails = [max(row["sent_packets"] - row["receiver_expected_packets"], 0) for row in reports]
    sent = sum(counts)
    ledger = []
    for idx, row in enumerate(reports):
        sp = row.get("sent_packets")
        rp = row.get("packets")
        exp = row.get("receiver_expected_packets")
        lp = row.get("lost_packets")
        tail = max(sp - exp, 0) if (sp is not None and exp is not None) else None
        uniq = (exp - lp) if (exp is not None and lp is not None) else None
        dup = max(0, rp - uniq) if (rp is not None and uniq is not None) else None
        tot_lost = (lp + tail) if (lp is not None and tail is not None) else None
        ledger.append(dict(client_index=idx + 1,
                           sent_packets=sp,
                           received_packets=rp,
                           receiver_expected_packets=exp,
                           interior_lost_packets=lp,
                           terminal_tail_gap=tail,
                           estimated_unique_packets=uniq,
                           estimated_duplicate_packets=dup,
                           unique_received_packets=uniq,
                           duplicate_packets=dup,
                           total_lost_packets=tot_lost,
                           net_packet_gap=(sp - rp) if (sp is not None and rp is not None) else None,
                           out_of_order=row.get("out_of_order"),
                           jitter_ms=row.get("jitter_ms")))
    return dict(udp_delivery_accounting_match=all(gap == 0 for gap in gaps),
                udp_sender_receiver_packet_gap=sum(gaps),
                udp_sender_receiver_gap_percent=100.0 * sum(abs(gap) for gap in gaps) / sent if sent else None,
                udp_sender_unobserved_tail_packets=sum(tails), udp_client_packet_gaps=gaps,
                udp_sequence_ledger=ledger)


def worker_counter_deltas(before, after):
    if not before or not after:
        raise ValueError("worker status snapshot missing")
    if "pid" not in before or "pid" not in after:
        raise ValueError("worker status missing process identity")
    if before["pid"] != after["pid"]:
        raise ValueError("worker process identity changed")
    if "snapshot_sequence" not in before or "snapshot_sequence" not in after:
        raise ValueError("worker status missing snapshot sequence")
    if after["snapshot_sequence"] <= before["snapshot_sequence"]:
        raise ValueError("worker snapshot sequence not strictly increasing")
    if before.get("workers_synced") is not True or after.get("workers_synced") is not True:
        raise ValueError("worker snapshot synchronization timed out")
    if before.get("unacknowledged_worker_slots") or after.get("unacknowledged_worker_slots"):
        raise ValueError(f"unacknowledged worker slots: before={before.get('unacknowledged_worker_slots')}, after={after.get('unacknowledged_worker_slots')}")
    if "workers" not in before or "workers" not in after:
        raise ValueError("worker list missing from status")
    old = {w["slot"]: w for w in before["workers"]}
    new = {w["slot"]: w for w in after["workers"]}
    if old.keys() != new.keys():
        raise ValueError("worker slot set changed during measurement")
    deltas = []
    fields = ("rx_packets_v4", "tx_packets_v4", "rx_packets_v6", "tx_packets_v6", "dropped_packets", "error_packets")
    for slot in sorted(new.keys()):
        b = old[slot]
        a = new[slot]
        d = dict(slot=slot, worker_id=a.get("worker_id", slot))
        for field in fields:
            if field not in b or field not in a:
                raise ValueError(f"worker slot {slot} missing field {field}")
            b_val, a_val = b[field], a[field]
            if not isinstance(b_val, int) or isinstance(b_val, bool) or b_val < 0 or \
               not isinstance(a_val, int) or isinstance(a_val, bool) or a_val < 0:
                raise ValueError(f"worker slot {slot} field {field} invalid counter value")
            diff = a_val - b_val
            if diff < 0:
                raise ValueError(f"worker slot {slot} field {field} counter reset")
            d[field] = diff
        deltas.append(d)
    return deltas


def thread_counter_deltas(before, after):
    elapsed = (after["monotonic_ns"] - before["monotonic_ns"]) / 1_000_000_000
    if elapsed <= 0 or before["pid"] != after["pid"] or before["clock_ticks"] != after["clock_ticks"]:
        raise ValueError("thread process/clock identity changed")
    old = {row["tid"]: row for row in before["threads"]}
    new = {row["tid"]: row for row in after["threads"]}
    if old.keys() != new.keys():
        raise ValueError("thread set changed during capture")
    result = []
    for tid, row in new.items():
        if old[tid]["start_ticks"] != row["start_ticks"]:
            raise ValueError("thread identity reused during capture")
        counters = {}
        for name in ("cpu_ticks", "voluntary_context_switches", "involuntary_context_switches",
                     "migrations", "scheduler_running_ns", "runqueue_wait_ns"):
            counters[name] = row[name] - old[tid][name] if row.get(name) is not None and old[tid].get(name) is not None else None
            if counters[name] is not None and counters[name] < 0:
                raise ValueError("thread counter reset")
        if counters["cpu_ticks"] is None:
            raise ValueError("thread CPU counters unavailable")
        result.append(dict(tid=tid, comm=row["comm"], main_thread=tid == before["pid"],
                           cpu_cores=counters["cpu_ticks"] / before["clock_ticks"] / elapsed,
                           cpus_allowed_before=old[tid].get("cpus_allowed_list"),
                           cpus_allowed_after=row.get("cpus_allowed_list"), **counters))
    return dict(elapsed_seconds=elapsed, threads=result)

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
            report["iperf_reported_sender_sequence_packets"] = sent.get("packets")
            stream_ooo = [s.get("udp", {}).get("out_of_order") for s in end.get("streams", [])]
            report.update(
                          lost_percent=received.get("lost_percent"),
                          jitter_ms=received.get("jitter_ms"),
                          out_of_order=(sum(stream_ooo) if stream_ooo and all(v is not None for v in stream_ooo) else None))
        report["socket_buffers"] = {key: doc.get("start", {}).get(key) for key in
                                    ("sock_bufsize", "sndbuf_actual", "rcvbuf_actual")}
        reports.append(report)
    except Exception as exc:
        print(f"ERROR direction={direction} file={os.path.basename(path)} reason={exc}", file=sys.stderr)
        workload_errors.append(f"client report {os.path.basename(path)} error: {exc}")

start_gate_status = None
if protocol == "udp" and os.environ.get("IPERF_START_GATE", "on") == "on":
    try:
        start_gate_status = json.load(open(os.path.join(run_dir, "iperf-start.released.json")))
        expected = 2 * int(os.environ["CLIENTS"])
        if start_gate_status["expected"] != expected or start_gate_status["arrived"] != expected or start_gate_status["released"] != 1:
            raise ValueError("not all endpoints reached the start gate")
    except (OSError, ValueError, KeyError) as exc:
        capture_errors.append(f"iperf start gate validation failed: {exc}")

drain_status = None
if protocol == "udp" and float(os.environ.get("RECEIVER_DRAIN_SECONDS", "0.5")) > 0:
    try:
        drain_status = json.load(open(os.path.join(run_dir, "udp-drain.status.json")))
        if drain_status["stopped"] != 1 or drain_status["attached"] < 2 * int(os.environ["CLIENTS"]) or drain_status["blocked_writes"] <= 0:
            raise ValueError("drain guard did not attach and suppress UDP writes")
    except (OSError, ValueError, KeyError) as exc:
        capture_errors.append(f"UDP drain validation failed: {exc}")
if os.path.exists(os.path.join(run_dir, "capture_errors.txt")):
    with open(os.path.join(run_dir, "capture_errors.txt")) as cef:
        for line in cef:
            line = line.strip()
            if line:
                capture_errors.append(line)

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
def negotiated_offload_mode(statuses, requested):
    if len(statuses) != 2:
        raise ValueError("before/after offload state is required")
    modes = {status["offload_effective"] for status in statuses}
    sizes = {status["vnet_hdr_sz"] for status in statuses}
    if len(modes) != 1 or len(sizes) != 1:
        raise ValueError("negotiated capabilities changed during capture")
    mode, size = modes.pop(), sizes.pop()
    flags = {"off": 0, "tcp": 7, "udp": 103}
    if mode not in flags or requested not in ("auto", "off", "tcp", "udp"):
        raise ValueError("unknown offload policy/capability")
    if requested != "auto" and requested != mode:
        raise ValueError("explicit offload mode was not established")
    if size not in (0, 10, 12) or (mode != "off" and size == 0):
        raise ValueError("unsupported negotiated framing")
    for status in statuses:
        if (status.get("offload_negotiation_complete") is not True or
                status.get("offload_mode") != requested or
                type(status.get("offload_flags")) is not int or
                status["offload_flags"] != flags[mode] or
                status.get("udp_offload_available") is not (mode == "udp")):
            raise ValueError("negotiated capability fields disagree")
    return mode

effective_offload = "unknown"
try:
    negotiated = [json.load(open(os.path.join(run_dir, f"tayga-status.{phase}.json")))
                  for phase in ("before", "after")]
    effective_offload = negotiated_offload_mode(negotiated, offload_requested)
except (OSError, ValueError, KeyError, TypeError) as exc:
    capture_errors.append(f"effective TUN offload state could not be verified: {exc}")

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
if (effective_offload in ("tcp", "udp") and protocol == "tcp" and
        (not gso_delta or gso_delta.get("rx_pkts", 0) + gso_delta.get("tx_pkts", 0) <= 0)):
    capture_errors.append("TUN offload active but no GSO packets were observed")
udp_aggregate_count = ((gso_delta or {}).get("udp_rx_aggregates", 0) +
                       (gso_delta or {}).get("udp_tx_aggregates", 0))


network_udp_counters = {}
network_counter_errors = []
for counter_ns in ("client", "router", "clatns", "server"):
    network_udp_counters[counter_ns] = {}
    for suffix, ipv6 in (("snmp", False), ("snmp6", True)):
        try:
            snapshots = [parse_udp_snmp(open(os.path.join(run_dir, f"{counter_ns}.{suffix}.{phase}")).read(), ipv6)
                         for phase in ("before", "after")]
            network_udp_counters[counter_ns][suffix] = udp_snmp_delta(*snapshots)
        except (OSError, ValueError) as exc:
            network_udp_counters[counter_ns][suffix] = None
            network_counter_errors.append(f"{counter_ns}/{suffix}: {exc}")
qdisc_deltas = {}
for counter_ns in ("client", "router", "clatns", "server"):
    try:
        snapshots = [json.load(open(os.path.join(run_dir, f"{counter_ns}.qdisc.{phase}.json")))
                     for phase in ("before", "after")]
        qdisc_deltas[counter_ns] = qdisc_counter_delta(*snapshots)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        qdisc_deltas[counter_ns] = None
        network_counter_errors.append(f"{counter_ns}/qdisc: {exc}")
interface_deltas = {}
for counter_ns in ("client", "router", "clatns", "server"):
    try:
        snapshots = [json.load(open(os.path.join(run_dir, f"{counter_ns}.links.{phase}.json")))
                     for phase in ("before", "after")]
        interface_deltas[counter_ns] = interface_counter_delta(*snapshots)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        interface_deltas[counter_ns] = None
        network_counter_errors.append(f"{counter_ns}/interfaces: {exc}")
# InErrors already includes RcvbufErrors. Preserve both, never sum them.
if protocol == "udp" and network_counter_errors:
    capture_errors.extend(network_counter_errors)


thread_metrics, thread_counter_error = None, None
try:
    thread_metrics = thread_counter_deltas(*[json.load(open(os.path.join(run_dir, f"thread-counters.{phase}.json")))
                                            for phase in ("before", "after")])
except (OSError, ValueError, KeyError, TypeError) as exc:
    thread_counter_error = str(exc)
    capture_errors.append(f"thread CPU counter capture: {exc}")

worker_metrics = None
status_b_path = os.path.join(run_dir, "tayga-status.before.json")
status_a_path = os.path.join(run_dir, "tayga-status.after.json")
if os.path.exists(status_b_path) and os.path.exists(status_a_path):
    try:
        worker_metrics = worker_counter_deltas(json.load(open(status_b_path)),
                                               json.load(open(status_a_path)))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        worker_metrics = None
        capture_errors.append(f"worker counter capture: {exc}")
else:
    capture_errors.append("worker status snapshots missing")

result = dict(direction=direction, clients=len(reports), expected_clients=expected_clients,
              capture_valid=not capture_errors, workload_valid=True, acceptance_pass=True,
              schema_version=6, guest_cpu_count=os.cpu_count(),
              degraded_reasons=list(capture_errors),
              perf_mode=perf_mode, perf_scope=os.environ["PERF_SCOPE"],
              thread_metrics=thread_metrics, thread_counter_error=thread_counter_error,
              worker_metrics=worker_metrics,
              receiver_drain_guard_sha256=(open(os.path.join(run_dir, "udp-drain-guard.sha256")).read().split()[0] if drain_status else None),
              receiver_drain_method="udp-write-eagain-v1" if os.path.exists(os.path.join(run_dir, "udp-drain.status.json")) else "none",
              iperf_start_gate=start_gate_status,
              iperf_start_gate_sha256=(open(os.path.join(run_dir, "iperf-start-gate.sha256")).read().split()[0] if start_gate_status else None),
              receiver_drain_seconds=float(os.environ.get("RECEIVER_DRAIN_SECONDS", "0.5")),
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
              pacing_timer_us=int(os.environ["PACING_TIMER_US"]), fq_rate=os.environ["FQ_RATE"],
              socket_buffer_bytes=int(os.environ["SOCKET_BUFFER_BYTES"]), sender_fq=os.environ["SENDER_FQ"],
              sender_fq_flow_limit=int(os.environ["SENDER_FQ_FLOW_LIMIT"]),
              sender_fq_limit=int(os.environ["SENDER_FQ_LIMIT"]), veth_queues=int(os.environ["VETH_QUEUES"]),
              sender_fq_topology=os.environ["SENDER_FQ_TOPOLOGY"],
              tayga_cpuset=os.environ["TAYGA_CPUSET"], client_cpuset=os.environ["CLIENT_CPUSET"],
              server_cpuset=os.environ["SERVER_CPUSET"],
              qdisc_deltas=qdisc_deltas, interface_deltas=interface_deltas,
              socket_sample_interval=int(os.environ["SOCKET_SAMPLE_INTERVAL"]) if protocol == "udp" else 0,
              network_udp_counters=network_udp_counters, network_counter_errors=network_counter_errors,
              iperf_socket_buffers=[x["socket_buffers"] for x in reports],
              rate_per_flow=(rate or "unlimited"), duration_seconds=int(duration), warmup_seconds=int(warmup),
              datagram_size=int(datagram_size) if protocol == "udp" else None,
              block_size=(block_size or None),
              sent_mbps=sent, received_mbps=received,
              udp_drain_status=drain_status,
              iperf_reported_sender_sequence_packets=[x.get("iperf_reported_sender_sequence_packets") for x in reports] if protocol == "udp" else None,
              received_active_window_mbps=(received_bytes * 8 / ((int(mono_traffic_end)-int(mono_traffic_start))/1e9) / 1e6 if protocol == "udp" and int(mono_traffic_end)>int(mono_traffic_start) else None),
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
              measurement_window=dict(monotonic_start_ns=int(mono_before),
                                     monotonic_traffic_start_ns=int(mono_traffic_start),
                                     monotonic_traffic_end_ns=int(mono_traffic_end) if mono_traffic_end else None,
                                     monotonic_drain_end_ns=int(mono_drain_end) if mono_drain_end else None,
                                     monotonic_end_ns=int(mono_after),
                                     traffic_duration_seconds=(int(mono_traffic_end) - int(mono_traffic_start)) / 1_000_000_000 if mono_traffic_end else None,
                                     drain_duration_seconds=(int(mono_drain_end) - int(mono_traffic_end)) / 1_000_000_000 if (mono_traffic_end and mono_drain_end) else None,
                                     elapsed_seconds=elapsed, intended_duration_seconds=int(duration)))

if protocol == "udp":
    for counter_ns, devices in interface_deltas.items():
        for device, counters in (devices or {}).items():
            for direction_name, fields in counters.items():
                for field in ("dropped", "errors"):
                    # TUN transmit drops already use the explicit MAX_TUN_DROPS gate.
                    if counter_ns == "clatns" and device == "clat" and direction_name == "tx" and field == "dropped":
                        continue
                    if fields[field] > 0:
                        result["acceptance_pass"] = False
                        result["degraded_reasons"].append(f"{counter_ns}/{device} {direction_name} {field} increased by {fields[field]}")
    for counter_ns, rows in qdisc_deltas.items():
        for row in rows or []:
            if row["counters"]["drops"] > 0:
                result["acceptance_pass"] = False
                result["degraded_reasons"].append(f"{counter_ns}/{row['dev']}/{row['kind']} qdisc drops increased by {row['counters']['drops']}")
    for counter_ns, families in network_udp_counters.items():
        for family, counters in families.items():
            for key, value in (counters or {}).items():
                if value > 0 and key.endswith(("InErrors", "SndbufErrors", "NoPorts", "MemErrors")):
                    result["acceptance_pass"] = False
                    result["degraded_reasons"].append(f"{counter_ns} {key} increased by {value}")
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
                  udp_accounting_version=3,
                  udp_counter_definitions=dict(received="receiver bytes divided by configured fixed datagram size",
                                               receiver_expected="iperf receiver highest-sequence packet count; includes lost packets",
                                               sent="successful sender bytes divided by configured fixed datagram size"),
                  udp_sent_packets=total_sent,
                  udp_receiver_expected_packets=receiver_expected,
                  received_udp_packets_per_second=sum(x.get("packets", 0) / max(x.get("seconds", 0), 0.001) for x in reports),
                  udp_loss_percent=loss_pct,
                  udp_jitter_ms_max=jitter_max,
                  udp_out_of_order=ooo)
    reconciliation = udp_delivery_reconciliation(reports)
    result.update(reconciliation)
    gap_percent = reconciliation["udp_sender_receiver_gap_percent"]

    # Record receiver kernel SNMP datagram count for context; do not conflate socket reads with loss.
    receiver_ns = "server" if direction == "upload" else "client"
    receiver_family = "snmp6" if direction == "upload" else "snmp"
    counter_key = "Udp6InDatagrams" if direction == "upload" else "UdpInDatagrams"
    kernel_rx = (network_udp_counters.get(receiver_ns, {}).get(receiver_family, {}) or {}).get(counter_key)
    result["receiver_kernel_udp_datagrams"] = kernel_rx

    if gap_percent is None or gap_percent > float(max_udp_loss):
        result["acceptance_pass"] = False
        result["degraded_reasons"].append("UDP sender/receiver packet counts do not reconcile within the loss threshold")
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
