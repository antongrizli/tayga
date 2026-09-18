#!/bin/sh
# Reproducible static-map CLAT benchmark. It exercises LAN NAT44, the real
# clat-start.sh entrypoint and an IPv6-only upstream server.
set -u

DURATION=${DURATION:-60}
WARMUP=${WARMUP:-10}
FLOWS=${FLOWS:-1}
CLIENTS=${CLIENTS:-20}
WORKERS=${WORKERS:-3}
DIRECTIONS=${DIRECTIONS:-"upload download"}
PROTOCOL=${PROTOCOL:-tcp}
RATE=${RATE:-}
DATAGRAM_SIZE=${DATAGRAM_SIZE:-1200}
BLOCK_SIZE=${BLOCK_SIZE:-}
ARTIFACT_DIR=${ARTIFACT_DIR:-/tmp/tayga-clat-results}
PERF_MODE=${PERF_MODE:-none}
MAX_UDP_LOSS_PERCENT=${MAX_UDP_LOSS_PERCENT:-0}
MAX_TUN_DROPS=${MAX_TUN_DROPS:-0}
TUN_TXQLEN=${TUN_TXQLEN:-1000}
CLAT_OFFLOAD=${CLAT_OFFLOAD:-off}

case "$PROTOCOL" in tcp|udp) ;; *) echo 'PROTOCOL must be tcp or udp' >&2; exit 64;; esac
case "$CLAT_OFFLOAD" in off|tcp|auto) ;; *) echo 'CLAT_OFFLOAD must be off, tcp or auto' >&2; exit 64;; esac
case "$PERF_MODE" in none|stat|record) ;; *) echo 'PERF_MODE must be none, stat or record' >&2; exit 64;; esac
case "$DURATION:$WARMUP" in *[!0-9:]*|:) echo 'DURATION and WARMUP must be integers' >&2; exit 64;; esac
case "$MAX_TUN_DROPS" in ''|*[!0-9]*) echo 'MAX_TUN_DROPS must be a non-negative integer' >&2; exit 64;; esac
case "$TUN_TXQLEN" in
  '') ;;
  *[!0-9]*) echo 'TUN_TXQLEN must be a non-negative integer' >&2; exit 64;;
esac
[ "$DURATION" -gt 0 ] || { echo 'DURATION must be positive' >&2; exit 64; }
mkdir -p "$ARTIFACT_DIR"

clat_pid=
iperf_pids=
release_pids=
cleanup() {
  test -n "$clat_pid" && kill "$clat_pid" 2>/dev/null || true
  for iperf_pid in $iperf_pids; do kill "$iperf_pid" 2>/dev/null || true; done
  for release_pid in $release_pids; do kill "$release_pid" 2>/dev/null || true; done
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
ip netns exec clatns env PREF64=64:ff9b::/96 ROUTER4=172.31.64.1 \
  CLAT_WORKERS="$WORKERS" CLAT_OFFLOAD="$CLAT_OFFLOAD" /usr/local/sbin/clat-start.sh \
  >"$ARTIFACT_DIR/clat.log" 2>&1 &
clat_pid=$!

ip -n server link set lo up
ip -n server link set server0 up
ip -n server -6 addr add 2600:464::2/64 dev server0
ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo
ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0
start_iperf_servers() {
  for old_iperf_pid in $iperf_pids; do
    kill "$old_iperf_pid" 2>/dev/null || true
  done
  for old_iperf_pid in $iperf_pids; do
    wait "$old_iperf_pid" 2>/dev/null || true
  done
  iperf_pids=
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
    ip -n clatns -s link show > "$run_dir/clat.timeout.links" 2>&1 || true
    cat /proc/"$clat_pid"/status > "$run_dir/clat.timeout.status" 2>&1 || true
    while read -r child_pid; do
      kill -9 "$child_pid" 2>/dev/null || true
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
  wait_clients "$warmup_dir" || { echo "warmup failed for $1" >&2; return 1; }
}

run_iperf() {
  local direction=$1
  local run_dir="$ARTIFACT_DIR/$direction"
  mkdir -p "$run_dir"
  run_warmup "$direction" || return 1
  start_iperf_servers || return 1
  start_clients "$run_dir" "$direction" "$DURATION" yes
  # Give every wrapper time to block on its FIFO before a common release.
  sleep 1
  ticks_before=$(ticks)
  uptime_before=$(uptime_seconds)
  monotonic_before=$(monotonic_ns)
  ps -L -p "$clat_pid" -o pid,tid,psr,pcpu,stat,comm > "$run_dir/tayga.threads.before"
  cat "/proc/$clat_pid/status" > "$run_dir/tayga.status.before"
  ip -n clatns -s link show > "$run_dir/clat.links.before"
  ip -n clatns -j -s link show > "$run_dir/clat.links.before.json"
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
  ip netns exec client ping -c "$DURATION" -i 1 -W 1 11.0.0.2 > "$run_dir/ping.txt" 2>&1 &
  ping_pid=$!
  release_pids=
  while read -r gate; do printf 'go\n' > "$gate" & release_pids="$release_pids $!"; done < "$run_dir/gates"
  for release_pid in $release_pids; do wait "$release_pid" || true; done
  release_pids=
  wait_clients "$run_dir"; status=$?
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
  ip -n clatns -s link show > "$run_dir/clat.links.after"
  ip -n clatns -j -s link show > "$run_dir/clat.links.after.json"
  ip -n router -j -s link show > "$run_dir/router.links.after.json"
  cat /proc/softirqs > "$run_dir/softirqs.after"
  cat /proc/net/softnet_stat > "$run_dir/softnet.after"
  cat /proc/stat > "$run_dir/proc_stat.after"
  printf '%s\n' "$status" > "$run_dir/exit-status"
  python3 - "$run_dir" "$direction" "$ticks_before" "$ticks_after" "$uptime_before" "$uptime_after" "$monotonic_before" "$monotonic_after" "$PROTOCOL" "$MAX_UDP_LOSS_PERCENT" "$MAX_TUN_DROPS" <<'PY'
import glob, json, os, sys
run_dir, direction, before, after, up_before, up_after, mono_before, mono_after, protocol, max_udp_loss, max_tun_drops = sys.argv[1:]
reports = []
for path in sorted(glob.glob(os.path.join(run_dir, "client-*.json"))):
    try:
        doc = json.load(open(path))
        if doc.get("error"):
            raise ValueError(doc["error"])
        end = doc["end"]
        sent, received = end["sum_sent"], end["sum_received"]
        report = dict(sent_bps=sent["bits_per_second"], received_bps=received["bits_per_second"],
                      sent_bytes=sent.get("bytes", 0), received_bytes=received.get("bytes", 0),
                      retransmits=sent.get("retransmits", 0), seconds=received.get("seconds", 0))
        if protocol == "udp":
            report.update(lost_packets=received.get("lost_packets", 0),
                          packets=received.get("packets", 0),
                          lost_percent=received.get("lost_percent", 0),
                          jitter_ms=received.get("jitter_ms", 0),
                          out_of_order=received.get("out_of_order", 0))
        reports.append(report)
    except Exception as exc:
        print(f"ERROR direction={direction} file={os.path.basename(path)} reason={exc}", file=sys.stderr)
        sys.exit(1)
if not reports:
    raise SystemExit("no iperf reports")
elapsed = (int(mono_after) - int(mono_before)) / 1_000_000_000
if elapsed <= 0:
    elapsed = float(up_after) - float(up_before)
cores = (int(after) - int(before)) / os.sysconf("SC_CLK_TCK") / elapsed
sent = sum(x["sent_bps"] for x in reports) / 1_000_000
received = sum(x["received_bps"] for x in reports) / 1_000_000
retransmits = sum(x["retransmits"] for x in reports)
received_bytes = sum(x["received_bytes"] for x in reports)
def counters(path, ifname):
    for link in json.load(open(path)):
        if link.get("ifname") == ifname:
            stats = link.get("stats64", link.get("stats", {}))
            return {side: {field: int(stats.get(side, {}).get(field, 0))
                                for field in ("bytes", "packets", "errors", "dropped")}
                    for side in ("rx", "tx")}
    raise ValueError(f"interface {ifname} absent from {path}")
def delta(before_path, after_path, ifname):
    before_stats, after_stats = counters(before_path, ifname), counters(after_path, ifname)
    return {side: {field: after_stats[side][field] - before_stats[side][field]
                   for field in before_stats[side]}
            for side in before_stats}
router_delta = delta(os.path.join(run_dir, "router.links.before.json"),
                     os.path.join(run_dir, "router.links.after.json"), "rclat")
clat_delta = delta(os.path.join(run_dir, "clat.links.before.json"),
                   os.path.join(run_dir, "clat.links.after.json"), "clat")
router_packets = router_delta["rx"]["packets"] + router_delta["tx"]["packets"]
tun_drops = clat_delta["rx"]["dropped"] + clat_delta["tx"]["dropped"]
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
result = dict(direction=direction, clients=len(reports), expected_clients=int(os.environ.get("CLIENTS", len(reports))),
              capture_valid=True, workload_valid=True, acceptance_pass=True, degraded_reasons=[],
              sent_mbps=sent, received_mbps=received,
              retransmits=retransmits, tayga_cpu_cores=cores,
              tayga_core_per_gbps=cores / (received / 1000) if received else None,
              system_busy_cores=sys_busy_cores,
              system_softirq_cores=sys_softirq_cores,
              perf_stat_metrics=perf_stat_metrics,
              received_application_MBps=received_bytes / elapsed / 1_000_000,
              router_rclat_packets_per_second=router_packets / elapsed,
              router_rclat_delta=router_delta, clat_tun_delta=clat_delta, tun_drops=tun_drops,
              elapsed_s=elapsed, workload_protocol=protocol)
validation_errors = []
if protocol == "udp":
    packets = sum(x["packets"] for x in reports)
    lost = sum(x["lost_packets"] for x in reports)
    result.update(udp_packets=packets, udp_lost_packets=lost,
                  udp_loss_percent=(100 * lost / packets if packets else 0),
                  udp_jitter_ms_max=max(x["jitter_ms"] for x in reports),
                  udp_out_of_order=sum(x["out_of_order"] for x in reports))
    if result["udp_loss_percent"] > 0:
        result["acceptance_pass"] = False
        result["degraded_reasons"].append(f"UDP loss observed: {result['udp_loss_percent']:.3f}%")
    if result["udp_loss_percent"] > float(max_udp_loss):
        validation_errors.append(f"UDP loss {result['udp_loss_percent']:.3f}% exceeds {max_udp_loss}%")
ping_file = os.path.join(run_dir, "ping.txt")
if os.path.exists(ping_file):
    try:
        for line in open(ping_file):
            if "rtt min/avg/max/mdev" in line:
                parts = line.split("=")[1].strip().split()[0].split("/")
                result.update(ping_min_ms=float(parts[0]), ping_avg_ms=float(parts[1]),
                              ping_max_ms=float(parts[2]), ping_mdev_ms=float(parts[3]))
    except Exception:
        pass
if tun_drops > int(max_tun_drops):
    validation_errors.append(f"TUN drops {tun_drops} exceeds {max_tun_drops}")
if tun_drops > 0:
    result["acceptance_pass"] = False
    result["degraded_reasons"].append(f"TUN drops observed: {tun_drops}")
if validation_errors:
    result["workload_valid"] = False
    result["acceptance_pass"] = False
    result["degraded_reasons"].extend(validation_errors)
with open(os.path.join(run_dir, "result.json"), "w") as out:
    json.dump(result, out, indent=2, sort_keys=True)
print("RESULT " + " ".join(f"{key}={value:.3f}" if isinstance(value, float) else f"{key}={value}" for key, value in result.items()))
if validation_errors:
    raise SystemExit("INVALID " + "; ".join(validation_errors))
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
