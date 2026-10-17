#!/bin/sh
# Sourced by benchmark-clat.sh; configuration is owned by the entrypoint.
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
  if [ -s "$TAYGA_STATUS_FILE" ]; then
    cur_seq=$(python3 -c 'import json, sys, os; d=json.load(open(os.environ.get("TAYGA_STATUS_FILE", "/run/tayga-status.json"))); print(d.get("snapshot_sequence", 0) if d.get("pid") == int(sys.argv[1]) else 0)' "$clat_pid" 2>/dev/null || echo 0)
  fi
  kill -USR2 "$clat_pid" 2>/dev/null || true
  local fresh=0
  for _ in $(seq 1 50); do
    test "$(( _ % 10 ))" -ne 0 || kill -USR2 "$clat_pid" 2>/dev/null || true
    sleep 0.02
    if [ -s "$TAYGA_STATUS_FILE" ]; then
      fresh=$(python3 -c '
import json, sys, os
try:
    d = json.load(open(os.environ.get("TAYGA_STATUS_FILE", "/run/tayga-status.json")))
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

ticks() {
  awk '{ticks += $14 + $15} END {print ticks + 0}' /proc/"$clat_pid"/task/*/stat
}

