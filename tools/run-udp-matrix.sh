#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
touch /tmp/tayga-perf-workflow.lock 2>/dev/null || true
exec 9</tmp/tayga-perf-workflow.lock
flock -n 9 || { echo "Another TAYGA workflow is active in this guest." >&2; exit 75; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_DIR:-$REPO/perf-sessions/$STAMP-udp-capacity-search}"
CLIENTS="${CLIENTS:-20}"
FLOWS="${FLOWS:-1}"
WORKERS="${WORKERS:-3}"
DURATION="${DURATION:-10}"
WARMUP="${WARMUP:-0}"
INITIAL_TOTAL_RATE_MBIT="${INITIAL_TOTAL_RATE_MBIT:-500}"
RATE_GROWTH="${RATE_GROWTH:-1.5}"
MAX_SEARCH_RUNS="${MAX_SEARCH_RUNS:-12}"
MAX_OVERLOAD_RUNS="${MAX_OVERLOAD_RUNS:-4}"
BOUNDARY_REPEATS="${BOUNDARY_REPEATS:-3}"
MAX_TOTAL_RATE_MBIT="${MAX_TOTAL_RATE_MBIT:-0}"
MAX_UDP_LOSS_PERCENT="${MAX_UDP_LOSS_PERCENT:-0.1}"
MAX_TUN_DROPS="${MAX_TUN_DROPS:-0}"
CLAT_OFFLOAD="${CLAT_OFFLOAD:-auto}"
FORWARDING_GRO="${FORWARDING_GRO:-off}"
export FORWARDING_GRO
SIZES="${SIZES:-1200}"
DIRECTIONS="${DIRECTIONS:-upload download}"
RECEIVER_DRAIN_SECONDS="${RECEIVER_DRAIN_SECONDS:-0.5}"
case "$CLAT_OFFLOAD" in auto|tcp|udp|off) ;; *) echo "invalid CLAT_OFFLOAD: $CLAT_OFFLOAD" >&2; exit 64;; esac
case "$FORWARDING_GRO" in on|off) ;; *) echo "invalid FORWARDING_GRO: $FORWARDING_GRO" >&2; exit 64;; esac
for direction in $DIRECTIONS; do
  case "$direction" in upload|download) ;; *) echo "invalid direction: $direction" >&2; exit 64;; esac
done

for n in "$CLIENTS" "$FLOWS" "$DURATION" "$MAX_SEARCH_RUNS" "$MAX_OVERLOAD_RUNS" "$BOUNDARY_REPEATS" "$INITIAL_TOTAL_RATE_MBIT"; do
  [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )) || { echo "expected positive integer, got: $n" >&2; exit 64; }
done
[[ "$RATE_GROWTH" =~ ^[0-9]+([.][0-9]+)?$ ]] && awk -v x="$RATE_GROWTH" 'BEGIN { exit !(x > 1) }' || {
  echo "RATE_GROWTH must be greater than 1" >&2; exit 64;
}
[[ "$MAX_TOTAL_RATE_MBIT" =~ ^[0-9]+$ ]] || { echo "MAX_TOTAL_RATE_MBIT must be 0 or a positive integer" >&2; exit 64; }
mkdir -p "$OUT_DIR"

# The guest runner freezes and hashes the exact snapshot used to compile the
# benchmarked daemon. Keep the environment stable across all search points.
make -B VERSION="${TAYGA_VERSION:-0.9.12}"
make udp-drain-tools CC=gcc
sudo install -Dm0755 tools/udp-drain-control /usr/local/libexec/tayga-perf/udp-drain-control
sudo install -Dm0755 tools/udp-drain-guard.so /usr/local/lib/tayga-perf/udp-drain-guard.so
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh
sudo install -D -m 0755 tayga /usr/sbin/tayga
sudo install -D -m 0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh
GIT_REVISION="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
SOURCE_TREE_SHA256="$(git ls-files -co --exclude-standard -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')"

next_rate() {
  awk -v n="$1" -v g="$RATE_GROWTH" -v quantum="$((CLIENTS * FLOWS))" \
    'BEGIN { value = int(n * g / quantum + 0.999999) * quantum; if (value <= n) value = n + quantum; printf "%.0f", value }'
}

for size in $SIZES; do
  [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 && size <= 65507 )) || {
    echo "invalid UDP payload size: $size" >&2; exit 64;
  }
  for direction in $DIRECTIONS; do
    search_dir="$OUT_DIR/size${size}/$direction"
    mkdir -p "$search_dir"
    low=0
    high=0
    rate="$INITIAL_TOTAL_RATE_MBIT"
    runs=0
    confirmation_runs=0
    status="search_limit"
    while (( runs < MAX_SEARCH_RUNS )); do
      if (( MAX_TOTAL_RATE_MBIT > 0 && rate > MAX_TOTAL_RATE_MBIT )); then
        status="explicit_rate_limit"
        break
      fi
      rate_per_client=$(( (rate + CLIENTS * FLOWS / 2) / (CLIENTS * FLOWS) ))
      (( rate_per_client > 0 )) || rate_per_client=1
      actual_target=$((rate_per_client * CLIENTS * FLOWS))
      run_dir="$search_dir/rate-${actual_target}m"
      mkdir -p "$run_dir"
      echo "UDP search: size=${size}B direction=$direction target=${actual_target}Mbit/s run=$((runs + 1))/$MAX_SEARCH_RUNS"
      set +e
      sudo env ARTIFACT_DIR="$run_dir" PERF_MODE=none \
        GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
        CLIENTS="$CLIENTS" FLOWS="$FLOWS" WORKERS="$WORKERS" \
        CLAT_OFFLOAD="$CLAT_OFFLOAD" CLAT_OFFLINK_MTU="${CLAT_OFFLINK_MTU:-1280}" \
        FORWARDING_GRO="$FORWARDING_GRO" \
        PERF_SCOPE="${PERF_SCOPE:-process}" \
        PACING_TIMER_US="${PACING_TIMER_US:-1000}" \
        FQ_RATE="${FQ_RATE:-0}" \
        SOCKET_BUFFER_BYTES="${SOCKET_BUFFER_BYTES:-0}" \
        SENDER_FQ="${SENDER_FQ:-off}" \
        SENDER_FQ_FLOW_LIMIT="${SENDER_FQ_FLOW_LIMIT:-100}" \
        SENDER_FQ_LIMIT="${SENDER_FQ_LIMIT:-10000}" \
        VETH_QUEUES="${VETH_QUEUES:-0}" \
        SENDER_FQ_TOPOLOGY="${SENDER_FQ_TOPOLOGY:-auto}" \
        TAYGA_CPUSET="${TAYGA_CPUSET:-all}" \
        CLIENT_CPUSET="${CLIENT_CPUSET:-all}" \
        SERVER_CPUSET="${SERVER_CPUSET:-all}" \
        SOCKET_SAMPLE_INTERVAL="${SOCKET_SAMPLE_INTERVAL:-1}" \
        RECEIVER_DRAIN_SECONDS="$RECEIVER_DRAIN_SECONDS" \
        PROTOCOL=udp RATE="${rate_per_client}M" DURATION="$DURATION" WARMUP="$WARMUP" \
        DIRECTIONS="$direction" MAX_TUN_DROPS="$MAX_TUN_DROPS" \
        MAX_UDP_LOSS_PERCENT="$MAX_UDP_LOSS_PERCENT" TUN_TXQLEN="${TUN_TXQLEN:-1000}" \
        DATAGRAM_SIZE="$size" /usr/local/sbin/benchmark-clat.sh
      command_status=$?
      set -e
      result="$run_dir/$direction/result.json"
      if [[ ! -s "$result" ]]; then
        status="invalid_no_result"
        printf 'benchmark_exit_status=%s\n' "$command_status" > "$run_dir/invocation.txt"
        break
      fi
      sample="$(python3 - "$result" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("invalid")
    raise SystemExit
if not d.get("capture_valid") or not d.get("workload_valid"):
    print("invalid")
else:
    print("pass" if d.get("acceptance_pass") else "fail")
PY
)"
      printf 'benchmark_exit_status=%s\nsearch_sample=%s\n' "$command_status" "$sample" > "$run_dir/search.txt"
      runs=$((runs + 1))
      if [[ "$sample" == pass ]]; then
        low="$actual_target"
        if (( high > 0 )); then
          status="bracketed"
          break
        fi
        rate="$(next_rate "$actual_target")"
      elif [[ "$sample" == fail ]]; then
        high="$actual_target"
        status="bracketed"
        (( low > 0 )) || status="threshold_exceeded_at_initial_rate"
        break
      else
        status="invalid_sample"
        break
      fi
    done

    # Confirm both sides of a provisional boundary before treating it as
    # repeatable. A transient queue drop must not define capacity by itself.
    if [[ "$status" == bracketed ]] && (( low > 0 && high > low && BOUNDARY_REPEATS > 1 )); then
      low_confirmations_ok=1
      high_confirmations_ok=1
      for endpoint in low high; do
        endpoint_rate="$low"
        [[ "$endpoint" == high ]] && endpoint_rate="$high"
        endpoint_passes=0
        endpoint_fails=0
        for ((rep=2; rep<=BOUNDARY_REPEATS; rep++)); do
          rate_per_client=$(( (endpoint_rate + CLIENTS * FLOWS / 2) / (CLIENTS * FLOWS) ))
          (( rate_per_client > 0 )) || rate_per_client=1
          actual_target=$((rate_per_client * CLIENTS * FLOWS))
          run_dir="$search_dir/rate-${actual_target}m-confirm-${endpoint}-${rep}"
          mkdir -p "$run_dir"
          echo "UDP boundary confirmation: direction=$direction endpoint=$endpoint rate=${actual_target}Mbit/s repeat=$rep/$BOUNDARY_REPEATS"
          set +e
          sudo env ARTIFACT_DIR="$run_dir" PERF_MODE=none \
            GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
            CLIENTS="$CLIENTS" FLOWS="$FLOWS" WORKERS="$WORKERS" \
            CLAT_OFFLOAD="$CLAT_OFFLOAD" CLAT_OFFLINK_MTU="${CLAT_OFFLINK_MTU:-1280}" \
        FORWARDING_GRO="$FORWARDING_GRO" \
        PERF_SCOPE="${PERF_SCOPE:-process}" \
        PACING_TIMER_US="${PACING_TIMER_US:-1000}" \
        FQ_RATE="${FQ_RATE:-0}" \
        SOCKET_BUFFER_BYTES="${SOCKET_BUFFER_BYTES:-0}" \
        SENDER_FQ="${SENDER_FQ:-off}" \
        SENDER_FQ_FLOW_LIMIT="${SENDER_FQ_FLOW_LIMIT:-100}" \
        SENDER_FQ_LIMIT="${SENDER_FQ_LIMIT:-10000}" \
        VETH_QUEUES="${VETH_QUEUES:-0}" \
        SENDER_FQ_TOPOLOGY="${SENDER_FQ_TOPOLOGY:-auto}" \
        TAYGA_CPUSET="${TAYGA_CPUSET:-all}" \
        CLIENT_CPUSET="${CLIENT_CPUSET:-all}" \
        SERVER_CPUSET="${SERVER_CPUSET:-all}" \
        SOCKET_SAMPLE_INTERVAL="${SOCKET_SAMPLE_INTERVAL:-1}" \
        RECEIVER_DRAIN_SECONDS="$RECEIVER_DRAIN_SECONDS" \
            PROTOCOL=udp RATE="${rate_per_client}M" DURATION="$DURATION" WARMUP="$WARMUP" \
            DIRECTIONS="$direction" MAX_TUN_DROPS="$MAX_TUN_DROPS" \
            MAX_UDP_LOSS_PERCENT="$MAX_UDP_LOSS_PERCENT" TUN_TXQLEN="${TUN_TXQLEN:-1000}" \
            DATAGRAM_SIZE="$size" /usr/local/sbin/benchmark-clat.sh
          command_status=$?
          set -e
          result="$run_dir/$direction/result.json"
          [[ -s "$result" ]] || { status="invalid_boundary_confirmation"; continue; }
          sample="$(python3 - "$result" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
print("invalid" if not d.get("capture_valid") or not d.get("workload_valid") else ("pass" if d.get("acceptance_pass") else "fail"))
PY
)"
          printf 'benchmark_exit_status=%s\nsearch_sample=%s\nconfirmation_endpoint=%s\n' \
            "$command_status" "$sample" "$endpoint" > "$run_dir/search.txt"
          confirmation_runs=$((confirmation_runs + 1))
          case "$sample" in
            pass) endpoint_passes=$((endpoint_passes + 1));;
            fail) endpoint_fails=$((endpoint_fails + 1));;
            *) status="invalid_boundary_confirmation";;
          esac
        done
        if [[ "$endpoint" == low ]] && (( endpoint_passes != BOUNDARY_REPEATS - 1 )); then
          low_confirmations_ok=0
        fi
        if [[ "$endpoint" == high ]] && (( endpoint_fails != BOUNDARY_REPEATS - 1 )); then
          high_confirmations_ok=0
        fi
      done
      if [[ "$status" == bracketed ]]; then
        if (( ! low_confirmations_ok )); then
          status="unstable_sustainable_point"
        elif (( ! high_confirmations_ok )); then
          status="non_monotonic_boundary"
        fi
      fi
    fi

    # Refine the sustainable boundary to approximately 5% when a passing and
    # failing point bracket it. Every trial remains saved, including failures.
    while [[ "$status" == bracketed ]] && (( low > 0 && high > low && runs < MAX_SEARCH_RUNS + 6 )); do
      if awk -v lo="$low" -v hi="$high" 'BEGIN { exit !((hi-lo)/lo > 0.05) }'; then
        rate=$(( (low + high) / 2 ))
      else
        status="threshold_refined"
        break
      fi
      rate_per_client=$(( (rate + CLIENTS * FLOWS / 2) / (CLIENTS * FLOWS) ))
      (( rate_per_client > 0 )) || rate_per_client=1
      actual_target=$((rate_per_client * CLIENTS * FLOWS))
      run_dir="$search_dir/rate-${actual_target}m-refine-$((runs + 1))"
      mkdir -p "$run_dir"
      set +e
      sudo env ARTIFACT_DIR="$run_dir" PERF_MODE=none \
        GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
        CLIENTS="$CLIENTS" FLOWS="$FLOWS" WORKERS="$WORKERS" \
        CLAT_OFFLOAD="$CLAT_OFFLOAD" CLAT_OFFLINK_MTU="${CLAT_OFFLINK_MTU:-1280}" \
        FORWARDING_GRO="$FORWARDING_GRO" \
        PERF_SCOPE="${PERF_SCOPE:-process}" \
        PACING_TIMER_US="${PACING_TIMER_US:-1000}" \
        FQ_RATE="${FQ_RATE:-0}" \
        SOCKET_BUFFER_BYTES="${SOCKET_BUFFER_BYTES:-0}" \
        SENDER_FQ="${SENDER_FQ:-off}" \
        SENDER_FQ_FLOW_LIMIT="${SENDER_FQ_FLOW_LIMIT:-100}" \
        SENDER_FQ_LIMIT="${SENDER_FQ_LIMIT:-10000}" \
        VETH_QUEUES="${VETH_QUEUES:-0}" \
        SENDER_FQ_TOPOLOGY="${SENDER_FQ_TOPOLOGY:-auto}" \
        TAYGA_CPUSET="${TAYGA_CPUSET:-all}" \
        CLIENT_CPUSET="${CLIENT_CPUSET:-all}" \
        SERVER_CPUSET="${SERVER_CPUSET:-all}" \
        SOCKET_SAMPLE_INTERVAL="${SOCKET_SAMPLE_INTERVAL:-1}" \
        RECEIVER_DRAIN_SECONDS="$RECEIVER_DRAIN_SECONDS" \
        PROTOCOL=udp RATE="${rate_per_client}M" DURATION="$DURATION" WARMUP="$WARMUP" \
        DIRECTIONS="$direction" MAX_TUN_DROPS="$MAX_TUN_DROPS" \
        MAX_UDP_LOSS_PERCENT="$MAX_UDP_LOSS_PERCENT" TUN_TXQLEN="${TUN_TXQLEN:-1000}" \
        DATAGRAM_SIZE="$size" /usr/local/sbin/benchmark-clat.sh
      command_status=$?
      set -e
      result="$run_dir/$direction/result.json"
      [[ -s "$result" ]] || { status="invalid_no_result"; break; }
      sample="$(python3 - "$result" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
print("invalid" if not d.get("capture_valid") or not d.get("workload_valid") else ("pass" if d.get("acceptance_pass") else "fail"))
PY
)"
      printf 'benchmark_exit_status=%s\nsearch_sample=%s\n' "$command_status" "$sample" > "$run_dir/search.txt"
      runs=$((runs + 1))
      case "$sample" in
        pass) low="$actual_target";;
        fail) high="$actual_target";;
        *) status="invalid_sample"; break;;
      esac
    done
    boundary_status="$status"

    # Continue through valid overload samples to look for a delivered-rate
    # plateau. If completion fails, report the maximum as unresolved.
    overload_runs=0
    previous_received=""
    plateau_streak=0
    plateau_found=false
    if (( high > 0 )); then
      rate="$high"
      while (( overload_runs < MAX_OVERLOAD_RUNS )); do
        rate="$(next_rate "$rate")"
        if (( MAX_TOTAL_RATE_MBIT > 0 && rate > MAX_TOTAL_RATE_MBIT )); then
          status="explicit_rate_limit"
          break
        fi
        rate_per_client=$(( (rate + CLIENTS * FLOWS / 2) / (CLIENTS * FLOWS) ))
        (( rate_per_client > 0 )) || rate_per_client=1
        actual_target=$((rate_per_client * CLIENTS * FLOWS))
        run_dir="$search_dir/rate-${actual_target}m-overload-$((overload_runs + 1))"
        mkdir -p "$run_dir"
        echo "UDP overload search: size=${size}B direction=$direction target=${actual_target}Mbit/s sample=$((overload_runs + 1))/$MAX_OVERLOAD_RUNS"
        set +e
        sudo env ARTIFACT_DIR="$run_dir" PERF_MODE=none \
          GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
          CLIENTS="$CLIENTS" FLOWS="$FLOWS" WORKERS="$WORKERS" \
          CLAT_OFFLOAD="$CLAT_OFFLOAD" CLAT_OFFLINK_MTU="${CLAT_OFFLINK_MTU:-1280}" \
        FORWARDING_GRO="$FORWARDING_GRO" \
        PERF_SCOPE="${PERF_SCOPE:-process}" \
        PACING_TIMER_US="${PACING_TIMER_US:-1000}" \
        FQ_RATE="${FQ_RATE:-0}" \
        SOCKET_BUFFER_BYTES="${SOCKET_BUFFER_BYTES:-0}" \
        SENDER_FQ="${SENDER_FQ:-off}" \
        SENDER_FQ_FLOW_LIMIT="${SENDER_FQ_FLOW_LIMIT:-100}" \
        SENDER_FQ_LIMIT="${SENDER_FQ_LIMIT:-10000}" \
        VETH_QUEUES="${VETH_QUEUES:-0}" \
        SENDER_FQ_TOPOLOGY="${SENDER_FQ_TOPOLOGY:-auto}" \
        TAYGA_CPUSET="${TAYGA_CPUSET:-all}" \
        CLIENT_CPUSET="${CLIENT_CPUSET:-all}" \
        SERVER_CPUSET="${SERVER_CPUSET:-all}" \
        SOCKET_SAMPLE_INTERVAL="${SOCKET_SAMPLE_INTERVAL:-1}" \
        RECEIVER_DRAIN_SECONDS="$RECEIVER_DRAIN_SECONDS" \
          PROTOCOL=udp RATE="${rate_per_client}M" DURATION="$DURATION" WARMUP="$WARMUP" \
          DIRECTIONS="$direction" MAX_TUN_DROPS="$MAX_TUN_DROPS" \
          MAX_UDP_LOSS_PERCENT="$MAX_UDP_LOSS_PERCENT" TUN_TXQLEN="${TUN_TXQLEN:-1000}" \
          DATAGRAM_SIZE="$size" /usr/local/sbin/benchmark-clat.sh
        command_status=$?
        set -e
        result="$run_dir/$direction/result.json"
        [[ -s "$result" ]] || { status="invalid_overload_sample"; break; }
        read -r sample received < <(python3 - "$result" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
valid=bool(d.get("capture_valid") and d.get("workload_valid"))
print(("valid" if valid else "invalid"), d.get("received_mbps") or 0)
PY
)
        printf 'benchmark_exit_status=%s\nsearch_sample=%s\n' "$command_status" "$sample" > "$run_dir/search.txt"
        [[ "$sample" == valid ]] || { status="invalid_overload_sample"; break; }
        overload_runs=$((overload_runs + 1))
        if [[ -n "$previous_received" ]] && awk -v old="$previous_received" -v new="$received" \
            'BEGIN { if (old > 0 && (new-old)/old < 0.01) exit 0; exit 1 }'; then
          plateau_streak=$((plateau_streak + 1))
        else
          plateau_streak=0
        fi
        previous_received="$received"
        if (( plateau_streak >= 2 )); then
          plateau_found=true
          status="delivered_throughput_plateau"
          break
        fi
      done
    fi

python3 - "$search_dir" "$status" "$boundary_status" "$low" "$high" "$runs" "$confirmation_runs" "$MAX_UDP_LOSS_PERCENT" "$overload_runs" "$plateau_found" "$CLAT_OFFLOAD" <<'PY'
import glob, json, os, re, sys
root, status, boundary_status, low, high, runs, confirmation_runs, threshold, overload_runs, plateau_found, offload = sys.argv[1:]
samples=[]
for path in glob.glob(os.path.join(root, "rate-*", "*", "result.json")):
    try:
        d=json.load(open(path))
        if d.get("capture_valid") and d.get("workload_valid"):
            relative=os.path.relpath(path, root)
            run_name=relative.split(os.sep, 1)[0]
            match=re.match(r"rate-(\d+)m(?:-|$)", run_name)
            samples.append({"path":relative, "requested_rate_mbps":int(match.group(1)) if match else None,
                            "offered_mbps":d.get("sent_mbps"),
                            "received_mbps":d.get("received_mbps"), "loss_percent":d.get("udp_loss_percent"),
                            "tun_drops":d.get("tun_drops"), "acceptance_pass":d.get("acceptance_pass")})
    except Exception:
        pass
samples.sort(key=lambda x: x["offered_mbps"] or 0)
best=max(samples, key=lambda x: x["received_mbps"] or 0) if samples else None
first_rejected=min((x["requested_rate_mbps"] for x in samples if x["acceptance_pass"] is False and x["requested_rate_mbps"] is not None), default=None)
outcomes={}
for x in samples:
    if x["requested_rate_mbps"] is not None:
        outcomes.setdefault(x["requested_rate_mbps"],set()).add(bool(x["acceptance_pass"]))
acceptance_variability=any(len(v)>1 for v in outcomes.values())
non_monotonic=first_rejected is not None and any(x["acceptance_pass"] is True and x["requested_rate_mbps"] > first_rejected for x in samples)
non_monotonic=non_monotonic or acceptance_variability
summary={"schema_version":1,"search_status":status,"boundary_status":boundary_status,"sustainable_rate_lower_bound_mbps":int(low),
         "first_rejected_rate_mbps":int(high),"run_count":int(runs),"boundary_confirmation_run_count":int(confirmation_runs),
         "offload_mode":offload,
         "overload_sample_count":int(overload_runs),"delivered_throughput_plateau_found":plateau_found == "true",
         "non_monotonic_acceptance_observed":non_monotonic,
         "acceptance_variability_at_same_rate_observed":acceptance_variability,
         "max_udp_loss_percent":float(threshold),"highest_valid_received_sample":best,
         "maximum_found":plateau_found == "true","samples":samples}
with open(os.path.join(root,"search-summary.json"),"w") as f:
    json.dump(summary,f,indent=2,sort_keys=True); f.write("\n")
print(json.dumps({k:v for k,v in summary.items() if k != "samples"},sort_keys=True))
PY
  done
done

echo "UDP capacity searches completed. A maximum delivered rate is established only when delivered_throughput_plateau_found is true; otherwise report a bound or unresolved search. Results: $OUT_DIR"
