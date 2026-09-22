#!/usr/bin/env bash
# ==============================================================================
# Deep Perf Session Analysis: Stats OFF vs Stats ON
# Captures perf stat hardware counters and perf record callgraphs
# ==============================================================================
set -euo pipefail

REPO_DIR="/Users/antongrizli/Documents/MikroTik/tayga-clat-perf"
OUT_DIR="$REPO_DIR/perf-sessions/profile-analysis-arm64"
mkdir -p "$OUT_DIR"

echo "============================================================"
echo " Starting Deep Perf Session Profiling"
echo " Environment: Debian 13 ARM64 (Lima VM)"
echo "============================================================"

# 1. Build Candidate A (Stats OFF)
echo "--> Building Candidate A (Stats OFF: -DSTATS_DISABLED)..."
cd "$REPO_DIR"
make clean
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer -DSTATS_DISABLED' LDFLAGS='-flto -Wl,--build-id'
cp tayga "$OUT_DIR/tayga-stats-off"

# 2. Build Candidate B (Stats ON)
echo "--> Building Candidate B (Stats ON: Batched Telemetry)..."
make clean
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer' LDFLAGS='-flto -Wl,--build-id'
cp tayga "$OUT_DIR/tayga-stats-on"

# Install benchmark scripts
sudo install -Dm0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh
sudo install -Dm0755 scripts/container/tayga-status.sh /usr/local/sbin/tayga-status
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh

run_perf_profile() {
    local candidate_bin="$1"
    local cand_name="$2"
    local case_dir="$OUT_DIR/${cand_name}"
    mkdir -p "$case_dir"

    echo "------------------------------------------------------------"
    echo " Profiling Candidate: ${cand_name}"
    echo "------------------------------------------------------------"
    sudo install -m0755 "$candidate_bin" /usr/sbin/tayga

    # Run benchmark in stat mode to get HW counters
    sudo env \
      CLAT_OFFLOAD="tcp" \
      RATE="" \
      CLIENTS=20 \
      FLOWS=1 \
      DURATION=15 \
      WARMUP=5 \
      DIRECTIONS="upload" \
      MAX_TUN_DROPS=100000 \
      PERF_MODE=stat \
      ARTIFACT_DIR="$case_dir-stat" \
      /usr/local/sbin/benchmark-clat.sh 2>&1 | tee "$case_dir-stat.log"

    # Run benchmark in record mode to get callgraph breakdown
    sudo env \
      CLAT_OFFLOAD="tcp" \
      RATE="" \
      CLIENTS=20 \
      FLOWS=1 \
      DURATION=15 \
      WARMUP=5 \
      DIRECTIONS="upload" \
      MAX_TUN_DROPS=100000 \
      PERF_MODE=record \
      ARTIFACT_DIR="$case_dir-record" \
      /usr/local/sbin/benchmark-clat.sh 2>&1 | tee "$case_dir-record.log"

    # Process perf record report if perf.data exists
    if [ -f "$case_dir-record/upload/perf.data" ]; then
        sudo perf report -f -i "$case_dir-record/upload/perf.data" --stdio --no-children --max-stack=10 > "$case_dir-perf-report.txt" || true
    fi
}

run_perf_profile "$OUT_DIR/tayga-stats-off" "stats-off"
run_perf_profile "$OUT_DIR/tayga-stats-on"  "stats-on"

# Restore Candidate B as default binary
sudo install -m0755 "$OUT_DIR/tayga-stats-on" /usr/sbin/tayga

echo ""
echo "============================================================"
echo " Generating Perf Analysis Report"
echo "============================================================"

python3 - <<'EOF'
import json, os

out_dir = "/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/perf-sessions/profile-analysis-arm64"

def get_stat(path):
    with open(os.path.join(path, "upload", "result.json")) as f:
        return json.load(f)

stat_off = get_stat(f"{out_dir}/stats-off-stat")
stat_on  = get_stat(f"{out_dir}/stats-on-stat")

print("\n--- PERF STAT HARDWARE METRICS ---")
print(f"Stats OFF Throughput: {stat_off['received_mbps']/1000.0:.2f} Gbps")
print(f"Stats ON  Throughput: {stat_on['received_mbps']/1000.0:.2f} Gbps")
print(f"Stats OFF Metrics: {stat_off.get('perf_stat_metrics', {})}")
print(f"Stats ON  Metrics: {stat_on.get('perf_stat_metrics', {})}")

EOF
