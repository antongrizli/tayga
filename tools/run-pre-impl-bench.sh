#!/usr/bin/env bash
# ==============================================================================
# Pre-Implementation Maximum Speed Baseline Benchmark
# Executes unthrottled A/B benchmark (offload=off vs offload=tcp) on Debian ARM64 VM
# ==============================================================================
set -euo pipefail

REPO_DIR="/Users/antongrizli/Documents/MikroTik/tayga-clat-perf"
OUT_DIR="$REPO_DIR/perf-sessions/pre-impl-saturation-arm64"
mkdir -p "$OUT_DIR/baseline-off" "$OUT_DIR/gso-tcp"

echo "============================================================"
echo " Starting Pre-Implementation Baseline Saturation Benchmark"
echo " Date: $(date -u)"
echo " Environment: Debian 13 ARM64 (Lima VM)"
echo "============================================================"

# 1. Build and install latest tree in VM
echo "--> 1. Building current TAYGA binary in VM..."
cd "$REPO_DIR"
make clean
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer' LDFLAGS='-flto -Wl,--build-id'

sudo install -Dm0755 tayga /usr/sbin/tayga
sudo install -Dm0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh

# Record system metadata
uname -a > "$OUT_DIR/uname.txt"
lscpu > "$OUT_DIR/lscpu.txt"
sha256sum /usr/sbin/tayga > "$OUT_DIR/tayga.sha256"
git rev-parse HEAD > "$OUT_DIR/git-revision.txt"

# 2. Run Candidate A: Baseline (CLAT_OFFLOAD=off)
echo ""
echo "============================================================"
echo "--> 2. Running Candidate A: Baseline (CLAT_OFFLOAD=off, RATE=unlimited)"
echo "============================================================"
sudo env \
  CLAT_OFFLOAD=off \
  RATE="" \
  CLIENTS=20 \
  FLOWS=1 \
  DURATION=20 \
  WARMUP=5 \
  DIRECTIONS="upload download" \
  MAX_TUN_DROPS=100000 \
  PERF_MODE=stat \
  ARTIFACT_DIR="$OUT_DIR/baseline-off" \
  /usr/local/sbin/benchmark-clat.sh 2>&1 | tee "$OUT_DIR/baseline-off.log"

# 3. Run Candidate B: GSO (CLAT_OFFLOAD=tcp)
echo ""
echo "============================================================"
echo "--> 3. Running Candidate B: GSO Fast-Path (CLAT_OFFLOAD=tcp, RATE=unlimited)"
echo "============================================================"
sudo env \
  CLAT_OFFLOAD=tcp \
  RATE="" \
  CLIENTS=20 \
  FLOWS=1 \
  DURATION=20 \
  WARMUP=5 \
  DIRECTIONS="upload download" \
  MAX_TUN_DROPS=100000 \
  PERF_MODE=stat \
  ARTIFACT_DIR="$OUT_DIR/gso-tcp" \
  /usr/local/sbin/benchmark-clat.sh 2>&1 | tee "$OUT_DIR/gso-tcp.log"

# 4. Generate comparison summary
echo ""
echo "============================================================"
echo " Generating Comparison Summary..."
echo "============================================================"

python3 - <<'PY'
import json, os, sys

out_dir = "/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/perf-sessions/pre-impl-saturation-arm64"
base_dir = os.path.join(out_dir, "baseline-off")
gso_dir = os.path.join(out_dir, "gso-tcp")

def load_res(d, direction):
    p = os.path.join(d, direction, "result.json")
    if os.path.exists(p):
        return json.load(open(p))
    return {}

base_up = load_res(base_dir, "upload")
base_dl = load_res(base_dir, "download")
gso_up = load_res(gso_dir, "upload")
gso_dl = load_res(gso_dir, "download")

report_md = f"""# Pre-Implementation Baseline Saturation Benchmark (Debian ARM64)

> Date: $(date -u)
> Environment: Debian 13 ARM64 (Lima VM tayga-perf)
> Parameters: 20 clients, 1 flow/client, RATE=unlimited, 20s test + 5s warmup

## Results Summary

| Direction | Metric | Candidate A (offload=off) | Candidate B (offload=tcp) | Δ / Improvement |
| :--- | :--- | :--- | :--- | :--- |
| **Upload (IPv4 -> IPv6)** | **Goodput** | **{base_up.get('received_mbps', 0)/1000:.2f} Gbps** | **{gso_up.get('received_mbps', 0)/1000:.2f} Gbps** | **+{((gso_up.get('received_mbps', 1)/(base_up.get('received_mbps', 1) or 1)) - 1)*100:.1f}%** |
| | **TAYGA CPU** | {base_up.get('tayga_cpu_cores', 0):.3f} cores | {gso_up.get('tayga_cpu_cores', 0):.3f} cores | {((gso_up.get('tayga_cpu_cores', 0)/(base_up.get('tayga_cpu_cores', 1) or 1)) - 1)*100:.1f}% |
| | **Efficiency** | {base_up.get('tayga_core_per_gbps', 0):.3f} cores/Gbps | {gso_up.get('tayga_core_per_gbps', 0):.3f} cores/Gbps | {((gso_up.get('tayga_core_per_gbps', 0)/(base_up.get('tayga_core_per_gbps', 1) or 1)) - 1)*100:.1f}% |
| | **TUN Drops** | {base_up.get('tun_drops', 0)} | {gso_up.get('tun_drops', 0)} | |
| | **Retransmits**| {base_up.get('retransmits', 0)} | {gso_up.get('retransmits', 0)} | |
| **Download (IPv6 -> IPv4)**| **Goodput** | **{base_dl.get('received_mbps', 0)/1000:.2f} Gbps** | **{gso_dl.get('received_mbps', 0)/1000:.2f} Gbps** | **+{((gso_dl.get('received_mbps', 1)/(base_dl.get('received_mbps', 1) or 1)) - 1)*100:.1f}%** |
| | **TAYGA CPU** | {base_dl.get('tayga_cpu_cores', 0):.3f} cores | {gso_dl.get('tayga_cpu_cores', 0):.3f} cores | {((gso_dl.get('tayga_cpu_cores', 0)/(base_dl.get('tayga_cpu_cores', 1) or 1)) - 1)*100:.1f}% |
| | **Efficiency** | {base_dl.get('tayga_core_per_gbps', 0):.3f} cores/Gbps | {gso_dl.get('tayga_core_per_gbps', 0):.3f} cores/Gbps | {((gso_dl.get('tayga_core_per_gbps', 0)/(base_dl.get('tayga_core_per_gbps', 1) or 1)) - 1)*100:.1f}% |
| | **TUN Drops** | {base_dl.get('tun_drops', 0)} | {gso_dl.get('tun_drops', 0)} | |
| | **Retransmits**| {base_dl.get('retransmits', 0)} | {gso_dl.get('retransmits', 0)} | |
"""

with open(os.path.join(out_dir, "PRE-IMPL-BASELINE-REPORT.md"), "w") as f:
    f.write(report_md)

print(report_md)
PY

echo ""
echo "============================================================"
echo " Baseline Saturation Benchmark Complete!"
echo " Results written to $OUT_DIR/PRE-IMPL-BASELINE-REPORT.md"
echo "============================================================"
