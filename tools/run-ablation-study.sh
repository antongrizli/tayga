#!/usr/bin/env bash
# ==============================================================================
# Ablation Study: Stats OFF vs. Stats ON (Batched Lock-Free)
# Multi-pass alternating order (A/B, B/A) with PERF_MODE=none
# ==============================================================================
set -euo pipefail

REPO_DIR="/Users/antongrizli/Documents/MikroTik/tayga-clat-perf"
OUT_DIR="$REPO_DIR/perf-sessions/ablation-study-arm64"
mkdir -p "$OUT_DIR"

echo "============================================================"
echo " Starting Ablation Study: Stats OFF vs Stats ON (Batched)"
echo " Date: $(date -u)"
echo " Environment: Debian 13 ARM64 (Lima VM)"
echo " PERF_MODE: none (zero tracepoint distortion)"
echo "============================================================"

# 1. Build Candidate A (Stats OFF: no-op hooks)
echo "--> 1. Building Candidate A (Stats OFF: -DSTATS_DISABLED)..."
cd "$REPO_DIR"
make clean
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer -DSTATS_DISABLED' LDFLAGS='-flto -Wl,--build-id'
cp tayga "$OUT_DIR/tayga-stats-off"

# 2. Build Candidate B (Stats ON: batched per-worker stats + background telemetry)
echo "--> 2. Building Candidate B (Stats ON: Batched + Decoupled Telemetry)..."
make clean
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer' LDFLAGS='-flto -Wl,--build-id'
cp tayga "$OUT_DIR/tayga-stats-on"

# Install benchmark scripts
sudo install -Dm0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh
sudo install -Dm0755 scripts/container/tayga-status.sh /usr/local/sbin/tayga-status
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh

run_subcase() {
    local candidate_bin="$1"
    local cand_name="$2"
    local offload_mode="$3"
    local pass_num="$4"
    local case_dir="$OUT_DIR/pass${pass_num}-${cand_name}-${offload_mode}"
    mkdir -p "$case_dir"

    echo "------------------------------------------------------------"
    echo " Running Pass ${pass_num}: ${cand_name} (offload=${offload_mode})"
    echo "------------------------------------------------------------"
    sudo install -m0755 "$candidate_bin" /usr/sbin/tayga

    sudo env \
      CLAT_OFFLOAD="$offload_mode" \
      RATE="" \
      CLIENTS=20 \
      FLOWS=1 \
      DURATION=10 \
      WARMUP=3 \
      DIRECTIONS="upload download" \
      MAX_TUN_DROPS=100000 \
      PERF_MODE=none \
      ARTIFACT_DIR="$case_dir" \
      /usr/local/sbin/benchmark-clat.sh 2>&1 | tee "$case_dir.log"
}

# Pass configuration: 5 alternating A/B pairs
# Pass 1: OFF -> ON
# Pass 2: ON  -> OFF
# Pass 3: OFF -> ON
# Pass 4: ON  -> OFF
# Pass 5: OFF -> ON

for p in 1 2 3 4 5; do
    echo ""
    echo "============================================================"
    echo " Running Alternating Pass $p of 5"
    echo "============================================================"
    if [ $((p % 2)) -eq 1 ]; then
        echo "--> Order: Stats OFF first, then Stats ON"
        run_subcase "$OUT_DIR/tayga-stats-off" "stats-off" "off" "$p"
        run_subcase "$OUT_DIR/tayga-stats-off" "stats-off" "tcp" "$p"
        run_subcase "$OUT_DIR/tayga-stats-on"  "stats-on"  "off" "$p"
        run_subcase "$OUT_DIR/tayga-stats-on"  "stats-on"  "tcp" "$p"
    else
        echo "--> Order: Stats ON first, then Stats OFF"
        run_subcase "$OUT_DIR/tayga-stats-on"  "stats-on"  "tcp" "$p"
        run_subcase "$OUT_DIR/tayga-stats-on"  "stats-on"  "off" "$p"
        run_subcase "$OUT_DIR/tayga-stats-off" "stats-off" "tcp" "$p"
        run_subcase "$OUT_DIR/tayga-stats-off" "stats-off" "off" "$p"
    fi
done

# Restore Candidate B as standard installed binary
sudo install -m0755 "$OUT_DIR/tayga-stats-on" /usr/sbin/tayga

# ==============================================================================
# Analysis and Report Generation
# ==============================================================================
echo ""
echo "============================================================"
echo " Generating Ablation Study Comparison Report (5 Pairs)"
echo "============================================================"

python3 - <<'EOF'
import json, os, sys, math

def get_run(path):
    up_path = os.path.join(path, "upload", "result.json")
    dn_path = os.path.join(path, "download", "result.json")
    with open(up_path) as f:
        up = json.load(f)
    with open(dn_path) as f:
        dn = json.load(f)
    return {"upload": up, "download": dn}

out_dir = "/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/perf-sessions/ablation-study-arm64"

passes = [1, 2, 3, 4, 5]
cases = {
    "off_baseline": [get_run(f"{out_dir}/pass{p}-stats-off-off") for p in passes],
    "on_baseline":  [get_run(f"{out_dir}/pass{p}-stats-on-off")  for p in passes],
    "off_gso":      [get_run(f"{out_dir}/pass{p}-stats-off-tcp") for p in passes],
    "on_gso":       [get_run(f"{out_dir}/pass{p}-stats-on-tcp")  for p in passes],
}

def stats_summary(runs, direction):
    bws = [r[direction]["received_mbps"] / 1000.0 for r in runs]
    cpus = [r[direction]["tayga_cpu_cores"] for r in runs]
    effs = [c / b if b > 0 else 0 for c, b in zip(cpus, bws)]
    drops = [r[direction]["tun_drops"] for r in runs]
    
    mean_bw = sum(bws) / len(bws)
    std_bw = math.sqrt(sum((x - mean_bw)**2 for x in bws) / (len(bws) - 1)) if len(bws) > 1 else 0
    mean_cpu = sum(cpus) / len(cpus)
    std_cpu = math.sqrt(sum((x - mean_cpu)**2 for x in cpus) / (len(cpus) - 1)) if len(cpus) > 1 else 0
    mean_eff = sum(effs) / len(effs)
    std_eff = math.sqrt(sum((x - mean_eff)**2 for x in effs) / (len(effs) - 1)) if len(effs) > 1 else 0
    mean_drops = sum(drops) / len(drops)
    
    return {
        "bw_mean": mean_bw,
        "bw_std": std_bw,
        "cpu_mean": mean_cpu,
        "cpu_std": std_cpu,
        "eff_mean": mean_eff,
        "eff_std": std_eff,
        "drops": mean_drops,
        "raw_bw": bws
    }

metrics = {}
for k, runs in cases.items():
    metrics[f"{k}_up"] = stats_summary(runs, "upload")
    metrics[f"{k}_dn"] = stats_summary(runs, "download")

def fmt_cell(m):
    return f"{m['bw_mean']:.2f} ± {m['bw_std']:.2f} Gbps | {m['cpu_mean']:.2f}c ({m['eff_mean']:.3f} c/Gbps)"

report = f"""# Ablation Study: Lock-Free Batched Stats vs. Stats OFF (5 Alternating Pairs)

- **Environment:** Debian 13 ARM64 (Lima VM on Apple Silicon, 4 vCPUs, 4 GiB RAM)
- **Measurement Methodology:** `PERF_MODE=none` (eliminating `raw_syscalls:*` kernel tracepoint distortion)
- **Execution Order:** 5 alternating A/B passes (Pass 1, 3, 5: OFF -> ON; Pass 2, 4: ON -> OFF)
- **Workload:** 20 parallel TCP clients, unthrottled maximum throughput, 10s run + 3s warmup per test

## Measured Performance Comparison Table (N=5 Pairs)

| Scenario | Candidate A: Stats OFF (mean ± std) | Candidate B: Stats ON (mean ± std) | Net Delta (Throughput) | Net Delta (CPU Efficiency) |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline Upload** | {fmt_cell(metrics['off_baseline_up'])} | {fmt_cell(metrics['on_baseline_up'])} | {((metrics['on_baseline_up']['bw_mean'] - metrics['off_baseline_up']['bw_mean']) / metrics['off_baseline_up']['bw_mean']) * 100:+.2f}% | {((metrics['on_baseline_up']['eff_mean'] - metrics['off_baseline_up']['eff_mean']) / metrics['off_baseline_up']['eff_mean']) * 100:+.2f}% |
| **Baseline Download** | {fmt_cell(metrics['off_baseline_dn'])} | {fmt_cell(metrics['on_baseline_dn'])} | {((metrics['on_baseline_dn']['bw_mean'] - metrics['off_baseline_dn']['bw_mean']) / metrics['off_baseline_dn']['bw_mean']) * 100:+.2f}% | {((metrics['on_baseline_dn']['eff_mean'] - metrics['off_baseline_dn']['eff_mean']) / metrics['off_baseline_dn']['eff_mean']) * 100:+.2f}% |
| **GSO Upload** | {fmt_cell(metrics['off_gso_up'])} | {fmt_cell(metrics['on_gso_up'])} | {((metrics['on_gso_up']['bw_mean'] - metrics['off_gso_up']['bw_mean']) / metrics['off_gso_up']['bw_mean']) * 100:+.2f}% | {((metrics['on_gso_up']['eff_mean'] - metrics['off_gso_up']['eff_mean']) / metrics['off_gso_up']['eff_mean']) * 100:+.2f}% |
| **GSO Download** | {fmt_cell(metrics['off_gso_dn'])} | {fmt_cell(metrics['on_gso_dn'])} | {((metrics['on_gso_dn']['bw_mean'] - metrics['off_gso_dn']['bw_mean']) / metrics['off_gso_dn']['bw_mean']) * 100:+.2f}% | {((metrics['on_gso_dn']['eff_mean'] - metrics['off_gso_dn']['eff_mean']) / metrics['off_gso_dn']['eff_mean']) * 100:+.2f}% |

## Pass-by-Pass Raw Throughput (Gbps)

| Scenario | Candidate | Pass 1 | Pass 2 | Pass 3 | Pass 4 | Pass 5 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| Baseline Upload | Stats OFF | {metrics['off_baseline_up']['raw_bw'][0]:.2f} | {metrics['off_baseline_up']['raw_bw'][1]:.2f} | {metrics['off_baseline_up']['raw_bw'][2]:.2f} | {metrics['off_baseline_up']['raw_bw'][3]:.2f} | {metrics['off_baseline_up']['raw_bw'][4]:.2f} |
| Baseline Upload | Stats ON  | {metrics['on_baseline_up']['raw_bw'][0]:.2f} | {metrics['on_baseline_up']['raw_bw'][1]:.2f} | {metrics['on_baseline_up']['raw_bw'][2]:.2f} | {metrics['on_baseline_up']['raw_bw'][3]:.2f} | {metrics['on_baseline_up']['raw_bw'][4]:.2f} |
| Baseline Download | Stats OFF | {metrics['off_baseline_dn']['raw_bw'][0]:.2f} | {metrics['off_baseline_dn']['raw_bw'][1]:.2f} | {metrics['off_baseline_dn']['raw_bw'][2]:.2f} | {metrics['off_baseline_dn']['raw_bw'][3]:.2f} | {metrics['off_baseline_dn']['raw_bw'][4]:.2f} |
| Baseline Download | Stats ON  | {metrics['on_baseline_dn']['raw_bw'][0]:.2f} | {metrics['on_baseline_dn']['raw_bw'][1]:.2f} | {metrics['on_baseline_dn']['raw_bw'][2]:.2f} | {metrics['on_baseline_dn']['raw_bw'][3]:.2f} | {metrics['on_baseline_dn']['raw_bw'][4]:.2f} |
| GSO Upload | Stats OFF | {metrics['off_gso_up']['raw_bw'][0]:.2f} | {metrics['off_gso_up']['raw_bw'][1]:.2f} | {metrics['off_gso_up']['raw_bw'][2]:.2f} | {metrics['off_gso_up']['raw_bw'][3]:.2f} | {metrics['off_gso_up']['raw_bw'][4]:.2f} |
| GSO Upload | Stats ON  | {metrics['on_gso_up']['raw_bw'][0]:.2f} | {metrics['on_gso_up']['raw_bw'][1]:.2f} | {metrics['on_gso_up']['raw_bw'][2]:.2f} | {metrics['on_gso_up']['raw_bw'][3]:.2f} | {metrics['on_gso_up']['raw_bw'][4]:.2f} |
| GSO Download | Stats OFF | {metrics['off_gso_dn']['raw_bw'][0]:.2f} | {metrics['off_gso_dn']['raw_bw'][1]:.2f} | {metrics['off_gso_dn']['raw_bw'][2]:.2f} | {metrics['off_gso_dn']['raw_bw'][3]:.2f} | {metrics['off_gso_dn']['raw_bw'][4]:.2f} |
| GSO Download | Stats ON  | {metrics['on_gso_dn']['raw_bw'][0]:.2f} | {metrics['on_gso_dn']['raw_bw'][1]:.2f} | {metrics['on_gso_dn']['raw_bw'][2]:.2f} | {metrics['on_gso_dn']['raw_bw'][3]:.2f} | {metrics['on_gso_dn']['raw_bw'][4]:.2f} |
"""

report_file = os.path.join(out_dir, "ABLATION-REPORT.md")
with open(report_file, "w") as f:
    f.write(report)

print(report)
EOF
