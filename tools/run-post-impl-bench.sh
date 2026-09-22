#!/usr/bin/env bash
# ==============================================================================
# Post-Implementation Maximum Speed Saturation Benchmark
# Executes unthrottled A/B benchmark (offload=off vs offload=tcp) on Debian ARM64 VM
# ==============================================================================
set -euo pipefail

REPO_DIR="/Users/antongrizli/Documents/MikroTik/tayga-clat-perf"
OUT_DIR="$REPO_DIR/perf-sessions/post-impl-saturation-arm64"
mkdir -p "$OUT_DIR/baseline-off" "$OUT_DIR/gso-tcp"

echo "============================================================"
echo " Starting Post-Implementation Saturation Benchmark"
echo " Date: $(date -u)"
echo " Environment: Debian 13 ARM64 (Lima VM)"
echo "============================================================"

# 1. Build and install latest tree in VM
echo "--> 1. Building updated TAYGA binary in VM..."
cd "$REPO_DIR"
make clean
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer' LDFLAGS='-flto -Wl,--build-id'

sudo install -Dm0755 tayga /usr/sbin/tayga
sudo install -Dm0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh
sudo install -Dm0755 scripts/container/tayga-status.sh /usr/local/sbin/tayga-status
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
  PERF_MODE=${PERF_MODE:-none} \
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
  PERF_MODE=${PERF_MODE:-none} \
  ARTIFACT_DIR="$OUT_DIR/gso-tcp" \
  /usr/local/sbin/benchmark-clat.sh 2>&1 | tee "$OUT_DIR/gso-tcp.log"

# 4. Generate Post-Implementation Report & Comparison
echo ""
echo "============================================================"
echo "--> 4. Generating Comparison Summary..."
echo "============================================================"

python3 - <<'EOF'
import json, os, sys

def parse_run(d):
    up_path = os.path.join(d, "upload", "result.json")
    dn_path = os.path.join(d, "download", "result.json")
    if not os.path.exists(up_path):
        raise FileNotFoundError(f"Missing expected upload result: {up_path}")
    if not os.path.exists(dn_path):
        raise FileNotFoundError(f"Missing expected download result: {dn_path}")
    with open(up_path) as f:
        up = json.load(f)
    with open(dn_path) as f:
        dn = json.load(f)
    return {"upload": up, "download": dn}

repo = "/Users/antongrizli/Documents/MikroTik/tayga-clat-perf"
pre_off = parse_run(f"{repo}/perf-sessions/pre-impl-saturation-arm64/baseline-off")
pre_tcp = parse_run(f"{repo}/perf-sessions/pre-impl-saturation-arm64/gso-tcp")

post_off = parse_run(f"{repo}/perf-sessions/post-impl-saturation-arm64/baseline-off")
post_tcp = parse_run(f"{repo}/perf-sessions/post-impl-saturation-arm64/gso-tcp")

def get_row(label, s):
    up = s["upload"]
    dn = s["download"]
    up_bw = up.get("received_mbps", 0) / 1000.0
    dn_bw = dn.get("received_mbps", 0) / 1000.0
    up_cpu = up.get("tayga_cpu_cores", 0.0)
    dn_cpu = dn.get("tayga_cpu_cores", 0.0)
    up_drops = up.get("tun_drops", 0)
    dn_drops = dn.get("tun_drops", 0)
    up_eff = up_cpu / up_bw if up_bw > 0 else 0
    dn_eff = dn_cpu / dn_bw if dn_bw > 0 else 0
    return f"| {label} | {up_bw:.2f} Gbps ({up_drops} drops, {up_eff:.3f} c/Gbps) | {dn_bw:.2f} Gbps ({dn_drops} drops, {dn_eff:.3f} c/Gbps) | {up_cpu:.3f} cores | {dn_cpu:.3f} cores |"

# Regression checks against pre-implementation numbers
tolerance_pct = float(os.environ.get("BENCHMARK_TOLERANCE_PCT", "-5.0"))

base_up_pre = pre_off["upload"]["received_mbps"]
base_up_post = post_off["upload"]["received_mbps"]
base_up_delta = ((base_up_post - base_up_pre) / base_up_pre) * 100.0

base_dn_pre = pre_off["download"]["received_mbps"]
base_dn_post = post_off["download"]["received_mbps"]
base_dn_delta = ((base_dn_post - base_dn_pre) / base_dn_pre) * 100.0

gso_up_pre = pre_tcp["upload"]["received_mbps"]
gso_up_post = post_tcp["upload"]["received_mbps"]
gso_up_delta = ((gso_up_post - gso_up_pre) / gso_up_pre) * 100.0

gso_dn_pre = pre_tcp["download"]["received_mbps"]
gso_dn_post = post_tcp["download"]["received_mbps"]
gso_dn_delta = ((gso_dn_post - gso_dn_pre) / gso_dn_pre) * 100.0

regressions = []
if base_up_delta < tolerance_pct:
    regressions.append(f"Baseline upload degraded by {base_up_delta:.1f}% (< {tolerance_pct}%)")
if base_dn_delta < tolerance_pct:
    regressions.append(f"Baseline download degraded by {base_dn_delta:.1f}% (< {tolerance_pct}%)")
if gso_up_delta < tolerance_pct:
    regressions.append(f"GSO upload degraded by {gso_up_delta:.1f}% (< {tolerance_pct}%)")
if gso_dn_delta < tolerance_pct:
    regressions.append(f"GSO download degraded by {gso_dn_delta:.1f}% (< {tolerance_pct}%)")

if regressions:
    verdict = "**REGRESSION DETECTED (Exceeds tolerance):** " + "; ".join(regressions)
else:
    verdict = (
        f"**Measured Deltas (Relative to pre-implementation):**\n"
        f"- Baseline Upload: {base_up_delta:+.1f}%\n"
        f"- Baseline Download: {base_dn_delta:+.1f}%\n"
        f"- GSO Fast-Path Upload: {gso_up_delta:+.1f}%\n"
        f"- GSO Fast-Path Download: {gso_dn_delta:+.1f}%"
    )

report_md = f"""# Post-Implementation Saturation Benchmark & Pre/Post Comparison

- **Environment:** Debian 13 ARM64 (Lima VM on Apple Silicon)
- **Workload:** 20 parallel TCP streams, unthrottled maximum throughput
- **Test Duration:** 20s per direction (warmup 5s)

## Saturation Benchmark Comparison Table

| Session / Mode | Upload (IPv4 -> IPv6) | Download (IPv6 -> IPv4) | Upload CPU | Download CPU |
| :--- | :--- | :--- | :--- | :--- |
{get_row("**Pre-Impl Baseline (offload=off)**", pre_off)}
{get_row("**Post-Impl Baseline (offload=off)**", post_off)}
{get_row("**Pre-Impl GSO (offload=tcp)**", pre_tcp)}
{get_row("**Post-Impl GSO (offload=tcp)**", post_tcp)}

## Analysis & Regression Check
- **Baseline Offload (MTU 1500):** Validates standard translation path overhead with added lock-free packet counters.
- **GSO Fast-Path (64KB superpackets):** Validates zero-copy GSO acceleration path with lock-free atomic counters.
- **Regression Verdict:**
{verdict}
"""

with open(f"{repo}/perf-sessions/post-impl-saturation-arm64/POST-IMPL-REPORT.md", "w") as f:
    f.write(report_md)

print(report_md)
if regressions:
    sys.exit(1)
EOF
