#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$REPO/perf-sessions/$STAMP-udp-eval-lima"
mkdir -p "$OUT_DIR"

# The benchmark starter launches this installed binary. Build and install from
# this checkout before recording its source identity so results cannot silently
# describe an older system binary.
make -B VERSION="${TAYGA_VERSION:-0.9.12}"
sudo install -D -m 0755 tayga /usr/sbin/tayga
sudo install -D -m 0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh

GIT_REVISION="$(git -C "$REPO" rev-parse HEAD)"
SOURCE_TREE_SHA256="$(git -C "$REPO" ls-files -co --exclude-standard -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"

echo "=== Starting UDP Rate Ladder & Payload Matrix Benchmark ==="
echo "Artifacts will be written to: $OUT_DIR"

SIZES=(64 256 512 1200)

for size in "${SIZES[@]}"; do
  if [ "$size" -eq 64 ]; then
    rates=(2M 5M 10M 15M 20M)
  elif [ "$size" -eq 256 ]; then
    rates=(10M 25M 50M 75M)
  elif [ "$size" -eq 512 ]; then
    rates=(25M 50M 75M 100M)
  else
    rates=(50M 100M 150M 200M)
  fi

  for per_flow in "${rates[@]}"; do
    total_rate="$(awk -v n="$per_flow" 'BEGIN { sub(/M$/, "", n); printf "%.0f", n * 20 }')"
    case_name="sz${size}_rate${total_rate}m"
    case_dir="$OUT_DIR/$case_name"
    mkdir -p "$case_dir"
    echo "--- Running payload=${size}B, offered load=${total_rate}Mbps aggregate (${per_flow} x 20 clients) ---"
    sudo env ARTIFACT_DIR="$case_dir" PERF_MODE=none \
      GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
      CLIENTS=20 FLOWS=1 WORKERS=3 \
      CLAT_OFFLOAD=auto CLAT_OFFLINK_MTU=1280 \
      PROTOCOL=udp RATE="$per_flow" \
      DURATION=15 WARMUP=0 \
      DIRECTIONS="upload download" MAX_TUN_DROPS=0 \
      MAX_UDP_LOSS_PERCENT=0 TUN_TXQLEN=1000 \
      DATAGRAM_SIZE="$size" \
      "$REPO/benchmark-clat.sh" || true
  done
done

echo "=== Matrix Benchmark Completed! Summary of Results: ==="
python3 - "$OUT_DIR" <<'PY'
import glob, json, os, sys
out_dir = sys.argv[1]
results = []
for p in sorted(glob.glob(os.path.join(out_dir, "**", "result.json"), recursive=True)):
    try:
        doc = json.load(open(p))
        doc["_dir"] = os.path.basename(os.path.dirname(p))
        doc["_case"] = os.path.basename(os.path.dirname(os.path.dirname(p)))
        results.append(doc)
    except Exception:
        pass

print(f"{'Case':<16} {'Dir':<9} {'Sz':<5} {'Req(M)':<7} {'Rcv(M)':<8} {'Loss%':<7} {'TUN Drop%':<10} {'UDP rx pps':<11} {'CPU':<6} {'Valid':<6}")
print("-" * 90)
best = {}
for r in results:
    case = r.get("_case", "")
    direction = r.get("direction", "")
    sz = r.get("datagram_size", "")
    sent = r.get("sent_mbps", 0)
    rcv = r.get("received_mbps", 0)
    loss = r.get("udp_loss_percent", 0)
    tun_drop = r.get("tun_tx_drop_percent", 0)
    pps = r.get("received_udp_packets_per_second", 0)
    cpu = r.get("tayga_cpu_cores", 0)
    valid = "PASS" if r.get("acceptance_pass") else ("DEGR" if r.get("capture_valid") and r.get("workload_valid") else "INVALID")
    print(f"{case:<16} {direction:<9} {sz:<5} {sent:<7.1f} {rcv:<8.1f} {loss:<7.3f} {tun_drop:<10.3f} {pps:<11.0f} {cpu:<6.2f} {valid:<6}")
    if r.get("capture_valid") and r.get("workload_valid"):
        key = (sz, direction)
        if key not in best or rcv > best[key][0]:
            best[key] = (rcv, case, loss)
print("\nHighest valid received throughput by payload and direction:")
for (sz, direction), (rate, case, loss) in sorted(best.items()):
    print(f"  {sz}B {direction}: {rate:.1f} Mbps in {case} (UDP loss {loss:.3f}%)")
PY
