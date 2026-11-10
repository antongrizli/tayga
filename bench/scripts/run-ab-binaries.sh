#!/usr/bin/env bash
# A/B of two tayga binaries with identical scripts/settings, alternating order.
# EXTRA_ENV="PROTOCOL=udp DATAGRAM_SIZE=64 WORKERS=3 ..." adds benchmark variables.
# usage: run-ab-binaries.sh BASE_BIN NEW_BIN [ROUNDS] ; run from a repo tree with build/benchmark-clat.sh
set -euo pipefail
BASE=$(readlink -f "$1"); NEW=$(readlink -f "$2"); ROUNDS=${3:-3}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${AB_OUT:-$HOME/ab-$(date +%H%M%S)}
sudo install -Dm0755 "$REPO/container/rootfs/usr/local/sbin/clat-start.sh" /usr/local/sbin/clat-start.sh
sudo install -Dm0755 "$REPO/container/rootfs/usr/local/sbin/tayga-status" /usr/local/sbin/tayga-status
sudo install -Dm0755 "$REPO/build/benchmark-clat.sh" /usr/local/sbin/benchmark-clat.sh
for r in $(seq "$ROUNDS"); do
  order="base new"; [ $((r % 2)) -eq 0 ] && order="new base"
  for v in $order; do
    bin=$BASE; [ "$v" = new ] && bin=$NEW
    sudo install -Dm0755 "$bin" /usr/sbin/tayga
    d="$OUT/$v-$r"; mkdir -p "$d"
    sudo env CLAT_OFFLOAD=${OFFLOAD:-tcp} RATE="" CLIENTS=${CLIENTS:-8} FLOWS=1 DURATION=${DURATION:-10} \
      WARMUP=3 DIRECTIONS="upload download" MAX_TUN_DROPS=100000 PERF_MODE=none ARTIFACT_DIR="$d" ${EXTRA_ENV:-} \
      /usr/local/sbin/benchmark-clat.sh > "$d.log" 2>&1 || echo "run $v-$r failed"
  done
done
python3 - "$OUT" <<'P'
import json,sys,glob,os,statistics as st
out=sys.argv[1]; res={}
for d in sorted(glob.glob(out+"/*-*/")):
    v=os.path.basename(d.rstrip("/")).split("-")[0]
    for dr in ("upload","download"):
        p=f"{d}{dr}/result.json"
        if os.path.exists(p):
            j=json.load(open(p)); res.setdefault((v,dr),[]).append((j.get("received_mbps",0),j.get("tayga_cpu_cores",0)))
for (v,dr),l in sorted(res.items()):
    print(v,dr,"n=%d Mbps med=%.0f"%(len(l),st.median(x[0] for x in l)),"cpu med=%.2f"%st.median(x[1] for x in l),[round(x[0]) for x in l])
P
echo "out: $OUT"
