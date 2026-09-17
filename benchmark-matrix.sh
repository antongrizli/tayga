#!/bin/sh
# Run a reproducible worker/payload matrix around benchmark-clat.sh.
set -u

CLIENTS=${CLIENTS:-10}
RATE=${RATE:-10M}
DURATION=${DURATION:-10}
WARMUP=${WARMUP:-2}
PROTOCOL=${PROTOCOL:-udp}
DIRECTION=${DIRECTION:-download}
PAYLOADS=${PAYLOADS:-"64 256 512 1200"}
WORKERS_LIST=${WORKERS_LIST:-"0 1 2 3"}
MATRIX_DIR=${MATRIX_DIR:-/tmp/tayga-clat-matrix}
MAX_TUN_DROPS=${MAX_TUN_DROPS:-0}
MAX_UDP_LOSS_PERCENT=${MAX_UDP_LOSS_PERCENT:-0}

mkdir -p "$MATRIX_DIR"
printf 'workers\tpayload\tstatus\tresult\n' > "$MATRIX_DIR/summary.tsv"
status=0

for workers in $WORKERS_LIST; do
  for payload in $PAYLOADS; do
    run_name="workers-${workers}-payload-${payload}"
    run_dir="$MATRIX_DIR/$run_name"
    mkdir -p "$run_dir"
    printf 'MATRIX workers=%s payload=%s\n' "$workers" "$payload"
    if CLIENTS="$CLIENTS" RATE="$RATE" DURATION="$DURATION" WARMUP="$WARMUP" \
       WORKERS="$workers" PROTOCOL="$PROTOCOL" DIRECTIONS="$DIRECTION" \
       DATAGRAM_SIZE="$payload" MAX_TUN_DROPS="$MAX_TUN_DROPS" \
       MAX_UDP_LOSS_PERCENT="$MAX_UDP_LOSS_PERCENT" ARTIFACT_DIR="$run_dir" \
       /usr/local/sbin/benchmark-clat.sh >"$run_dir/stdout.log" 2>"$run_dir/stderr.log"; then
      run_status=pass
    else
      run_status=invalid
      status=1
    fi
    result_file=$(find "$run_dir" -type f -name result.json | head -n 1)
    if test -n "$result_file"; then
      result=$(python3 - "$result_file" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
fields = ("tayga_cpu_cores", "router_rclat_packets_per_second", "received_mbps",
          "udp_loss_percent", "tun_drops")
print(" ".join(f"{key}={doc[key]}" for key in fields if key in doc))
PY
      )
    else
      result=missing-result
    fi
    printf '%s\t%s\t%s\t%s\n' "$workers" "$payload" "$run_status" "$result" >> "$MATRIX_DIR/summary.tsv"
    cat "$run_dir/stdout.log"
  done
done

cat "$MATRIX_DIR/summary.tsv"
exit "$status"
