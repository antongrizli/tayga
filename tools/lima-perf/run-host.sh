#!/usr/bin/env bash
set -euo pipefail

INSTANCE="${INSTANCE:-tayga-perf}"
PROJECT="${PROJECT:-/Users/antongrizli/Documents/MikroTik}"
REPO="${REPO:-$PROJECT/tayga-clat-perf}"
ISO="${ISO:-/Users/antongrizli/Downloads/debian-13.7.0-arm64-netinst.iso}"
CPUS="${CPUS:-4}"
MEMORY_GB="${MEMORY_GB:-4}"
DISK_GB="${DISK_GB:-24}"
VM_TYPE="${VM_TYPE:-vz}"
SESSION_STAMP="${SESSION_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
GIT_REVISION="${GIT_REVISION:-$(git -C "$REPO" rev-parse HEAD 2>/dev/null || printf unknown)}"

if ! command -v limactl >/dev/null 2>&1; then
  echo "limactl is required (install Lima with Homebrew)." >&2
  exit 127
fi
if [ ! -d "$REPO" ]; then
  echo "Repository not found: $REPO" >&2
  exit 1
fi
if [ -f "$ISO" ]; then
  echo "Found Debian installer ISO: $ISO"
  echo "Lima uses the signed Debian cloud template for unattended setup; the ISO is retained for a manual UTM install."
else
  echo "Warning: installer ISO not found at $ISO" >&2
fi

status="$(limactl list 2>/dev/null | awk -v n="$INSTANCE" 'NR > 1 && $1 == n { print $2; exit }')"
if [ -z "$status" ]; then
  echo "Creating ARM64 Debian 13 VM: $INSTANCE"
  limactl start --yes --name="$INSTANCE" --arch=aarch64 --vm-type="$VM_TYPE" \
    --cpus="$CPUS" --memory="$MEMORY_GB" --disk="$DISK_GB" \
    --mount="$PROJECT:w" template:debian-13
elif [ "$status" != "Running" ]; then
  echo "Starting existing VM: $INSTANCE"
  limactl start "$INSTANCE"
fi

echo "Running guest perf workflow"
# This workflow is noninteractive. Preserve stdin for any calling matrix script.
limactl shell "$INSTANCE" -- env \
  "REPO=$REPO" "PROJECT=$PROJECT" \
  "SESSION_STAMP=$SESSION_STAMP" "GIT_REVISION=$GIT_REVISION" \
  "CLIENTS=${CLIENTS:-20}" "FLOWS=${FLOWS:-1}" "WORKERS=${WORKERS:-3}" \
  "CLAT_OFFLOAD=${CLAT_OFFLOAD:-auto}" "CLAT_OFFLINK_MTU=${CLAT_OFFLINK_MTU:-1280}" \
  "FORWARDING_GRO=${FORWARDING_GRO:-off}" \
  "PERF_SCOPE=${PERF_SCOPE:-process}" \
  "PACING_TIMER_US=${PACING_TIMER_US:-1000}" \
  "FQ_RATE=${FQ_RATE:-0}" \
  "SOCKET_BUFFER_BYTES=${SOCKET_BUFFER_BYTES:-0}" \
  "SENDER_FQ=${SENDER_FQ:-off}" \
  "SENDER_FQ_FLOW_LIMIT=${SENDER_FQ_FLOW_LIMIT:-100}" \
  "SENDER_FQ_LIMIT=${SENDER_FQ_LIMIT:-10000}" \
  "VETH_QUEUES=${VETH_QUEUES:-0}" \
  "SENDER_FQ_TOPOLOGY=${SENDER_FQ_TOPOLOGY:-auto}" \
  "TAYGA_CPUSET=${TAYGA_CPUSET:-all}" \
  "CLIENT_CPUSET=${CLIENT_CPUSET:-all}" \
  "SERVER_CPUSET=${SERVER_CPUSET:-all}" \
  "SOCKET_SAMPLE_INTERVAL=${SOCKET_SAMPLE_INTERVAL:-1}" \
  "IPERF_START_GATE=${IPERF_START_GATE:-on}" \
  "RECEIVER_DRAIN_SECONDS=${RECEIVER_DRAIN_SECONDS:-0.5}" \
  "PROTOCOL=${PROTOCOL:-tcp}" "RATE=${RATE:-0}" \
  "DURATION=${DURATION:-60}" "WARMUP=${WARMUP:-10}" \
  "DIRECTIONS=${DIRECTIONS:-download}" "MAX_TUN_DROPS=${MAX_TUN_DROPS:-0}" \
  "MAX_UDP_LOSS_PERCENT=${MAX_UDP_LOSS_PERCENT:-0}" "TUN_TXQLEN=${TUN_TXQLEN-1000}" \
  "MAX_PING_LOSS_PERCENT=${MAX_PING_LOSS_PERCENT:-0}" \
  "PERF_MODES=${PERF_MODES:-stat record}" \
  "DATAGRAM_SIZE=${DATAGRAM_SIZE:-1200}" "BLOCK_SIZE=${BLOCK_SIZE-}" \
  bash -c '
    task_runner=$(mktemp /tmp/tayga-perf-runner.XXXXXX)
    cp "$1" "$task_runner" || exit
    bash "$task_runner"
    task_status=$?
    rm -f "$task_runner"
    exit "$task_status"
  ' bash "$REPO/tools/lima-perf/run-guest.sh" < /dev/null

SESSION_DIR="$REPO/perf-sessions/$SESSION_STAMP-lima-debian13-arm64"
if [ -d "$SESSION_DIR" ]; then
  printf 'requested_revision=%s\n' "$GIT_REVISION" > "$SESSION_DIR/host-request.txt"
fi
