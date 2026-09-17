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
limactl shell "$INSTANCE" -- bash "$REPO/tools/lima-perf/run-guest.sh"
