#!/usr/bin/env bash
set -euo pipefail

PROJECT="${PROJECT:-/Users/antongrizli/Documents/MikroTik}"
REPO="${REPO:-$PROJECT/tayga-clat-perf}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SESSION_ROOT="${SESSION_ROOT:-/tmp/tayga-perf-sessions/$STAMP-lima-debian13-arm64}"
BUILD_ROOT="${BUILD_ROOT:-$(mktemp -d /tmp/tayga-clat-perf-build.XXXXXX)}"
PERF_MODES="${PERF_MODES:-stat record}"

if [ ! -d "$REPO" ]; then
  echo "Mounted repository not found: $REPO" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y build-essential gcc make binutils iproute2 iperf3 nftables procps python3 jq git ca-certificates python3-scapy
if ! command -v perf >/dev/null 2>&1; then
  sudo apt-get install -y linux-perf || sudo apt-get install -y perf
fi
command -v perf >/dev/null 2>&1 || { echo "Linux perf is unavailable in this guest" >&2; exit 1; }

sudo sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
sudo sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1 || true

mkdir -p "$BUILD_ROOT"
cp -a "$REPO"/. "$BUILD_ROOT"/
cd "$BUILD_ROOT"
make -B CC=gcc CFLAGS='-O3 -flto -g -fno-omit-frame-pointer' LDFLAGS='-flto -Wl,--build-id'
sudo install -Dm0755 tayga /usr/sbin/tayga
sudo install -Dm0755 "$PROJECT/telekom-nat64-minimal/clat-start.sh" /usr/local/sbin/clat-start.sh
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh

mkdir -p "$SESSION_ROOT"
uname -a > "$SESSION_ROOT/uname.txt"
lscpu > "$SESSION_ROOT/lscpu.txt"
gcc --version > "$SESSION_ROOT/compiler.txt"
perf --version > "$SESSION_ROOT/perf-version.txt"
perf list > "$SESSION_ROOT/perf-list.txt" 2>&1 || true
sha256sum tayga > "$SESSION_ROOT/tayga.sha256"
if git -C "$REPO" rev-parse HEAD > "$SESSION_ROOT/git-revision.txt" 2>/dev/null; then
  git -C "$REPO" diff --binary > "$SESSION_ROOT/source.patch" || true
else
  printf '%s\n' 'Repository is not a Git worktree.' > "$SESSION_ROOT/git-revision.txt"
fi

run_case() {
  local mode="$1"
  local case_dir="$SESSION_ROOT/$mode"
  mkdir -p "$case_dir"
  echo "Starting PERF_MODE=$mode; artifacts: $case_dir"
  sudo env ARTIFACT_DIR="$case_dir" PERF_MODE="$mode" \
    CLIENTS="${CLIENTS:-20}" FLOWS="${FLOWS:-1}" WORKERS="${WORKERS:-3}" \
    PROTOCOL="${PROTOCOL:-tcp}" RATE="${RATE-15M}" \
    DURATION="${DURATION:-60}" WARMUP="${WARMUP:-10}" \
    DIRECTIONS="${DIRECTIONS:-download}" MAX_TUN_DROPS="${MAX_TUN_DROPS:-0}" \
    TUN_TXQLEN="${TUN_TXQLEN:-1000}" \
    /usr/local/sbin/benchmark-clat.sh
}

overall_status=0
for mode in $PERF_MODES; do
  case "$mode" in
    none|stat|record) run_case "$mode" || overall_status=1;;
    *) echo "PERF_MODES contains unsupported mode: $mode" >&2; overall_status=64;;
  esac
done

record_data=""
if [ -d "$SESSION_ROOT/record" ]; then
  record_data="$(find "$SESSION_ROOT/record" -name perf.data -type f | head -1 || true)"
fi
if [ -n "$record_data" ]; then
  report_status=0
  sudo perf report --stdio --children --percent-limit 0.1 -i "$record_data" > "$SESSION_ROOT/perf-report.txt" 2>&1 || report_status=$?
  printf '%s\n' "$report_status" > "$SESSION_ROOT/perf-report-status"
  script_status=0
  sudo perf script -i "$record_data" > "$SESSION_ROOT/perf-script.txt" 2>&1 || script_status=$?
  printf '%s\n' "$script_status" > "$SESSION_ROOT/perf-script-status"
  sudo cp "$record_data" "$SESSION_ROOT/perf.data"
  sudo chown "$(id -u):$(id -g)" "$SESSION_ROOT/perf.data" "$SESSION_ROOT/perf-report.txt" "$SESSION_ROOT/perf-script.txt" 2>/dev/null || true
fi

find "$SESSION_ROOT" -maxdepth 3 -type f -printf '%P\n' | sort > "$SESSION_ROOT/file-list.txt"
HOST_RESULTS="$REPO/perf-sessions/$STAMP-lima-debian13-arm64"
if mkdir -p "$HOST_RESULTS" 2>/dev/null && cp -a "$SESSION_ROOT"/. "$HOST_RESULTS"/ 2>/dev/null; then
  echo "Perf session copied to host mount: $HOST_RESULTS"
else
  echo "Perf session remains in guest: $SESSION_ROOT"
fi
echo "Perf session complete: $SESSION_ROOT"
exit "$overall_status"
