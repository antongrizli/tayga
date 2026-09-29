#!/usr/bin/env bash
set -euo pipefail

PROJECT="${PROJECT:-/Users/antongrizli/Documents/MikroTik}"
REPO="${REPO:-$PROJECT/tayga-clat-perf}"
STAMP="${SESSION_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
if [ -z "${SESSION_ROOT:-}" ]; then
  SESSION_ROOT="/tmp/tayga-perf-sessions/$STAMP-lima-debian13-arm64"
  REMOVE_SESSION_ROOT=yes
else
  REMOVE_SESSION_ROOT=no
fi
if [ -z "${BUILD_ROOT:-}" ]; then
  BUILD_ROOT="$(mktemp -d /tmp/tayga-clat-perf-build.XXXXXX)"
  REMOVE_BUILD_ROOT=yes
else
  REMOVE_BUILD_ROOT=no
fi
PERF_MODES="${PERF_MODES:-stat record}"

cleanup_build_root() {
  if [ "$REMOVE_BUILD_ROOT" = yes ]; then
    rm -rf -- "$BUILD_ROOT"
  fi
}
trap cleanup_build_root EXIT

if [ ! -d "$REPO" ]; then
  echo "Mounted repository not found: $REPO" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y build-essential gcc make binutils iproute2 iperf3 nftables procps python3 jq git ca-certificates python3-scapy ethtool socat
if ! command -v perf >/dev/null 2>&1; then
  sudo apt-get install -y linux-perf || sudo apt-get install -y perf
fi
command -v perf >/dev/null 2>&1 || { echo "Linux perf is unavailable in this guest" >&2; exit 1; }

sudo sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
sudo sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1 || true

mkdir -p "$BUILD_ROOT"
tar -C "$REPO" \
  --exclude='./.git' --exclude='./perf-sessions' --exclude='./dist' \
  --exclude='./.codex' --exclude='./.agents' \
  -cf - . | tar -C "$BUILD_ROOT" -xf -
cd "$BUILD_ROOT"
BUILD_CFLAGS="-O3 -flto -g -fno-omit-frame-pointer -ffile-prefix-map=$BUILD_ROOT=."
BUILD_LDFLAGS='-flto -Wl,--build-id'
make -B CC=gcc CFLAGS="$BUILD_CFLAGS" LDFLAGS="$BUILD_LDFLAGS"
sudo install -Dm0755 tayga /usr/sbin/tayga
sudo install -Dm0755 "$REPO/scripts/container/clat-start.sh" /usr/local/sbin/clat-start.sh
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh

mkdir -p "$SESSION_ROOT"
uname -a > "$SESSION_ROOT/uname.txt"
lscpu > "$SESSION_ROOT/lscpu.txt"
gcc --version > "$SESSION_ROOT/compiler.txt"
perf --version > "$SESSION_ROOT/perf-version.txt"
perf list > "$SESSION_ROOT/perf-list.txt" 2>&1 || true
sha256sum tayga > "$SESSION_ROOT/tayga.sha256"
GIT_REVISION="${GIT_REVISION:-$(git -C "$REPO" rev-parse HEAD 2>/dev/null || printf unknown)}"
printf 'CC=gcc\nCFLAGS=%s\nLDFLAGS=%s\n' "$BUILD_CFLAGS" "$BUILD_LDFLAGS" > "$SESSION_ROOT/build-flags.txt"
SOURCE_TREE_SHA256="$(python3 - "$REPO" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
paths = sorted(p for p in root.rglob("*") if p.is_file()
               and (p.suffix in (".c", ".h") or p.name == "Makefile")
               and not {".git", "perf-sessions", "dist"}.intersection(p.parts))
h = hashlib.sha256()
for path in paths:
    h.update(path.relative_to(root).as_posix().encode() + b"\0")
    h.update(path.read_bytes())
print(h.hexdigest())
PY
)"
printf '%s\n' "$SOURCE_TREE_SHA256" > "$SESSION_ROOT/source-tree.sha256"
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
    CLAT_OFFLOAD="${CLAT_OFFLOAD:-auto}" CLAT_OFFLINK_MTU="${CLAT_OFFLINK_MTU:-1280}" \
    GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
    PROTOCOL="${PROTOCOL:-tcp}" RATE="${RATE:-0}" \
    DURATION="${DURATION:-60}" WARMUP="${WARMUP:-10}" \
    DIRECTIONS="${DIRECTIONS:-download}" MAX_TUN_DROPS="${MAX_TUN_DROPS:-0}" \
    MAX_UDP_LOSS_PERCENT="${MAX_UDP_LOSS_PERCENT:-0}" \
    TUN_TXQLEN="${TUN_TXQLEN-1000}" \
    DATAGRAM_SIZE="${DATAGRAM_SIZE:-1200}" BLOCK_SIZE="${BLOCK_SIZE-}" \
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
  sudo perf report --stdio --no-children --percent-limit 0.5 --sort=symbol,dso \
    -i "$record_data" > "$SESSION_ROOT/perf-report.txt" 2>&1 || report_status=$?
  printf '%s\n' "$report_status" > "$SESSION_ROOT/perf-report-status"
  python3 - "$SESSION_ROOT/perf-report.txt" "$SESSION_ROOT/perf-symbol-summary.txt" <<'PY'
import re, sys
source, target = sys.argv[1:]
pattern = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)%\s+(.+?)\s*$")
rows = []
for line in open(source, errors="replace"):
    match = pattern.match(line)
    if match:
        rows.append(f"{float(match.group(1)):6.2f}% {match.group(2)}")
        if len(rows) == 40:
            break
with open(target, "w") as out:
    out.write("Top sampled symbols (perf report self overhead; first 40 entries)\n")
    out.write("\n".join(rows) + ("\n" if rows else "No symbol rows were parsed; inspect perf-report.txt.\n"))
PY
  script_status=0
  sudo perf script -i "$record_data" > "$SESSION_ROOT/perf-script.txt" 2>&1 || script_status=$?
  printf '%s\n' "$script_status" > "$SESSION_ROOT/perf-script-status"
  sudo cp "$record_data" "$SESSION_ROOT/perf.data"
  sudo chown "$(id -u):$(id -g)" "$SESSION_ROOT/perf.data" "$SESSION_ROOT/perf-report.txt" "$SESSION_ROOT/perf-script.txt" 2>/dev/null || true
fi

# perf.data is root-owned by perf; make the session readable before the host
# mount copy so the raw profile is preserved with the text summaries.
sudo chown -R "$(id -u):$(id -g)" "$SESSION_ROOT"

find "$SESSION_ROOT" -maxdepth 3 -type f -printf '%P\n' | sort > "$SESSION_ROOT/file-list.txt"
HOST_RESULTS="$REPO/perf-sessions/$STAMP-lima-debian13-arm64"
if mkdir -p "$HOST_RESULTS" 2>/dev/null && cp -a "$SESSION_ROOT"/. "$HOST_RESULTS"/ 2>/dev/null; then
  echo "Perf session copied to host mount: $HOST_RESULTS"
  if [ "$REMOVE_SESSION_ROOT" = yes ]; then
    rm -rf -- "$SESSION_ROOT"
  fi
else
  echo "Perf session remains in guest: $SESSION_ROOT"
fi
echo "Perf session complete: $SESSION_ROOT"
exit "$overall_status"
