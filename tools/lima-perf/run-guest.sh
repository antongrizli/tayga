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

# Serialize snapshot/build/install as well as network setup and collection.
# Read-only opening lets root and the regular guest user share the same lock.
touch /tmp/tayga-perf-workflow.lock 2>/dev/null || true
exec 9</tmp/tayga-perf-workflow.lock
flock -n 9 || { echo "Another TAYGA workflow is active in this guest." >&2; exit 75; }

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

required_commands=(gcc make ip iperf3 nft python3 jq git sha256sum perf)
missing_commands=()
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || missing_commands+=("$command_name")
done
if [ "${#missing_commands[@]}" -ne 0 ]; then
  echo "Guest dependencies are missing: ${missing_commands[*]}" >&2
  echo "Prepare the guest separately with apt, then rerun without changing packages during A/B measurements." >&2
  exit 1
fi

sudo sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
sudo sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1 || true

mkdir -p "$BUILD_ROOT"
tar -C "$REPO" \
  --exclude='./.git' --exclude='./perf-sessions' --exclude='./dist' \
  --exclude='./.codex' --exclude='./.agents' --exclude='./tayga' \
  --exclude='./unit_conffile' --exclude='./unit_checksum' --exclude='./unit_udp_checksum' \
  --exclude='./unit_ip4_id' --exclude='./unit_tun' --exclude='./unit_gso' \
  --exclude='./unit_pref64' --exclude='./unit_stats' --exclude='./tools/probe-tun-offload' \
  -cf - . | tar -C "$BUILD_ROOT" -xf -
cd "$BUILD_ROOT"
GIT_REVISION="${GIT_REVISION:-$(git -C "$REPO" rev-parse HEAD 2>/dev/null || printf unknown)}"
SOURCE_TREE_SHA256="$(python3 - "$BUILD_ROOT" "$SESSION_ROOT" <<'PY'
import hashlib, pathlib, sys
root, session = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
files = sorted(path for path in root.rglob("*") if path.is_file())
manifest = session / "source-manifest.sha256"
manifest.parent.mkdir(parents=True, exist_ok=True)
rows = []
tree = hashlib.sha256()
for path in files:
    relative = path.relative_to(root).as_posix()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append(f"{digest}  {relative}")
    tree.update(relative.encode() + b"\0" + bytes.fromhex(digest))
manifest.write_text("\n".join(rows) + "\n")
print(tree.hexdigest())
PY
)"
printf '%s\n' "$GIT_REVISION" > "$SESSION_ROOT/git-revision.txt"
printf '%s\n' "$SOURCE_TREE_SHA256" > "$SESSION_ROOT/source-tree.sha256"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$BUILD_ROOT" -cf - . | gzip -n > "$SESSION_ROOT/source-snapshot.tar.gz"
sha256sum "$SESSION_ROOT/source-snapshot.tar.gz" > "$SESSION_ROOT/source-snapshot.sha256"
BUILD_CFLAGS="-O3 -flto -g -fno-omit-frame-pointer -ffile-prefix-map=$BUILD_ROOT=."
BUILD_LDFLAGS='-flto -Wl,--build-id'
BUILD_BRANCH="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || printf detached)"
make -B CC=gcc VERSION="${TAYGA_VERSION:-0.9.12}" COMMIT="$GIT_REVISION" BRANCH="$BUILD_BRANCH" CFLAGS="$BUILD_CFLAGS" LDFLAGS="$BUILD_LDFLAGS"
sudo install -Dm0755 tayga /usr/sbin/tayga
sudo install -Dm0755 "$BUILD_ROOT/scripts/container/clat-start.sh" /usr/local/sbin/clat-start.sh
sudo install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh

mkdir -p "$SESSION_ROOT"
uname -a > "$SESSION_ROOT/uname.txt"
lscpu > "$SESSION_ROOT/lscpu.txt"
gcc --version > "$SESSION_ROOT/compiler.txt"
perf --version > "$SESSION_ROOT/perf-version.txt"
perf list > "$SESSION_ROOT/perf-list.txt" 2>&1 || true
sha256sum tayga > "$SESSION_ROOT/tayga.sha256"
readelf -n tayga > "$SESSION_ROOT/tayga-build-id.txt" 2>&1 || true
printf 'CC=gcc\nCFLAGS=%s\nLDFLAGS=%s\n' "$BUILD_CFLAGS" "$BUILD_LDFLAGS" > "$SESSION_ROOT/build-flags.txt"
git -C "$REPO" diff --binary > "$SESSION_ROOT/source.patch" 2>/dev/null || true

run_case() {
  local mode="$1"
  local case_dir="$SESSION_ROOT/$mode"
  mkdir -p "$case_dir"
  echo "Starting PERF_MODE=$mode; artifacts: $case_dir"
  sudo env ARTIFACT_DIR="$case_dir" PERF_MODE="$mode" \
    CLIENTS="${CLIENTS:-20}" FLOWS="${FLOWS:-1}" WORKERS="${WORKERS:-3}" \
    CLAT_OFFLOAD="${CLAT_OFFLOAD:-auto}" CLAT_OFFLINK_MTU="${CLAT_OFFLINK_MTU:-1280}" \
    FORWARDING_GRO="${FORWARDING_GRO:-off}" \
    GIT_REVISION="$GIT_REVISION" SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
    PROTOCOL="${PROTOCOL:-tcp}" RATE="${RATE:-0}" \
    DURATION="${DURATION:-60}" WARMUP="${WARMUP:-10}" \
    DIRECTIONS="${DIRECTIONS:-download}" MAX_TUN_DROPS="${MAX_TUN_DROPS:-0}" \
    MAX_UDP_LOSS_PERCENT="${MAX_UDP_LOSS_PERCENT:-0}" MAX_PING_LOSS_PERCENT="${MAX_PING_LOSS_PERCENT:-0}" \
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

if [ -d "$SESSION_ROOT/record" ]; then
  # Workloads create directional directories as root. Shell redirection happens
  # before sudo perf starts, so give the exporting user ownership first.
  sudo chown -R "$(id -u):$(id -g)" "$SESSION_ROOT/record"
  while IFS= read -r -d '' record_data; do
    profile_dir="$(dirname "$record_data")"
    report_path="$profile_dir/perf-report.txt"
    script_path="$profile_dir/perf-script.txt"
    report_status=0
    perf report --stdio --no-children --percent-limit 0.5 --sort=symbol,dso \
      -i "$record_data" > "$report_path" 2>&1 || report_status=$?
    printf '%s\n' "$report_status" > "$profile_dir/perf-report-status"
    python3 - "$report_path" "$profile_dir/perf-symbol-summary.txt" <<'PY'
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
    perf script -i "$record_data" > "$script_path" 2>&1 || script_status=$?
    printf '%s\n' "$script_status" > "$profile_dir/perf-script-status"
    sudo chown -R "$(id -u):$(id -g)" "$profile_dir" 2>/dev/null || true
  done < <(find "$SESSION_ROOT/record" -name perf.data -type f -print0 | sort -z)
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
