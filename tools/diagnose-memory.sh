#!/usr/bin/env bash
# Separate allocator diagnostics; excluded from ordinary capacity comparisons.
set -euo pipefail
OUTPUT=${1:?output directory required}
SOURCE_SESSION=${2:-}
MEMORY_DURATION=${MEMORY_DURATION:-120}
MEMORY_RATE=${MEMORY_RATE:-0}
case "$MEMORY_DURATION" in ''|*[!0-9]*) exit 64;; esac
MEMORY_DURATION=$((10#$MEMORY_DURATION))
(( MEMORY_DURATION > 0 )) || exit 64
REPO=${MEMORY_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
case "$OUTPUT" in /*) ;; *) echo "Use an absolute output directory." >&2; exit 64;; esac
cd "$REPO"
exec 9</tmp/tayga-perf-workflow.lock
flock -n 9 || { echo 'Another TAYGA workflow is active.' >&2; exit 75; }
mkdir -p "$(dirname "$OUTPUT")"
mkdir "$OUTPUT"
cp /usr/local/sbin/clat-start.sh "$OUTPUT/clat-start.original"
cleanup() { cp "$OUTPUT/clat-start.original" /usr/local/sbin/clat-start.sh; }
trap cleanup EXIT
sha256sum /usr/sbin/tayga > "$OUTPUT/tayga.sha256"
cp /usr/sbin/tayga "$OUTPUT/tayga"
ldconfig -p > "$OUTPUT/libraries.txt"
if [ -n "$SOURCE_SESSION" ]; then
  expected=$(awk '{print $1}' "$SOURCE_SESSION/tayga.sha256")
  observed=$(sha256sum /usr/sbin/tayga | awk '{print $1}')
  [ "$expected" = "$observed" ] || { echo 'Source session does not match the installed executable.' >&2; exit 64; }
  GIT_REVISION=$(cat "$SOURCE_SESSION/git-revision.txt")
  SOURCE_TREE_SHA256=$(cat "$SOURCE_SESSION/source-tree.sha256")
  export GIT_REVISION SOURCE_TREE_SHA256
fi
for allocator in libc tcmalloc; do
  cleanup
  mkdir -p "$OUTPUT/$allocator/heap"
  if [ "$allocator" = tcmalloc ]; then
    python3 - "$OUTPUT" <<'PY'
from pathlib import Path
import sys, shlex, subprocess
p=Path('/usr/local/sbin/clat-start.sh')
s=p.read_text()
old='exec /usr/sbin/tayga -c /run/clat.conf -d'
assert s.count(old)==1
prefix=sys.argv[1]+'/tcmalloc/heap/tayga'
libraries=subprocess.check_output(['ldconfig', '-p'], text=True).splitlines()
library=next(line.split('=>', 1)[1].strip() for line in libraries if line.split()[0]=='libtcmalloc.so.4')
s=s.replace(old, 'exec env '+shlex.quote('LD_PRELOAD='+library)+' '+shlex.quote('HEAPPROFILE='+prefix)+' HEAP_PROFILE_TIME_INTERVAL=5 '+old[5:])
p.write_text(s)
PY
  fi
  python3 "$REPO/tools/sample-process-memory.py" --seconds "$((2 * MEMORY_DURATION + 40))" --output "$OUTPUT/$allocator/memory.jsonl" &
  sampler=$!
  if ! env WORKERS=1 CLIENTS=2 FLOWS=1 CLAT_OFFLOAD=auto FORWARDING_GRO=on \
      WARMUP=0 DURATION="$MEMORY_DURATION" DIRECTIONS='upload download' PROTOCOL=udp RATE="$MEMORY_RATE" \
      PERF_MODE=none ARTIFACT_DIR="$OUTPUT/$allocator/workload" \
      /usr/local/sbin/benchmark-clat.sh > "$OUTPUT/$allocator/workload.log" 2>&1; then
    kill "$sampler" 2>/dev/null || true
    wait "$sampler" || true
    exit 1
  fi
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" || true
  printf 'COMPLETED memory diagnostic: %s\n' "$allocator"
done
