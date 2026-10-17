#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 BASELINE_SESSION CANDIDATE_SESSION" >&2
  exit 64
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="${PERF_COMPARISON_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/tayga/perf-comparisons}/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
python3 "$SCRIPT_DIR/../taygabench/compare.py" "$1" "$2" \
  --mode "${MODE:-build}" \
  --json "$OUT_DIR/comparison.json" --markdown "$OUT_DIR/comparison.md"
echo "Comparison written to $OUT_DIR"

