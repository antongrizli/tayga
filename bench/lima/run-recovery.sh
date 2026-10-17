#!/usr/bin/env bash
# Sequential, alternating same-build controls. Keep failed sessions for acceptance.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO="${REPO:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}"
BASELINE_REPO="${BASELINE_REPO:-$REPO}"
CANDIDATE_REPO="${CANDIDATE_REPO:-$REPO}"
RECOVERY_MODE="${RECOVERY_MODE:-configuration}"
ROOT="${PERF_SESSION_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/tayga/perf-sessions}"
STAMP="${RECOVERY_STAMP:-recovery-$(date -u +%Y%m%dT%H%M%SZ)}"
REPEATS="${REPEATS:-5}"
[[ "$STAMP" =~ ^[A-Za-z0-9_.-]+$ ]] || exit 64
case "$RECOVERY_MODE" in configuration|build) ;; *) echo 'RECOVERY_MODE must be configuration or build' >&2; exit 64;; esac
[ -d "$BASELINE_REPO" ] && [ -d "$CANDIDATE_REPO" ] || { echo 'Both source trees must exist' >&2; exit 64; }
[[ "$REPEATS" =~ ^[0-9]+$ ]] && [ "$REPEATS" -ge 5 ] && [ "$REPEATS" -le 20 ] || { echo 'REPEATS must be 5..20' >&2; exit 64; }
baselines=(); candidates=()
for ((trial=1; trial<=REPEATS; trial++)); do
  modes=(kernel flows)
  if ((trial % 2 == 0)); then modes=(flows kernel); fi
  for mode in "${modes[@]}"; do
    name="$STAMP-$mode-r$trial"
    session="$ROOT/$name-lima-debian13-arm64"
    [ ! -e "$session" ] || { echo "Refusing to overwrite session: $session" >&2; exit 64; }
    if [ "$mode" = kernel ]; then
      baselines+=("$session"); arm_repo="$BASELINE_REPO"
    else
      candidates+=("$session"); arm_repo="$CANDIDATE_REPO"
    fi
    echo "Recovery trial $trial/$REPEATS: $mode"
    # Separate warmup/directional ports avoid TIME_WAIT reuse in one namespace.
    REPO="$arm_repo" CLIENTS=4 FLOWS=1 WORKERS=3 CLIENT_PORT_BASE="$((40000 + trial * 100))" \
      DURATION=20 WARMUP=5 DIRECTIONS='download upload' PERF_MODES=none \
      PROTOCOL=tcp CLAT_OFFLOAD=auto CLAT_OFFLINK_MTU=1280 \
      CLAT_STEERING="$mode" SESSION_STAMP="$name" \
      "$SCRIPT_DIR/run-host.sh" || echo "Retained failed trial: $name" >&2
  done
done
PYTHONPATH="$REPO/bench${PYTHONPATH:+:$PYTHONPATH}" python3 -m taygabench.acceptance \
  --baseline "${baselines[@]}" --candidate "${candidates[@]}" --min-repeats "$REPEATS" \
  --mode "$RECOVERY_MODE" \
  --json "$ROOT/$STAMP-acceptance.json" --markdown "$ROOT/$STAMP-acceptance.md"
