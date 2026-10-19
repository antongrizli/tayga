#!/usr/bin/env bash
# Sequential, alternating same-build controls. Keep failed sessions for acceptance.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO="${REPO:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}"
HARNESS_REPO="${HARNESS_REPO:-$REPO}"
BASELINE_REPO="${BASELINE_REPO:-$REPO}"
CANDIDATE_REPO="${CANDIDATE_REPO:-$REPO}"
RECOVERY_MODE="${RECOVERY_MODE:-configuration}"
RECOVERY_PURPOSE="${RECOVERY_PURPOSE:-acceptance}"
BASELINE_STEERING="${BASELINE_STEERING:-kernel}"
CANDIDATE_STEERING="${CANDIDATE_STEERING:-flows}"
ROOT="${PERF_SESSION_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/tayga/perf-sessions}"
STAMP="${RECOVERY_STAMP:-recovery-$(date -u +%Y%m%dT%H%M%SZ)}"
REPEATS="${REPEATS:-5}"
[[ "$STAMP" =~ ^[A-Za-z0-9_.-]+$ ]] || exit 64
case "$RECOVERY_MODE" in configuration|build) ;; *) echo 'RECOVERY_MODE must be configuration or build' >&2; exit 64;; esac
case "$RECOVERY_PURPOSE" in acceptance|diagnostic) ;; *) echo 'RECOVERY_PURPOSE must be acceptance or diagnostic' >&2; exit 64;; esac
for steering in "$BASELINE_STEERING" "$CANDIDATE_STEERING"; do
  case "$steering" in kernel|groups|flows) ;; *) echo 'Invalid steering policy' >&2; exit 64;; esac
done
if [ "$RECOVERY_PURPOSE" = acceptance ] && { [ "$BASELINE_STEERING" != kernel ] || [ "$CANDIDATE_STEERING" != flows ]; }; then
  echo 'Product acceptance requires kernel baseline and flows candidate' >&2; exit 64
fi
[ -d "$BASELINE_REPO" ] && [ -d "$CANDIDATE_REPO" ] || { echo 'Both source trees must exist' >&2; exit 64; }
[[ "$REPEATS" =~ ^[0-9]+$ ]] && [ "$REPEATS" -ge 5 ] && [ "$REPEATS" -le 20 ] || { echo 'REPEATS must be 5..20' >&2; exit 64; }
baselines=(); candidates=()
for ((trial=1; trial<=REPEATS; trial++)); do
  arms=(baseline candidate)
  if ((trial % 2 == 0)); then arms=(candidate baseline); fi
  for arm in "${arms[@]}"; do
    name="$STAMP-$arm-r$trial"
    session="$ROOT/$name-lima-debian13-arm64"
    [ ! -e "$session" ] || { echo "Refusing to overwrite session: $session" >&2; exit 64; }
    if [ "$arm" = baseline ]; then
      baselines+=("$session"); arm_repo="$BASELINE_REPO"; mode="$BASELINE_STEERING"
      revision="${BASELINE_REVISION:-$(git -C "$arm_repo" rev-parse HEAD 2>/dev/null || printf unknown)}"
    else
      candidates+=("$session"); arm_repo="$CANDIDATE_REPO"; mode="$CANDIDATE_STEERING"
      revision="${CANDIDATE_REVISION:-$(git -C "$arm_repo" rev-parse HEAD 2>/dev/null || printf unknown)}"
    fi
    echo "Recovery trial $trial/$REPEATS: $arm ($mode)"
    # Separate warmup/directional ports avoid TIME_WAIT reuse in one namespace.
    REPO="$arm_repo" HARNESS_REPO="$HARNESS_REPO" GIT_REVISION="$revision" EXPERIMENT_ID="$STAMP" PAIR_ID="$trial" ARM_ID="$arm" \
      CLIENTS=4 FLOWS=1 WORKERS=3 CLIENT_PORT_BASE="$((40000 + trial * 100))" \
      DURATION=20 WARMUP=5 DIRECTIONS='download upload' PERF_MODES=none \
      PROTOCOL=tcp CLAT_OFFLOAD=auto CLAT_OFFLINK_MTU=1280 \
      CLAT_STEERING="$mode" SESSION_STAMP="$name" \
      "$HARNESS_REPO/bench/lima/run-host.sh" || echo "Retained failed trial: $name" >&2
  done
done
set --
if [ "$RECOVERY_PURPOSE" = diagnostic ]; then set -- --diagnostic; fi
PYTHONPATH="$HARNESS_REPO/bench${PYTHONPATH:+:$PYTHONPATH}" python3 -m taygabench.acceptance \
  --baseline "${baselines[@]}" --candidate "${candidates[@]}" --min-repeats "$REPEATS" \
  --mode "$RECOVERY_MODE" \
  --baseline-steering "$BASELINE_STEERING" --candidate-steering "$CANDIDATE_STEERING" "$@" \
  --json "$ROOT/$STAMP-acceptance.json" --markdown "$ROOT/$STAMP-acceptance.md"
