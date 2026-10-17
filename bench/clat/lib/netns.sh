#!/bin/sh
# Sourced by benchmark-clat.sh; configuration is owned by the entrypoint.
exec_with_affinity() {
  local child_cpuset=$1
  shift
  if [ "$child_cpuset" = all ]; then exec "$@"; else exec taskset -c "$child_cpuset" "$@"; fi
}

cleanup() {
  test -n "$socket_sampler_pid" && kill "$socket_sampler_pid" 2>/dev/null || true
  test -n "$clat_pid" && kill "$clat_pid" 2>/dev/null || true
  for iperf_pid in $iperf_pids; do kill "$iperf_pid" 2>/dev/null || true; done
  for client_pid in $client_pids; do kill "$client_pid" 2>/dev/null || true; done
  for release_pid in $release_pids; do kill "$release_pid" 2>/dev/null || true; done
  # Reap owned children before releasing namespaces/locks or starting the next
  # allocator/throughput arm. A slow shutdown must not overlap that next arm.
  python3 - $clat_pid $iperf_pids $client_pids $release_pids $socket_sampler_pid <<'PY'
import os, signal, sys, time
from pathlib import Path
parent = os.getppid()
def identity(pid):
    try:
        fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        return (int(fields[1]), int(fields[19]), fields[0])
    except (OSError, ValueError, IndexError):
        return None
owned = {}
for pid in map(int, sys.argv[1:]):
    state = identity(pid)
    if state and state[0] == parent:
        owned[pid] = state[:2]
deadline = time.monotonic() + 3
while owned:
    owned = {pid: start for pid, start in owned.items()
             if (state := identity(pid)) and state[:2] == start and state[2] != 'Z'}
    if time.monotonic() >= deadline:
        for pid in owned:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        break
    if owned: time.sleep(.025)
PY
  for owned_pid in $clat_pid $iperf_pids $client_pids $release_pids $socket_sampler_pid; do
    wait "$owned_pid" 2>/dev/null || true
  done
  for owned_ns in $owned_namespaces; do ip netns del "$owned_ns" 2>/dev/null || true; done
  if test -n "$saved_rmem_max"; then
    sysctl -qw "net.core.rmem_max=$saved_rmem_max" "net.core.wmem_max=$saved_wmem_max" || {
      echo 'ERROR: could not restore socket buffer limits' >&2; return 1;
    }
  fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
}

