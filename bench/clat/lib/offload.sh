#!/bin/sh
# Sourced by benchmark-clat.sh; configuration is owned by the entrypoint.
configure_clat_ingress_rps() {
  # Only this disposable namespace/interface is touched, before traffic starts.
  # Preserve readback evidence even when the kernel rejects a requested mask.
  ip netns exec clatns python3 - "$CLAT_INGRESS_RPS_CPUS" > "$ARTIFACT_DIR/clat-ingress-rps.json" <<'PY'
import json, sys
from pathlib import Path
requested = sys.argv[1]
report = dict(interface='veth-nat64', namespace='clatns', requested=requested, queues=[])
try:
    paths = sorted(Path('/sys/class/net/veth-nat64/queues').glob('rx-*/rps_cpus'))
    report['available'] = bool(paths)
    if not paths and requested != 'unchanged': raise RuntimeError('no ingress RPS queue controls')
    for path in paths:
        row = dict(queue=path.parent.name, before=path.read_text().strip())
        report['queues'].append(row)
        if requested != 'unchanged': path.write_text(requested+'\n')
        row['after'] = path.read_text().strip()
        if requested != 'unchanged' and int(row['after'].replace(',', ''), 16) != int(requested.replace(',', ''), 16):
            raise RuntimeError('RPS mask readback mismatch')
except (OSError, ValueError, RuntimeError) as exc:
    report['error'] = str(exc)
finally:
    print(json.dumps(report, indent=2))
if 'error' in report:
    print(report['error'], file=sys.stderr)
    sys.exit(1)
PY
}

configure_sender_fq() {
  local sender_ns=$1 sender_dev=$2 tx_count topology queue_no queue_limit flow_limit
  tx_count=$(awk '/Current hardware settings:/ { current=1; next } current && /^TX:/ { print $2; exit }'     "$ARTIFACT_DIR/channels-$sender_ns-$sender_dev.after.txt")
  case "$tx_count" in ''|*[!0-9]*|0) echo 'could not determine active TX channels' >&2; exit 1;; esac
  topology=$SENDER_FQ_TOPOLOGY
  if [ "$topology" = auto ]; then
    topology=single
    [ "$tx_count" -le 1 ] || topology=mq
  fi
  printf '%s/%s topology=%s tx_channels=%s total_limit=%s flow_limit=%s fq_rate=%s\n'     "$sender_ns" "$sender_dev" "$topology" "$tx_count" "$SENDER_FQ_LIMIT" "$SENDER_FQ_FLOW_LIMIT" "$FQ_RATE"     >> "$ARTIFACT_DIR/sender-qdisc-settings.txt"
  if [ "$topology" = single ]; then
    ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" root fq       limit "$SENDER_FQ_LIMIT" flow_limit "$SENDER_FQ_FLOW_LIMIT"
  else
    [ "$SENDER_FQ_LIMIT" -ge "$tx_count" ] || { echo 'total fq limit must cover all TX queues' >&2; exit 64; }
    # Each hardware TX queue gets its own scheduler. Partition the total budget
    # exactly; adding channels must not silently multiply buffered memory.
    ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" root handle 1: mq
    for queue_no in $(seq 1 "$tx_count"); do
      queue_limit=$((SENDER_FQ_LIMIT / tx_count))
      if [ "$queue_no" -le "$((SENDER_FQ_LIMIT % tx_count))" ]; then queue_limit=$((queue_limit + 1)); fi
      flow_limit=$SENDER_FQ_FLOW_LIMIT
      [ "$flow_limit" -le "$queue_limit" ] || flow_limit=$queue_limit
      ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" parent "1:$queue_no" fq         limit "$queue_limit" flow_limit "$flow_limit"
    done
  fi
}

