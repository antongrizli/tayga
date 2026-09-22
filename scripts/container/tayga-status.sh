#!/bin/sh
#
# tayga-status.sh -- CLI status viewer for TAYGA CLAT
#
# Reads /run/tayga-status.json and formats human-readable telemetry.
#

set -e

STATUS_FILE="/run/tayga-status.json"

TAYGA_PID=$(pidof tayga 2>/dev/null || pgrep -x tayga 2>/dev/null || true)
DAEMON_RUNNING=false
if [ -n "$TAYGA_PID" ] && kill -0 "$TAYGA_PID" 2>/dev/null; then
  DAEMON_RUNNING=true
  kill -USR2 "$TAYGA_PID" 2>/dev/null || true
  usleep 25000 2>/dev/null || sleep 0.05 2>/dev/null || true
fi

if [ ! -f "$STATUS_FILE" ]; then
  if [ "$DAEMON_RUNNING" = "false" ]; then
    echo "Error: TAYGA daemon is not running and no telemetry snapshot found at $STATUS_FILE." >&2
  else
    echo "Error: Status file $STATUS_FILE not found (daemon starting up?)." >&2
  fi
  exit 1
fi

if [ "$1" = "--json" ] || [ "$1" = "-j" ]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys, os
is_running = (os.environ.get("DAEMON_RUNNING") == "true")
with open("'"$STATUS_FILE"'") as f:
    d = json.load(f)
d["daemon_running"] = is_running
if not is_running:
    d["state"] = "stopped"
print(json.dumps(d, indent=2))
'
  else
    cat "$STATUS_FILE"
  fi
  if [ "$DAEMON_RUNNING" = "true" ]; then
    exit 0
  else
    exit 1
  fi
fi

# Parse and format JSON using python3
if command -v python3 >/dev/null 2>&1; then
  DAEMON_RUNNING="$DAEMON_RUNNING" python3 - <<'EOF'
import json, sys, os

def fmt_bytes(b):
    if b >= 1024**3:
        return f"{b / (1024**3):.2f} GiB"
    elif b >= 1024**2:
        return f"{b / (1024**2):.2f} MiB"
    elif b >= 1024:
        return f"{b / 1024:.2f} KiB"
    return f"{b} B"

is_running = (os.environ.get("DAEMON_RUNNING") == "true")

with open("/run/tayga-status.json") as f:
    d = json.load(f)

v = d.get("version", "unknown")
pid = d.get("pid", "unknown")
gen_at = d.get("generated_at", "unknown")
uptime = d.get("uptime_sec", 0)
hours = uptime // 3600
mins = (uptime % 3600) // 60
secs = uptime % 60

print("================================================================")
print(f"  TAYGA CLAT Status -- Version {v}")
print("================================================================")
if is_running:
    print(f"  Daemon State    : RUNNING (PID {pid}, updated {gen_at})")
else:
    print(f"  Daemon State    : STOPPED / INACTIVE (Last known snapshot: {gen_at}, PID {pid})")
print(f"  Uptime          : {hours}h {mins}m {secs}s ({uptime} seconds)")
print(f"  CLAT IPv4       : {d.get('clat_ipv4', 'none')}")
print(f"  CLAT IPv6       : {d.get('clat_ipv6', 'none')}")
print(f"  NAT64 Prefix    : {d.get('pref64', 'none')} (source: {d.get('pref64_source', 'none')})")
print(f"  Offload Mode    : {d.get('offload_mode', 'off')}")

tf = d.get("traffic", {})
print("----------------------------------------------------------------")
print("  Traffic Summary:")
rx4_p = tf.get("rx_packets_v4", 0)
rx4_b = tf.get("rx_bytes_v4", 0)
tx4_p = tf.get("tx_packets_v4", 0)
tx4_b = tf.get("tx_bytes_v4", 0)

rx6_p = tf.get("rx_packets_v6", 0)
rx6_b = tf.get("rx_bytes_v6", 0)
tx6_p = tf.get("tx_packets_v6", 0)
tx6_b = tf.get("tx_bytes_v6", 0)

drop_p = tf.get("dropped_packets", 0)
drop_b = tf.get("dropped_bytes", 0)
errs = tf.get("errors", 0)

print(f"    IPv4 RX       : {rx4_p:>10,d} pkts  ({fmt_bytes(rx4_b):>10})")
print(f"    IPv4 TX       : {tx4_p:>10,d} pkts  ({fmt_bytes(tx4_b):>10})")
print(f"    IPv6 RX       : {rx6_p:>10,d} pkts  ({fmt_bytes(rx6_b):>10})")
print(f"    IPv6 TX       : {tx6_p:>10,d} pkts  ({fmt_bytes(tx6_b):>10})")
print(f"    Drops         : {drop_p:>10,d} pkts  ({fmt_bytes(drop_b):>10})")
print(f"    Errors        : {errs:>10,d}")

gso = d.get("gso", {})
if gso:
    print("----------------------------------------------------------------")
    print("  GSO Offload Telemetry:")
    g_rx_p = gso.get("rx_packets", 0)
    g_tx_p = gso.get("tx_packets", 0)
    g_rx_b = gso.get("rx_bytes", 0)
    g_tx_b = gso.get("tx_bytes", 0)
    split_tail = gso.get("split_tail_packets", 0)
    sw_seg = gso.get("sw_seg_packets", 0)
    sw_out = gso.get("sw_seg_out_packets", 0)
    fallback = gso.get("fallback_packets", 0)
    invalid = gso.get("invalid_packets", 0)
    write_err = gso.get("tun_write_errors", 0)

    print(f"    GSO RX (super): {g_rx_p:>10,d} pkts  ({fmt_bytes(g_rx_b):>10})")
    print(f"    GSO TX (super): {g_tx_p:>10,d} pkts  ({fmt_bytes(g_tx_b):>10})")
    print(f"    Split Tails   : {split_tail:>10,d} pkts")
    print(f"    SW Segments   : {sw_seg:>10,d} in -> {sw_out:>10,d} out")
    print(f"    Fallbacks     : {fallback:>10,d} pkts")
    print(f"    Invalid GSO   : {invalid:>10,d} pkts")
    print(f"    TUN Write Errs: {write_err:>10,d}")

dyn = d.get("dynamic_pool", {})
if dyn and any(dyn.values()):
    print("----------------------------------------------------------------")
    print("  Dynamic Pool:")
    print(f"    Active Mappings : {dyn.get('active_mappings', 0):,d}")
    print(f"    Dormant Mappings: {dyn.get('dormant_mappings', 0):,d}")
    print(f"    Free Addresses  : {dyn.get('free_addresses', 0):,d}")

print("================================================================")
if not is_running:
    sys.exit(1)
EOF
else
  cat "$STATUS_FILE"
  if [ "$DAEMON_RUNNING" != "true" ]; then
    echo "WARNING: TAYGA process is not running." >&2
    exit 1
  fi
fi
