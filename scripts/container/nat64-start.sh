#!/bin/sh
set -eu

# Helper to enable kernel forwarding safely
enable_forwarding() {
  key=$1
  sysctl -w "$key=1" >/dev/null 2>&1 || [ "$(sysctl -n "$key" 2>/dev/null)" = "1" ] || {
    echo "ERROR: Cannot enable $key and current value is not 1; container requires net.admin capability or host forwarding enabled" >&2
    exit 1
  }
}

# Validate unsigned integer helper
validate_uint() {
  var_name=$1
  var_val=$2
  case "$var_val" in
    ''|*[!0-9]*)
      echo "ERROR: $var_name must be an unsigned integer, got '$var_val'" >&2
      exit 64
      ;;
  esac
}

TAYGA_PREF64="${TAYGA_PREF64:-64:ff9b::/96}"
TAYGA_POOL4="${TAYGA_POOL4:-192.168.240.0/20}"
TAYGA_ADDR4="${TAYGA_ADDR4:-192.168.240.1}"
TAYGA_ADDR6="${TAYGA_ADDR6:-fc68::2}"
TAYGA_WORKERS="${TAYGA_WORKERS:-3}"
TAYGA_OFFLOAD="${TAYGA_OFFLOAD:-off}"
TAYGA_OFFLINK_MTU="${TAYGA_OFFLINK_MTU:-1280}"
DNS64_UPSTREAM="${DNS64_UPSTREAM:-1.1.1.1,8.8.8.8}"
DATA_DIR="${TAYGA_DATA_DIR:-/var/lib/tayga}"

validate_uint "TAYGA_WORKERS" "$TAYGA_WORKERS"
validate_uint "TAYGA_OFFLINK_MTU" "$TAYGA_OFFLINK_MTU"

case "$TAYGA_OFFLOAD" in
  off|tcp|auto) ;;
  *)
    echo "ERROR: TAYGA_OFFLOAD must be 'off', 'tcp', or 'auto' (got '$TAYGA_OFFLOAD')" >&2
    exit 64
    ;;
esac

echo "============================================================"
echo " TAYGA Unified NAT64 (Server-Side Translator RFC 6146/6147)"
echo "------------------------------------------------------------"
echo " NAT64 Prefix      : $TAYGA_PREF64"
echo " IPv4 Dynamic Pool : $TAYGA_POOL4"
echo " IPv4 Address      : $TAYGA_ADDR4"
echo " IPv6 Address      : $TAYGA_ADDR6"
echo " Workers           : $TAYGA_WORKERS"
echo " Offload Mode      : $TAYGA_OFFLOAD"
echo " Offlink MTU       : $TAYGA_OFFLINK_MTU"
echo " DNS64 Upstreams   : $DNS64_UPSTREAM"
echo " Data Directory    : $DATA_DIR"
echo "============================================================"

mkdir -p /run "$DATA_DIR"

# Generate tayga.conf
cat > /run/tayga.conf <<CONF_EOF
tun-device nat64
ipv4-addr ${TAYGA_ADDR4}
ipv6-addr ${TAYGA_ADDR6}
prefix ${TAYGA_PREF64}
dynamic-pool ${TAYGA_POOL4}
workers ${TAYGA_WORKERS}
offlink-mtu ${TAYGA_OFFLINK_MTU}
tun-offload ${TAYGA_OFFLOAD}
data-dir ${DATA_DIR}
wkpf-strict false
CONF_EOF

# Generate unbound.conf for DNS64
mkdir -p /run/unbound
cat > /run/unbound.conf <<CONF_EOF
server:
    verbosity: 1
    interface: 0.0.0.0
    interface: ::0
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow
    module-config: "dns64 validator iterator"
    dns64-prefix: ${TAYGA_PREF64}
    dns64-synthall: no
    hide-identity: yes
    hide-version: yes
    use-syslog: no

forward-zone:
    name: "."
CONF_EOF

# Add forward addresses to unbound.conf
OLD_IFS="$IFS"
IFS=","
for upstream in $DNS64_UPSTREAM; do
  trimmed=$(echo "$upstream" | tr -d ' ')
  if [ -n "$trimmed" ]; then
    echo "    forward-addr: $trimmed" >> /run/unbound.conf
  fi
done
IFS="$OLD_IFS"

# Make tunnel adapter
echo "==> Creating tunnel adapter nat64..."
/usr/sbin/tayga -c /run/tayga.conf --mktun
ip link set dev nat64 up
ip route replace "$TAYGA_POOL4" dev nat64
ip -6 route replace "$TAYGA_PREF64" dev nat64

enable_forwarding net.ipv4.ip_forward
enable_forwarding net.ipv6.conf.all.forwarding

# Supervisor setup: manage both TAYGA and Unbound
TAYGA_PID=""
UNBOUND_PID=""

cleanup() {
  exit_code="${1:-0}"
  echo "==> Terminating child processes (exit code $exit_code)..."
  if [ -n "$UNBOUND_PID" ] && kill -0 "$UNBOUND_PID" 2>/dev/null; then
    kill -TERM "$UNBOUND_PID" 2>/dev/null || true
  fi
  if [ -n "$TAYGA_PID" ] && kill -0 "$TAYGA_PID" 2>/dev/null; then
    kill -TERM "$TAYGA_PID" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  exit "$exit_code"
}

trap 'cleanup 0' INT TERM HUP

echo "==> Starting Unbound DNS64..."
/usr/sbin/unbound -d -c /run/unbound.conf &
UNBOUND_PID=$!

echo "==> Starting TAYGA..."
/usr/sbin/tayga -c /run/tayga.conf -d &
TAYGA_PID=$!

# Monitor child processes; exit with code 1 if either dies
while true; do
  if ! kill -0 "$UNBOUND_PID" 2>/dev/null; then
    echo "ERROR: Unbound DNS64 exited unexpectedly" >&2
    cleanup 1
  fi
  if ! kill -0 "$TAYGA_PID" 2>/dev/null; then
    echo "ERROR: TAYGA process exited unexpectedly" >&2
    cleanup 1
  fi
  sleep 2
done
