#!/bin/sh
set -eu

enable_forwarding() {
  key=$1
  if sysctl -w "$key=1" >/dev/null 2>&1 || [ "$(sysctl -n "$key" 2>/dev/null)" = "1" ]; then
    return 0
  fi
  echo "WARNING: Cannot set $key=1 and current value is not 1; forwarding should be enabled on the host" >&2
}

PREF64=${PREF64:-auto}
if [ "$PREF64" = "auto" ]; then
  DISCOVERED=""
  if [ -x /usr/local/sbin/pref64-discover ]; then
    DISCOVERED=$(/usr/local/sbin/pref64-discover 2>/dev/null || true)
  fi
  if [ -n "$DISCOVERED" ]; then
    PREF64="$DISCOVERED"
  else
    echo "WARNING: RFC 7050 discovery failed. Falling back to 64:ff9b::/96" >&2
    PREF64="64:ff9b::/96"
  fi
fi
TUN=clat
V4_CLIENT=${CLAT_V4_CLIENT:-192.0.0.1}
V4_TAYGA=${CLAT_V4_TAYGA:-192.0.0.2}
V4_HOST=${CLAT_V4_HOST:-192.0.0.3}
V6_CLIENT=${CLAT_V6_CLIENT:-fd9b:64:1:ff::10}
V6_TAYGA=${CLAT_V6_TAYGA:-fd9b:64:1:ff::11}
V6_HOST=${CLAT_V6_HOST:-fd9b:64:1:ff::12}
ROUTER4=${ROUTER4:-172.31.64.1}
CLAT_WORKERS=${CLAT_WORKERS:-3}
CLAT_OFFLINK_MTU=${CLAT_OFFLINK_MTU:-1280}
CLAT_OFFLOAD=${CLAT_OFFLOAD:-off}

validate_uint() {
  case "$2" in
    ''|*[!0-9]*) echo "$1 must be an unsigned integer" >&2; exit 64 ;;
  esac
}

validate_uint CLAT_WORKERS "$CLAT_WORKERS"
validate_uint CLAT_OFFLINK_MTU "$CLAT_OFFLINK_MTU"
if [ "$CLAT_WORKERS" -gt 63 ]; then
  echo "CLAT_WORKERS must be between 0 and 63" >&2
  exit 64
fi
if [ "$CLAT_OFFLINK_MTU" -lt 1280 ] || [ "$CLAT_OFFLINK_MTU" -gt 1500 ]; then
  echo "CLAT_OFFLINK_MTU must be between 1280 and 1500" >&2
  exit 64
fi

UPLINK_IF=${CLAT_UPLINK_IF:-$(ip route get "$ROUTER4" | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)}
if [ -z "$UPLINK_IF" ] || ! ip link show dev "$UPLINK_IF" >/dev/null 2>&1; then
  echo "Cannot determine the CLAT uplink interface for router $ROUTER4" >&2
  exit 1
fi

# Enable GRO on uplink interface if offload is requested and ethtool is available
if [ "$CLAT_OFFLOAD" != "off" ] && command -v ethtool >/dev/null 2>&1; then
  ethtool -K "$UPLINK_IF" gro on 2>/dev/null || true
fi

cat > /run/clat.conf <<CONF_EOF
tun-device ${TUN}
ipv4-addr ${V4_TAYGA}
ipv6-addr ${V6_TAYGA}
prefix ${PREF64}
map ${V4_CLIENT} ${V6_CLIENT}
workers ${CLAT_WORKERS}
offlink-mtu ${CLAT_OFFLINK_MTU}
tun-offload ${CLAT_OFFLOAD}
CONF_EOF

tayga -c /run/clat.conf --mktun
ip link set "$TUN" up
ip addr replace "$V4_HOST/32" dev "$TUN"
ip -6 addr replace "$V6_HOST/128" dev "$TUN"
ip route replace "$V4_CLIENT/32" via "$ROUTER4" dev "$UPLINK_IF"
ip -6 route replace "$V6_CLIENT/128" dev "$TUN"
ip route replace default dev "$TUN"
enable_forwarding net.ipv4.ip_forward
enable_forwarding net.ipv6.conf.all.forwarding
exec tayga -c /run/clat.conf -d
