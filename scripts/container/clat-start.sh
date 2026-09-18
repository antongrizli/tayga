#!/bin/sh
set -eu

# Helper to enable kernel forwarding safely
enable_forwarding() {
  key=$1
  if sysctl -w "$key=1" >/dev/null 2>&1 || [ "$(sysctl -n "$key" 2>/dev/null)" = "1" ]; then
    return 0
  fi
  echo "ERROR: Kernel forwarding for $key is disabled and cannot be set (forwarding must be enabled on host)" >&2
  exit 1
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

# Resolve aliases and detect conflicts
resolve_alias() {
  modern_name=$1
  modern_val=$2
  legacy_name=$3
  legacy_val=$4
  default_val=$5

  if [ -n "$modern_val" ] && [ -n "$legacy_val" ] && [ "$modern_val" != "$legacy_val" ]; then
    echo "ERROR: Conflicting values for $modern_name ('$modern_val') and legacy $legacy_name ('$legacy_val')" >&2
    exit 64
  fi

  if [ -n "$modern_val" ]; then
    echo "$modern_val"
  elif [ -n "$legacy_val" ]; then
    echo "$legacy_val"
  else
    echo "$default_val"
  fi
}

TAYGA_WORKERS_VAL=$(resolve_alias "TAYGA_WORKERS" "${TAYGA_WORKERS:-}" "CLAT_WORKERS" "${CLAT_WORKERS:-}" "3")
TAYGA_OFFLOAD_VAL=$(resolve_alias "TAYGA_OFFLOAD" "${TAYGA_OFFLOAD:-}" "CLAT_OFFLOAD" "${CLAT_OFFLOAD:-}" "off")
TAYGA_OFFLINK_MTU_VAL=$(resolve_alias "TAYGA_OFFLINK_MTU" "${TAYGA_OFFLINK_MTU:-}" "CLAT_OFFLINK_MTU" "${CLAT_OFFLINK_MTU:-}" "1280")

validate_uint "TAYGA_WORKERS" "$TAYGA_WORKERS_VAL"
validate_uint "TAYGA_OFFLINK_MTU" "$TAYGA_OFFLINK_MTU_VAL"

if [ "$TAYGA_WORKERS_VAL" -gt 63 ]; then
  echo "ERROR: TAYGA_WORKERS must be between 0 and 63 (got $TAYGA_WORKERS_VAL)" >&2
  exit 64
fi

if [ "$TAYGA_OFFLINK_MTU_VAL" -lt 1280 ] || [ "$TAYGA_OFFLINK_MTU_VAL" -gt 1500 ]; then
  echo "ERROR: TAYGA_OFFLINK_MTU must be between 1280 and 1500 (got $TAYGA_OFFLINK_MTU_VAL)" >&2
  exit 64
fi

case "$TAYGA_OFFLOAD_VAL" in
  off|tcp|auto) ;;
  *)
    echo "ERROR: TAYGA_OFFLOAD must be 'off', 'tcp', or 'auto' (got '$TAYGA_OFFLOAD_VAL')" >&2
    exit 64
    ;;
esac

PREF64="${PREF64:-auto}"
FALLBACK_TO_WELL_KNOWN_PREFIX="${FALLBACK_TO_WELL_KNOWN_PREFIX:-false}"

if [ "$PREF64" = "auto" ]; then
  echo "==> Discovering NAT64 prefix via RFC 7050 (ipv4only.arpa)..."
  DISCOVERED=""
  if [ -x /usr/local/sbin/pref64-discover ]; then
    DISCOVERED=$(/usr/local/sbin/pref64-discover 2>/dev/null || true)
  fi
  if [ -n "$DISCOVERED" ]; then
    PREF64="$DISCOVERED"
    echo "==> Discovered PREF64: $PREF64"
  else
    if [ "$FALLBACK_TO_WELL_KNOWN_PREFIX" = "true" ]; then
      echo "WARNING: RFC 7050 discovery failed. FALLBACK_TO_WELL_KNOWN_PREFIX=true: using 64:ff9b::/96 (RFC 6052)" >&2
      PREF64="64:ff9b::/96"
    else
      echo "ERROR: RFC 7050 discovery failed (DNS64 / ipv4only.arpa unreachable). Set PREF64 explicitly (e.g. PREF64=64:ff9b::/96) or enable FALLBACK_TO_WELL_KNOWN_PREFIX=true." >&2
      exit 1
    fi
  fi
fi

# Validate prefix length if format is prefix/len
case "$PREF64" in
  */32|*/40|*/48|*/56|*/64|*/96) ;;
  *)
    echo "ERROR: Unsupported or invalid PREF64 '$PREF64'. Prefix length must be 32, 40, 48, 56, 64, or 96." >&2
    exit 64
    ;;
esac

TUN="clat"
V4_CLIENT="${CLAT_V4_CLIENT:-192.0.0.1}"
V4_TAYGA="${CLAT_V4_TAYGA:-192.0.0.2}"
V4_HOST="${CLAT_V4_HOST:-192.0.0.3}"
V6_CLIENT="${CLAT_V6_CLIENT:-fd9b:64:1:ff::10}"
V6_TAYGA="${CLAT_V6_TAYGA:-fd9b:64:1:ff::11}"
V6_HOST="${CLAT_V6_HOST:-fd9b:64:1:ff::12}"
ROUTER4="${ROUTER4:-172.31.64.1}"

# Determine uplink interface towards RouterOS gateway
UPLINK_IF="${CLAT_UPLINK_IF:-}"
if [ -z "$UPLINK_IF" ]; then
  UPLINK_IF=$(ip route get "$ROUTER4" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1 || true)
fi
if [ -z "$UPLINK_IF" ]; then
  # Fallback to default route dev or first non-lo dev
  UPLINK_IF=$(ip route show default 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1 || true)
fi
if [ -z "$UPLINK_IF" ]; then
  UPLINK_IF=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n 1 || true)
fi

if [ -z "$UPLINK_IF" ] || ! ip link show dev "$UPLINK_IF" >/dev/null 2>&1; then
  echo "ERROR: Cannot determine uplink interface for router $ROUTER4" >&2
  exit 1
fi

echo "============================================================"
echo " TAYGA Unified CLAT (Customer-Side Translator RFC 6877)"
echo "------------------------------------------------------------"
echo " Uplink Interface  : $UPLINK_IF (Router: $ROUTER4)"
echo " NAT64 Prefix      : $PREF64"
echo " Workers           : $TAYGA_WORKERS_VAL"
echo " Offload Mode      : $TAYGA_OFFLOAD_VAL"
echo " Offlink MTU       : $TAYGA_OFFLINK_MTU_VAL"
echo " IPv4 Map          : $V4_CLIENT <-> $V6_CLIENT"
echo " TAYGA Addresses   : v4=$V4_TAYGA, v6=$V6_TAYGA"
echo " Host Addresses    : v4=$V4_HOST, v6=$V6_HOST"
echo "============================================================"

# Configure GRO on uplink interface if requested and ethtool is present
if [ "$TAYGA_OFFLOAD_VAL" != "off" ] && command -v ethtool >/dev/null 2>&1; then
  echo "==> Configuring GRO on $UPLINK_IF..."
  ethtool -K "$UPLINK_IF" gro on 2>/dev/null || echo "Note: ethtool GRO toggle not supported on $UPLINK_IF (continuing)"
fi

# Generate /run/clat.conf
mkdir -p /run
cat > /run/clat.conf <<CONF_EOF
tun-device ${TUN}
ipv4-addr ${V4_TAYGA}
ipv6-addr ${V6_TAYGA}
prefix ${PREF64}
map ${V4_CLIENT} ${V6_CLIENT}
workers ${TAYGA_WORKERS_VAL}
offlink-mtu ${TAYGA_OFFLINK_MTU_VAL}
tun-offload ${TAYGA_OFFLOAD_VAL}
CONF_EOF

# Set up TUN adapter and routes
echo "==> Setting up TUN device $TUN and routing table..."
/usr/sbin/tayga -c /run/clat.conf --mktun
ip link set "$TUN" up
ip addr replace "$V4_HOST/32" dev "$TUN"
ip -6 addr replace "$V6_HOST/128" dev "$TUN"
ip route replace "$V4_CLIENT/32" via "$ROUTER4" dev "$UPLINK_IF"
ip -6 route replace "$V6_CLIENT/128" dev "$TUN"
ip route replace default dev "$TUN"

enable_forwarding net.ipv4.ip_forward
enable_forwarding net.ipv6.conf.all.forwarding

echo "==> Launching TAYGA daemon in foreground..."
exec /usr/sbin/tayga -c /run/clat.conf -d
