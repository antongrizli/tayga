#!/bin/sh
set -u

echo "============================================================"
echo " TAYGA Unified Container Diagnostics"
echo " Date: $(date -u)"
echo "============================================================"

echo ""
echo "--- 1. Environment & Mode ---"
echo "MODE                : ${MODE:-clat (default)}"
echo "TAYGA_WORKERS       : ${TAYGA_WORKERS:-not set}"
echo "TAYGA_OFFLOAD       : ${TAYGA_OFFLOAD:-not set}"
echo "TAYGA_OFFLINK_MTU   : ${TAYGA_OFFLINK_MTU:-not set}"
echo "PREF64              : ${PREF64:-not set}"
echo "ROUTER4             : ${ROUTER4:-not set}"

echo ""
echo "--- 2. TAYGA Binary ---"
if [ -x /usr/sbin/tayga ]; then
  /usr/sbin/tayga -v 2>&1 || true
else
  echo "TAYGA binary not found at /usr/sbin/tayga"
fi

if [ -x /usr/local/sbin/pref64-discover ]; then
  echo "RFC 7050 helper available at /usr/local/sbin/pref64-discover"
fi

echo ""
echo "--- 3. Running Processes ---"
ps -ef 2>/dev/null || ps aux 2>/dev/null || ps

echo ""
echo "--- 4. Network Interfaces ---"
ip -details link show 2>/dev/null || ip link show

echo ""
echo "--- 5. IP Addresses ---"
ip addr show

echo ""
echo "--- 6. Routing Tables ---"
echo "IPv4 Routes:"
ip -4 route show
echo "IPv6 Routes:"
ip -6 route show

echo ""
echo "--- 7. Kernel Forwarding Sysctls ---"
sysctl net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
sysctl net.ipv6.conf.all.forwarding 2>/dev/null || cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

echo ""
echo "--- 8. Active Configuration Files ---"
for f in /run/clat.conf /run/tayga.conf /run/unbound.conf; do
  if [ -f "$f" ]; then
    echo ">>> $f:"
    cat "$f"
    echo ""
  fi
done

echo ""
echo "--- 9. Offload / Ethtool Interface Statistics ---"
if command -v ethtool >/dev/null 2>&1; then
  for iface in $(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    if [ "$iface" != "lo" ]; then
      echo ">>> Offload features for $iface:"
      ethtool -k "$iface" 2>/dev/null | grep -E "generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|rx-checksumming|tx-checksumming" || true
    fi
  done
else
  echo "ethtool is not available in current environment"
fi

echo ""
echo "============================================================"
echo " Diagnostics complete."
echo "============================================================"
