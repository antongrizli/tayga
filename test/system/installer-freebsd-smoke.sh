#!/bin/sh
# System smoke test for FreeBSD: network controller, pf, rc.d, and rollback.
# Must run ONLY on a dedicated disposable FreeBSD VM as root.
set -eu

if [ "${TAYGA_ISOLATED_TEST:-}" != yes ] || [ "$(uname -s)" != FreeBSD ] || [ "$(id -u)" -ne 0 ]; then
    echo "Requires TAYGA_ISOLATED_TEST=yes, FreeBSD, and root privileges" >&2
    exit 2
fi

bundle=${1:?path to installer bundle required}
[ -f "$bundle" ] || { echo "Installer bundle not found: $bundle" >&2; exit 2; }

echo "=== 1. Checking clean initial state ==="
if ifconfig tun64 >/dev/null 2>&1; then
    echo "FAIL: tun64 interface already exists" >&2
    exit 1
fi
if [ -e /usr/local/etc/rc.d/tayga-managed ]; then
    echo "FAIL: tayga-managed rc.d script already exists" >&2
    exit 1
fi

cleanup() {
    rc=$?
    echo "=== Cleaning up ==="
    if [ -x /usr/local/sbin/tayga-ctl ] && [ -d /var/lib/tayga-installer/files ]; then
        /usr/local/sbin/tayga-ctl uninstall || :
        /usr/local/sbin/tayga-ctl uninstall || :
    fi
    if ifconfig tun64 >/dev/null 2>&1; then
        ifconfig tun64 destroy || :
    fi
    pfctl -a 'tayga_sfx/*' -F all >/dev/null 2>&1 || :
    exit $rc
}
trap cleanup EXIT HUP INT TERM

echo "=== 2. Running SFX installation in SIIT mode ==="
# SIIT mode creates the TUN interface, sets up routes, loads pf anchors,
# and starts the service, all without requiring an external PLAT/gateway.
sh "$bundle" --mode=siit --pref64=64:ff9b::/96 --map-ipv4=192.0.2.42 --map-ipv6=2001:db8:64::42 --yes

echo "=== 3. Verifying FreeBSD service and network state ==="
# Binary and scripts installed
[ -x /usr/local/sbin/tayga ]
[ -x /usr/local/sbin/pref64-discover ]
[ -x /usr/local/sbin/tayga-ctl ]
[ -x /usr/local/libexec/tayga/tayga-net-ctl ]
[ -f /usr/local/etc/rc.d/tayga-managed ]
[ -f /usr/local/etc/rc.d/tayga-recovery ]

# Service status
service tayga-managed status
service tayga-managed onestatus
/usr/local/sbin/tayga-ctl status | grep -E '(running|active|PID)'

# Interface
ifconfig tun64 >/dev/null
ifconfig tun64 | grep -q 'UP'

# Routes
route -n get 192.0.2.42 | grep -q 'interface: tun64'
route -n get -inet6 64:ff9b::1 | grep -q 'interface: tun64'

# Sysctl
[ "$(sysctl -n net.inet.ip.forwarding)" = "1" ]
[ "$(sysctl -n net.inet6.ip6.forwarding)" = "1" ]
[ "$(sysctl -n net.inet6.ip6.accept_rtadv)" = "1" ]

# PF firewall rules
pfctl -s info | grep -q 'Status: Enabled'
pfctl -sr | grep -q 'anchor "tayga_sfx/\*"'
pfctl -a 'tayga_sfx/tun64' -sr | grep -q 'scrub on tun64'
pfctl -a 'tayga_sfx/tun64' -sr | grep -q 'pass in quick on tun64'

echo "=== 4. Testing rc.d restart ==="
service tayga-managed restart
service tayga-managed status
ifconfig tun64 >/dev/null

echo "=== 5. Testing early file copy recovery limitation (Step 4) ==="
# Simulate interrupted file transaction
mkdir -p /var/lib/tayga-installer/files-transaction
cp -Rp /var/lib/tayga-installer/files /var/lib/tayga-installer/files-transaction/metadata
printf 'stale_marker\n' > /var/lib/tayga-installer/files-transaction/stale_test
# Running boot recover should detect and clear orphaned files-transaction
/usr/local/libexec/tayga/tayga-boot-recover.sh
[ ! -d /var/lib/tayga-installer/files-transaction ]
[ -d /var/lib/tayga-installer/files ]
echo "PASS: Early file copy recovery cleaned orphaned transaction"

echo "=== 6. Testing rollback protection ==="
# Creating an invalid configuration candidate and running configure/apply
# should fail validation and leave the current service operational.
work=$(mktemp -d)
cat > "$work/invalid.conf" <<'EOF'
# installer-mode siit
tun-device tun64
ipv4-addr 192.0.2.1
ipv6-addr 2001:db8::1
prefix 64:ff9b::/96
# Missing required map directive for SIIT
EOF

if /usr/local/libexec/tayga/tayga-lifecycle.sh apply "$work/invalid.conf"; then
    echo "FAIL: Expected invalid SIIT profile to fail apply" >&2
    exit 1
fi
rm -rf "$work"

# Verify original SIIT service remains active and healthy
service tayga-managed status
ifconfig tun64 >/dev/null

echo "=== 7. Testing clean uninstall ==="
# Uninstall removes the active managed profile (siit) and uninstalls owned files
/usr/local/sbin/tayga-ctl uninstall
if ifconfig tun64 >/dev/null 2>&1; then
    echo "FAIL: tun64 interface was not destroyed on uninstall" >&2
    exit 1
fi
if [ -e /usr/local/etc/rc.d/tayga-managed ]; then
    echo "FAIL: tayga-managed rc.d script remains after uninstall" >&2
    exit 1
fi
if [ -e /usr/local/sbin/tayga ]; then
    echo "FAIL: /usr/local/sbin/tayga remains after file uninstall" >&2
    exit 1
fi
[ ! -f /var/lib/tayga-installer/current ]
[ ! -d /var/lib/tayga-installer/files ]

# Check PF anchor was flushed
if pfctl -a 'tayga_sfx/tun64' -sr 2>/dev/null | grep -q 'scrub on tun64'; then
    echo "FAIL: PF anchor rules remain after uninstall" >&2
    exit 1
fi

trap - EXIT HUP INT TERM
echo "PASS: FreeBSD end-to-end network, pf, rc.d, recovery, and rollback verification"
