#!/bin/sh
# Disposable OpenWrt rootfs only; no running procd or kernel mounts required.
set -eu
[ "$#" -ge 4 ] || exit 2
root=$(realpath "$1")
base=$(realpath "$2")
service=$(realpath "$3")
shift 3
[ "$root" != / ] && [ -f "$root/etc/openwrt_release" ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
[ ! -e "$root/usr/sbin/tayga" ] || exit 2
mkdir -p "$root/tmp" "$root/var/lock"
dependency_count=$#
while [ "$dependency_count" -gt 0 ]; do
    dependency=$1; shift
    cp "$dependency" "$root/tmp/$(basename "$dependency")"
    set -- "$@" "/tmp/$(basename "$dependency")"
    dependency_count=$((dependency_count - 1))
done
cp "$base" "$service" "$root/tmp/"
if [ -x "$root/bin/opkg" ]; then
    chroot "$root" opkg --offline-root / install "$@"
    chroot "$root" /usr/bin/env IPKG_NO_SCRIPT=1 opkg install "/tmp/$(basename "$base")" "/tmp/$(basename "$service")"
    manager=opkg
elif [ -x "$root/usr/bin/apk" ] || [ -x "$root/sbin/apk" ]; then
    # Disposable rootfs: local unsigned test packages have no persistent cache.
    chroot "$root" apk --no-network --no-scripts --allow-untrusted --force-non-repository add "$@" "/tmp/$(basename "$base")" "/tmp/$(basename "$service")"
    manager=apk
else
    echo 'OpenWrt package manager missing' >&2
    exit 1
fi
[ "$(chroot "$root" uci -q get tayga_managed.main.enabled)" = 0 ]
mkdir -p "$root/sys/class/net/tun64"
echo 0x1001 > "$root/sys/class/net/tun64/tun_flags"
cat > "$root/etc/tayga/managed.conf" <<'EOF'
tun-device tun64
ipv4-addr 192.0.2.1
ipv6-addr fd64::1
prefix 64:ff9b::/96
data-dir /var/lib/tayga/check-only
EOF
# Validation must work unprivileged in a rootfs without /dev/net/tun.
chroot --userspec=65534:65534 "$root" /usr/sbin/tayga --check-config --config /etc/tayga/managed.conf --runtime-dir /tmp/check-runtime --status-file /tmp/check-status
[ ! -e "$root/var/lib/tayga/check-only" ]
[ ! -e "$root/tmp/check-runtime" ]
[ ! -e "$root/tmp/check-status" ]
if chroot "$root" /usr/sbin/tayga --check-offload --check-config --config /etc/tayga/managed.conf; then exit 1; fi
chroot "$root" /usr/libexec/tayga/openwrt-state prepare /etc/tayga/managed.conf
chroot "$root" /usr/libexec/tayga/openwrt-state commit
snapshot=$root/etc/tayga-managed/active.conf
grep -Fx 'data-dir /etc/tayga-managed/data' "$snapshot"
cp "$snapshot" "$root/tmp/accepted.conf"
cat > "$root/etc/tayga/next.conf" <<'EOF'
tun-device tun64
ipv4-addr 192.0.2.9
ipv6-addr fd64::9
prefix 64:ff9b::/96
EOF
chroot "$root" /usr/libexec/tayga/openwrt-state prepare /etc/tayga/next.conf
grep -Fx 'ipv4-addr 192.0.2.9' "$snapshot"
chroot "$root" /usr/libexec/tayga/openwrt-state rollback external
cmp "$snapshot" "$root/tmp/accepted.conf"
echo invalid >> "$root/etc/tayga/managed.conf"
if chroot "$root" /usr/libexec/tayga/openwrt-state prepare /etc/tayga/managed.conf; then exit 1; fi
cmp "$snapshot" "$root/tmp/accepted.conf"
# Simulate loss of power after publication but before transaction commit.
pending=$root/etc/tayga-managed/pending
mkdir "$pending"
cp "$snapshot" "$pending/old.conf"
echo yes > "$pending/previous"
echo v1 > "$pending/ready"
echo interrupted > "$snapshot"
chroot "$root" /usr/libexec/tayga/openwrt-state recover
cmp "$snapshot" "$root/tmp/accepted.conf"
[ ! -e "$pending" ]
chroot "$root" uci set tayga_managed.main.enabled=1
chroot "$root" uci commit tayga_managed
[ "$(chroot "$root" uci -q get tayga_managed.main.enabled)" = 1 ]
echo '# retained edit' >> "$root/etc/config/tayga_managed"
echo retained > "$root/etc/tayga-managed/data/state-test"
# In a chroot ubus has no socket: prerm cannot reach the VM's procd or network.
if [ "$manager" = opkg ]; then
    chroot "$root" opkg remove tayga-managed-openwrt-procd
else
    chroot "$root" apk --no-scripts del tayga-managed-openwrt-procd
fi
grep -q 'retained edit' "$root/etc/config/tayga_managed"
grep -q retained "$root/etc/tayga-managed/data/state-test"
[ -f "$snapshot" ]
echo 'OpenWrt service state smoke passed (process supervision is tested separately)'
