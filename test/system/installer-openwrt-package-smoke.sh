#!/bin/sh
# Run only against a disposable, matching OpenWrt rootfs in a Linux test VM.
# No bind mounts, kernel/network setup, or downloads. Supply matching dependencies.
set -eu
[ "$#" -ge 3 ] || exit 2
root=$(realpath "$1")
package=$(realpath "$2")
[ "$root" != / ] && [ -f "$root/etc/openwrt_release" ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
[ ! -e "$root/usr/sbin/tayga" ] || exit 2
mkdir -p "$root/tmp" "$root/var/lock"
cp "$package" "$root/tmp/$(basename "$package")"
shift 2
# Pass only files copied explicitly into this rootfs; no untrusted shell expansion.
dependency_count=$#
while [ "$dependency_count" -gt 0 ]; do
    dependency=$1; shift
    cp "$dependency" "$root/tmp/$(basename "$dependency")"
    set -- "$@" "/tmp/$(basename "$dependency")"
    dependency_count=$((dependency_count - 1))
done
before=$(mktemp)
after=$(mktemp)
trap 'rm -f "$before" "$after"' 0
for name in network firewall dhcp; do
    if [ -f "$root/etc/config/$name" ]; then sha256sum "$root/etc/config/$name" >> "$before"
    else echo "missing: $name" >> "$before"; fi
done
if [ -x "$root/bin/opkg" ]; then
    # Dependencies must never run module hooks against the VM kernel.
    chroot "$root" opkg --offline-root / install "$@"
    # offline-root omits conffile hashes. Exercise normal file ownership for
    # this binary-only package, suppressing its generated postinstall script.
    chroot "$root" /usr/bin/env IPKG_NO_SCRIPT=1 opkg install "/tmp/$(basename "$package")"
    chroot "$root" opkg status tayga-managed-openwrt | grep '^Depends:.*kmod-tun'
    manager=opkg
elif [ -x "$root/usr/bin/apk" ] || [ -x "$root/sbin/apk" ]; then
    # Disposable rootfs: local unsigned test packages have no persistent cache.
    chroot "$root" apk --no-network --no-scripts --allow-untrusted --force-non-repository add "$@" "/tmp/$(basename "$package")"
    manager=apk
else echo 'OpenWrt package manager missing' >&2; exit 1
fi
chroot "$root" /usr/sbin/tayga --help > /dev/null
chroot "$root" /usr/sbin/pref64-discover --check 64:ff9b::192.0.0.170 | grep -Fx '64:ff9b::/96'
[ "$(cat "$root/usr/libexec/tayga/package-owner")" = openwrt-sdk ]
[ ! -e "$root/etc/init.d/tayga-managed" ]
for name in network firewall dhcp; do
    if [ -f "$root/etc/config/$name" ]; then sha256sum "$root/etc/config/$name" >> "$after"
    else echo "missing: $name" >> "$after"; fi
done
cmp "$before" "$after"
echo '# local test edit' >> "$root/etc/tayga/tayga.conf.example"
mkdir -p "$root/var/lib/tayga"
echo retained > "$root/var/lib/tayga/package-smoke"
if [ "$manager" = opkg ]; then
    chroot "$root" /usr/bin/env IPKG_NO_SCRIPT=1 opkg remove tayga-managed-openwrt
else chroot "$root" apk --no-scripts del tayga-managed-openwrt
fi
[ ! -e "$root/usr/sbin/tayga" ]
grep -q 'local test edit' "$root/etc/tayga/tayga.conf.example"
grep -q retained "$root/var/lib/tayga/package-smoke"
echo 'OpenWrt binary-only package smoke passed (no live network activation)'
