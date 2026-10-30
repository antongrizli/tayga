#!/bin/sh
# Only in a dedicated disposable VM/container. Packages remain unsigned test artifacts.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
[ "$#" -eq 4 ] || exit 2
kind=$1; first=$2; second=$3; version=$4
state=/var/lib/tayga-installer
for path in /usr/sbin/tayga /usr/local/sbin/tayga "$state/files" "$state/current" "$state/nat64.conf" /var/lib/tayga/native-package-smoke-data; do
    if [ -e "$path" ] || [ -L "$path" ]; then echo "Expected clean VM: $path" >&2; exit 2; fi
done
work=$(mktemp -d)
config=/etc/tayga/tayga.conf.example
[ ! -L "$config" ] || exit 2
if [ -e "$config" ]; then cp -p "$config" "$work/config.before"; fi
cleanup() {
    rm -f "$state/nat64.conf"
    if [ "$kind" = apk ] && [ -f /usr/libexec/tayga/package-lock.sh ]; then sh /usr/libexec/tayga/package-lock.sh unlock || :; fi
    case "$kind" in
        deb) dpkg --purge tayga-managed >/dev/null 2>&1 || : ;;
        apk) apk del tayga-managed >/dev/null 2>&1 || : ;;
        rpm) rpm -e tayga-managed >/dev/null 2>&1 || : ;;
    esac
    if [ -f "$work/config.before" ]; then cp -p "$work/config.before" "$config"; fi
    rm -f /var/lib/tayga/native-package-smoke-data
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
install_package() {
    case "$kind" in
        deb) dpkg --force-confold -i "$1" ;;
        apk) apk add --allow-untrusted "$1" ;;
        rpm) dnf install -y "$1" ;;
        *) exit 2 ;;
    esac
}
package_version() {
    case "$kind" in
        deb) dpkg-query -W -f='${Version}' tayga-managed ;;
        apk) apk info -v | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p' ;;
        rpm) rpm -q --qf '%{VERSION}-%{RELEASE}' tayga-managed ;;
    esac
}
cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding > "$work/sysctl.before"
install_package "$first"
/usr/sbin/tayga --help | grep -Fx "TAYGA version $version"
/usr/sbin/pref64-discover --check 64:ff9b::192.0.0.170 | grep -Fx '64:ff9b::/96'
[ -f /usr/libexec/tayga/package-owner ]
mkdir -p /var/lib/tayga "$state"
printf 'retained dynamic data\n' > /var/lib/tayga/native-package-smoke-data
printf '# native package administrator edit\n' >> "$config"
before=$(package_version)
# Guard configured profiles before modifying any installed executable.
if [ "$kind" = apk ]; then sh /usr/libexec/tayga/package-lock.sh lock; fi
printf 'configured profile fixture\n'  > "$state/nat64.conf"
if install_package "$second" > "$work/blocked.log" 2>&1; then cat "$work/blocked.log"; exit 1; fi
[ "$(package_version)" = "$before" ]

# Coordinated live upgrade succeeds with the configured profile retained.
/usr/sbin/tayga-ctl upgrade "$second"
[ "$(package_version)" != "$before" ]
[ -f "$state/nat64.conf" ]
rm "$state/nat64.conf"
if [ "$kind" = apk ]; then sh /usr/libexec/tayga/package-lock.sh unlock; fi
grep -Fx '# native package administrator edit' "$config"
cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding > "$work/sysctl.after"
cmp "$work/sysctl.before" "$work/sysctl.after"
case "$kind" in
    deb) dpkg --remove tayga-managed ;;
    apk) apk del tayga-managed ;;
    rpm) dnf remove -y tayga-managed ;;
esac
[ ! -e /usr/sbin/tayga ]
grep -Fx 'retained dynamic data' /var/lib/tayga/native-package-smoke-data
preserved=no
for candidate in "$config" "$config.rpmsave" "$config.apk-save"; do
    if [ -f "$candidate" ] && grep -Fx '# native package administrator edit' "$candidate" >/dev/null; then preserved=yes; fi
done
[ "$preserved" = yes ]
echo "PASS: $kind install, guarded upgrade, live upgrade, config/data preservation and removal"
