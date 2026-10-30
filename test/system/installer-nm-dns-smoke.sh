#!/bin/sh
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${1:-/opt/tayga-source}
helper=$base/packaging/installer/tayga-host-dns.sh
if ip link show clat >/dev/null 2>&1; then exit 2; fi
work=$(mktemp -d)
export TAYGA_HOST_DNS_RUNTIME="$work/runtime"
cleanup() {
 sh "$helper" down "$work/config" || :
 ip link del clat || :
 rm -rf "$work"
}
trap cleanup EXIT
ip tuntap add mode tun name clat
ip addr add 192.0.0.1/32 dev clat
ip link set clat up
nmcli device set clat managed yes
for _ in $(seq 1 20); do
 [ "$(nmcli -g GENERAL.STATE device show clat | cut -d ' ' -f 1)" != 100 ] || break
 sleep 1
done
nmcli -g GENERAL.STATE device show clat
nmcli -g IP4.DNS device show clat > "$work/before"
ip -4 route show > "$work/routes.before"
printf 'tun-device clat\n# installer-host-dns public-nm\n' > "$work/config"
sh "$helper" prepare "$work/config"
sh "$helper" up "$work/config"
nmcli -g IP4.DNS device show clat | tr '|' '\n' | awk '{$1=$1;print}' | grep -Fx 1.1.1.1
sh "$helper" down "$work/config"
nmcli -g IP4.DNS device show clat > "$work/after"
cmp "$work/before" "$work/after"
ip -4 route show > "$work/routes.after"
cmp "$work/routes.before" "$work/routes.after"
echo 'PASS: native NetworkManager DNS and checkpoint rollback on TUN'
