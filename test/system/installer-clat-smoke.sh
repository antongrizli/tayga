#!/bin/sh
# Called inside the disposable NAT64 test container while the IPv4 server runs.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${1:-/work}
work=$(mktemp -d)
daemon=
address_mode=${TAYGA_TEST_CLAT_ADDRESS_MODE:-routed}
cleanup() {
    [ -z "$daemon" ] || kill "$daemon" 2>/dev/null || :
    # Positional arguments are expanded by the child shell.
    # shellcheck disable=SC2016
    ip netns exec clatclient sh -ec 'if [ "$1" = yes ]; then mount -o remount,rw /proc/sys; fi; shift; exec "$@"' sh "${TAYGA_TEST_REMOUNT_SYSCTL:-yes}" env TAYGA_NET_STATE="$work/state" sh "$base/packaging/installer/tayga-net-ctl.sh" down "$work/clat.conf" || :
    ip netns del clatclient || :
    ip link del crouter0 2>/dev/null || :
    rm -rf "$work"
}
trap cleanup 0
ip netns add clatclient
ip link add crouter0 type veth peer name cwan0
ip link set cwan0 netns clatclient
ip addr add 10.77.0.1/24 dev crouter0
ip -6 addr add 2001:db8:2::1/64 dev crouter0 nodad
ip link set crouter0 up
ip netns exec clatclient ip link set lo up
ip netns exec clatclient ip addr add 10.77.0.2/24 dev cwan0
ip netns exec clatclient ip -6 addr add 2001:db8:2::2/128 dev cwan0 nodad
ip netns exec clatclient ip link set cwan0 up
ip netns exec clatclient ip -4 route add default via 10.77.0.1 dev cwan0
ip netns exec clatclient ip -6 route add default via 2001:db8:2::1 dev cwan0 onlink
clat6=2001:db8:2::464
daemon6=2001:db8:2::465
case "$address_mode" in
 routed)
    ip -6 route add "$clat6/128" via 2001:db8:2::2 dev crouter0
    ip -6 route add "$daemon6/128" via 2001:db8:2::2 dev crouter0
    ;;
 proxy-ndp) ;; # Deliberately no host routes: upstream must use neighbor discovery.
 nat66) clat6=fd64:2::464; daemon6=fd64:2::465 ;;
 *) exit 2 ;;
esac
# Docker mounts /proc/sys read-only. Remount only within ip-netns-exec's
# private mount namespace so the test can exercise runtime sysctl changes.
mkdir -p /var/lib/tayga/clat "$work/runtime"
nat66_address=
if [ "$address_mode" = nat66 ]; then nat66_address=2001:db8:2::2; fi
NAT66_ADDRESS=$nat66_address sh "$base/packaging/installer/configure.sh" --mode=clat --pref64=2001:db8:64::/96 \
    --clat-ipv6="$clat6" --tayga-ipv6="$daemon6" \
    --clat-address-mode="$address_mode" \
    --workers=1 --offload="${TAYGA_TEST_OFFLOAD:-auto}" --firewall="${TAYGA_TEST_FIREWALL:-iptables}" --output="$work/clat.conf"
# Positional arguments are expanded by the child shell.
# shellcheck disable=SC2016
ip netns exec clatclient sh -ec 'if [ "$1" = yes ]; then mount -o remount,rw /proc/sys; fi; shift; exec "$@"' sh "${TAYGA_TEST_REMOUNT_SYSCTL:-yes}" env TAYGA_NET_STATE="$work/state" sh "$base/packaging/installer/tayga-net-ctl.sh" up "$work/clat.conf"
ip netns exec clatclient tayga --config "$work/clat.conf" --runtime-dir "$work/runtime" --nodetach > "$work/daemon.log" 2>&1 &
daemon=$!
ready=no
for _ in 1 2 3 4 5; do
    if ip netns exec clatclient curl -4 --noproxy '*' --silent --max-time 2 http://1.1.1.1/ > "$work/result"; then ready=yes; break; fi
    sleep 1
done
[ "$ready" = yes ] || { cat "$work/daemon.log"; exit 1; }
grep -q 'translated HTTP works' "$work/result"
ip netns exec clatclient curl -4 --noproxy '*' --silent --show-error --max-time 15 http://1.1.1.1/large.bin > "$work/download.bin"
dd if=/dev/zero of="$work/expected.bin" bs=4096 count=256 2>/dev/null
cmp "$work/expected.bin" "$work/download.bin"
ip netns exec clatclient ip -4 route get 1.1.1.1 | grep 'dev clat'
ip netns exec clatclient ping -4 -c 1 -W 3 1.1.1.1
ip netns exec clatclient sh "$base/packaging/installer/tayga-verify.sh" "$work/clat.conf"
kill "$daemon"
wait "$daemon" || :
daemon=
# Positional arguments are expanded by the child shell.
# shellcheck disable=SC2016
ip netns exec clatclient sh -ec 'if [ "$1" = yes ]; then mount -o remount,rw /proc/sys; fi; shift; exec "$@"' sh "${TAYGA_TEST_REMOUNT_SYSCTL:-yes}" env TAYGA_NET_STATE="$work/state" sh "$base/packaging/installer/tayga-net-ctl.sh" down "$work/clat.conf"
if ip netns exec clatclient iptables-save | grep -q TAYGA_SFX; then exit 1; fi
if ip netns exec clatclient ip6tables-save | grep -q TAYGA_SFX; then exit 1; fi
if command -v nft >/dev/null && ip netns exec clatclient nft list tables | grep -q tayga_sfx_; then exit 1; fi
if [ -n "$(ip netns exec clatclient ip -6 neigh show proxy dev cwan0)" ]; then exit 1; fi
echo "PASS: $address_mode IPv4 application -> CLAT -> NAT64 -> IPv4 HTTP/ICMP, followed by cleanup"
