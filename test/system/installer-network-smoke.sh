#!/bin/sh
# Run ONLY in a disposable container: this test replaces its default route.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || { echo 'Requires TAYGA_ISOLATED_TEST=yes in a disposable container' >&2; exit 2; }
ip link set lo up
base=${1:-/work}
work=$(mktemp -d)
daemon=
http=
cleanup() {
    [ -z "$daemon" ] || kill "$daemon" 2>/dev/null || :
    [ -z "$http" ] || kill "$http" 2>/dev/null || :
    sh "$base/packaging/installer/tayga-net-ctl.sh" down "$work/nat64.conf" || :
    ip netns del upstream || :
    ip link del wan0 || :
    rm -rf "$work"
}
trap cleanup 0
ip netns add upstream
ip link add wan0 type veth peer name peer0
ip link set peer0 netns upstream
ip addr add 198.18.0.2/24 dev wan0
ip -6 addr add 2001:db8:1::2/64 dev wan0 nodad
ip link set wan0 up
ip netns exec upstream ip link set lo up
ip netns exec upstream ip addr add 1.1.1.1/32 dev lo
ip netns exec upstream ip addr add 198.18.0.1/24 dev peer0
ip netns exec upstream ip -6 addr add 2001:db8:1::1/64 dev peer0 nodad
ip netns exec upstream ip link set peer0 up
ip -4 route del default || :
ip -4 route add default via 198.18.0.1 dev wan0
ip -6 route add default via 2001:db8:1::1 dev wan0
ip netns exec upstream ip -6 route add 2001:db8:64::/96 via 2001:db8:1::2 dev peer0
mkdir -p /var/lib/tayga/nat64
sh "$base/packaging/installer/configure.sh" --mode=nat64 --pref64=2001:db8:64::/96 --workers=1 --offload="${TAYGA_TEST_OFFLOAD:-auto}" --firewall="${TAYGA_TEST_FIREWALL:-iptables}" --output="$work/nat64.conf"
printf 'translated HTTP works\n' > "$work/index.html"
dd if=/dev/zero of="$work/large.bin" bs=4096 count=256 2>/dev/null
ip netns exec upstream python3 -m http.server 80 --bind 0.0.0.0 --directory "$work" &
http=$!
server_ready=no
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ip netns exec upstream curl -4 --noproxy '*' --silent --max-time 2 http://198.18.0.1/ > /dev/null; then server_ready=yes; break; fi
    sleep 1
done
[ "$server_ready" = yes ] || { echo 'IPv4 HTTP fixture failed to start' >&2; exit 1; }
sh "$base/packaging/installer/tayga-net-ctl.sh" up "$work/nat64.conf"
tayga --config "$work/nat64.conf" --nodetach > "$work/daemon.log" 2>&1 &
daemon=$!
ready=no
for _ in 1 2 3 4 5; do
    if ip netns exec upstream curl -6 --noproxy '*' --silent --max-time 2 'http://[2001:db8:64::c612:1]/' > "$work/result"; then ready=yes; break; fi
    sleep 1
done
[ "$ready" = yes ] || {
    cat "$work/daemon.log"
    ip -s link show nat64
    iptables-save -c
    ip6tables-save -c
    ip netns exec upstream ss -ltnp
    ip netns exec upstream curl -v -6 --noproxy '*' --max-time 2 'http://[2001:db8:64::c612:1]/' || :
    exit 1
}
grep -q 'translated HTTP works' "$work/result"
ip netns exec upstream curl -6 --noproxy '*' --silent --show-error --max-time 15 'http://[2001:db8:64::c612:1]/large.bin' > "$work/download.bin"
cmp "$work/large.bin" "$work/download.bin"
ip netns exec upstream ping -6 -c 1 -W 3 2001:db8:64::c612:1
sh "$base/packaging/installer/tayga-verify.sh" "$work/nat64.conf"
for address_mode in routed proxy-ndp nat66; do
    TAYGA_TEST_CLAT_ADDRESS_MODE=$address_mode sh "$base/test/system/installer-clat-smoke.sh" "$base"
done
sh "$base/test/system/installer-dns64-smoke.sh" "$base"
kill "$http"
wait "$http" || :
http=
if sh "$base/packaging/installer/tayga-verify.sh" "$work/nat64.conf"; then
    echo 'Readiness unexpectedly passed with HTTP server stopped' >&2
    exit 1
fi
kill "$daemon"
wait "$daemon" || :
daemon=
sh "$base/packaging/installer/tayga-net-ctl.sh" down "$work/nat64.conf"
if iptables-save | grep -q TAYGA_SFX; then exit 1; fi
if ip6tables-save | grep -q TAYGA_SFX; then exit 1; fi
if command -v nft >/dev/null && nft list tables | grep -q tayga_sfx_; then exit 1; fi
echo 'PASS: IPv6 client -> NAT64 -> IPv4 HTTP/ICMP, followed by network cleanup'
