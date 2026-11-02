#!/bin/sh
# Bidirectional static EAM translation, only in a disposable test container.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${1:-/work}
work=$(mktemp -d)
daemon=
http4=
http6=
cleanup() {
    for pid in "$daemon" "$http4" "$http6"; do [ -z "$pid" ] || kill "$pid" 2>/dev/null || :; done
    sh "$base/packaging/installer/tayga-net-ctl.sh" down "$work/siit.conf" || :
    ip netns del siit4 || :
    ip netns del siit6 || :
    ip link del swan0 || :
    ip link del slan0 || :
    rm -rf "$work"
}
trap cleanup 0
ip netns add siit4
ip netns add siit6
ip link add swan0 type veth peer name peer4
ip link add slan0 type veth peer name peer6
ip link set peer4 netns siit4
ip link set peer6 netns siit6
ip addr add 198.18.10.2/24 dev swan0
ip -6 addr add 2001:db8:10::2/64 dev swan0 nodad
ip -6 addr add 2001:db8:20::1/64 dev slan0 nodad
ip link set swan0 up
ip link set slan0 up
ip netns exec siit4 ip link set lo up
ip netns exec siit4 ip addr add 198.18.10.1/24 dev peer4
ip netns exec siit4 ip link set peer4 up
ip netns exec siit4 ip route add 198.51.100.42/32 via 198.18.10.2 dev peer4
ip netns exec siit6 ip link set lo up
ip netns exec siit6 ip -6 addr add 2001:db8:20::42/64 dev peer6 nodad
ip netns exec siit6 ip link set peer6 up
ip netns exec siit6 ip -6 route add default via 2001:db8:20::1 dev peer6
ip -4 route del default 2>/dev/null || :
ip -4 route add default via 198.18.10.1 dev swan0
ip -6 route add default dev swan0
mkdir -p /var/lib/tayga/siit "$work/runtime"
sh "$base/packaging/installer/configure.sh" --mode=siit --pref64=2001:db8:64::/96 \
    --map-ipv4=198.51.100.42 --map-ipv6=2001:db8:20::42 --workers=1 \
    --offload="${TAYGA_TEST_OFFLOAD:-auto}" --firewall="${TAYGA_TEST_FIREWALL:-iptables}" --output="$work/siit.conf"
printf 'static SIIT works\n' > "$work/index.html"
dd if=/dev/zero of="$work/large.bin" bs=4096 count=256 2>/dev/null
ip netns exec siit4 python3 -m http.server 8080 --bind 198.18.10.1 --directory "$work" > "$work/http4.log" 2>&1 &
http4=$!
ip netns exec siit6 python3 -m http.server 8080 --bind 2001:db8:20::42 --directory "$work" > "$work/http6.log" 2>&1 &
http6=$!
ready=no
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ip netns exec siit4 curl -4 --noproxy '*' -s --max-time 2 http://198.18.10.1:8080/ >/dev/null &&
        ip netns exec siit6 curl -6 --noproxy '*' -s --max-time 2 'http://[2001:db8:20::42]:8080/' >/dev/null; then ready=yes; break; fi
    sleep 1
done
[ "$ready" = yes ] || { cat "$work/http4.log" "$work/http6.log"; exit 1; }
sh "$base/packaging/installer/tayga-net-ctl.sh" up "$work/siit.conf"
tayga --config "$work/siit.conf" --runtime-dir "$work/runtime" --nodetach > "$work/daemon.log" 2>&1 &
daemon=$!
ready=no
for _ in 1 2 3 4 5; do
    if ip netns exec siit4 curl -4 --noproxy '*' -s --max-time 2 http://198.51.100.42:8080/ > "$work/result4"; then ready=yes; break; fi
    sleep 1
done
[ "$ready" = yes ] || { cat "$work/daemon.log"; exit 1; }
grep -q 'static SIIT works' "$work/result4"
ip netns exec siit4 curl -4 --noproxy '*' -sS --max-time 15 http://198.51.100.42:8080/large.bin > "$work/download4"
ip netns exec siit6 curl -6 --noproxy '*' -sS --max-time 15 'http://[2001:db8:64::c612:a01]:8080/large.bin' > "$work/download6"
cmp "$work/large.bin" "$work/download4"
cmp "$work/large.bin" "$work/download6"
# Source remains the explicitly mapped address: NAT44 is deliberately absent.
grep -q '^198.51.100.42 ' "$work/http4.log"
ip netns exec siit4 ping -4 -c 1 -W 3 198.51.100.42
ip netns exec siit6 ping -6 -c 1 -W 3 2001:db8:64::c612:a01
sh "$base/packaging/installer/tayga-verify.sh" "$work/siit.conf"
kill "$daemon"
wait "$daemon" || :
daemon=
sh "$base/packaging/installer/tayga-net-ctl.sh" down "$work/siit.conf"
if iptables-save | grep -q TAYGA_SFX; then exit 1; fi
if ip6tables-save | grep -q TAYGA_SFX; then exit 1; fi
if command -v nft >/dev/null && nft list tables | grep -q tayga_sfx_; then exit 1; fi
echo 'PASS: bidirectional SIIT HTTP/ICMP, 1 MiB transfer, preserved IPv4 source and cleanup'
