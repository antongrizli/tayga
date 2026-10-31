#!/bin/sh
# Disposable VM only: real IPv4 client -> SIIT -> IPv6 HTTP endpoint.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
for ns in tayga-wire-client tayga-wire-server; do
    if ip netns list | grep -q "^$ns "; then exit 2; fi
done
for interface in twclient twserver; do
    if ip link show dev "$interface" >/dev/null 2>&1; then exit 2; fi
done
work=$(mktemp -d)
server=
cleanup() {
    if [ -n "$server" ]; then kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :; fi
    ip netns del tayga-wire-client 2>/dev/null || :
    ip netns del tayga-wire-server 2>/dev/null || :
    ip link del twclient 2>/dev/null || :
    ip link del twserver 2>/dev/null || :
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
ip netns add tayga-wire-client
ip netns add tayga-wire-server
ip link add twclient type veth peer name eth0 netns tayga-wire-client
ip link add twserver type veth peer name eth0 netns tayga-wire-server
ip addr add 198.18.20.1/24 dev twclient
ip link set twclient up
ip -6 addr add fd64:201::1/64 dev twserver nodad
ip link set twserver up
ip -n tayga-wire-client link set lo up
ip -n tayga-wire-client addr add 198.18.20.2/24 dev eth0
ip -n tayga-wire-client link set eth0 up
ip -n tayga-wire-client route add 198.18.10.1/32 via 198.18.20.1
ip -n tayga-wire-server link set lo up
ip -n tayga-wire-server -6 addr add fd64:201::2/64 dev eth0 nodad
ip -n tayga-wire-server -6 addr add fd64:200::1/128 dev lo nodad
ip -n tayga-wire-server link set eth0 up
ip -n tayga-wire-server -6 route add fd64:100::/96 via fd64:201::1
ip -6 route add fd64:200::1/128 via fd64:201::2 dev twserver
printf 'translated-native-wire-proof\n' > "$work/proof"
ip netns exec tayga-wire-server python3 -m http.server 18080 --bind fd64:200::1 --directory "$work" > "$work/server.log" 2>&1 &
server=$!
ip netns exec tayga-wire-client ping -c 2 -W 3 198.18.10.1
for _ in $(seq 1 10); do
    if ip netns exec tayga-wire-client curl -fsS --noproxy '*' --connect-timeout 2 --max-time 4 http://198.18.10.1:18080/proof > "$work/result"; then break; fi
    sleep 1
done
grep -Fx 'translated-native-wire-proof' "$work/result"
# The IPv6 server must observe the translated client, not a host-side proxy.
grep -F 'fd64:100::c612:1402' "$work/server.log"
echo 'PASS: forwarded SIIT ICMP and TCP/HTTP between independent namespaces'
