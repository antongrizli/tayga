#!/bin/sh
# Dedicated disposable Linux VM: real firewalld, CLAT and IPv6-only upstream.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
base=${1:?source checkout}
work=${2:?persistent evidence directory}
firewall-cmd --state
if ip link show fwtest0 >/dev/null 2>&1 || ip link show clat >/dev/null 2>&1; then exit 2; fi
if ip netns list | grep -q '^tayga-fw-upstream '; then exit 2; fi
[ -z "$(ip -6 route show default)" ] || { echo 'Fixture needs no preexisting IPv6 default route' >&2; exit 2; }
mkdir -p "$work"
daemon=; server=; config=
cleanup() {
    rc=$?
    [ -z "$daemon" ] || { kill "$daemon" 2>/dev/null || :; wait "$daemon" 2>/dev/null || :; }
    [ -z "$server" ] || { kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :; }
    if [ -n "$config" ]; then
        TAYGA_NET_STATE="$work/state" sh "$base/packaging/installer/tayga-net-ctl.sh" down "$config" || rc=1
    fi
    ip netns del tayga-fw-upstream 2>/dev/null || :
    ip link del fwtest0 2>/dev/null || :
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
firewall-cmd --direct --get-all-rules | LC_ALL=C sort > "$work/direct.before"
firewall-cmd --list-all-zones > "$work/zones.before"
ip netns add tayga-fw-upstream
ip link add fwtest0 type veth peer name eth0 netns tayga-fw-upstream
ip -6 addr add 2001:db8:2::2/128 dev fwtest0 nodad
ip link set fwtest0 up
ip -6 route add default via 2001:db8:2::1 dev fwtest0 onlink
ip -n tayga-fw-upstream link set lo up
ip -n tayga-fw-upstream -6 addr add 2001:db8:2::1/64 dev eth0 nodad
ip -n tayga-fw-upstream -6 addr add fd64:100::101:101/128 dev lo nodad
ip -n tayga-fw-upstream link set eth0 up
sysctl_keys='net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.accept_ra net.ipv6.conf.fwtest0.accept_ra net.ipv6.conf.fwtest0.proxy_ndp'
# Fixed test-owned key list, intentionally split into separate arguments.
# shellcheck disable=SC2086
sysctl -n $sysctl_keys > "$work/sysctl.before"
printf 'firewalld-translated-proof\n' > "$work/proof"
dd if=/dev/zero of="$work/large" bs=4096 count=256 2>/dev/null
for mode in nat66 proxy-ndp; do
    config=$work/$mode.conf
    clat6=2001:db8:2::464; daemon6=2001:db8:2::465; external=
    if [ "$mode" = nat66 ]; then clat6=fd64:2::464; daemon6=fd64:2::465; external=2001:db8:2::2; fi
    NAT66_ADDRESS=$external sh "$base/packaging/installer/configure.sh" --mode=clat \
        --pref64=fd64:100::/96 --clat-ipv6="$clat6" --tayga-ipv6="$daemon6" \
        --clat-address-mode="$mode" --firewall=firewalld --offload=off --workers=1 --output="$config"
    TAYGA_NET_STATE="$work/state" sh "$base/packaging/installer/tayga-net-ctl.sh" up "$config"
    mkdir -p "$work/runtime-$mode"
    tayga --config "$config" --runtime-dir "$work/runtime-$mode" --nodetach > "$work/$mode.daemon.log" 2>&1 &
    daemon=$!
    ip netns exec tayga-fw-upstream python3 -m http.server 80 --bind fd64:100::101:101 --directory "$work" > "$work/$mode.http.log" 2>&1 &
    server=$!
    for _ in $(seq 1 10); do
        if curl -4 -fsS --noproxy '*' --connect-timeout 2 --max-time 4 http://1.1.1.1/proof > "$work/$mode.result"; then break; fi
        sleep 1
    done
    grep -Fx 'firewalld-translated-proof' "$work/$mode.result"
    curl -4 -fsS --noproxy '*' --max-time 20 http://1.1.1.1/large > "$work/$mode.large"
    cmp "$work/large" "$work/$mode.large"
    ping -4 -c 2 -W 3 1.1.1.1
    if [ "$mode" = nat66 ]; then grep -F '2001:db8:2::2' "$work/$mode.http.log";
    else grep -F '2001:db8:2::464' "$work/$mode.http.log"; fi
    kill "$daemon" "$server"
    wait "$daemon" 2>/dev/null || :; wait "$server" 2>/dev/null || :
    daemon=; server=
    TAYGA_NET_STATE="$work/state" sh "$base/packaging/installer/tayga-net-ctl.sh" down "$config"
    config=
    [ -z "$(ip -6 neigh show proxy dev fwtest0)" ]
    # shellcheck disable=SC2086
    sysctl -n $sysctl_keys > "$work/$mode.sysctl.after"
    cmp "$work/sysctl.before" "$work/$mode.sysctl.after"

    firewall-cmd --direct --get-all-rules | LC_ALL=C sort > "$work/$mode.direct.after"
    cmp "$work/direct.before" "$work/$mode.direct.after"
done
ip link del fwtest0
ip netns del tayga-fw-upstream
firewall-cmd --list-all-zones > "$work/zones.after"
cmp "$work/zones.before" "$work/zones.after"
trap - EXIT HUP INT TERM
echo 'PASS: firewalld NAT66/Proxy NDP ICMP, HTTP, 1 MiB TCP and ownership cleanup'
