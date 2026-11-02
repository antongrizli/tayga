#!/bin/sh
# Required service readiness probe. Failure lets systemd stop and clean up.
set -eu
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/sbin:/bin:/usr/sbin:/usr/bin}:/usr/local/sbin:/usr/local/bin"; export PATH ;; esac
[ "$#" -eq 1 ] || { echo 'Usage: tayga-verify CONFIG' >&2; exit 2; }
config=$1
mode=$(awk '$1=="#" && $2=="installer-mode" {print $3}' "$config")
if [ -z "$mode" ]; then
    mode=$(awk '$1=="tun-device" {print $2}' "$config")
fi
case "$mode" in clat|nat64|siit) ;; *) echo 'Unsupported verification profile' >&2; exit 2 ;; esac
dev=$(awk '$1=="tun-device" {print $2}' "$config")
if [ "$(uname -s)" = FreeBSD ]; then
    ifconfig "$dev" >/dev/null
else
    ip link show dev "$dev" >/dev/null
fi
if [ "$mode" = siit ]; then
    map4=$(awk '$1=="map" {print $2}' "$config")
    prefix=$(awk '$1=="prefix" {print $2}' "$config")
    for value in "$map4" "$prefix"; do
        case "$value" in ''|*[!0-9a-fA-F:./]*) exit 1 ;; esac
    done
    if [ "$(uname -s)" = FreeBSD ]; then
        route4=$(route -n get "${map4%/*}" 2>/dev/null || :)
        route6=$(route -n get -inet6 "${prefix%/*}" 2>/dev/null || :)
        case "$route4" in *"interface: $dev"*) ;; *) echo '[FAIL] SIIT IPv4 translation route missing' >&2; exit 1 ;; esac
        case "$route6" in *"interface: $dev"*) ;; *) echo '[FAIL] SIIT IPv6 translation route missing' >&2; exit 1 ;; esac
    else
        for route in "$(ip -4 route get "${map4%/*}")" "$(ip -6 route get "${prefix%/*}")"; do
            case "$route" in *'dev siit '*|*'dev siit') ;; *) echo '[FAIL] SIIT translation route missing' >&2; exit 1 ;; esac
        done
    fi
    echo '[PASS] TUN Interface & Routes active'
    echo '[PASS] SIIT translation routes verified'
    exit 0
fi
# Probe NAT64 through its IPv6 translation route, never through native IPv4.
# A hexadecimal dotted-quad suffix is valid only for a /96 prefix.
if [ "$mode" = nat64 ]; then
    prefix=$(awk '$1=="prefix" {print $2}' "$config")
    case "$prefix" in */96) ;; *) echo 'Automatic NAT64 verification currently requires /96' >&2; exit 1 ;; esac
    address=${prefix%/96}
    case "$address" in *::) target=${address}101:101 ;; *) echo 'Verification requires a canonical /96 prefix ending in ::' >&2; exit 1 ;; esac
    family=-6
    url=http://[$target]/
else
    target=1.1.1.1
    family=-4
    url=http://$target/
fi
# HTTP tests TCP as well as PMTU/MSS; accepting ICMP alone can hide black holes.
# Never use proxies: they could bypass the route being tested.
for _ in 1 2 3; do
    if curl "$family" --noproxy '*' --connect-timeout 3 --max-time 5 \
        --silent --show-error --output /dev/null "$url" 2>/dev/null; then
        echo '[PASS] TUN Interface & Routes active'
        echo '[PASS] Outbound TCP/HTTPv4 connectivity'
        echo '[PASS] Routing isolation verified'
        exit 0
    fi
done
echo '[FAIL] Translated TCP/HTTP connectivity; service startup will be rolled back' >&2
exit 1
