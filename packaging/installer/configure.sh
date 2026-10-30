#!/bin/sh
# Generate a reviewable profile; this helper never applies network changes.
set -eu
fail() { echo "ERROR: $*" >&2; exit 2; }
mode=${MODE:-nat64}
pref64=${PREF64:-64:ff9b::/96}
dns64=${DNS64_SERVER:-}
pool4=${DYNAMIC_POOL:-192.168.240.0/20}
addr4=${TAYGA_IPV4:-}
addr6=${TAYGA_IPV6:-fd64::2}
source6=${TUN_IPV6:-fd64::1}
clat6=${CLAT_IPV6:-}
map4=${MAP_IPV4:-}
map6=${MAP_IPV6:-}
mtu=${OFFLINK_MTU:-1400}
offload=${TUN_OFFLOAD:-auto}
workers=${WORKERS:-auto}
firewall=${FIREWALL:-auto}
enable_dns64=${ENABLE_DNS64:-no}
dns64_listen=${DNS64_LISTEN:-::1}
dns64_allow=${DNS64_ALLOW:-::1/128}
dns64_upstream=${DNS64_UPSTREAM:-1.1.1.1}
dns64_dnssec=${DNS64_DNSSEC:-validate}
host_dns=${HOST_DNS:-keep}
address_mode=${CLAT_ADDRESS_MODE:-routed}
nat66_address=${NAT66_ADDRESS:-}
out=
management4=${SSH_CONNECTION:-}
management4=${management4%% *}
case "$management4" in *:*) management4= ;; *[!0-9.]*) fail 'Invalid SSH peer address' ;; esac
while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode=*) mode=${1#*=} ;;
        --pref64=*) pref64=${1#*=} ;;
        --dns64-server=*) dns64=${1#*=} ;;
        --pool4=*) pool4=${1#*=} ;;
        --tayga-ipv4=*) addr4=${1#*=} ;;
        --tayga-ipv6=*) addr6=${1#*=} ;;
        --tun-ipv6=*) source6=${1#*=} ;;
        --clat-ipv6=*) clat6=${1#*=} ;;
        --map-ipv4=*) map4=${1#*=} ;;
        --map-ipv6=*) map6=${1#*=} ;;
        --mtu=*) mtu=${1#*=} ;;
        --offload=*) offload=${1#*=} ;;
        --workers=*) workers=${1#*=} ;;
        --firewall=*) firewall=${1#*=} ;;
        --dns64=*) enable_dns64=${1#*=} ;;
        --dns64-listen=*) dns64_listen=${1#*=} ;;
        --dns64-allow=*) dns64_allow=${1#*=} ;;
        --dns64-upstream=*) dns64_upstream=${1#*=} ;;
        --dns64-dnssec=*) dns64_dnssec=${1#*=} ;;
        --clat-address-mode=*) address_mode=${1#*=} ;;
        --nat66-address=*) nat66_address=${1#*=} ;;
        --host-dns=*) host_dns=${1#*=} ;;
        --output=*) out=${1#*=} ;;
        --configure-only=*|--yes|-y|--non-interactive|--defaults|--watchdog-seconds=*) ;;
        *) fail "Unknown profile argument: $1" ;;
    esac
    shift
done
case "$mode" in clat|nat64|siit) ;; *) fail 'Mode must be clat, nat64 or siit' ;; esac
[ -n "$out" ] || fail 'An output path is required'
pref64_source=manual
if [ "$pref64" = auto ] || [ "$pref64" = public ]; then
    [ "$mode" = clat ] || fail 'PREF64 discovery is only valid for CLAT'
    helper=${PREF64_HELPER:-pref64-discover}
    if [ -n "$dns64" ]; then
        case "$dns64" in *[!0-9a-fA-F:.]*) fail 'Invalid DNS64 server address' ;; esac
        pref64=$("$helper" -s "$dns64") || fail 'RFC 7050 discovery failed; specify --pref64 explicitly'
    elif [ "$pref64" = public ]; then
        pref64=$("$helper" -p) || fail 'Public NAT64 discovery failed; specify --pref64 explicitly'
    else
        pref64=$("$helper" 2>/dev/null || "$helper" -p) || fail 'RFC 7050 discovery failed; specify --pref64 explicitly'
    fi
    pref64_source=rfc7050
fi
if [ -z "$addr4" ]; then
    if [ "$mode" = clat ]; then addr4=192.0.0.2; else addr4=192.168.240.1; fi
fi
# Reject whitespace, comments and extra directives before rendering any input.
for value in "$pref64" "$pool4" "$addr4" "$addr6"; do
    case "$value" in ''|*[!0-9a-fA-F:./]*) fail "Invalid address token: $value" ;; esac
done
case "$pref64" in */32|*/40|*/48|*/56|*/64|*/96) ;; *) fail 'Unsupported NAT64 prefix length' ;; esac
case "$addr6" in *:*) ;; *) fail 'TAYGA IPv6 address required' ;; esac
case "$addr6" in */*) fail 'TAYGA IPv6 address must not contain a prefix length' ;; esac
case "$source6" in ''|*[!0-9a-fA-F:]*) fail 'Invalid TUN IPv6 source' ;; esac
case "$source6" in *:*) ;; *) fail 'Invalid TUN IPv6 source' ;; esac
if [ "$mode" = nat64 ]; then
    [ "$source6" != "$addr6" ] || fail 'TUN source and daemon identity must differ'
fi
case "$addr4" in *[!0-9.]*|*/*) fail 'TAYGA IPv4 address required' ;; esac
case "$mtu" in ''|*[!0-9]*|????????*) fail 'Invalid MTU' ;; esac
if [ "$mtu" -lt 1280 ] || [ "$mtu" -gt 65535 ]; then fail 'MTU must be 1280..65535'; fi
case "$offload" in auto|off|tcp|udp) ;; *) fail 'Invalid offload mode' ;; esac
if [ "$(uname -s)" = FreeBSD ]; then
    case "$firewall" in auto) firewall=pf ;; pf) ;; *) fail 'FreeBSD profile generation supports the pf backend' ;; esac
else
    case "$firewall" in auto|iptables|nft|firewalld) ;; *) fail 'Linux profile generation supports iptables, nft or firewalld' ;; esac
fi
case "$enable_dns64" in yes) [ "$mode" = nat64 ] || fail 'DNS64 provisioning requires NAT64' ;; no) ;; *) fail 'DNS64 must be yes or no' ;; esac
case "$dns64_dnssec" in validate|off) ;; *) fail 'Invalid DNS64 DNSSEC policy' ;; esac
case "$host_dns" in keep) ;; public|public-resolvconf|public-file|public-nm) [ "$mode" = clat ] || fail 'Public host DNS is available for CLAT' ;; *) fail 'Host DNS must be keep, public, public-resolvconf public-file or public-nm' ;; esac
for value in "$dns64_listen" "$dns64_allow" "$dns64_upstream"; do
    case "$value" in ''|*[!0-9a-fA-F:./@]*) fail 'Invalid DNS64 address token' ;; esac
done
case "$workers" in auto) ;; ''|*[!0-9]*|???*) fail 'Invalid worker count' ;; *) [ "$workers" -le 63 ] || fail 'Workers must be auto or 0..63' ;; esac
generate_deterministic_ula() {
    seed=
    if [ -f /etc/machine-id ] && [ -s /etc/machine-id ]; then
        seed=$(cat /etc/machine-id)
    elif [ -f /var/lib/dbus/machine-id ]; then
        seed=$(cat /var/lib/dbus/machine-id)
    elif command -v sysctl >/dev/null 2>&1 && sysctl -n kern.hostuuid >/dev/null 2>&1; then
        seed=$(sysctl -n kern.hostuuid 2>/dev/null)
    fi
    [ -n "$seed" ] || seed="tayga-clat-$(uname -n)-$(date +%s 2>/dev/null || echo 1)"
    hash=
    if command -v sha256sum >/dev/null 2>&1; then
        hash=$(printf '%s\n' "$seed" | sha256sum 2>/dev/null | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        hash=$(printf '%s\n' "$seed" | shasum -a 256 2>/dev/null | awk '{print $1}')
    fi
    [ -n "$hash" ] || hash="fd4242424242"
    p1=$(printf '%s' "$hash" | cut -c 1-2)
    p2=$(printf '%s' "$hash" | cut -c 3-6)
    p3=$(printf '%s' "$hash" | cut -c 7-10)
    printf 'fd%s:%s:%s:1' "$p1" "$p2" "$p3"
}
if [ "$clat6" = auto ] && [ "$mode" = clat ]; then
    if [ "$address_mode" = nat66 ]; then
        ula_prefix=$(generate_deterministic_ula)
        clat6="${ula_prefix}::2"
        addr6="${ula_prefix}::1"
    else
        uplink=
        if [ "$(uname -s)" = FreeBSD ]; then
            uplink=$(route -n get -inet6 default 2>/dev/null | awk '$1=="interface:" {print $2}')
            [ -n "$uplink" ] || uplink=$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2}')
            global_v6=$(ifconfig "$uplink" inet6 2>/dev/null | awk '$1=="inet6" && $2!~/^fe80/ {print $2; exit}')
        else
            uplink=$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
            [ -n "$uplink" ] || uplink=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
            global_v6=$(ip -6 addr show dev "$uplink" scope global -deprecated -tentative 2>/dev/null | awk '$1=="inet6" {print $2; exit}')
        fi
        ip_base=${global_v6%/*}
        case "$ip_base" in
            *::*) clat6="${ip_base%::*}::464" ;;
            *:*:*) clat6="$(printf '%s\n' "$ip_base" | sed -E 's/:[0-9a-fA-F]+$/:464/')" ;;
            *) clat6="2001:db8::464" ;;
        esac
    fi
fi
if [ "$address_mode" = nat66 ] && [ "$nat66_address" = auto ]; then
    if [ "$(uname -s)" = FreeBSD ]; then
        uplink=$(route -n get -inet6 default 2>/dev/null | awk '$1=="interface:" {print $2}')
        [ -n "$uplink" ] || uplink=$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2}')
        nat66_address=$(ifconfig "$uplink" inet6 2>/dev/null | awk '$1=="inet6" && $2!~/^fe80/ {split($2,a,"/");print a[1]; exit}')
    else
        uplink=$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
        [ -n "$uplink" ] || uplink=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
        nat66_address=$(ip -6 addr show dev "$uplink" scope global -deprecated -tentative 2>/dev/null | awk '$1=="inet6" {split($2,a,"/");print a[1]; exit}')
    fi
fi
if [ "$mode" = clat ]; then
    case "$clat6" in ''|*[!0-9a-fA-F:]* ) fail 'CLAT requires an explicit routed --clat-ipv6 address' ;; esac
    case "$clat6" in *:*) ;; *) fail 'Invalid CLAT IPv6 address' ;; esac
    [ "$clat6" != "$addr6" ] || fail 'CLAT and daemon IPv6 addresses must differ'
fi
if [ "$mode" = siit ]; then
    for value in "$map4" "$map6"; do
        case "$value" in ''|*[!0-9a-fA-F:./]*) fail 'SIIT requires --map-ipv4 and --map-ipv6' ;; esac
    done
fi
case "$address_mode" in routed) ;; proxy-ndp|nat66)
    [ "$mode" = clat ] || fail 'Address adaptation is only supported for CLAT'
    if [ "$(uname -s)" = FreeBSD ]; then
        case "$firewall" in auto|pf) ;; *) fail 'FreeBSD address adaptation requires pf' ;; esac
    else
        case "$firewall" in auto|iptables|nft|firewalld) ;; *) fail 'Address adaptation requires iptables, nft or firewalld' ;; esac
    fi
    ;;
    *) fail 'Invalid CLAT address mode' ;;
esac
if [ "$address_mode" = nat66 ]; then
    case "$nat66_address" in ''|*[!0-9a-fA-F:]*) fail 'An explicit --nat66-address is required' ;; esac
    case "$nat66_address" in *:*) ;; *) fail 'NAT66 requires an IPv6 address' ;; esac
    for value in "$addr6" "$clat6"; do
        case "$value" in [fF][cCdD][0-9a-fA-F][0-9a-fA-F]:*) ;; *) fail 'NAT66 requires ULA CLAT and daemon addresses' ;; esac
    done
elif [ -n "$nat66_address" ]; then fail 'NAT66 address requires nat66 mode'
fi
device=$mode
if [ "$(uname -s)" = FreeBSD ]; then
    device=tun64
    offload=off
    [ "$workers" = auto ] || fail 'Worker counts are Linux-only'
fi
umask 077
tmp=$(mktemp "${out}.XXXXXXXX")
trap 'rm -f "$tmp"' 0
trap 'exit 1' HUP INT TERM
{
    printf '# Generated TAYGA %s profile; review before activation.\n' "$mode"
    printf '# installer-mode %s\n' "$mode"
    printf '# installer-firewall %s\n' "$firewall"
    printf '# installer-dns64 %s\n' "$enable_dns64"
    printf '# installer-dns64-listen %s\n# installer-dns64-allow %s\n' "$dns64_listen" "$dns64_allow"
    printf '# installer-dns64-upstream %s\n# installer-dns64-dnssec %s\n' "$dns64_upstream" "$dns64_dnssec"
    printf '# installer-clat-address-mode %s\n' "$address_mode"
    [ -z "$nat66_address" ] || printf '# installer-nat66-address %s\n' "$nat66_address"
    printf '# installer-host-dns %s\n' "$host_dns"
    printf '# installer-pref64-source %s\n' "$pref64_source"
    if [ "$mode" = clat ] && [ -n "$management4" ]; then
        printf '# installer-management4 %s\n' "$management4"
    fi
    printf 'tun-device %s\nipv4-addr %s\nipv6-addr %s\n' "$device" "$addr4" "$addr6"
    printf 'prefix %s\nofflink-mtu %s\ntun-offload %s\n' "$pref64" "$mtu" "$offload"
    if [ "$workers" != auto ]; then printf 'workers %s\n' "$workers"; fi
    printf 'data-dir /var/lib/tayga/%s\n' "$mode"
    case "$mode" in
        nat64) printf '# installer-source6 %s\ndynamic-pool %s\n' "$source6" "$pool4" ;;
        clat) printf 'map 192.0.0.1 %s\n' "$clat6" ;;
        siit) printf 'map %s %s\n' "$map4" "$map6" ;;
    esac
} > "$tmp"
if [ -e "$out" ] || [ -L "$out" ]; then
    cmp -s "$tmp" "$out" || fail "Refusing to overwrite existing profile: $out"
else
    # Hard-link publication refuses concurrent creation and symlink replacement.
    ln "$tmp" "$out"
fi
