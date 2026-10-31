#!/bin/sh
set -eu
[ "$#" -ge 1 ] || { echo 'Usage: wizard OUTPUT' >&2; exit 2; }
out=$1
shift
for option in "$@"; do
    value=${option#*=}
    case "$option" in
        --mode=*) MODE=$value; export MODE ;;
        --pref64=*) PREF64=$value; export PREF64 ;;
        --dns64-server=*) DNS64_SERVER=$value; export DNS64_SERVER ;;
        --pool4=*) DYNAMIC_POOL=$value; export DYNAMIC_POOL ;;
        --tayga-ipv4=*) TAYGA_IPV4=$value; export TAYGA_IPV4 ;;
        --tayga-ipv6=*) TAYGA_IPV6=$value; export TAYGA_IPV6 ;;
        --tun-ipv6=*) TUN_IPV6=$value; export TUN_IPV6 ;;
        --clat-ipv6=*) CLAT_IPV6=$value; export CLAT_IPV6 ;;
        --map-ipv4=*) MAP_IPV4=$value; export MAP_IPV4 ;;
        --map-ipv6=*) MAP_IPV6=$value; export MAP_IPV6 ;;
        --mtu=*) OFFLINK_MTU=$value; export OFFLINK_MTU ;;
        --offload=*) TUN_OFFLOAD=$value; export TUN_OFFLOAD ;;
        --workers=*) WORKERS=$value; export WORKERS ;;
        --firewall=*) FIREWALL=$value; export FIREWALL ;;
        --dns64=*) ENABLE_DNS64=$value; export ENABLE_DNS64 ;;
        --dns64-listen=*) DNS64_LISTEN=$value; export DNS64_LISTEN ;;
        --dns64-allow=*) DNS64_ALLOW=$value; export DNS64_ALLOW ;;
        --dns64-upstream=*) DNS64_UPSTREAM=$value; export DNS64_UPSTREAM ;;
        --dns64-dnssec=*) DNS64_DNSSEC=$value; export DNS64_DNSSEC ;;
        --clat-address-mode=*) CLAT_ADDRESS_MODE=$value; export CLAT_ADDRESS_MODE ;;
        --nat66-address=*) NAT66_ADDRESS=$value; export NAT66_ADDRESS ;;
        --host-dns=*) HOST_DNS=$value; export HOST_DNS ;;
        --wizard|--configure-only=*|--watchdog-seconds=*) ;;
        *) echo "Unsupported wizard argument: $option" >&2; exit 2 ;;
    esac
done
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ "${TAYGA_WIZARD_STDIN:-}" = 1 ]; then
    exec 3<&0
else
    exec 3</dev/tty || { echo 'A terminal is required; use --mode and --yes for unattended installation' >&2; exit 2; }
fi
prompt() {
    printf '%s [%s]: ' "$1" "$2" >&2
    IFS= read -r answer <&3 || { echo 'Input ended; cancelled' >&2; exit 2; }
    [ -n "$answer" ] || answer=$2
}
has_v6=
has_v4=
uplink6=
if [ "$(uname -s)" = FreeBSD ]; then
    uplink6=$(route -n get -inet6 default 2>/dev/null | awk '$1=="interface:" {print $2}')
    has_v6=$uplink6
    has_v4=$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2}')
elif command -v ip >/dev/null; then
    uplink6=$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
    has_v6=$uplink6
    has_v4=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
fi

has_external_v4=yes
if [ -z "$has_v4" ]; then
    has_external_v4=no
elif command -v curl >/dev/null 2>&1; then
    gcp_ext=$(curl -s -f -m 1 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null || :)
    if [ "$gcp_ext" = "" ] && curl -s -f -m 1 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/id >/dev/null 2>&1; then
        has_external_v4=no
    elif ! curl -4 --noproxy '*' --silent --connect-timeout 2 --max-time 3 --output /dev/null http://1.1.1.1/ 2>/dev/null; then
        has_external_v4=no
    fi
fi

mode=${MODE:-}
if [ -z "$mode" ]; then
    if [ -n "$has_v6" ] && [ "$has_external_v4" = no ]; then
        mode=clat
    else
        mode=nat64
    fi
fi
prompt 'Mode: clat, nat64, siit or binary-only' "$mode"
mode=$answer
case "$mode" in
    binary-only) exit 3 ;;
    nat64)
        if [ "$has_external_v4" = no ]; then
            echo 'Warning: No external IPv4 egress detected. NAT64 requires an external IPv4 address. If this is an IPv6-only instance, CLAT is recommended.' >&2
        fi
        ;;
    clat|siit) ;;
    *) echo 'Unsupported wizard mode' >&2; exit 2 ;;
esac
if [ "$mode" = clat ]; then default_prefix=auto; else default_prefix=64:ff9b::/96; fi
prompt 'NAT64 prefix (auto: local RFC 7050 or lowest RTT public gateway)' "${PREF64:-$default_prefix}"
pref64=$answer
if [ "$pref64" = auto ]; then
    prompt 'DNS64 server (empty: local DNS first, then fastest public gateway)' "${DNS64_SERVER:-}"
    dns64=$answer
else dns64=; fi
prompt 'Daemon IPv6 identity' "${TAYGA_IPV6:-fd64::2}"
addr6=$answer
if [ "$mode" = nat64 ]; then
    prompt 'Provision an isolated Unbound DNS64 resolver: yes or no' "${ENABLE_DNS64:-no}"
    ENABLE_DNS64=$answer
    if [ "$ENABLE_DNS64" = yes ]; then
        prompt 'DNS64 listen address' "${DNS64_LISTEN:-::1}"
        DNS64_LISTEN=$answer
        prompt 'DNS64 client network allowed to recurse' "${DNS64_ALLOW:-::1/128}"
        DNS64_ALLOW=$answer
        prompt 'DNS64 upstream resolver' "${DNS64_UPSTREAM:-1.1.1.1}"
        DNS64_UPSTREAM=$answer
        prompt 'DNSSEC: validate or off' "${DNS64_DNSSEC:-validate}"
        DNS64_DNSSEC=$answer
    fi
else ENABLE_DNS64=no
fi
export ENABLE_DNS64 DNS64_LISTEN DNS64_ALLOW DNS64_UPSTREAM DNS64_DNSSEC
generate_deterministic_ula() {
    if [ -f "$base/configure.sh" ]; then
        sh "$base/configure.sh" --generate-ula
    else
        echo 'Cannot locate configure.sh for ULA generation' >&2
        exit 2
    fi
}
if [ "$mode" = clat ]; then
    default_clat6=${CLAT_IPV6:-}
    global_v6=
    if [ -n "$uplink6" ]; then
        if [ "$(uname -s)" = FreeBSD ]; then
            global_v6=$(ifconfig "$uplink6" inet6 2>/dev/null | awk '$1=="inet6" && $2!~/^fe80/ {print $2; exit}')
        elif command -v ip >/dev/null; then
            global_v6=$(ip -6 addr show dev "$uplink6" scope global -deprecated -tentative 2>/dev/null | awk '$1=="inet6" {print $2; exit}')
        fi
        if [ -z "$default_clat6" ] && [ -n "$global_v6" ]; then
            ip_base=${global_v6%/*}
            case "$ip_base" in
                *::*) default_clat6="${ip_base%::*}::464" ;;
                *:*:*) default_clat6="$(echo "$ip_base" | sed -E 's/:[0-9a-fA-F]+$/:464/')" ;;
            esac
        fi
    fi
    prompt 'CLAT address mode: nat66, proxy-ndp or routed' "${CLAT_ADDRESS_MODE:-nat66}"
    clat_addr_mode=$answer
    case "$clat_addr_mode" in
        nat66)
            CLAT_ADDRESS_MODE=nat66
            ula_prefix=$(generate_deterministic_ula)
            default_clat6="${ula_prefix}::2"
            default_tayga_v6="${ula_prefix}::1"
            prompt 'NAT66 CLAT IPv6 address (ULA)' "$default_clat6"
            clat6=$answer
            prompt 'NAT66 daemon IPv6 address (ULA)' "$default_tayga_v6"
            addr6=$answer
            uplink_v6=
            if [ -n "$global_v6" ]; then uplink_v6=${global_v6%/*}; fi
            prompt 'NAT66 external uplink IPv6 address' "${NAT66_ADDRESS:-$uplink_v6}"
            NAT66_ADDRESS=$answer
            ;;
        proxy-ndp)
            CLAT_ADDRESS_MODE=proxy-ndp
            prompt 'Proxy NDP CLAT IPv6 address (on WAN /64)' "$default_clat6"
            clat6=$answer
            NAT66_ADDRESS=
            ;;
        routed)
            CLAT_ADDRESS_MODE=routed
            prompt 'Routed CLAT IPv6 address (from assigned routed prefix)' "$default_clat6"
            clat6=$answer
            NAT66_ADDRESS=
            ;;
        *) echo 'Unsupported CLAT address mode' >&2; exit 2 ;;
    esac
    [ -n "$clat6" ] || { echo 'An assigned routed CLAT address is required' >&2; exit 2; }
    prompt 'Host DNS: keep or public (systemd-resolved stub required)' "${HOST_DNS:-keep}"
    HOST_DNS=$answer
else clat6=; fi
if [ "$mode" != clat ]; then HOST_DNS=keep; CLAT_ADDRESS_MODE=routed; NAT66_ADDRESS=; export CLAT_ADDRESS_MODE NAT66_ADDRESS; fi
export HOST_DNS
if [ "$mode" = siit ]; then
    prompt 'Routed IPv4 address/prefix to map' "${MAP_IPV4:-}"
    MAP_IPV4=$answer
    prompt 'Native IPv6 endpoint address/prefix' "${MAP_IPV6:-}"
    MAP_IPV6=$answer
    export MAP_IPV4 MAP_IPV6
fi
prompt 'Offlink MTU' "${OFFLINK_MTU:-1400}"
mtu=$answer
prompt 'TUN offload: auto, tcp, udp or off' "${TUN_OFFLOAD:-auto}"
offload=$answer
prompt 'Workers: auto or number' "${WORKERS:-auto}"
workers=$answer
MODE=$mode PREF64=$pref64 DNS64_SERVER=$dns64 TAYGA_IPV6=$addr6 CLAT_IPV6=$clat6 \
    OFFLINK_MTU=$mtu TUN_OFFLOAD=$offload WORKERS=$workers sh "$base/configure.sh" --output="$out"
echo "Generated $mode profile:" >&2
cat "$out" >&2
