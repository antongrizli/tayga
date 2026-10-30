#!/bin/sh
# Linux and FreeBSD network lifecycle for installer-generated profiles.
set -eu
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/sbin:/bin:/usr/sbin:/usr/bin}:/usr/local/sbin:/usr/local/bin"; export PATH ;; esac
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'Usage: tayga-net-ctl up|down CONFIG'
action=$1
config=$2
os=$(uname -s)
case "$os" in Linux|FreeBSD) ;; *) fail 'Network activation requires Linux or FreeBSD' ;; esac
[ "$(id -u)" -eq 0 ] || fail 'Network activation requires root'
get() { awk -v key="$1" '$1 == key { if (NF != 2 || seen++) exit 1; value=$2 } END { print value }' "$config"; }
dev=$(get tun-device)
mode=$(awk '$1=="#" && $2=="installer-mode" {print $3}' "$config")
if [ -z "$mode" ]; then mode=$dev; fi
case "$mode" in clat|nat64|siit) ;; *) fail 'Expected an installer-generated profile' ;; esac
case "$dev" in clat|nat64|siit|tun[0-9]*) ;; *) fail 'Expected an installer-generated tun-device' ;; esac
state=${TAYGA_NET_STATE:-/run/tayga-installer}
case "$state" in /*) ;; *) fail 'State directory must be absolute' ;; esac
umask 077
mkdir -p "$state"
[ ! -L "$state" ] || fail 'State directory must not be a symlink'
lock=$state/operation.lock
mkdir "$lock" 2>/dev/null || fail 'Another network operation is in progress'
trap 'rmdir "$lock"' 0
journal=$state/$dev.undo
rollback() {
    if [ -f "$journal" ]; then
        # All journal arguments originate from validated tokens below.
        while [ -s "$journal" ]; do
            undo=$(tail -n 1 "$journal")
            sh -ec "$undo" || return 1
            sed '$d' "$journal" > "$lock/undo"
            mv "$lock/undo" "$journal"
        done
        rm -f "$journal" "$lock/undo"
    fi
}
case "$action" in
    down) rollback; exit ;;
    up)
        for active in "$state"/*.undo; do
            [ ! -e "$active" ] || fail 'A managed profile is already active; run down before up'
        done
        ;;
    *) fail 'Expected up or down' ;;
esac
command -v tayga >/dev/null || fail 'tayga is required'
firewall=$(awk '$1=="#" && $2=="installer-firewall" {print $3}' "$config")
firewall=${firewall:-auto}
if [ "$os" = FreeBSD ]; then
    command -v ifconfig >/dev/null || fail 'ifconfig is required'
    command -v route >/dev/null || fail 'route is required'
    case "$firewall" in auto|pf) firewall=pf ;; *) fail 'FreeBSD requires the pf firewall backend' ;; esac
    command -v pfctl >/dev/null || fail 'pfctl is required'
else
    command -v ip >/dev/null || fail 'iproute2 is required'
    if [ "$firewall" = auto ]; then
        if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
            firewall=firewalld
        elif command -v iptables >/dev/null && command -v ip6tables >/dev/null; then
            firewall=iptables
        else
            firewall=nft
        fi
    fi
    case "$firewall" in
        iptables)
            if ! command -v iptables >/dev/null || ! command -v ip6tables >/dev/null; then fail 'iptables and ip6tables are required'; fi
            ;;
        nft) command -v nft >/dev/null || fail 'nft is required' ;;
        firewalld)
            command -v firewall-cmd >/dev/null || fail 'firewall-cmd is required'
            firewall-cmd --state >/dev/null 2>&1 || fail 'firewalld is not running'
            ;;
        *) fail 'Invalid firewall backend' ;;
    esac
fi
if [ "$os" = FreeBSD ]; then
    ifconfig "$dev" >/dev/null 2>&1 && fail "Interface $dev already exists"
else
    ip link show dev "$dev" >/dev/null 2>&1 && fail "Interface $dev already exists"
fi
pref64=$(get prefix)
addr6=$(get ipv6-addr)
pool=$(get dynamic-pool)
mtu=$(get offlink-mtu)
case "$mtu" in ''|*[!0-9]*|????????*) fail 'Invalid offlink-mtu' ;; esac
if [ "$mtu" -lt 1280 ] || [ "$mtu" -gt 65535 ]; then fail 'Invalid offlink-mtu'; fi
for token in "$pref64" "$addr6" "$pool"; do
    case "$token" in *[!0-9a-fA-F:./]*) fail 'Invalid profile address token' ;; esac
done
if [ -z "$pref64" ] || [ -z "$addr6" ]; then fail 'Missing profile addresses'; fi
address_mode=$(awk '$1=="#" && $2=="installer-clat-address-mode" {print $3}' "$config")
address_mode=${address_mode:-routed}
nat66_address=$(awk '$1=="#" && $2=="installer-nat66-address" {print $3}' "$config")
case "$address_mode" in routed) ;; proxy-ndp|nat66)
    if [ "$mode" != clat ]; then fail 'Address adaptation requires CLAT'; fi
    if [ "$os" = FreeBSD ]; then
        case "$firewall" in pf) ;; *) fail 'FreeBSD address adaptation requires pf' ;; esac
    else
        case "$firewall" in iptables|nft|firewalld) ;; *) fail 'Address adaptation requires iptables, nft, or firewalld' ;; esac
    fi
    ;;
    *) fail 'Invalid CLAT address mode' ;;
esac
case "$nat66_address" in *[!0-9a-fA-F:]*) fail 'Invalid NAT66 address' ;; esac
# Full daemon validation occurs before the first network mutation in --mktun.
: > "$journal"
committed=no
cleanup() {
    if [ "$committed" != yes ]; then rollback || echo 'Rollback incomplete; run down again' >&2; fi
    rm -f "$lock/undo" "$lock/rules.nft" "$lock/rules.pf" "$lock/root.pf"
    rmdir "$lock"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
# Validate/create TUN first; failure never removes a pre-existing interface.
tayga --config "$config" --mktun
if [ "$os" = FreeBSD ]; then
    printf 'ifconfig %s destroy 2>/dev/null || tayga --config %s --rmtun\n' "$dev" "$config" >> "$journal"
    ifconfig "$dev" mtu "$mtu" up
else
    printf 'ip link delete dev %s\n' "$dev" >> "$journal"
    ip link set dev "$dev" mtu "$mtu" up
fi
if [ "$mode" = nat64 ]; then
    # The daemon's ICMP identity is reserved in its address map. Host-originated
    # probes need a separate IPv6 source to receive a dynamic IPv4 mapping.
    source6=$(awk '$1=="#" && $2=="installer-source6" {print $3}' "$config")
    source6=${source6:-fd64::1}
    case "$source6" in *[!0-9a-fA-F:]*|'') fail 'Invalid NAT64 host source address' ;; esac
    [ "$source6" != "$addr6" ] || fail 'NAT64 host source must differ from daemon identity'
    target_addr6=$source6
else
    target_addr6=$addr6
fi
if [ "$os" = FreeBSD ]; then
    ifconfig "$dev" inet6 "$target_addr6/128" up
else
    ip -6 addr add "$target_addr6/128" dev "$dev"
fi
set_sysctl() {
    key=$1
    desired=$2
    previous=$(sysctl -n "$key")
    case "$previous" in ''|*[!0-9]*) fail 'Unexpected sysctl value' ;; esac
    if [ "$previous" != "$desired" ]; then
        sysctl -w "$key=$desired" >/dev/null
        printf 'sysctl -w %s=%s >/dev/null\n' "$key" "$previous" >> "$journal"
    fi
}
if [ "$os" = FreeBSD ]; then
    uplink6=$(route -n get -inet6 default 2>/dev/null | awk '$1=="interface:" {print $2}')
    if [ -z "$uplink6" ] && command -v rtsol >/dev/null 2>&1; then
        for iface in $(ifconfig -l 2>/dev/null || :); do
            case "$iface" in lo*|tun*|tap*|bridge*) continue ;; esac
            rtsol "$iface" >/dev/null 2>&1 || :
        done
        uplink6=$(route -n get -inet6 default 2>/dev/null | awk '$1=="interface:" {print $2}')
    fi
    if [ -z "$uplink6" ]; then
        uplink6=$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2}')
    fi
    if [ -z "$uplink6" ]; then
        for iface in $(ifconfig -l 2>/dev/null || :); do
            case "$iface" in lo*|tun*|tap*|bridge*) continue ;; esac
            uplink6=$iface
            break
        done
    fi
    case "$uplink6" in ''|*[!a-zA-Z0-9_.:-]*) fail 'An IPv6 default-route interface is required' ;; esac
    set_sysctl net.inet6.ip6.accept_rtadv 1
    set_sysctl net.inet.ip.forwarding 1
    set_sysctl net.inet6.ip6.forwarding 1
else
    uplink6=$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
    if [ -z "$uplink6" ]; then
        uplink6=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
    fi
    case "$uplink6" in ''|*[!a-zA-Z0-9_.:-]*) fail 'An IPv6 default-route interface is required' ;; esac
    set_sysctl net.ipv6.conf.all.accept_ra 2
    set_sysctl "net.ipv6.conf.$uplink6.accept_ra" 2
    set_sysctl net.ipv4.ip_forward 1
    set_sysctl net.ipv6.conf.all.forwarding 1
fi
add_route() {
    family=$1; destination=$2; shift 2
    if [ "$os" = FreeBSD ]; then
        case "$family" in
            -4)
                route add -net "$destination" "$@"
                printf 'route del -net %s >/dev/null 2>&1 || :\n' "$destination" >> "$journal"
                ;;
            -6)
                route add -inet6 "$destination" "$@"
                printf 'route del -inet6 %s >/dev/null 2>&1 || :\n' "$destination" >> "$journal"
                ;;
        esac
    else
        ip "$family" route add "$destination" "$@"
        printf 'ip %s route del %s' "$family" "$destination" >> "$journal"
        for arg in "$@"; do printf ' %s' "$arg" >> "$journal"; done
        printf '\n' >> "$journal"
    fi
}
fw_chain() {
    tool=$1; table=$2; parent=$3
    chain=TAYGA_SFX_$dev
    "$tool" -w -t "$table" -N "$chain"
    printf '%s -w -t %s -F %s && %s -w -t %s -X %s\n' "$tool" "$table" "$chain" "$tool" "$table" "$chain" >> "$journal"
    "$tool" -w -t "$table" -I "$parent" 1 -j "$chain"
    printf '%s -w -t %s -D %s -j %s\n' "$tool" "$table" "$parent" "$chain" >> "$journal"
}
fw_accept6() {
    fw_chain ip6tables filter FORWARD
    if [ "$mode" = nat64 ] || [ "$mode" = siit ]; then
        ip6tables -w -t filter -A "$chain" -o "$dev" -d "$1" -j ACCEPT
        if [ "$mode" = siit ]; then
            ip6tables -w -t filter -A "$chain" -i "$dev" -s "$1" -j ACCEPT
        else
            ip6tables -w -t filter -A "$chain" -i "$dev" -s "$1" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        fi
    else
        ip6tables -w -t filter -A "$chain" -i "$dev" -o "$uplink6" -s "$1" -j ACCEPT
        ip6tables -w -t filter -A "$chain" -i "$uplink6" -o "$dev" -d "$1" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
}
if [ "$firewall" = iptables ]; then
    fw_chain iptables mangle FORWARD
    iptables -w -t mangle -A "$chain" -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    fw_chain ip6tables mangle FORWARD
    ip6tables -w -t mangle -A "$chain" -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
elif [ "$firewall" = firewalld ]; then
    firewall-cmd --zone=trusted --add-interface="$dev"
    printf 'firewall-cmd --zone=trusted --remove-interface=%s >/dev/null 2>&1 || :\n' "$dev" >> "$journal"
    firewall-cmd --direct --add-rule ipv4 mangle FORWARD 0 -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    printf 'firewall-cmd --direct --remove-rule ipv4 mangle FORWARD 0 -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || :\n' "$dev" >> "$journal"
    firewall-cmd --direct --add-rule ipv6 mangle FORWARD 0 -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    printf 'firewall-cmd --direct --remove-rule ipv6 mangle FORWARD 0 -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || :\n' "$dev" >> "$journal"
fi
fw_firewalld() {
    wan_zone=$(firewall-cmd --get-zone-of-interface="$wan" 2>/dev/null || :)
    [ -n "$wan_zone" ] || wan_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo public)
    case "$wan_zone" in ''|*[!a-zA-Z0-9_.:-]*) wan_zone=public ;; esac
    firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i "$dev" -o "$wan" -s "$pool" -j ACCEPT
    printf 'firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i %s -o %s -s %s -j ACCEPT >/dev/null 2>&1 || :\n' "$dev" "$wan" "$pool" >> "$journal"
    if [ "$mode" = siit ]; then
        firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i "$wan" -o "$dev" -d "$pool" -j ACCEPT
        printf 'firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i %s -o %s -d %s -j ACCEPT >/dev/null 2>&1 || :\n' "$wan" "$dev" "$pool" >> "$journal"
    else
        firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i "$wan" -o "$dev" -d "$pool" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        printf 'firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i %s -o %s -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || :\n' "$wan" "$dev" "$pool" >> "$journal"
        firewall-cmd --zone="$wan_zone" --add-rich-rule="rule family='ipv4' source address='$pool' masquerade"
        printf 'firewall-cmd --zone=%s --remove-rich-rule="rule family=\047ipv4\047 source address=\047%s\047 masquerade" >/dev/null 2>&1 || :\n' "$wan_zone" "$pool" >> "$journal"
    fi
    firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -o "$dev" -d "$pref64" -j ACCEPT
    printf 'firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -o %s -d %s -j ACCEPT >/dev/null 2>&1 || :\n' "$dev" "$pref64" >> "$journal"
    if [ "$mode" = siit ]; then
        firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i "$dev" -s "$pref64" -j ACCEPT
        printf 'firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i %s -s %s -j ACCEPT >/dev/null 2>&1 || :\n' "$dev" "$pref64" >> "$journal"
    else
        firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i "$dev" -s "$pref64" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        printf 'firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i %s -s %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || :\n' "$dev" "$pref64" >> "$journal"
    fi
}
fw_nft() {
    table=tayga_sfx_$dev
    if nft list table inet "$table" >/dev/null 2>&1; then fail 'Owned nftables table already exists'; fi
    {
        printf 'table inet %s {\n' "$table"
        printf 'chain clamp_forward { type filter hook forward priority -150; policy accept; oifname "%s" tcp flags syn tcp option maxseg size set rt mtu; }\n' "$dev"
        if [ "$mode" = clat ]; then
            printf 'chain clamp_output { type route hook output priority -150; policy accept; meta nfproto ipv4 oifname "%s" tcp flags syn tcp option maxseg size set rt mtu; }\n' "$dev"
        fi
        printf 'chain forward { type filter hook forward priority -1; policy accept;\n'
        if [ "$mode" = nat64 ] || [ "$mode" = siit ]; then
            printf 'iifname "%s" oifname "%s" ip saddr %s accept\n' "$dev" "$wan" "$pool"
            if [ "$mode" = siit ]; then
                printf 'iifname "%s" oifname "%s" ip daddr %s accept\n' "$wan" "$dev" "$pool"
            else
                printf 'iifname "%s" oifname "%s" ip daddr %s ct state established,related accept\n' "$wan" "$dev" "$pool"
            fi
            printf 'oifname "%s" ip6 daddr %s accept\n' "$dev" "$pref64"
            if [ "$mode" = siit ]; then
                printf 'iifname "%s" ip6 saddr %s accept\n' "$dev" "$pref64"
            else
                printf 'iifname "%s" ip6 saddr %s ct state established,related accept\n' "$dev" "$pref64"
            fi
        else
            printf 'iifname "%s" oifname "%s" ip6 saddr %s accept\n' "$dev" "$uplink6" "$clat6"
            printf 'iifname "%s" oifname "%s" ip6 daddr %s ct state established,related accept\n' "$uplink6" "$dev" "$clat6"
        fi
        printf '}\n'
        if [ "$mode" = clat ] && [ "$address_mode" = nat66 ]; then
            printf 'chain nat66 { type nat hook postrouting priority 100; policy accept; oifname "%s" ip6 saddr { %s, %s } ip6 daddr %s snat ip6 to %s; }\n' "$uplink6" "$clat6" "$addr6" "$pref64" "$nat66_address"
        fi
        if [ "$mode" = nat64 ]; then
            printf 'chain postrouting { type nat hook postrouting priority 100; policy accept; oifname "%s" ip saddr %s masquerade; }\n' "$wan" "$pool"
        fi
        printf '}\n'
    } > "$lock/rules.nft"
    nft -f "$lock/rules.nft"
    printf 'nft delete table inet %s\n' "$table" >> "$journal"
    rm -f "$lock/rules.nft"
}
fw_pf() {
    if [ ! -c /dev/pf ]; then
        kldload pf 2>/dev/null || :
        printf 'kldunload pf >/dev/null 2>&1 || :\n' >> "$journal"
    fi
    was_pf_enabled=no
    if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
        was_pf_enabled=yes
    else
        pfctl -e >/dev/null 2>&1 || :
        printf 'pfctl -d >/dev/null 2>&1 || :\n' >> "$journal"
    fi
    root_needs_anchor=no
    if ! pfctl -sr 2>/dev/null | grep -q 'anchor "tayga_sfx/\*"'; then
        root_needs_anchor=yes
    fi
    if [ "$root_needs_anchor" = yes ]; then
        {
            pfctl -sr 2>/dev/null || :
            printf 'anchor "tayga_sfx/*"\n'
        } > "$lock/root.pf"
        pfctl -f "$lock/root.pf" 2>/dev/null || :
        if [ "$was_pf_enabled" = yes ]; then
            printf 'pfctl -f /etc/pf.conf 2>/dev/null || :\n' >> "$journal"
        else
            printf 'pfctl -F rules 2>/dev/null || :\n' >> "$journal"
        fi
        rm -f "$lock/root.pf"
    fi
    mss=$(( mtu - 40 ))
    {
        printf 'scrub on %s proto tcp all max-mss %d\n' "$dev" "$mss"
        if [ "$mode" = nat64 ]; then
            printf 'nat on %s inet from %s to any -> (%s)\n' "$wan" "$pool" "$wan"
            printf 'pass in quick on %s inet from %s to any keep state\n' "$dev" "$pool"
            printf 'pass out quick on %s inet from %s to any keep state\n' "$wan" "$pool"
            printf 'pass in quick on %s inet6 from any to %s keep state\n' "$wan" "$pref64"
            printf 'pass out quick on %s inet6 from any to %s keep state\n' "$dev" "$pref64"
        elif [ "$mode" = siit ]; then
            printf 'pass in quick on %s inet from %s to any keep state\n' "$dev" "$pool"
            printf 'pass out quick on %s inet from %s to any keep state\n' "$wan" "$pool"
            printf 'pass in quick on %s inet from any to %s keep state\n' "$wan" "$pool"
            printf 'pass out quick on %s inet from any to %s keep state\n' "$dev" "$pool"
            printf 'pass in quick on %s inet6 from %s to any keep state\n' "$dev" "$pref64"
            printf 'pass out quick on %s inet6 from %s to any keep state\n' "$wan" "$pref64"
            printf 'pass in quick on %s inet6 from any to %s keep state\n' "$wan" "$pref64"
            printf 'pass out quick on %s inet6 from any to %s keep state\n' "$dev" "$pref64"
        elif [ "$mode" = clat ]; then
            printf 'pass in quick on %s inet from any to any keep state\n' "$dev"
            printf 'pass out quick on %s inet from any to any keep state\n' "$dev"
            if [ "$address_mode" = nat66 ]; then
                printf 'nat on %s inet6 from { %s, %s } to %s -> %s\n' "$uplink6" "$clat6" "$addr6" "$pref64" "$nat66_address"
                printf 'pass out quick on %s inet6 from { %s, %s, %s } to any keep state\n' "$uplink6" "$clat6" "$addr6" "$nat66_address"
                printf 'pass in quick on %s inet6 from any to { %s, %s } keep state\n' "$uplink6" "$clat6" "$nat66_address"
            else
                printf 'pass out quick on %s inet6 from %s to any keep state\n' "$uplink6" "$clat6"
                printf 'pass in quick on %s inet6 from any to %s keep state\n' "$uplink6" "$clat6"
            fi
        fi
    } > "$lock/rules.pf"
    pfctl -a "tayga_sfx/$dev" -f "$lock/rules.pf"
    printf 'pfctl -a tayga_sfx/%s -F rules >/dev/null 2>&1 && pfctl -a tayga_sfx/%s -F nat >/dev/null 2>&1 || :\n' "$dev" "$dev" >> "$journal"
    rm -f "$lock/rules.pf"
}
case "$mode" in
    nat64|siit)
        if [ "$mode" = siit ]; then
            pool=$(awk '$1=="map" {print $2}' "$config")
            map6=$(awk '$1=="map" {print $3}' "$config")
            for token in "$pool" "$map6"; do
                case "$token" in ''|*[!0-9a-fA-F:./]*) fail 'SIIT requires exactly one inline map' ;; esac
            done
        else [ -n "$pool" ] || fail 'NAT64 requires dynamic-pool'
        fi
        if [ "$os" = FreeBSD ]; then
            ifconfig "$dev" inet "$(get ipv4-addr)" "$(get ipv4-addr)" up
            add_route -4 "$pool" -interface "$dev"
            add_route -6 "$pref64" -interface "$dev"
            wan=$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2}')
            case "$wan" in ''|*[!a-zA-Z0-9_.:-]*) fail 'An IPv4 default-route interface is required' ;; esac
            fw_pf
        else
            ip -4 addr add "$(get ipv4-addr)/32" dev "$dev"
            add_route -4 "$pool" dev "$dev"
            add_route -6 "$pref64" dev "$dev"
            if [ "$mode" = siit ]; then
                native=$(ip -6 route get "${map6%/*}")
                case "$native" in
                    *"dev $dev "*|*"dev $dev") fail 'SIIT IPv6 endpoint routes back into the translator' ;;
                    *'dev '*) ;;
                    *) fail 'SIIT requires a native route to the IPv6 endpoint' ;;
                esac
            fi
            wan=$(ip -4 route show default | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
            case "$wan" in ''|*[!a-zA-Z0-9_.:-]*) fail 'An IPv4 default-route interface is required' ;; esac
            if [ "$firewall" = iptables ]; then
                fw_chain iptables filter FORWARD
                iptables -w -t filter -A "$chain" -i "$dev" -o "$wan" -s "$pool" -j ACCEPT
                if [ "$mode" = siit ]; then
                    iptables -w -t filter -A "$chain" -i "$wan" -o "$dev" -d "$pool" -j ACCEPT
                else
                    iptables -w -t filter -A "$chain" -i "$wan" -o "$dev" -d "$pool" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
                    fw_chain iptables nat POSTROUTING
                    iptables -w -t nat -A "$chain" -s "$pool" -o "$wan" -j MASQUERADE
                fi
                fw_accept6 "$pref64"
            elif [ "$firewall" = firewalld ]; then
                fw_firewalld
            else fw_nft
            fi
        fi
        ;;
    clat)
        if [ "$os" = FreeBSD ]; then
            default=$(route -n get default 2>/dev/null)
            gateway=$(printf '%s\n' "$default" | awk '$1=="gateway:" {print $2}')
            uplink=$(printf '%s\n' "$default" | awk '$1=="interface:" {print $2}')
        else
            default=$(ip -4 route show default | head -n 1)
            gateway=$(printf '%s\n' "$default" | awk '{for(i=1;i<NF;i++)if($i=="via")print $(i+1)}')
            uplink=$(printf '%s\n' "$default" | awk '{for(i=1;i<NF;i++)if($i=="dev")print $(i+1)}')
        fi
        case "$gateway" in ''|*[!0-9.]*) fail 'CLAT requires an IPv4 gateway for access-route protection' ;; esac
        case "$uplink" in ''|*[!a-zA-Z0-9_.:-]*) fail 'Invalid uplink interface' ;; esac
        peer=${SSH_CONNECTION:-}
        peer=${peer%% *}
        case "$peer" in '') ;; *:*) peer= ;; *[!0-9.]*) fail 'Invalid SSH peer' ;; *) peer=$peer/32 ;; esac
        saved_peer=$(awk '$1=="#" && $2=="installer-management4" {print $3}' "$config")
        case "$saved_peer" in '') ;; *[!0-9.]*) fail 'Invalid saved SSH peer' ;; *) saved_peer=$saved_peer/32 ;; esac
        for destination in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.169.254/32 35.235.240.0/20 $peer $saved_peer; do
            if [ "$os" = FreeBSD ]; then
                if ! netstat -rn -f inet | awk '{print $1}' | grep -Fx "$destination" >/dev/null 2>&1; then
                    add_route -4 "$destination" "$gateway"
                fi
            else
                if [ -z "$(ip -4 route show exact "$destination")" ]; then
                    add_route -4 "$destination" via "$gateway" dev "$uplink"
                fi
            fi
        done
        clat6=$(awk '$1=="map" && $2=="192.0.0.1" {print $3}' "$config")
        case "$clat6" in ''|*[!0-9a-fA-F:]*) fail 'Missing CLAT mapping' ;; esac
        if [ "$address_mode" = proxy-ndp ]; then
            if [ "$os" = FreeBSD ]; then
                for address in "$clat6" "$addr6"; do
                    if ifconfig "$uplink6" inet6 2>/dev/null | awk '$1=="inet6" {split($2,a,"/");print a[1]}' | grep -Fx "$address" >/dev/null; then
                        fail 'Proxy address is already assigned to the uplink'
                    fi
                    ifconfig "$uplink6" inet6 "$address/128" alias
                    printf 'ifconfig %s inet6 %s -alias >/dev/null 2>&1 || :\n' "$uplink6" "$address" >> "$journal"
                done
            else
                set_sysctl "net.ipv6.conf.$uplink6.proxy_ndp" 1
                for address in "$clat6" "$addr6"; do
                    if ip -6 neigh show proxy dev "$uplink6" | awk '{print $1}' | grep -Fx "$address" >/dev/null; then fail 'A proxy NDP entry already exists'; fi
                    if ip -6 addr show dev "$uplink6" | awk '$1=="inet6" {split($2,a,"/");print a[1]}' | grep -Fx "$address" >/dev/null; then fail 'Proxy address is already assigned to the uplink'; fi
                    ip -6 neigh add proxy "$address" dev "$uplink6"
                    printf 'ip -6 neigh del proxy %s dev %s\n' "$address" "$uplink6" >> "$journal"
                done
            fi
        elif [ "$address_mode" = nat66 ]; then
            for address in "$clat6" "$addr6"; do
                case "$address" in [fF][cCdD][0-9a-fA-F][0-9a-fA-F]:*) ;; *) fail 'NAT66 requires ULA translation addresses' ;; esac
            done
            [ -n "$nat66_address" ] || fail 'Missing NAT66 source address'
            if [ "$os" = FreeBSD ]; then
                ifconfig "$uplink6" inet6 2>/dev/null | awk '$1=="inet6" && !/tentative|duplicated/ {split($2,a,"/");print a[1]}' | grep -Fx "$nat66_address" >/dev/null || fail 'NAT66 source must be assigned to the uplink (use its displayed spelling)'
            else
                ip -6 addr show dev "$uplink6" | awk '$1=="inet6" && !/tentative|dadfailed/ {split($2,a,"/");print a[1]}' | grep -Fx "$nat66_address" >/dev/null || fail 'NAT66 source must be assigned to the uplink (use its displayed spelling)'
                if [ "$firewall" = iptables ]; then
                    fw_chain ip6tables nat POSTROUTING
                    for address in "$clat6" "$addr6"; do
                        ip6tables -w -t nat -A "$chain" -s "$address/128" -d "$pref64" -o "$uplink6" -j SNAT --to-source "$nat66_address"
                    done
                elif [ "$firewall" = firewalld ]; then
                    for address in "$clat6" "$addr6"; do
                        firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -o "$uplink6" -s "$address/128" -d "$pref64" -j SNAT --to-source "$nat66_address"
                        printf 'firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -o %s -s %s/128 -d %s -j SNAT --to-source %s >/dev/null 2>&1 || :\n' "$uplink6" "$address" "$pref64" "$nat66_address" >> "$journal"
                    done
                fi
            fi
        fi
        if [ "$os" = FreeBSD ]; then
            ifconfig "$dev" inet 192.0.0.1 192.0.0.2 up
            fw_pf
            add_route -6 "$clat6/128" -interface "$dev"
            add_route -4 0.0.0.0/1 -interface "$dev"
            add_route -4 128.0.0.0/1 -interface "$dev"
        else
            ip -4 addr add 192.0.0.1/32 dev "$dev"
            if [ "$firewall" = iptables ]; then
                fw_accept6 "$clat6/128"
                # Reuse the mangle chain from FORWARD for locally generated IPv4.
                iptables -w -t mangle -I OUTPUT 1 -j "TAYGA_SFX_$dev"
                printf 'iptables -w -t mangle -D OUTPUT -j TAYGA_SFX_%s\n' "$dev" >> "$journal"
            elif [ "$firewall" = firewalld ]; then
                firewall-cmd --direct --add-rule ipv4 mangle OUTPUT 0 -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
                printf 'firewall-cmd --direct --remove-rule ipv4 mangle OUTPUT 0 -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || :\n' "$dev" >> "$journal"
                firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i "$dev" -o "$uplink6" -s "$clat6" -j ACCEPT
                printf 'firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i %s -o %s -s %s -j ACCEPT >/dev/null 2>&1 || :\n' "$dev" "$uplink6" "$clat6" >> "$journal"
                firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i "$uplink6" -o "$dev" -d "$clat6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
                printf 'firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i %s -o %s -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || :\n' "$uplink6" "$dev" "$clat6" >> "$journal"
            else fw_nft
            fi
            add_route -6 "$clat6/128" dev "$dev"
            add_route -4 0.0.0.0/1 dev "$dev"
            add_route -4 128.0.0.0/1 dev "$dev"
        fi
        ;;
esac
committed=yes
trap 'rmdir "$lock"' 0
