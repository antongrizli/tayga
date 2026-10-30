#!/bin/sh
# Runtime-only netifd/fw4/dnsmasq ownership. No edits to network/firewall/dhcp UCI files.
# net_cleanup also receives the optional lease from the sourcing netifd protocol; ash uses fd 1000 for procd_lock.
# shellcheck disable=SC2034,SC2119,SC2120,SC3023
net=/var/run/tayga-managed/network
net_fail() { echo "ERROR: $*" >&2; return 1; }
net_get() { awk -v key="$1" '$1==key {print $2}' "$config"; }
net_meta() { awk -v key="$1" '$1=="#" && $2==key {print $3}' "$config"; }
net_parse() {
    config=$1
    tayga --check-config --config "$config" >&2 || return 1
    [ "$(net_get tun-device)" = tmg0 ] || { net_fail 'Managed device must be tmg0'; return 1; }
    mode=$(net_meta installer-mode)
    case "$mode" in nat64|siit|clat) ;; *) net_fail 'Managed networking supports CLAT/NAT64/SIIT generated profiles'; return 1 ;; esac
    addr4=$(net_get ipv4-addr); addr6=$(net_get ipv6-addr); prefix=$(net_get prefix)
    mtu=$(net_get offlink-mtu); mtu=${mtu:-1500}
    enable_dns64=$(net_meta installer-dns64); enable_dns64=${enable_dns64:-no}
    dns64_upstream=$(net_meta installer-dns64-upstream); dns64_upstream=${dns64_upstream:-9.9.9.9}
    host_dns=$(net_meta installer-host-dns); host_dns=${host_dns:-keep}
    address_mode=$(net_meta installer-clat-address-mode); address_mode=${address_mode:-routed}
    nat66_address=$(net_meta installer-nat66-address)
    management4=$(net_meta installer-management4)
    verify_target_meta=$(net_meta installer-verify-target)
    case "$enable_dns64" in yes) [ "$mode" = nat64 ] || return 1 ;; no) ;; *) return 1 ;; esac
    case "$host_dns" in keep) ;; public|public-resolvconf|public-file|public-nm) [ "$mode" = clat ] || return 1 ;; *) return 1 ;; esac
    case "$address_mode" in
        routed) [ -z "$nat66_address" ] || return 1 ;;
        proxy-ndp) [ "$mode" = clat ] && [ -z "$nat66_address" ] || return 1 ;;
        nat66) [ "$mode" = clat ] && [ -n "$nat66_address" ] || return 1 ;;
        *) return 1 ;;
    esac
    if [ "$mode" = nat64 ]; then
        pool=$(net_get dynamic-pool)
        source6=$(net_meta installer-source6)
        if [ -z "$source6" ] || [ "$source6" = "$addr6" ]; then net_fail 'NAT64 requires a distinct installer-source6'; return 1; fi
        case "$source6" in *[!0-9a-fA-F:.]*) return 1 ;; esac
        # Validate the host source with the daemon parser too; this writes nothing.
        awk -v source="$source6" '$1=="ipv6-addr" {$2=source} {print}' "$config" |
            tayga --check-config --config /dev/stdin >&2 || return 1
        map6=
    elif [ "$mode" = clat ]; then
        [ "$(awk '$1=="map" {n++} END {print n+0}' "$config")" = 1 ] || return 1
        pool=$(awk '$1=="map" {print $2}' "$config")
        map6=$(awk '$1=="map" {print $3}' "$config")
        if [ "$pool" != 192.0.0.1 ] || [ -z "$map6" ] || [ "$map6" = "$addr6" ]; then
            net_fail 'CLAT requires map 192.0.0.1 <clat6> distinct from ipv6-addr'
            return 1
        fi
        case "$map6" in */*) return 1 ;; esac
        if [ "$address_mode" = nat66 ]; then
            for ula_addr in "$addr6" "$map6"; do
                case "$ula_addr" in [fF][cCdD][0-9a-fA-F][0-9a-fA-F]:*) ;; *) return 1 ;; esac
            done
        fi
        source6=$addr6
    else
        [ "$(awk '$1=="map" {n++} END {print n+0}' "$config")" = 1 ] || return 1
        pool=$(awk '$1=="map" {print $2}' "$config")
        map6=$(awk '$1=="map" {print $3}' "$config")
        source6=$addr6
    fi
    for address_token in "$addr4" "$addr6" "$prefix" "$pool" "$map6" "$nat66_address" "$management4"; do
        case "$address_token" in *[!0-9a-fA-F:./]*) return 1 ;; esac
    done
    for target_token in "$dns64_upstream" "$verify_target_meta"; do
        case "$target_token" in *[!0-9a-fA-F:./@#_-]*) return 1 ;; esac
    done
    [ -n "$prefix" ] && [ -n "$pool" ] || return 1
    case "$pool" in */*) ;; *) pool=$pool/32 ;; esac
}
net_owned() {
    [ -d "$net" ] && [ ! -L "$net" ] && [ -f "$net/token" ] || return 1
    token=$(cat "$net/token")
    case "$token" in owner.*) ;; *) return 1 ;; esac
    case "$token" in *[!a-zA-Z0-9._]*) return 1 ;; esac
}
net_reload() { timeout 20 fw4 check && timeout 20 fw4 reload; }
net_dns_dirs() {
    printf '%s\n' /tmp/dnsmasq.d
    for d in /tmp/dnsmasq.*.d; do
        [ -d "$d" ] && printf '%s\n' "$d"
    done
    if command -v uci >/dev/null 2>&1; then
        uci -q show dhcp 2>/dev/null | sed -n 's/^dhcp\.\([^.=]*\)=dnsmasq$/\/tmp\/dnsmasq.\1.d/p'
    fi
}
net_dns_cleanup() {
    if [ -f "$net/dns64.identity" ]; then
        read -r dns_pid dns_ticks dns_tok < "$net/dns64.identity" || :
        if [ "$dns_tok" = "$token" ] && [ -n "$dns_pid" ] && [ -r "/proc/$dns_pid/stat" ]; then
            cur_ticks=$(awk '{print $22}' "/proc/$dns_pid/stat" 2>/dev/null || :)
            if [ "$cur_ticks" = "$dns_ticks" ] && tr '\000' ' ' < "/proc/$dns_pid/cmdline" 2>/dev/null | grep -Fq -- '--serve-dns64'; then
                kill "$dns_pid" 2>/dev/null || :
            fi
        fi
        rm -f "$net/dns64.identity"
    fi
    if [ -f "$net/dnsmasq.files" ]; then
        dns_changed=0
        while IFS= read -r dns_file; do
            [ -n "$dns_file" ] || continue
            if [ -f "$dns_file" ] && [ ! -L "$dns_file" ] && [ "$(head -n 1 "$dns_file" 2>/dev/null || :)" = "# tayga-managed:$token" ]; then
                rm -f "$dns_file"
                dns_changed=1
            fi
        done < "$net/dnsmasq.files"
        rm -f "$net/dnsmasq.files"
        if [ "$dns_changed" = 1 ] && [ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq running >/dev/null 2>&1; then
            /etc/init.d/dnsmasq restart >/dev/null 2>&1 || cleanup_result=1
        fi
    fi
}
net_dns_up() {
    want_dns=0
    if [ "$mode" = nat64 ] && [ "$enable_dns64" = yes ]; then
        want_dns=1
        pref64-discover --serve-dns64 127.0.0.1#5364 "$prefix" "$dns64_upstream" </dev/null >/dev/null 2>&1 8>&- &
        dns_pid=$!
        [ -r "/proc/$dns_pid/stat" ] || return 1
        dns_ticks=$(awk '{print $22}' "/proc/$dns_pid/stat" 2>/dev/null || :)
        [ -n "$dns_ticks" ] || { kill "$dns_pid" 2>/dev/null || :; return 1; }
        printf '%s %s %s\n' "$dns_pid" "$dns_ticks" "$token" > "$net/dns64.identity"
    elif [ "$mode" = clat ]; then
        case "$host_dns" in public*) want_dns=1 ;; esac
    fi
    [ "$want_dns" = 1 ] || return 0
    : > "$net/dnsmasq.files"
    for dns_dir in $(net_dns_dirs | sort -u); do
        [ ! -L "$dns_dir" ] || return 1
        mkdir -p "$dns_dir" || return 1
        dns_conf="$dns_dir/95-tayga-managed.conf"
        [ ! -L "$dns_conf" ] || return 1
        if [ -f "$dns_conf" ]; then
            case "$(head -n 1 "$dns_conf" 2>/dev/null || :)" in
                '# tayga-managed:'*) ;;
                *) net_fail 'Existing dnsmasq drop-in preserved'; return 1 ;;
            esac
        fi
        if [ "$mode" = nat64 ]; then
            {
                printf '# tayga-managed:%s\n' "$token"
                echo 'no-resolv'
                echo 'server=127.0.0.1#5364'
                echo 'rebind-domain-ok=ipv4only.arpa'
                echo 'rebind-domain-ok=internal'
                if [ -f /tmp/tayga-dns64.hosts ]; then
                    awk '!/^[[:space:]]*(#|$)/ {for(i=2;i<=NF;i++) print "rebind-domain-ok=" $i}' /tmp/tayga-dns64.hosts
                fi
            } > "$dns_conf"
        else
            {
                printf '# tayga-managed:%s\n' "$token"
                echo 'no-resolv'
                echo 'server=1.1.1.1'
                echo 'server=8.8.8.8'
            } > "$dns_conf"
        fi
        printf '%s\n' "$dns_conf" >> "$net/dnsmasq.files"
    done
    if [ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq running >/dev/null 2>&1; then
        /etc/init.d/dnsmasq restart >/dev/null 2>&1 || return 1
    fi
}
net_cleanup() (
    mkdir -p /var/run/tayga-managed
    exec 7> /var/run/tayga-managed/network-cleanup.lock
    flock -x 7
    net_owned || return 0
    [ "$#" = 0 ] || [ "$1" = "$token" ] || return 0
    [ ! -f "$net/cleaned" ] || return 0
    rm -f "$net/forward.rules.nft" "$net/output.rules.nft" "$net/srcnat.rules.nft"
    cleanup_result=0
    net_dns_cleanup
    if [ -f "$net/proxy_ndp.addrs" ] && [ -f "$net/wan" ]; then
        wan_dev=$(cat "$net/wan")
        while IFS= read -r proxy6; do
            if [ -n "$proxy6" ]; then
                ip -6 neigh del proxy "$proxy6" dev "$wan_dev" 2>/dev/null || :
            fi
        done < "$net/proxy_ndp.addrs"
        rm -f "$net/proxy_ndp.addrs"
    fi
    if [ -f "$net/proxy_ndp.prev" ] && [ -f "$net/wan" ]; then
        wan_dev=$(cat "$net/wan")
        prev_ndp=$(cat "$net/proxy_ndp.prev")
        if [ -w "/proc/sys/net/ipv6/conf/$wan_dev/proxy_ndp" ]; then
            printf '%s\n' "$prev_ndp" > "/proc/sys/net/ipv6/conf/$wan_dev/proxy_ndp" 2>/dev/null || :
        fi
        rm -f "$net/proxy_ndp.prev"
    fi
    if [ -f "$net/mgmt_route" ]; then
        read -r mgmt_cidr mgmt_gw mgmt_dev < "$net/mgmt_route" || :
        if [ -n "$mgmt_cidr" ] && [ -n "$mgmt_gw" ] && [ -n "$mgmt_dev" ]; then
            ip -4 route del "$mgmt_cidr" via "$mgmt_gw" dev "$mgmt_dev" 2>/dev/null || :
        fi
        rm -f "$net/mgmt_route"
    fi
    net_reload || cleanup_result=1
    if [ -f "$net/created" ] && [ -d /sys/class/net/tmg0 ]; then
        [ "$(cat /sys/class/net/tmg0/ifalias)" = "tayga-managed:$token" ] || {
            net_fail 'Managed TUN ownership changed; preserving interface'; return 1;
        }
        ip link delete dev tmg0 || return 1
    fi
    [ "$cleanup_result" != 0 ] || : > "$net/cleaned"
    return "$cleanup_result"
)
net_down() {
    [ -e "$net" ] || return 0
    net_owned || { net_fail 'Unowned managed network state'; return 1; }
    has_iface=0
    if ubus -t 5 call network.interface.tayga_managed status >/dev/null 2>&1; then
        [ "$(ubus call network.interface.tayga_managed status | jsonfilter -e '@.proto')" = tayga_managed ] || {
            net_fail 'Logical interface ownership changed'; return 1;
        }
        has_iface=1
    fi
    net_cleanup || return 1
    if [ "$has_iface" = 1 ]; then
        # Removing the TUN can make netifd retire the dynamic object first.
        for operation in down remove; do
            if ! ubus -t 5 call network.interface.tayga_managed "$operation" >/dev/null 2>&1; then
                if ubus -t 2 call network.interface.tayga_managed status >/dev/null 2>&1; then
                    net_fail "Could not $operation managed interface"; return 1
                fi
            fi
        done
        removed=0
        for _ in $(seq 1 20); do
            if ! ubus -t 2 call network.interface.tayga_managed status >/dev/null 2>&1; then
                removed=1
                break
            fi
            # A remove during asynchronous teardown can leave a down object.
            ubus -t 2 call network.interface.tayga_managed remove >/dev/null 2>&1 || :
            sleep 1
        done
        [ "$removed" = 1 ] || { net_fail 'Managed interface removal timed out'; return 1; }
    fi
    rm -rf "$net"
}
net_rules() {
    wan=$(cat "$net/wan"); inside=$(cat "$net/inside")
    for device in "$wan" "$inside"; do
        case "$device" in ''|tmg0|*[!a-zA-Z0-9_.:-]*|????????????????*) return 1 ;; esac
    done
    {
        echo 'oifname "tmg0" tcp flags syn tcp option maxseg size set rt mtu comment "tayga-managed MSS"'
        if [ "$mode" = nat64 ]; then
            printf 'iifname "%s" oifname "tmg0" ip6 daddr %s counter accept comment "tayga-managed IPv6"\n' "$inside" "$prefix"
            printf 'iifname "tmg0" oifname "%s" ip saddr %s counter accept comment "tayga-managed IPv4"\n' "$wan" "$pool"
            printf 'iifname "%s" oifname "tmg0" ip daddr %s ct state established,related counter accept comment "tayga-managed IPv4 reply"\n' "$wan" "$pool"
            printf 'iifname "tmg0" oifname "%s" ip6 saddr %s ct state established,related counter accept comment "tayga-managed IPv6 reply"\n' "$inside" "$prefix"
        elif [ "$mode" = clat ]; then
            printf 'iifname "%s" oifname "tmg0" meta nfproto ipv4 counter accept comment "tayga-managed CLAT LAN"\n' "$inside"
            printf 'iifname "tmg0" oifname "%s" meta nfproto ipv4 ct state established,related counter accept comment "tayga-managed CLAT LAN reply"\n' "$inside"
            printf 'iifname "tmg0" oifname "%s" ip6 saddr %s ip6 daddr %s counter accept comment "tayga-managed CLAT"\n' "$wan" "$map6" "$prefix"
            printf 'iifname "%s" oifname "tmg0" ip6 saddr %s ip6 daddr %s counter accept comment "tayga-managed CLAT reply"\n' "$wan" "$prefix" "$map6"
        else
            printf 'iifname "%s" oifname "tmg0" ip daddr %s counter accept comment "tayga-managed SIIT"\n' "$inside" "$pool"
            printf 'iifname "tmg0" oifname "%s" ip6 saddr %s ip6 daddr %s counter accept comment "tayga-managed SIIT"\n' "$wan" "$prefix" "$map6"
            printf 'iifname "%s" oifname "tmg0" ip6 saddr %s ip6 daddr %s counter accept comment "tayga-managed SIIT"\n' "$wan" "$map6" "$prefix"
            printf 'iifname "tmg0" oifname "%s" ip saddr %s counter accept comment "tayga-managed SIIT"\n' "$inside" "$pool"
        fi
    } > "$net/forward.rules.nft"
    : > "$net/output.rules.nft"
    : > "$net/srcnat.rules.nft"
    if [ "$mode" = nat64 ]; then
        printf 'oifname "tmg0" ip6 daddr %s counter accept comment "tayga-managed local"\n' "$prefix" > "$net/output.rules.nft"
        printf 'iifname "tmg0" oifname "%s" ip saddr %s counter masquerade comment "tayga-managed NAT64"\n' "$wan" "$pool" > "$net/srcnat.rules.nft"
    elif [ "$mode" = clat ]; then
        {
            echo 'oifname "tmg0" tcp flags syn tcp option maxseg size set rt mtu comment "tayga-managed local MSS"'
            echo 'oifname "tmg0" meta nfproto ipv4 counter accept comment "tayga-managed local CLAT"'
        } > "$net/output.rules.nft"
        printf 'iifname "%s" oifname "tmg0" meta nfproto ipv4 counter masquerade comment "tayga-managed CLAT LAN masq"\n' "$inside" > "$net/srcnat.rules.nft"
        if [ "$address_mode" = nat66 ]; then
            printf 'oifname "%s" ip6 saddr { %s, %s } ip6 daddr %s counter snat ip6 to %s comment "tayga-managed CLAT NAT66"\n' \
                "$wan" "$addr6" "$map6" "$prefix" "$nat66_address" >> "$net/srcnat.rules.nft"
        fi
    else
        {
            printf 'oifname "tmg0" ip6 daddr %s counter accept comment "tayga-managed local"\n' "$prefix"
            printf 'oifname "tmg0" ip daddr %s counter accept comment "tayga-managed local"\n' "$pool"
        } > "$net/output.rules.nft"
    fi
}
net_setup() {
    net_owned || return 1
    net_parse "$net/config" || return 1
    [ ! -e /sys/class/net/tmg0 ] || { net_fail 'Existing TUN preserved'; return 1; }
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ] || [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" != 1 ]; then
        net_fail 'Router IPv4/IPv6 forwarding must already be enabled'; return 1;
    fi
    wan=$(cat "$net/wan")
    if [ "$mode" = clat ]; then
        for check_v4 in 192.0.0.1 "$addr4"; do
            if ip -4 route get "$check_v4" 2>/dev/null | grep -q '^local '; then
                net_fail 'Managed address already belongs to the router'; return 1
            fi
        done
        for check_v6 in "$source6" "${map6%/*}"; do
            if ip -6 route get "$check_v6" 2>/dev/null | grep -q '^local '; then
                net_fail 'Managed address already belongs to the router'; return 1
            fi
        done
        for route4 in 0.0.0.0/1 128.0.0.0/1 "$addr4/32"; do
            existing=$(ip -4 route show exact "$route4") || return 1
            [ -z "$existing" ] || { net_fail 'Existing route preserved'; return 1; }
        done
        existing=$(ip -6 route show exact "${map6%/*}/128") || return 1
        [ -z "$existing" ] || { net_fail 'Existing route preserved'; return 1; }
        if [ "$address_mode" = nat66 ]; then
            ip -6 -o addr show dev "$wan" scope global 2>/dev/null | grep -Fq " $nat66_address/" || {
                net_fail 'NAT66 address must exist on uplink'; return 1;
            }
        fi
        if [ -n "$management4" ] && [ -z "$(ip -4 route show exact "$management4/32")" ]; then
            mgmt_get=$(ip -4 route get "$management4" 2>/dev/null | head -n 1 || :)
            mgmt_gw=$(printf '%s\n' "$mgmt_get" | awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')
            mgmt_dev=$(printf '%s\n' "$mgmt_get" | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
            if [ -n "$mgmt_gw" ] && [ -n "$mgmt_dev" ] && [ "$mgmt_dev" != lo ] && [ "$mgmt_dev" != tmg0 ]; then
                ip -4 route add "$management4/32" via "$mgmt_gw" dev "$mgmt_dev" || return 1
                printf '%s %s %s\n' "$management4/32" "$mgmt_gw" "$mgmt_dev" > "$net/mgmt_route"
            fi
        fi
        if [ "$address_mode" = proxy-ndp ]; then
            if [ -r "/proc/sys/net/ipv6/conf/$wan/proxy_ndp" ]; then
                cat "/proc/sys/net/ipv6/conf/$wan/proxy_ndp" > "$net/proxy_ndp.prev"
                echo 1 > "/proc/sys/net/ipv6/conf/$wan/proxy_ndp"
            fi
            : > "$net/proxy_ndp.addrs"
            for proxy6 in "${map6%/*}" "$addr6"; do
                if ! ip -6 neigh show proxy "$proxy6" dev "$wan" 2>/dev/null | grep -Fq "$proxy6"; then
                    ip -6 neigh replace proxy "$proxy6" dev "$wan" || { net_cleanup; return 1; }
                    printf '%s\n' "$proxy6" >> "$net/proxy_ndp.addrs"
                fi
            done
        fi
    else
        for family in 4 6; do
            if [ "$family" = 4 ]; then address=$addr4; route=$pool; else address=$source6; route=$prefix; fi
            if ip "-$family" route get "$address" 2>/dev/null | grep -q '^local '; then
                net_fail 'Managed address already belongs to the router'; return 1
            fi
            existing=$(ip "-$family" route show exact "$route") || return 1
            [ -z "$existing" ] || { net_fail 'Existing route preserved'; return 1; }
        done
    fi
    tayga --mktun --config "$net/config" >&2 || { net_cleanup; return 1; }
    printf 'tayga-managed:%s' "$token" > /sys/class/net/tmg0/ifalias
    : > "$net/created"
    if ! ip link set dev tmg0 mtu "$mtu" up || ! net_rules || ! net_reload; then
        net_cleanup
        return 1
    fi
}
net_verify() {
    verify_cfg=$1
    verify_arg=${2:-}
    net_parse "$verify_cfg" || return 1
    net_owned || { net_fail 'Managed network is not active'; return 1; }
    wan=$(cat "$net/wan")
    status=$(ubus -t 5 call network.interface.tayga_managed status 2>/dev/null || :)
    if [ "$(jsonfilter -s "$status" -e '@.up')" != true ] || [ "$(jsonfilter -s "$status" -e '@.data.tayga_owner')" != "$token" ]; then
        net_fail 'Logical interface is not ready'; return 1
    fi
    if [ ! -d /sys/class/net/tmg0 ] || [ "$(cat /sys/class/net/tmg0/ifalias 2>/dev/null || :)" != "tayga-managed:$token" ]; then
        net_fail 'Managed TUN device is not ready'; return 1
    fi
    daemon_ok=0
    # Allow the bounded procd respawn (5 s delay) after transient startup errors.
    for _ in $(seq 1 25); do
        svc_json=$(ubus -t 2 call service list '{"name":"tayga-managed"}' 2>/dev/null || :)
        svc_pid=$(jsonfilter -s "$svc_json" -e '@["tayga-managed"].instances.main.pid' 2>/dev/null || :)
        if [ "$(jsonfilter -s "$svc_json" -e '@["tayga-managed"].instances.main.running' 2>/dev/null || :)" = true ] &&
           [ -n "$svc_pid" ] && [ "$(cat "/proc/$svc_pid/comm" 2>/dev/null || :)" = tayga ]; then
            daemon_ok=1
            break
        fi
        sleep 1
    done
    [ "$daemon_ok" = 1 ] || { net_fail 'TAYGA daemon instance is not running'; return 1; }
    nft list chain inet fw4 forward 2>/dev/null | grep -q 'tayga-managed' || {
        net_fail 'Managed firewall rules are not active'; return 1;
    }
    if [ "$mode" = nat64 ]; then
        if [ -z "$(ip -6 route show exact "$prefix" dev tmg0)" ] || [ -z "$(ip -4 route show exact "$pool" dev tmg0)" ]; then
            net_fail 'NAT64 routes missing on tmg0'; return 1
        fi
        ping -6 -c 1 -W 2 "$source6" >/dev/null 2>&1 || { net_fail 'NAT64 IPv6 self-probe failed'; return 1; }
        ping -4 -c 1 -W 2 "$addr4" >/dev/null 2>&1 || { net_fail 'NAT64 IPv4 self-probe failed'; return 1; }
        if [ "$enable_dns64" = yes ]; then
            dns_ok=0
            for _ in 1 2 3; do
                dns_pref=$(pref64-discover -s 127.0.0.1 -t 2 2>/dev/null || :)
                if [ "$dns_pref" = "$prefix" ]; then
                    dns_ok=1
                    break
                fi
                sleep 1
            done
            [ "$dns_ok" = 1 ] || { net_fail 'DNS64 synthesis verification failed'; return 1; }
        fi
    elif [ "$mode" = clat ]; then
        if [ -z "$(ip -4 route show exact 0.0.0.0/1 dev tmg0)" ] ||
           [ -z "$(ip -4 route show exact 128.0.0.0/1 dev tmg0)" ] ||
           [ -z "$(ip -6 route show exact "${map6%/*}/128" dev tmg0)" ]; then
            net_fail 'CLAT routes missing on tmg0'; return 1
        fi
        ping -6 -c 1 -W 2 "$source6" >/dev/null 2>&1 || { net_fail 'CLAT IPv6 self-probe failed'; return 1; }
        clat_ok=0
        for _ in 1 2 3 4 5; do
            if ping -4 -c 1 -W 2 "$addr4" >/dev/null 2>&1; then
                clat_ok=1
                break
            fi
            sleep 1
        done
        [ "$clat_ok" = 1 ] || { net_fail 'CLAT IPv4 self-probe failed'; return 1; }
    else
        if [ -z "$(ip -4 route show exact "$pool" dev tmg0)" ] ||
           [ -z "$(ip -6 route show exact "$prefix" dev tmg0)" ]; then
            net_fail 'SIIT routes missing on tmg0'; return 1
        fi
        ping -4 -c 1 -W 2 "$addr4" >/dev/null 2>&1 || { net_fail 'SIIT IPv4 self-probe failed'; return 1; }
        ping -6 -c 1 -W 2 "$source6" >/dev/null 2>&1 || { net_fail 'SIIT IPv6 self-probe failed'; return 1; }
    fi
    probe_target=${verify_arg:-$verify_target_meta}
    if [ -n "$probe_target" ]; then
        case "$probe_target" in
            *:*)
                if [ "$mode" = nat64 ]; then
                    ping -6 -I "$source6" -c 1 -W 2 "$probe_target" >/dev/null 2>&1 || {
                        net_fail "Readiness probe failed for $probe_target"; return 1;
                    }
                else
                    ping -6 -c 1 -W 2 "$probe_target" >/dev/null 2>&1 || {
                        net_fail "Readiness probe failed for $probe_target"; return 1;
                    }
                fi
                ;;
            *)
                if [ "$mode" = nat64 ]; then
                    syn_target=$(pref64-discover --synthesize "$prefix" "$probe_target" 2>/dev/null || :)
                    if [ -z "$syn_target" ] || ! ping -6 -I "$source6" -c 1 -W 2 "$syn_target" >/dev/null 2>&1; then
                        net_fail "Readiness probe failed for $probe_target"; return 1
                    fi
                else
                    ping -4 -c 1 -W 2 "$probe_target" >/dev/null 2>&1 || {
                        net_fail "Readiness probe failed for $probe_target"; return 1;
                    }
                fi
                ;;
        esac
    fi
}
[ "${TAYGA_NETWORK_LIBRARY:-}" != 1 ] || return 0
set -e
exec 1000>&-
[ "$(id -u)" = 0 ] || exit 1
action=${1:-}; shift
case "$action" in
    check) [ "$#" = 1 ]; net_parse "$1" ;;
    verify) [ "$#" -ge 1 ] && [ "$#" -le 2 ] || exit 2; net_verify "$1" "${2:-}" ;;
    up)
        [ "$#" = 3 ] || exit 2
        config=$1; wan=$2; inside=$3
        [ "$wan" != "$inside" ] || { net_fail 'Inside and uplink must use distinct devices'; exit 1; }
        net_parse "$config"
        for device in "$wan" "$inside"; do
            case "$device" in ''|tmg0|*[!a-zA-Z0-9_.:-]*|????????????????*) exit 2 ;; esac
            [ -e "/sys/class/net/$device" ] || exit 1
        done
        mkdir -p /var/run/tayga-managed
        exec 8> /var/run/tayga-managed/network.lock
        flock -x 8
        uci -q get network.tayga_managed >/dev/null && { net_fail 'Existing UCI interface preserved'; exit 1; }
        key=$({ cat "$config"; printf '%s\n%s\n' "$wan" "$inside"; } | sha256sum); key=${key%% *}
        if net_owned && [ "$(cat "$net/key")" = "$key" ]; then
            status=$(ubus -t 5 call network.interface.tayga_managed status 2>/dev/null || :)
            if [ "$(jsonfilter -s "$status" -e '@.up')" = true ] && [ "$(jsonfilter -s "$status" -e '@.data.tayga_owner')" = "$token" ]; then
                exit 0
            fi
        fi
        if [ -e "$net" ]; then
            net_owned || exit 1
            old_pid=$(ubus -t 5 call service list '{"name":"tayga-managed"}' | jsonfilter -e '@["tayga-managed"].instances.main.pid')
            case "$old_pid" in ''|*[!0-9]*) old_pid= ;; esac
            # Stop supervision before removing the TUN: respawn can otherwise
            # recreate it between teardown and setup on a slow router.
            ubus -t 5 call service delete '{"name":"tayga-managed","instance":"main"}' >/dev/null 2>&1 || :
            for _ in $(seq 1 20); do
                if [ -z "$old_pid" ] || [ ! -d "/proc/$old_pid" ]; then break; fi
                sleep 1
            done
            if [ -n "$old_pid" ] && [ -d "/proc/$old_pid" ]; then
                net_fail 'Previous daemon has not stopped'; exit 1
            fi
            net_down
        elif ubus -t 5 call network.interface.tayga_managed status >/dev/null 2>&1; then net_fail 'Existing logical interface preserved'; exit 1; fi
        handlers=$(ubus -t 5 call network get_proto_handlers)
        printf '%s\n' "$handlers" | grep -q '"tayga_managed"' || { net_fail 'Reboot after installing the netifd protocol package'; exit 1; }
        mkdir -m 700 "$net"
        cp "$config" "$net/config"
        owner=$(mktemp "$net/owner.XXXXXXXX"); token=${owner##*/}; rm "$owner"
        printf '%s\n' "$token" > "$net/token"
        printf '%s\n' "$key" > "$net/key"
        printf '%s\n' "$wan" > "$net/wan"
        printf '%s\n' "$inside" > "$net/inside"
        # Check that the installed fw4 adapters are enabled before kernel mutation.
        fw4 print > "$net/fw4.before"
        for chain in forward output srcnat; do
            grep -Fq "/usr/share/nftables.d/chain-pre/$chain/95-tayga-managed.nft" "$net/fw4.before" || { net_down; exit 1; }
        done
        if ! ubus -t 5 call network add_dynamic "{\"name\":\"tayga_managed\",\"proto\":\"tayga_managed\",\"auto\":true,\"owner_token\":\"$token\"}"; then net_down; exit 1; fi
        for _ in $(seq 1 15); do
            status=$(ubus -t 5 call network.interface.tayga_managed status 2>/dev/null || :)
            if [ "$(jsonfilter -s "$status" -e '@.up')" = true ] && [ "$(jsonfilter -s "$status" -e '@.data.tayga_owner')" = "$token" ]; then
                if ip -6 addr show dev tmg0 | grep -Eq 'tentative|dadfailed'; then sleep 1; continue; fi
                if [ "$mode" = siit ]; then
                    native=$(ip -6 route get "${map6%/*}" 2>/dev/null || :)
                    case "$native" in *'dev tmg0'*|'') net_down; net_fail 'SIIT requires a native IPv6 endpoint route'; exit 1 ;; esac
                elif [ "$mode" = clat ]; then
                    native=$(ip -6 route get "${prefix%/*}1" 2>/dev/null || :)
                    case "$native" in *'dev tmg0'*|'') net_down; net_fail 'CLAT requires a native IPv6 PLAT route'; exit 1 ;; esac
                fi
                if ! net_dns_up; then
                    net_down
                    net_fail 'Managed DNS setup failed'; exit 1
                fi
                exit 0
            fi
            sleep 1
        done
        net_down
        net_fail 'Managed interface did not become ready'; exit 1
        ;;
    down)
        mkdir -p /var/run/tayga-managed
        exec 8> /var/run/tayga-managed/network.lock
        flock -x 8
        net_down
        ;;
    *) exit 2 ;;
esac
