#!/bin/sh
set -eu
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/sbin:/bin:/usr/sbin:/usr/bin}:/usr/local/sbin:/usr/local/bin"; export PATH ;; esac
action=${1:-status}
profile=${2:-}
lib=/usr/local/libexec/tayga
if [ "$action" = apply ]; then
    [ "$#" -eq 2 ] || { echo 'Usage: tayga-ctl apply CONFIG' >&2; exit 2; }
    exec sh "$lib/tayga-lifecycle.sh" apply "$2"
fi
if [ "$action" = upgrade ]; then
    [ "$#" -eq 2 ] || { echo 'Usage: tayga-ctl upgrade PACKAGE_FILE' >&2; exit 2; }
    exec sh "$lib/tayga-package-upgrade.sh" apply "$2"
fi
if [ "$action" = recover ]; then
    [ "$(id -u)" -eq 0 ] || { echo 'Recovery requires root' >&2; exit 1; }
    state=/var/lib/tayga-installer
    tx=$state/files-transaction
    gate=$state/operation.lock
    if [ -d "$tx" ] && [ ! -d "$gate" ]; then
        if [ -f "$tx/files.sh" ]; then
            exec sh "$tx/files.sh" rollback
        elif [ -f "$lib/tayga-files.sh" ]; then
            exec sh "$lib/tayga-files.sh" rollback
        fi
    fi
    if [ ! -f "$gate/transaction" ]; then
        if [ ! -d "$gate" ] && [ -f "$lib/package-owner" ] && [ "$(cat "$lib/package-owner")" = apk ]; then
            sh "$lib/package-lock.sh" unlock
        fi
        echo 'No activation transaction'
        exit 0
    fi
    session=$(cat "$gate/transaction")
    case "$session" in ''|*[!a-zA-Z0-9._-]*) echo 'Invalid transaction pointer' >&2; exit 1 ;; esac
    lock=$gate/$session
    [ -f "$lock/armed" ] || { echo 'No armed activation transaction'; exit 0; }
    if command -v setsid >/dev/null 2>&1; then
        setsid sh "$lock/watchdog.sh" "$lock" "$(cat "$lock/id")" 0 "$(cat "$lock/runner.pid")" "$(cat "$lock/runner.start")" &
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' sh "$lock/watchdog.sh" "$lock" "$(cat "$lock/id")" 0 "$(cat "$lock/runner.pid")" "$(cat "$lock/runner.start")" &
    else
        command -v setsid >/dev/null
    fi
    wait "$!"
    exit
fi
if [ -z "$profile" ] && [ -f /var/lib/tayga-installer/current ]; then profile=$(cat /var/lib/tayga-installer/current); fi
if [ "$action" = uninstall ] && { [ -z "$profile" ] || [ "$profile" = binary-only ]; }; then
    for mode in clat nat64 siit; do
        [ ! -f "/var/lib/tayga-installer/$mode.conf" ] || { echo 'Uninstall managed profiles first' >&2; exit 1; }
    done
    if [ -f "$lib/package-owner" ]; then echo 'Remove binaries with the package manager' >&2; exit 1; fi
    exec sh "$lib/tayga-files.sh" uninstall
fi
case "$profile" in clat|nat64|siit) ;; *)
    echo 'Usage: tayga-ctl start|stop|status|test|reconfigure|uninstall clat|nat64|siit' >&2
    echo '       tayga-ctl apply CONFIG | upgrade PACKAGE_FILE | recover' >&2
    exit 2
    ;;
esac
[ "$#" -le 2 ] || exit 2
init=systemd
if [ ! -d /run/systemd/system ] && [ -d /run/openrc ]; then
    init=openrc
    current=$(cat /var/lib/tayga-installer/current)
    [ "$current" = "$profile" ] || { echo 'OpenRC manages only the selected current profile' >&2; exit 2; }
elif [ "$(uname -s)" = FreeBSD ]; then
    init=freebsd_rc
    current=$(cat /var/lib/tayga-installer/current)
    [ "$current" = "$profile" ] || { echo 'FreeBSD rc.d manages only the selected current profile' >&2; exit 2; }
fi
case "$action" in
    start|stop)
        if [ "$init" = openrc ]; then exec rc-service tayga-managed "$action"; fi
        if [ "$init" = freebsd_rc ]; then exec service tayga-managed "one$action"; fi
        exec systemctl "$action" "tayga-managed@$profile.service"
        ;;
    status)
        awk '$1=="prefix" || $1=="tun-device" {print}' "/etc/tayga/$profile.conf"
        dev=$(awk '$1=="tun-device" {print $2}' "/etc/tayga/$profile.conf")
        if [ "$(uname -s)" = FreeBSD ]; then
            netstat -rn -f inet | grep "$dev" || :
            netstat -rn -f inet6 | grep "$dev" || :
            if [ -f "/var/run/tayga-managed-$profile.pid" ]; then
                kill -USR2 "$(cat "/var/run/tayga-managed-$profile.pid")" 2>/dev/null || :
            fi
            if [ -r "/var/run/tayga-managed-$profile/tayga-status.json" ]; then cat "/var/run/tayga-managed-$profile/tayga-status.json"; fi
            exec service tayga-managed onestatus
        else
            ip -4 route show dev "$dev" || :
            ip -6 route show dev "$dev" || :
            if [ "$init" = openrc ]; then exec rc-service tayga-managed status; fi
            if [ "$(id -u)" -eq 0 ]; then
                systemctl kill --kill-whom=main --signal=SIGUSR2 "tayga-managed@$profile.service" || :
            fi
            if [ -r "/run/tayga-managed-$profile/tayga-status.json" ]; then cat "/run/tayga-managed-$profile/tayga-status.json"; fi
            exec systemctl status "tayga-managed@$profile.service"
        fi
        ;;
    test) exec "$lib/tayga-verify" "/etc/tayga/$profile.conf" ;;
    reconfigure)
        [ "$(id -u)" -eq 0 ] || { echo 'Reconfiguration requires root' >&2; exit 1; }
        work=$(mktemp -d)
        trap 'rm -rf "$work"' 0
        config=/etc/tayga/$profile.conf
        field() { awk -v key="$1" '$1==key {print $2}' "$config"; }
        meta() { awk -v key="$1" '$1=="#" && $2==key {print $3}' "$config"; }
        PREF64=$(field prefix)
        TAYGA_IPV4=$(field ipv4-addr)
        TAYGA_IPV6=$(field ipv6-addr)
        DYNAMIC_POOL=$(field dynamic-pool)
        TUN_IPV6=$(awk '$1=="#" && $2=="installer-source6" {print $3}' "$config")
        CLAT_IPV6=$(awk '$1=="map" && $2=="192.0.0.1" {print $3}' "$config")
        MAP_IPV4=$(awk '$1=="map" {print $2}' "$config")
        MAP_IPV6=$(awk '$1=="map" {print $3}' "$config")
        OFFLINK_MTU=$(field offlink-mtu)
        TUN_OFFLOAD=$(field tun-offload)
        WORKERS=$(field workers)
        FIREWALL=$(meta installer-firewall)
        ENABLE_DNS64=$(meta installer-dns64)
        DNS64_LISTEN=$(meta installer-dns64-listen)
        DNS64_ALLOW=$(meta installer-dns64-allow)
        DNS64_UPSTREAM=$(meta installer-dns64-upstream)
        DNS64_DNSSEC=$(meta installer-dns64-dnssec)
        CLAT_ADDRESS_MODE=$(meta installer-clat-address-mode)
        NAT66_ADDRESS=$(meta installer-nat66-address)
        export CLAT_ADDRESS_MODE NAT66_ADDRESS
        HOST_DNS=$(meta installer-host-dns)
        export PREF64 TAYGA_IPV4 TAYGA_IPV6 DYNAMIC_POOL TUN_IPV6 CLAT_IPV6 MAP_IPV4 MAP_IPV6 OFFLINK_MTU TUN_OFFLOAD WORKERS
        export FIREWALL ENABLE_DNS64 DNS64_LISTEN DNS64_ALLOW DNS64_UPSTREAM DNS64_DNSSEC HOST_DNS
        MODE=$profile sh "$lib/wizard.sh" "$work/profile.conf"
        sh "$lib/tayga-lifecycle.sh" apply "$work/profile.conf"
        ;;
    uninstall) exec sh "$lib/tayga-lifecycle.sh" uninstall "$profile" ;;
    *) echo 'Unknown management action' >&2; exit 2 ;;
esac
