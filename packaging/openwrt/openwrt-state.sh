#!/bin/sh
# File-only publication/recovery. Never executes a stored journal or changes networking.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'OpenWrt state management requires root'
root=${TAYGA_TEST_ROOT:-}
[ -z "$root" ] || [ "${TAYGA_TESTING:-}" = 1 ] || fail 'Invalid test root'
state=$root/etc/tayga-managed
umask 077
[ ! -L "$state" ] || fail 'Persistent state must not be a symlink'
mkdir -p "$state" "$root/var/lock"
[ ! -L "$state/data" ] || fail 'Persistent data must not be a symlink'
chmod 700 "$state"
exec 9> "$root/var/lock/tayga-managed.lock"
flock -n 9 || fail 'Another OpenWrt state operation is in progress'
pending=$state/pending
active=$state/active.conf
finish_journal() {
    finished=$(mktemp -d "$state/finished.XXXXXXXX")
    rmdir "$finished"
    mv "$pending" "$finished"
    sync
    rm -rf "$finished"
}
recover() {
    [ ! -L "$pending" ] || fail 'Invalid pending snapshot'
    [ -d "$pending" ] || return 0
    [ "$(cat "$pending/ready")" = v1 ] || fail 'Incomplete recovery snapshot'
    case "$(cat "$pending/previous")" in
        yes)
            if [ ! -f "$pending/old.conf" ] || [ -L "$pending/old.conf" ]; then fail 'Missing previous configuration'; fi
            cp "$pending/old.conf" "$state/recover.conf"
            mv -f "$state/recover.conf" "$active"
            ;;
        no) rm -f "$active" ;;
        *) fail 'Invalid recovery metadata' ;;
    esac
    sync
    finish_journal
}
validate() {
    if [ ! -f "$1" ] || [ -L "$1" ]; then fail 'Missing regular configuration'; fi
    tayga --check-config --config "$1" >&2 || fail 'Configuration validation failed'
    device=$(awk '$1=="tun-device" {if (NF!=2 || seen++) exit 1; value=$2} END {print value}' "$1")
    case "$device" in ''|*[!a-zA-Z0-9_.-]*|????????????????*) fail 'Invalid TUN device' ;; esac
    if [ "$network_mode" = managed ]; then
        sh "$root/usr/libexec/tayga/openwrt-network" check "$1" || fail 'Invalid managed profile'
    else
        [ -f "$root/sys/class/net/$device/tun_flags" ] || fail 'External networking requires an existing TUN interface'
    fi
}
[ "$#" -ge 1 ] || exit 2
action=$1; shift
network_mode=external
case "$action:$#" in
    prepare:2) network_mode=$2; set -- "$1" ;;
    current:1) network_mode=$1; set -- ;;
    rollback:1) network_mode=$1; set -- ;;
esac
case "$network_mode" in external|managed) ;; *) exit 2 ;; esac
recover
case "$action" in
    recover) [ "$#" -eq 0 ] || exit 2 ;;
    commit)
        [ "$#" -eq 0 ] || exit 2
        rm -f "$state/previous.conf" "$state/previous.none"
        ;;
    rollback)
        [ "$#" -eq 0 ] || exit 2
        if [ -f "$state/previous.conf" ] && [ ! -L "$state/previous.conf" ]; then
            cp "$state/previous.conf" "$state/recover.conf"
            mv -f "$state/recover.conf" "$active"
            rm -f "$state/previous.conf" "$state/previous.none"
            sync
            printf '%s\n' "$active"
        elif [ -f "$state/previous.none" ]; then
            rm -f "$active" "$state/previous.conf" "$state/previous.none"
            sync
        elif [ -f "$active" ] && [ ! -L "$active" ]; then
            printf '%s\n' "$active"
        fi
        ;;
    current)
        [ "$#" -eq 0 ] || exit 2
        validate "$active"
        printf '%s\n' "$active"
        ;;
    prepare)
        [ "$#" -eq 1 ] || exit 2
        candidate=$1
        [ "${candidate%/*}" = "$root/etc/tayga" ] || fail 'Candidate must be directly inside /etc/tayga'
        if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then fail 'Candidate must be a regular file'; fi
        [ "$(wc -c < "$candidate")" -le 65536 ] || fail 'Candidate exceeds 64 KiB'
        work=$(mktemp -d "$state/stage.XXXXXXXX")
        trap 'rm -rf "$work"' 0
        trap 'exit 1' HUP INT TERM
        # No mutable map-file input: snapshots must contain their complete maps.
        awk -v data="$state/data" -v managed="$network_mode" '
            $1=="map-file" {exit 1}
            $1=="data-dir" {if (seen++) exit 1; next}
            $1=="tun-device" && managed=="managed" {$2="tmg0"}
            {print}
            END {print "data-dir " data}
        ' "$candidate" > "$work/candidate" || fail 'Duplicate data-dir or external map-file'
        validate "$work/candidate"
        [ ! -L "$active" ] || fail 'Active snapshot must not be a symlink'
        if [ -f "$active" ] && cmp -s "$active" "$work/candidate"; then
            printf '%s\n' "$active"
            exit 0
        fi
        if [ "$network_mode" = managed ] && [ -d "$root/var/run/tayga-managed/network" ] && [ "${TAYGA_MANAGED_SWITCH:-}" != 1 ]; then
            fail 'Stop the managed service before changing its profile'
        fi
        has_valid_prev=0
        if [ -f "$active" ]; then
            cp "$active" "$work/old.conf"
            echo yes > "$work/previous"
            if [ "$network_mode" != managed ] || "$root/usr/libexec/tayga/openwrt-network" check "$active" >/dev/null 2>&1; then
                has_valid_prev=1
            fi
        else
            echo no > "$work/previous"
        fi
        if [ "$has_valid_prev" = 1 ]; then
            cp "$active" "$state/previous.conf.tmp"
            mv -f "$state/previous.conf.tmp" "$state/previous.conf"
            rm -f "$state/previous.none"
        else
            rm -f "$state/previous.conf"
            : > "$state/previous.none"
        fi
        echo v1 > "$work/ready"
        mkdir -p "$state/data"
        sync
        mv "$work" "$pending"
        sync
        mv "$pending/candidate" "$active"
        sync
        finish_journal
        printf '%s\n' "$active"
        ;;
    *) exit 2 ;;
esac
