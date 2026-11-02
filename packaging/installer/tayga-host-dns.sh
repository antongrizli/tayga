#!/bin/sh
# Public CLAT DNS on an owned TUN link; global resolver files stay untouched.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'Usage: tayga-host-dns prepare|up|down CONFIG'
action=$1
config=$2
profile=$(awk '$1=="#" && $2=="installer-mode" {print $3}' "$config")
if [ -z "$profile" ]; then
    profile=$(awk '$1=="tun-device" {print $2}' "$config")
fi
case "$profile" in clat|nat64|siit) ;; *) fail 'Invalid host DNS profile' ;; esac
runtime=${TAYGA_HOST_DNS_RUNTIME:-/run/tayga-managed-$profile}
case "$runtime" in /*) ;; *) fail 'Runtime path must be absolute' ;; esac
marker=$runtime/host-dns
resolv_conf=${TAYGA_TEST_RESOLV_CONF:-/etc/resolv.conf}
persistent=${TAYGA_HOST_DNS_STATE:-/var/lib/tayga-installer/host-dns-file}
case "$persistent" in /*) ;; *) fail 'DNS state path must be absolute' ;; esac
nm_api() {
    busctl --system --timeout=10 call "$nm_owner" /org/freedesktop/NetworkManager org.freedesktop.NetworkManager "$@"
}
undo() {
    if [ -f "$marker" ]; then backend=$(cat "$marker")
    elif [ -f "$persistent/profile" ] && [ "$(cat "$persistent/profile")" = "$profile" ]; then backend="file"
    else return 0
    fi
    case "$backend" in
        file)
            if ! cmp -s "$resolv_conf" "$persistent/expected" && ! cmp -s "$resolv_conf" "$persistent/original"; then fail 'Resolver file was edited; DNS backup retained'; fi
            cp -p "$persistent/original" "$resolv_conf.tayga-restore"
            mv -f "$resolv_conf.tayga-restore" "$resolv_conf"
            sync
            rm -rf "$persistent"
            ;;
        nm)
            nm_owner=$(cat "$runtime/nm.owner")
            checkpoint=$(cat "$runtime/nm.checkpoint")
            case "$nm_owner" in :[0-9]*.[0-9]*) ;; *) fail 'Invalid NetworkManager owner' ;; esac
            case "$checkpoint" in /org/freedesktop/NetworkManager/Checkpoint/[0-9]*) ;; *) fail 'Invalid NetworkManager checkpoint' ;; esac
            if busctl --system --timeout=10 status "$nm_owner" >/dev/null 2>&1; then
                result=$(nm_api CheckpointRollback o "$checkpoint")
                # a{su}: exactly one device, return code 0 (success) or 1 (gone).
                case "$result" in *' 0'|*' 1') ;; *) fail 'NetworkManager rollback failed; checkpoint retained' ;; esac
            fi
            rm -f "$runtime/nm.owner" "$runtime/nm.checkpoint"
            ;;
        resolvconf) resolvconf -d "$profile.tayga" ;;
        *) if ip link show dev "$profile" >/dev/null 2>&1; then resolvectl revert "$profile"; fi ;;
    esac
    rm -f "$marker"
}
[ "$(id -u)" -eq 0 ] || fail 'Host DNS management requires root'
if [ "$action" = down ]; then undo; exit; fi
policy=$(awk '$1=="#" && $2=="installer-host-dns" {print $3}' "$config")
case "${policy:-keep}" in keep) exit ;; public|public-resolvconf|public-file|public-nm) ;; *) fail 'Invalid host DNS policy' ;; esac
[ "$profile" = clat ] || fail 'Public host DNS is available for CLAT'
case "$action" in prepare|up) ;; *) fail 'Unknown host DNS operation' ;; esac
if [ "$policy" = public-nm ]; then
    for tool in nmcli busctl; do command -v "$tool" >/dev/null || fail "$tool is required"; done
    nm_owner=$(busctl --system --timeout=10 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s org.freedesktop.NetworkManager | cut -d '"' -f 2)
    [ "$action" = up ] || exit 0
    [ "$(nmcli -g GENERAL.STATE device show "$profile" | cut -d ' ' -f 1)" = 100 ] || fail 'CLAT must already be active in NetworkManager'
    device=$(nmcli -g GENERAL.DBUS-PATH device show "$profile")
    case "$device" in /org/freedesktop/NetworkManager/Devices/[0-9]*) ;; *) fail 'Invalid NetworkManager device path' ;; esac
    umask 077
    mkdir -p "$runtime"
    [ ! -L "$runtime" ] || fail 'Runtime directory must not be a symlink'
    [ ! -e "$marker" ] || fail 'DNS operation is already active'
    printf '%s\n' "$nm_owner" > "$runtime/nm.owner"
    checkpoint=$(nm_api CheckpointCreate aouu 1 "$device" 0 0 | cut -d '"' -f 2)
    printf '%s\n' "$checkpoint" > "$runtime/nm.checkpoint"
    printf 'nm\n' > "$marker"
    complete=no
    trap 'if [ "$complete" != yes ]; then undo; fi' 0
    trap 'exit 1' HUP INT TERM
    nmcli --wait 10 device modify "$profile" ipv4.dns '1.1.1.1 8.8.8.8' ipv4.ignore-auto-dns yes ipv4.dns-priority -50 ipv4.dns-search '~.'
    ready=no
    for _ in 1 2 3; do
        servers=$(nmcli -g IP4.DNS device show "$profile" | tr '|' '\n' | awk '{$1=$1; print}')
        if printf '%s\n' "$servers" | grep -Fx 1.1.1.1 >/dev/null && printf '%s\n' "$servers" | grep -Fx 8.8.8.8 >/dev/null; then ready=yes; break; fi
        sleep 1
    done
    [ "$ready" = yes ] || fail 'NetworkManager DNS did not become active'
    complete=yes
    exit 0
fi
if [ "$policy" = public-resolvconf ] || [ "$policy" = public-file ]; then
    if [ "$policy" = public-resolvconf ]; then
        command -v resolvconf >/dev/null || fail 'resolvconf is required'
    else
        boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || sysctl -n kern.boottime)
        if [ -f "$persistent/boot" ] && [ "$(cat "$persistent/boot")" != "$boot" ]; then undo; fi
        if [ ! -f "$resolv_conf" ] || [ -L "$resolv_conf" ]; then fail 'Direct DNS requires a regular resolver file'; fi
        if [ -e "$persistent" ] || [ -L "$persistent" ]; then
            if [ "$action" = prepare ] && [ -f "$marker" ] && [ "$(cat "$marker")" = file ] &&
                [ "$(cat "$persistent/profile")" = "$profile" ] && cmp -s "$resolv_conf" "$persistent/expected"; then exit 0; fi
            fail 'A direct DNS transaction is pending'
        fi
    fi
    [ "$action" = up ] || exit 0
    umask 077
    mkdir -p "$runtime"
    [ ! -L "$runtime" ] || fail 'Runtime directory must not be a symlink'
    if [ "$policy" = public-resolvconf ]; then
        printf 'resolvconf\n' > "$marker"
        printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | resolvconf -a "$profile.tayga"
    else
        mkdir -p "$(dirname "$persistent")"
        mkdir "$persistent"
        printf '%s\n' "$boot" > "$persistent/boot"
        cp -p "$resolv_conf" "$persistent/original"
        printf '%s\n' "$profile" > "$persistent/profile"
        printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$persistent/expected"
        printf 'file\n' > "$marker"
        cp "$persistent/expected" "$resolv_conf.tayga-new"
        sync
        mv -f "$resolv_conf.tayga-new" "$resolv_conf"
    fi
    exit 0
fi
command -v resolvectl >/dev/null || fail 'Public host DNS requires systemd-resolved/resolvectl; use --host-dns=keep otherwise'
# A successful resolvectl query is not enough if applications bypass the stub.
awk '$1=="nameserver" {found=1;valid=($2=="127.0.0.53");exit} END {exit !(found && valid)}' "$resolv_conf" || fail 'Applications must already use the systemd-resolved stub; resolver files are preserved'
resolvectl status >/dev/null
[ "$action" = up ] || exit 0
ip link show dev "$profile" >/dev/null
umask 077
mkdir -p "$runtime"
[ ! -L "$runtime" ] || fail 'Runtime directory must not be a symlink'
: > "$marker"
complete=no
cleanup() { if [ "$complete" != yes ]; then undo; fi; }
trap cleanup 0
trap 'exit 1' HUP INT TERM
resolvectl dns "$profile" 1.1.1.1 8.8.8.8
resolvectl domain "$profile" '~.'
resolvectl default-route "$profile" yes
resolvectl --interface="$profile" --protocol=dns --type=A query ipv4only.arpa >/dev/null
complete=yes
echo '[PASS] Public CLAT DNS configured on the owned resolver link'
