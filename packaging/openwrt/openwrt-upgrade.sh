#!/bin/sh
# Coordinated replacement of the three OpenWrt packages; no firmware/feed upgrade.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
if [ "$(id -u)" != 0 ] || [ ! -f /etc/openwrt_release ]; then fail 'OpenWrt root required'; fi
# Keep the executing script outside files replaced by the package manager.
case "$0" in /var/run/tayga-managed/upgrade-worker.*) worker=$0 ;;
    *)
        mkdir -p /var/run/tayga-managed
        worker=$(mktemp /var/run/tayga-managed/upgrade-worker.XXXXXXXX)
        cp "$0" "$worker"; chmod 700 "$worker"
        exec sh "$worker" "$@"
        ;;
esac
trap 'rm -f "$worker"' 0
export LC_ALL=C
umask 077
state=/etc/tayga-managed
journal=$state/package-upgrade
service=/etc/init.d/tayga-managed
if [ -L "$state" ] || [ -L "$journal" ]; then fail 'Symlink state refused'; fi
mkdir -p "$state" /var/lock
exec 8> /var/lock/tayga-package-upgrade.lock
flock -n 8 || fail 'Another package operation is in progress'
stage=
stopped=0
state_locked=0
cleanup() {
    result=$?
    if [ "$state_locked" = 1 ]; then flock -u 9 || :; exec 9>&-; fi
    if [ -n "$stage" ]; then
        if [ "$stopped" = 1 ] && [ "$(cat "$stage/resume" 2>/dev/null || :)" = yes ]; then
            TAYGA_OPENWRT_UPGRADE=1 "$service" boot || :
        fi
        rm -rf "$stage"
    fi
    rm -f "$worker"
    exit "$result"
}
trap cleanup 0
if command -v opkg >/dev/null 2>&1; then manager=opkg; ext=ipk
else command -v apk >/dev/null 2>&1 || fail 'Package manager missing'; manager=apk; ext=apk; fi
trust=no
pkg_name() { case "$1" in base) echo tayga-managed-openwrt ;; *) echo "tayga-managed-openwrt-$1" ;; esac; }
metadata() {
    archive=$1
    [ -f "$archive" ] && [ ! -L "$archive" ] || return 1
    if [ "$manager" = opkg ]; then
        tar -xzOf "$archive" ./control.tar.gz | tar -xzOf - ./control
    else apk adbdump "$archive"; fi
}
field() {
    if [ "$manager" = opkg ]; then key=$1; else key=$2; fi
    awk -v key="$key:" '$1==key {print $2; exit}'
}
check_bundle() {
    bundle=$1; expected=${2:-}
    common=
    for role in base procd network; do
        meta=$(metadata "$bundle/$role.$ext") || fail "Unreadable $role archive"
        name=$(printf '%s\n' "$meta" | field Package name)
        version=$(printf '%s\n' "$meta" | field Version version)
        if [ "$name" != "$(pkg_name "$role")" ] || [ -z "$version" ]; then fail 'Wrong package identity'; fi
        case "$version" in *[!a-zA-Z0-9.+_~:-]*) fail 'Invalid package version' ;; esac
        [ -z "$common" ] || [ "$version" = "$common" ] || fail 'Mixed package revisions'
        common=$version
        if [ "$role" = procd ]; then
            printf '%s\n' "$meta" | grep -q 'tayga-openwrt-core-upgrade-api-1' || fail 'Core upgrade API 1 required'
        fi
        if [ "$expected" = installed ]; then
            if [ "$manager" = opkg ]; then
                installed=$(opkg status "$name")
                [ "$(printf '%s\n' "$installed" | field Version version)" = "$version" ] || fail 'Rollback version is not installed'
                printf '%s\n' "$installed" | grep -q '^Status:.* installed$' || fail 'Package is not installed'
            else apk info --exists "$name=$version" || fail 'Rollback version is not installed'; fi
        fi
    done
}
install_bundle() {
    bundle=$1; simulate=${2:-no}
    set -- "$bundle/base.$ext" "$bundle/procd.$ext" "$bundle/network.$ext"
    if [ "$manager" = opkg ]; then
        if [ "$simulate" = yes ]; then
            plan=$(opkg --noaction --force-downgrade --force-reinstall install "$@" 2>&1) || { printf '%s\n' "$plan"; return 1; }
            printf '%s\n' "$plan"
            printf '%s\n' "$plan" | awk '
                /^(Installing|Upgrading|Downgrading|Reinstalling|Removing) / {
                    name=($1=="Removing" && $2=="package") ? $3 : $2
                    if (name !~ /^tayga-managed-openwrt(-procd|-network)?$/) exit 1
                }' || return 1
        else opkg --force-downgrade --force-reinstall install "$@"; fi
    else
        [ "$trust" != yes ] || set -- --allow-untrusted "$@"
        [ "$simulate" != yes ] || set -- --simulate "$@"
        if [ "$simulate" = yes ]; then
            plan=$(apk --no-network --force-non-repository add --force-reinstall "$@" 2>&1) || { printf '%s\n' "$plan"; return 1; }
            printf '%s\n' "$plan"
            printf '%s\n' "$plan" | awk '
                /^\([0-9]+\/[0-9]+\)/ {
                    if ($3 !~ /^tayga-managed-openwrt(-procd|-network)?$/) exit 1
                }' || return 1
        else apk --no-network --force-non-repository add --force-reinstall "$@"; fi
    fi
}
check_journal() {
    [ -e "$journal" ] || return 1
    [ -d "$journal" ] || fail 'Invalid package upgrade journal'
    [ "$(cat "$journal/format")" = 1 ] || fail 'Unknown upgrade journal'
    [ "$(cat "$journal/manager")" = "$manager" ] || fail 'Package manager changed'
    trust=$(cat "$journal/trust")
    case "$trust" in yes|no) ;; *) fail 'Invalid signature policy' ;; esac
    (cd "$journal"; sha256sum -c SHA256SUMS) || fail 'Upgrade snapshot checksum mismatch'
}
stop_writer() {
    svc=$(ubus -t 2 call service list '{"name":"tayga-managed"}' 2>/dev/null || :)
    old_pid=$(jsonfilter -s "$svc" -e '@["tayga-managed"].instances.main.pid' 2>/dev/null || :)
    case "$old_pid" in ''|*[!0-9]*) old_pid= ;; esac
    ticks=
    [ -z "$old_pid" ] || ticks=$(awk '{print $22}' "/proc/$old_pid/stat" 2>/dev/null || :)
    if [ -x "$service" ]; then
        "$service" stop || return 1
    else
        # Cold recovery can run while the procd package files are absent.
        rm -f /var/run/tayga-managed/armed
        ubus -t 5 call service delete '{"name":"tayga-managed","instance":"main"}' >/dev/null 2>&1 || :
        [ ! -e /var/run/tayga-managed/network ] || return 1
    fi
    for _ in $(seq 1 25); do
        if [ -z "$old_pid" ] || [ -z "$ticks" ] ||
           [ "$(awk '{print $22}' "/proc/$old_pid/stat" 2>/dev/null || :)" != "$ticks" ]; then return 0; fi
        sleep 1
    done
    return 1
}
restore_files() {
    if [ -f "$journal/active.conf" ]; then
        cp "$journal/active.conf" "$state/active.conf.restored" || return 1
        mv -f "$state/active.conf.restored" "$state/active.conf" || return 1
    else rm -f "$state/active.conf" || return 1; fi
    cp "$journal/uci.conf" /etc/config/tayga_managed || return 1
    rm -rf "$state/data" || return 1
    if [ -f "$journal/data.tar.gz" ]; then tar -xzf "$journal/data.tar.gz" -C "$state" || return 1; fi
    sync
}
resume_service() {
    [ "$(cat "$journal/resume")" = yes ] || return 0
    TAYGA_OPENWRT_UPGRADE=1 "$service" boot || return 1
    [ -f /var/run/tayga-managed/armed ] || return 1
    uplink=$(uci -q get tayga_managed.main.uplink || :)
    if [ -n "$uplink" ]; then
        ready=0
        /usr/libexec/tayga/openwrt-uplink "$uplink" >/dev/null || ready=$?
        [ "$ready" != 3 ] || return 0
        [ "$ready" = 0 ] || return 1
    fi
    seen=
    for _ in $(seq 1 25); do
        svc=$(ubus -t 2 call service list '{"name":"tayga-managed"}' 2>/dev/null || :)
        pid=$(jsonfilter -s "$svc" -e '@["tayga-managed"].instances.main.pid' 2>/dev/null || :)
        if [ -n "$pid" ] && [ "$(jsonfilter -s "$svc" -e '@["tayga-managed"].instances.main.running' 2>/dev/null || :)" = true ]; then
            if [ "$pid" = "$seen" ] && [ "$(cat "/proc/$pid/comm" 2>/dev/null || :)" = tayga ]; then return 0; fi
            seen=$pid
        fi
        sleep 1
    done
    return 1
}
finish() {
    done_dir=$(mktemp -d "$state/package-finished.XXXXXXXX"); rmdir "$done_dir"
    mv "$journal" "$done_dir"; sync
    rm -rf "$done_dir"
}
recover() {
    check_journal || return 0
    stop_writer || return 1
    install_bundle "$journal/old" || return 1
    (check_bundle "$journal/old" installed) || return 1
    restore_files || return 1
    resume_service || return 1
    finish
    echo 'PASS: previous package set and accepted state restored'
}
action=${1:-}; [ "$#" = 0 ] || shift
case "$action" in
    recover)
        [ "$#" = 0 ] || fail 'Usage: openwrt-upgrade recover'
        recover
        ;;
    apply)
        [ "$#" = 2 ] || [ "$#" = 3 ] || fail 'Usage: openwrt-upgrade apply OLD_DIR NEW_DIR [--allow-untrusted]'
        if [ "$#" = 3 ]; then [ "$3" = --allow-untrusted ] || fail 'Unknown option'; trust=yes; fi
        [ ! -e "$journal" ] || fail 'Recover the pending package upgrade first'
        [ "$(cat /usr/libexec/tayga/package-upgrade-api)" = 1 ] || fail 'Upgrade-aware baseline required'
        old=$(CDPATH='' cd -- "$1" && pwd -P); new=$(CDPATH='' cd -- "$2" && pwd -P)
        check_bundle "$old" installed
        check_bundle "$new"
        stage=$(mktemp -d "$state/package-stage.XXXXXXXX")
        mkdir "$stage/old" "$stage/new"
        for role in base procd network; do
            cp "$old/$role.$ext" "$stage/old/$role.$ext"
            cp "$new/$role.$ext" "$stage/new/$role.$ext"
        done
        check_bundle "$stage/old" installed
        check_bundle "$stage/new"
        # Resolve both local sets before stopping traffic; only our packages may change.
        install_bundle "$stage/old" yes
        install_bundle "$stage/new" yes
        /usr/libexec/tayga/openwrt-state recover
        exec 9> /var/lock/tayga-managed.lock
        flock -n 9 || fail 'A profile operation is in progress'
        state_locked=1
        if [ -e "$state/previous.conf" ] || [ -e "$state/previous.none" ]; then
            fail 'Finish the pending profile transaction before package replacement'
        fi
        if [ ! -f /etc/config/tayga_managed ] || [ -L /etc/config/tayga_managed ]; then fail 'Regular UCI config required'; fi
        cp /etc/config/tayga_managed "$stage/uci.conf"
        if [ -e "$state/active.conf" ]; then
            if [ ! -f "$state/active.conf" ] || [ -L "$state/active.conf" ]; then fail 'Regular accepted snapshot required'; fi
            cp "$state/active.conf" "$stage/active.conf"
        fi
        echo no > "$stage/resume"
        [ ! -f /var/run/tayga-managed/armed ] || echo yes > "$stage/resume"
        stop_writer
        stopped=1
        # Snapshot data only after stopping its writer.
        if [ -e "$state/data" ]; then
            if [ ! -d "$state/data" ] || [ -L "$state/data" ]; then fail 'Regular data directory required'; fi
            tar -czf "$stage/data.tar.gz" -C "$state" data
        fi
        echo 1 > "$stage/format"; echo "$manager" > "$stage/manager"; echo "$trust" > "$stage/trust"
        (cd "$stage"; sha256sum old/* new/* uci.conf resume format manager trust > SHA256SUMS
         for file in active.conf data.tar.gz; do [ ! -f "$file" ] || sha256sum "$file" >> SHA256SUMS; done)
        sync; mv "$stage" "$journal"; stage=; sync
        flock -u 9; exec 9>&-; state_locked=0
        if install_bundle "$journal/new" &&
           (check_bundle "$journal/new" installed) &&
           [ "$(cat /usr/libexec/tayga/core-upgrade-api)" = 1 ] &&
           restore_files &&
           tayga --help >/dev/null &&
           pref64-discover --check 64:ff9b::192.0.0.170 >/dev/null &&
           { [ ! -f "$journal/active.conf" ] || tayga --check-config --config "$journal/active.conf"; } &&
           resume_service; then
            finish
            echo 'PASS: package set replaced; prior activation policy preserved'
        else
            echo 'ERROR: upgrade failed; restoring previous package set' >&2
            recover || { "$service" stop || :; fail 'Recovery failed; journal retained, service fenced'; }
            exit 1
        fi
        ;;
    *) fail 'Usage: openwrt-upgrade apply OLD_DIR NEW_DIR [--allow-untrusted] | recover' ;;
esac
