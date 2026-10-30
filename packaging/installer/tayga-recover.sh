#!/bin/sh
# Shared recovery path for EXIT traps and the independent watchdog.
set -eu
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/sbin:/bin:/usr/sbin:/usr/bin}:/usr/local/sbin:/usr/local/bin"; export PATH ;; esac
case "$#:${3:-}" in 2:|3:locked|3:boot|4:boot|4:locked) ;; *) exit 2 ;; esac
lock=$1
transaction=$2
[ "$(id -u)" -eq 0 ] || exit 1
root=${TAYGA_TEST_ROOT:-}
[ -z "$root" ] || [ "${TAYGA_TESTING:-}" = 1 ] || exit 1
state=$root/var/lib/tayga-installer
gate=$state/operation.lock
case "$lock" in "$gate"/session.token.*) ;; *) exit 2 ;; esac
case "${lock#"$gate/"}" in */*) exit 2 ;; esac
[ -f "$lock/id" ] && [ "$(cat "$lock/id")" = "$transaction" ] || exit 0
boot=no
[ "${3:-}" != boot ] || boot=yes
current_boot=
if [ -r /proc/sys/kernel/random/boot_id ]; then
    current_boot=$(cat /proc/sys/kernel/random/boot_id)
elif [ "$(uname -s)" = FreeBSD ]; then
    current_boot=$(sysctl -n kern.boottime 2>/dev/null | awk '{print $4,$7}')
fi
if [ "$boot" = yes ]; then
    identity=$root/etc/machine-id
    [ -s "$identity" ] || identity=$root/etc/hostid
    [ -s "$identity" ] || identity=$state/host.id
    if [ ! -s "$lock/machine.id" ] || ! cmp -s "$lock/machine.id" "$identity"; then
        echo 'Recovery belongs to another machine; backups retained' >&2; exit 1
    fi
    if [ -n "$current_boot" ]; then
        [ "$current_boot" != "$(cat "$lock/boot.id")" ] || exit 1
    fi
elif [ -f "$lock/boot.id" ] && [ -n "$current_boot" ]; then
    if [ "$current_boot" != "$(cat "$lock/boot.id")" ] ||
        [ "$(readlink /proc/self/ns/pid 2>/dev/null || :)" != "$(cat "$lock/pid.namespace" 2>/dev/null || :)" ] ||
        [ "$(readlink /proc/self/ns/net 2>/dev/null || :)" != "$(cat "$lock/net.namespace" 2>/dev/null || :)" ]; then
        echo 'Recovery belongs to another boot/namespace; backups retained for manual review' >&2
        exit 1
    fi
fi
if [ "$#" -eq 2 ] || { [ "$boot" = yes ] && [ "$#" -eq 3 ]; }; then
    if [ "$boot" = yes ]; then mode=boot; else mode=locked; fi
    # Kernel locks are released on SIGKILL and reboot.
    if command -v flock >/dev/null 2>&1; then
        if flock -n "$lock/recovery.flock" sh "$0" "$lock" "$transaction" "$mode" locked; then exit 0; fi
    elif command -v lockf >/dev/null 2>&1; then
        if lockf -s -t 0 "$lock/recovery.flock" sh "$0" "$lock" "$transaction" "$mode" locked; then exit 0; fi
    fi
    echo 'Recovery incomplete or already in progress; transaction backups retained' >&2
    exit 1
fi
profile=$(cat "$lock/profile")
old=$(cat "$lock/old")
init=$(cat "$lock/init")
case "$profile" in clat|nat64|siit) ;; *) exit 2 ;; esac
case "$old" in ''|clat|nat64|siit) ;; *) exit 2 ;; esac
case "$init" in systemd|openrc|freebsd_rc) ;; *) exit 2 ;; esac
service() {
    if [ "$init" = systemd ]; then timeout -k 5 30 systemctl "$1" "tayga-managed@$2.service"
    elif [ "$init" = openrc ]; then
        case "$1" in
            enable) timeout -k 5 30 rc-update add tayga-managed default ;;
            disable) timeout -k 5 30 rc-update del tayga-managed default ;;
            is-enabled) timeout -k 5 30 rc-update show default | awk '$1=="tayga-managed" {found=1} END {exit !found}' ;;
            *) timeout -k 5 30 rc-service tayga-managed "$1" ;;
        esac
    else
        case "$1" in
            enable) sysrc -f "$root/etc/rc.conf.d/tayga_managed" tayga_managed_enable=YES ;;
            disable) sysrc -f "$root/etc/rc.conf.d/tayga_managed" tayga_managed_enable=NO ;;
            is-enabled)
                val=$(sysrc -f "$root/etc/rc.conf.d/tayga_managed" -n tayga_managed_enable 2>/dev/null || echo NO)
                case "$val" in [Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac ;;
            *) command service tayga-managed "one$1" ;;
        esac
    fi
}
process_group() {
    if [ -d /proc/self ]; then
        [ -r "/proc/$1/stat" ] || return 1
        awk '{print $5}' "/proc/$1/stat"
    else ps -p "$1" -o pgid= 2>/dev/null | tr -d ' '
    fi
}
finish() {
    if [ -f "$lock/package-lock.sh" ]; then timeout -k 2 30 sh "$lock/package-lock.sh" unlock; fi
    # Do not signal ourselves when recovery is running in the guard's session.
    if [ "$boot" = no ] && [ -f "$lock/watcher.pid" ]; then
        watcher=$(cat "$lock/watcher.pid")
        case "$watcher" in ''|*[!0-9]*) exit 2 ;; esac
        current_group=$(process_group "$$")
        if [ "$current_group" != "$watcher" ] && [ "$(process_group "$watcher" || :)" = "$watcher" ]; then
            if [ -r "/proc/$watcher/stat" ]; then current_start=$(awk '{print $22}' "/proc/$watcher/stat")
            else current_start=$(LC_ALL=C ps -p "$watcher" -o lstart= 2>/dev/null || :)
            fi
            if [ "$current_start" = "$(cat "$lock/watcher.start")" ]; then kill -TERM "-$watcher" 2>/dev/null || :; fi
        fi
    fi
    # Atomic retirement makes a killed cleanup safe to resume and prevents an
    # old guard from observing a later transaction at operation.lock.
    complete=$(mktemp -d "$state/completed.XXXXXXXX")
    rmdir "$complete"
    sync
    mv "$gate" "$complete"
    sync
    rm -rf "$complete"
}
# The decision is an atomically published, immutable file, not shell code.
if [ "$(cat "$lock/decision" 2>/dev/null || :)" = commit ]; then
    if [ -f "$lock/files.id" ]; then sh "$lock/files.sh" commit "$(cat "$lock/files.id")"; fi
    finish
    exit 0
fi
if [ ! -f "$lock/mutating" ]; then
    # Arming failed or was interrupted before the first service/network change.
    if [ -f "$lock/files.id" ]; then sh "$lock/files.sh" rollback "$(cat "$lock/files.id")"; fi
    finish
    exit 0
fi
echo "Rolling back TAYGA transaction $transaction" >&2
if [ "$boot" = no ]; then
    service stop "$profile" || :
    # Run owned cleanup directly too: a failed init stop must not strand routes.
    for helper in dns64 host-dns net; do
        timeout -k 2 15 sh "$lock/$helper.sh" down "$lock/candidate"
    done
elif [ "$init" = systemd ]; then
    # Cancel any candidate job already queued by the boot target. Never wait
    # for a unit ordered after this recovery service.
    timeout -k 5 30 systemctl --no-block stop "tayga-managed@$profile.service"
fi
if service is-enabled "$profile" >/dev/null 2>&1; then service disable "$profile"; fi
target=$root/etc/tayga/$profile.conf
if [ "$init" = systemd ]; then unit=$root/etc/systemd/system/tayga-managed@.service
elif [ "$init" = openrc ]; then unit=$root/etc/init.d/tayga-managed
else unit=$root/usr/local/etc/rc.d/tayga-managed
fi
restore() {
    backup=$1
    destination=$2
    if [ -f "$backup" ]; then
        cp -p "$backup" "$destination.recover"
        mv -f "$destination.recover" "$destination"
    else rm -f "$destination"
    fi
}
restore "$lock/config.old" "$target"
restore "$lock/unit.old" "$unit"
if [ "$init" = openrc ]; then restore "$lock/extra.old" "$root/etc/conf.d/tayga-managed"; fi
if [ "$init" = freebsd_rc ]; then restore "$lock/extra.old" "$root/etc/rc.conf.d/tayga_managed"; fi
if [ "$init" = systemd ]; then recovery_unit=$root/etc/systemd/system/tayga-recovery.service
elif [ "$init" = openrc ]; then recovery_unit=$root/etc/init.d/tayga-recovery
else recovery_unit=$root/usr/local/etc/rc.d/tayga-recovery
fi
if [ "$(cat "$lock/recovery.enabled")" = no ]; then
    if [ "$init" = systemd ]; then timeout -k 5 30 systemctl disable tayga-recovery.service
    elif [ "$init" = openrc ]; then timeout -k 5 30 rc-update del tayga-recovery boot
    else sysrc -f "$root/etc/rc.conf.d/tayga_recovery" tayga_recovery_enable=NO
    fi
fi
restore "$lock/recovery.old" "$recovery_unit"
for saved in current clat.conf nat64.conf siit.conf unit openrc-env rc-conf-d recovery-unit; do
    restore "$lock/metadata/$saved" "$state/$saved"
done
if [ -f "$lock/files.id" ]; then sh "$lock/files.sh" rollback "$(cat "$lock/files.id")"; fi
if [ "$init" = systemd ]; then timeout -k 5 30 systemctl daemon-reload; fi
if [ -n "$old" ]; then
    if [ "$(cat "$lock/was_enabled")" = yes ]; then service enable "$old"; fi
    if [ "$boot" = yes ]; then
        if [ "$init" = systemd ] && [ "$(cat "$lock/was_enabled")" = yes ]; then
            timeout -k 5 30 systemctl --no-block start "tayga-managed@$old.service"
        fi
    elif [ "$(cat "$lock/was_active")" = yes ]; then service start "$old"; fi
fi
printf 'recovered\n' > "$lock/result"
echo "Recovered previous TAYGA configuration ($transaction)" >&2
finish
