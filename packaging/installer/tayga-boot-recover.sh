#!/bin/sh
# Early boot: restore persistent state without replaying a previous kernel's journal.
set -eu
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/sbin:/bin:/usr/sbin:/usr/bin}:/usr/local/sbin:/usr/local/bin"; export PATH ;; esac
root=${TAYGA_TEST_ROOT:-}
[ -z "$root" ] || [ "${TAYGA_TESTING:-}" = 1 ] || exit 1
state=$root/var/lib/tayga-installer
tx=$state/files-transaction
gate=$state/operation.lock
if [ -d "$state/package-upgrade" ]; then
    # Native systemd package transactions may invoke distribution triggers that
    # require basic.target (e.g. man-db/systemd-run). The separate package unit
    # runs after basic boot and remains a prerequisite of the managed service.
    if [ -d "$root/run/systemd/system" ] && [ -f "$root/usr/lib/systemd/system/tayga-package-recovery.service" ]; then
        exit 0
    fi
    TAYGA_BOOT_RECOVERY=1
    export TAYGA_BOOT_RECOVERY
    lib=$root/usr/local/libexec/tayga
    [ -d "$lib" ] || lib=$root/usr/libexec/tayga
    if [ -f "$lib/tayga-package-upgrade" ]; then
        sh "$lib/tayga-package-upgrade" recover || exit 1
    elif [ -f "$lib/tayga-package-upgrade.sh" ]; then
        sh "$lib/tayga-package-upgrade.sh" recover || exit 1
    elif [ -f "$state/package-upgrade/worker.sh" ]; then
        sh "$state/package-upgrade/worker.sh" recover || exit 1
    else
        echo 'ERROR: Pending package upgrade journal exists but no recovery helper found' >&2
        exit 1
    fi
fi
if [ -d "$tx" ] && [ ! -f "$gate/transaction" ]; then
    if [ -f "$tx/files.sh" ]; then
        sh "$tx/files.sh" rollback || :
    elif [ -f "$root/usr/local/libexec/tayga/tayga-files.sh" ]; then
        sh "$root/usr/local/libexec/tayga/tayga-files.sh" rollback || :
    fi
fi
[ -f "$gate/transaction" ] || exit 0
session=$(cat "$gate/transaction")
case "$session" in session.token.*) ;; *) exit 2 ;; esac
case "$session" in *[!a-zA-Z0-9._-]*) exit 2 ;; esac
lock=$gate/$session
[ -f "$lock/boot.id" ] || exit 1
# Starting the recovery dependency during a live activation must be a no-op.
current_boot=
if [ -r /proc/sys/kernel/random/boot_id ]; then
    current_boot=$(cat /proc/sys/kernel/random/boot_id)
elif [ "$(uname -s)" = FreeBSD ]; then
    current_boot=$(sysctl -n kern.boottime 2>/dev/null | awk '{print $4,$7}')
fi
[ -z "$current_boot" ] || [ "$(cat "$lock/boot.id")" != "$current_boot" ] || exit 0
exec sh "$lock/recover.sh" "$lock" "$(cat "$lock/id")" boot
