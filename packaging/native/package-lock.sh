#!/bin/sh
# APK does not abort unpacking on failed hooks. A virtual dependency pins the package.
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
state=/var/lib/tayga-installer
case "${1:-}" in
    lock)
        version=$(apk info -v | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p')
        case "$version" in ''|*[!0-9A-Za-z.+_~-]*) echo 'Cannot determine installed APK version' >&2; exit 1 ;; esac
        apk --no-network add --virtual .tayga-managed-profile "tayga-managed=$version"
        ;;
    unlock)
        is_package_upgrade=0
        if [ -d "$state/operation.lock" ] && [ -f "$state/operation.lock/package-upgrade" ]; then
            upg_pid=$(cat "$state/operation.lock/pid" 2>/dev/null || :)
            if [ -n "$upg_pid" ] && kill -0 "$upg_pid" 2>/dev/null; then
                is_package_upgrade=1
            fi
        elif [ "${TAYGA_PACKAGE_UPGRADE:-0}" = "1" ] || [ -f "$state/.package-upgrade" ]; then
            is_package_upgrade=1
        fi
        if [ "$is_package_upgrade" != 1 ]; then
            for profile in clat nat64 siit; do [ ! -f "$state/$profile.conf" ] || exit 0; done
        fi
        if apk info -e .tayga-managed-profile >/dev/null 2>&1; then apk --no-network del .tayga-managed-profile; fi
        ;;
    *) exit 2 ;;
esac
