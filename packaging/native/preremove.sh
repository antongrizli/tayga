#!/bin/sh
set -eu
state=/var/lib/tayga-installer
case "${1:-}" in
    upgrade) exit 0 ;;
esac
if [ "${1:-0}" -ge 1 ] 2>/dev/null; then
    exit 0
fi

is_package_upgrade=0
if [ -d "$state/operation.lock" ] && [ -f "$state/operation.lock/package-upgrade" ]; then
    upg_pid=$(cat "$state/operation.lock/pid" 2>/dev/null || :)
    if [ -n "$upg_pid" ] && kill -0 "$upg_pid" 2>/dev/null; then
        is_package_upgrade=1
    fi
fi

if [ "$is_package_upgrade" = 1 ]; then
    exit 0
fi
for profile in clat nat64 siit; do
    if [ -f "$state/$profile.conf" ]; then
        echo 'Remove managed profiles with tayga-ctl before removing/upgrading the package' >&2
        exit 1
    fi
done
if [ -d "$state/operation.lock" ] || [ -d "$state/files-transaction" ]; then
    echo 'An installer transaction is pending; recover it before package removal' >&2
    exit 1
fi
