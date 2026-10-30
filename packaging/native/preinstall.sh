#!/bin/sh
set -eu
if [ -f /etc/openwrt_release ]; then
    echo 'Use the target-matched OpenWrt SDK package; generic Linux packages are unsupported' >&2
    exit 1
fi
state=/var/lib/tayga-installer
if { [ -e /usr/sbin/tayga ] || [ -L /usr/sbin/tayga ]; } && [ ! -f /usr/libexec/tayga/package-owner ]; then
    echo 'An unmanaged or distribution TAYGA binary exists; migrate it first' >&2
    exit 1
fi

is_package_upgrade=0
if [ -d "$state/operation.lock" ] && [ -f "$state/operation.lock/package-upgrade" ]; then
    upg_pid=$(cat "$state/operation.lock/pid" 2>/dev/null || :)
    if [ -n "$upg_pid" ] && kill -0 "$upg_pid" 2>/dev/null; then
        is_package_upgrade=1
    fi
elif [ "${TAYGA_PACKAGE_UPGRADE:-}" = 1 ] && [ -f "$state/.package-upgrade" ]; then
    is_package_upgrade=1
fi

if [ "$is_package_upgrade" = 0 ]; then
    for path in "$state/files" "$state/files-transaction" "$state/operation.lock" /usr/local/sbin/tayga; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            echo "Cannot mix native package and SFX/manual installation: $path" >&2
            exit 1
        fi
    done
    for profile in clat nat64 siit; do
        if [ -f "$state/$profile.conf" ]; then
            echo 'Remove managed profiles with tayga-ctl before package upgrade, or use tayga-ctl upgrade <package>' >&2
            exit 1
        fi
    done
else
    for path in "$state/files" "$state/files-transaction" /usr/local/sbin/tayga; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            echo "Cannot mix native package and SFX/manual installation: $path" >&2
            exit 1
        fi
    done
fi
