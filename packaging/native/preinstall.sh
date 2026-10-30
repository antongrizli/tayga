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
for path in "$state/files" "$state/files-transaction" "$state/operation.lock" /usr/local/sbin/tayga; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        echo "Cannot mix native package and SFX/manual installation: $path" >&2
        exit 1
    fi
done
if [ "${TAYGA_PACKAGE_UPGRADE:-}" != 1 ] && [ ! -f "$state/.package-upgrade" ]; then
    for profile in clat nat64 siit; do
        if [ -f "$state/$profile.conf" ]; then
            echo 'Remove managed profiles with tayga-ctl before package upgrade, or use tayga-ctl upgrade <package>' >&2
            exit 1
        fi
    done
fi
