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
        for profile in clat nat64 siit; do [ ! -f "$state/$profile.conf" ] || exit 0; done
        if apk info -e .tayga-managed-profile >/dev/null 2>&1; then apk --no-network del .tayga-managed-profile; fi
        ;;
    *) exit 2 ;;
esac
