#!/bin/sh
# Coordinated live upgrade of native Linux packages (deb, rpm, apk)
# Preserves active managed profiles, verifies readiness, and handles package locks.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'Root required for package upgrade'
[ "$#" -ge 1 ] || fail 'Usage: tayga-package-upgrade apply PACKAGE_FILE'
action=$1; shift
[ "$action" = apply ] || fail "Unknown action: $action"
[ "$#" -eq 1 ] || fail 'Package file required'
pkg=$1
[ -f "$pkg" ] || fail "Package file not found: $pkg"

state=/var/lib/tayga-installer
lib=/usr/local/libexec/tayga
[ -d "$lib" ] || lib=/usr/libexec/tayga
gate=$state/operation.lock
[ ! -d "$gate" ] && [ ! -d "$state/files-transaction" ] || fail 'Another profile operation is in progress'

case "$pkg" in
    *.deb) kind=deb ;;
    *.rpm) kind=rpm ;;
    *.apk) kind=apk ;;
    *) fail 'Unsupported package format; expected .deb, .rpm, or .apk' ;;
esac

# Identify active profile and service state
active=
if [ -f "$state/current" ]; then
    active=$(cat "$state/current")
else
    for mode in clat nat64 siit; do
        if [ -f "$state/$mode.conf" ]; then
            active=$mode
            break
        fi
    done
fi

was_active=no
if [ -n "$active" ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active "tayga-managed@$active" >/dev/null 2>&1; then was_active=yes; fi
    elif [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1; then
        if rc-service tayga-managed status >/dev/null 2>&1; then was_active=yes; fi
    fi
fi

# Perform coordinated installation
export TAYGA_PACKAGE_UPGRADE=1
mkdir -p "$state"
touch "$state/.package-upgrade"
cleanup_flag() { rm -f "$state/.package-upgrade"; }
trap cleanup_flag EXIT HUP INT TERM

# Unlock solver pin if on Alpine APK
if [ "$kind" = apk ] && [ -f "$lib/package-lock.sh" ]; then
    sh "$lib/package-lock.sh" unlock || :
fi

upgrade_ok=yes
case "$kind" in
    deb) dpkg --force-confold -i "$pkg" || upgrade_ok=no ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$pkg" || upgrade_ok=no
        elif command -v rpm >/dev/null 2>&1; then
            rpm -U --replacepkgs "$pkg" || upgrade_ok=no
        else
            fail 'RPM package manager not found'
        fi
        ;;
    apk) apk add --allow-untrusted --force-non-repository "$pkg" || upgrade_ok=no ;;
esac

if [ "$upgrade_ok" != yes ]; then
    if [ "$kind" = apk ] && [ -f "$lib/package-lock.sh" ] && [ -n "$active" ]; then
        sh "$lib/package-lock.sh" lock || :
    fi
    fail "Package manager failed to install $pkg"
fi

# If a managed profile was active, restart and verify it with the new binary
if [ "$was_active" = yes ] && [ -n "$active" ] && [ -f "$state/$active.conf" ]; then
    echo "Restarting active profile $active after package upgrade..."
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || :
        systemctl restart "tayga-managed@$active" || fail "Failed to restart tayga-managed@$active"
    elif [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1; then
        rc-service tayga-managed restart || fail 'Failed to restart tayga-managed'
    fi
    if [ -x "$lib/tayga-verify" ]; then
        "$lib/tayga-verify" "$state/$active.conf" || fail "Readiness verification failed after upgrade for $active"
    elif [ -f "$lib/tayga-verify.sh" ]; then
        sh "$lib/tayga-verify.sh" "$state/$active.conf" || fail "Readiness verification failed after upgrade for $active"
    fi
fi

# Restore solver pin if on Alpine APK
if [ "$kind" = apk ] && [ -f "$lib/package-lock.sh" ] && [ -n "$active" ]; then
    sh "$lib/package-lock.sh" lock || :
fi

rm -f "$state/.package-upgrade"
trap - EXIT HUP INT TERM

echo "PASS: Coordinated live package upgrade successful ($pkg)"
