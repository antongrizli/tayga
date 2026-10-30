#!/bin/sh
# Coordinated transactional live upgrade of native Linux packages (deb, rpm, apk)
# Preserves active managed profiles, verifies readiness, and guarantees durable rollback.
set -eu

fail() { echo "ERROR: $*" >&2; exit 1; }
root=${TAYGA_TEST_ROOT:-}
[ -z "$root" ] || [ "${TAYGA_TESTING:-}" = 1 ] || fail 'Testing override disabled'
[ "$(id -u)" -eq 0 ] || [ -n "$root" ] || fail 'Root required for package upgrade'

# Ensure the coordinator executes outside replaced package directories
case "$0" in */upgrade-worker.*) worker=$0 ;;
    *)
        workdir=${root}/var/run/tayga-installer
        mkdir -p "$workdir"
        worker=$(mktemp "$workdir/upgrade-worker.XXXXXXXX")
        cp "$0" "$worker"; chmod 700 "$worker"
        exec sh "$worker" "$@"
        ;;
esac

action=${1:-}
shift || fail 'Usage: tayga-package-upgrade apply PACKAGE_FILE [OPTIONS] | recover'

state=$root/var/lib/tayga-installer
lib=$root/usr/local/libexec/tayga
[ -d "$lib" ] || lib=$root/usr/libexec/tayga
gate=$state/operation.lock
journal=$state/package-upgrade
lock_held=0

cleanup_lock() {
    rc=$?
    if [ "$lock_held" = 1 ]; then
        rm -rf "$gate" || :
    fi
    rm -f "$worker" || :
    exit "$rc"
}
trap cleanup_lock EXIT
trap 'exit 1' HUP INT TERM

if [ "$action" = recover ]; then
    [ -d "$journal" ] || { echo 'No pending package upgrade journal'; exit 0; }
    status=$(cat "$journal/status" 2>/dev/null || echo unknown)
    if [ "$status" = committed ]; then
        rm -rf "$journal" "$gate"
        echo 'Package upgrade already committed; cleaned up'
        exit 0
    fi
    kind=$(cat "$journal/kind" 2>/dev/null || echo deb)
    active=$(cat "$journal/active_profile" 2>/dev/null || echo none)
    was_active=$(cat "$journal/was_active" 2>/dev/null || echo no)
    init_type=$(cat "$journal/init_type" 2>/dev/null || echo none)
    apk_locked=$(cat "$journal/apk_locked" 2>/dev/null || echo no)

    echo "Recovering pending package upgrade (status: $status)..."
    if [ "$init_type" = systemd ] && [ "$active" != none ]; then
        systemctl stop "tayga-managed@$active" 2>/dev/null || :
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed stop 2>/dev/null || :
    fi

    if [ -f "$journal/old_pkg.archive" ]; then
        case "$kind" in
            deb) dpkg --force-confold -i "$journal/old_pkg.archive" 2>/dev/null || : ;;
            rpm) rpm -U --replacepkgs --oldpackage "$journal/old_pkg.archive" 2>/dev/null || : ;;
            apk) apk add --allow-untrusted --force-non-repository "$journal/old_pkg.archive" 2>/dev/null || : ;;
        esac
    fi
    if [ -d "$journal/backup" ]; then
        for b in tayga pref64-discover tayga-ctl; do
            if [ -f "$journal/backup/$b" ]; then cp -p "$journal/backup/$b" "$root/usr/sbin/$b" 2>/dev/null || :; fi
        done
        if [ -d "$journal/backup/libexec" ]; then
            mkdir -p "$lib"
            cp -rp "$journal/backup/libexec/"* "$lib/" 2>/dev/null || :
        fi
    fi
    if [ -f "$journal/accepted.conf" ] && [ "$active" != none ]; then
        cp -p "$journal/accepted.conf" "$state/$active.conf"
    fi
    if [ -d "$journal/data" ] && [ -d "$root/var/lib/tayga" ]; then
        cp -rp "$journal/data/"* "$root/var/lib/tayga/" 2>/dev/null || :
    fi
    if [ "$was_active" = yes ] && [ "$active" != none ]; then
        if [ "$init_type" = systemd ]; then
            systemctl daemon-reload 2>/dev/null || :
            systemctl start "tayga-managed@$active" 2>/dev/null || :
        elif [ "$init_type" = openrc ]; then
            rc-service tayga-managed start 2>/dev/null || :
        fi
    fi
    if [ "$apk_locked" = yes ] && [ -f "$lib/package-lock.sh" ]; then
        sh "$lib/package-lock.sh" lock 2>/dev/null || :
    fi
    rm -rf "$journal" "$gate"
    echo 'PASS: Package upgrade recovery complete'
    exit 0
fi

[ "$action" = apply ] || fail "Unknown action: $action; expected apply or recover"
[ "$#" -ge 1 ] || fail 'Package file required'
pkg=$1; shift

allow_downgrade=no
allow_untrusted=no
old_pkg_explicit=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --allow-downgrade) allow_downgrade=yes ;;
        --allow-untrusted) allow_untrusted=yes ;;
        --old-package) shift; [ "$#" -gt 0 ] || fail '--old-package requires argument'; old_pkg_explicit=$1 ;;
        *) fail "Unknown option: $1" ;;
    esac
    shift
done

[ -f "$pkg" ] || fail "Package file not found: $pkg"

# Acquire exclusive operation lock
mkdir -p "$state"
mkdir "$gate" 2>/dev/null || fail 'Another profile operation is in progress'
lock_held=1
touch "$gate/package-upgrade"
echo "$$" > "$gate/pid"
echo "$(date -u +%s 2>/dev/null || echo 0)" > "$gate/start"

case "$pkg" in
    *.deb) kind=deb ;;
    *.rpm) kind=rpm ;;
    *.apk) kind=apk ;;
    *) fail 'Unsupported package format; expected .deb, .rpm, or .apk' ;;
esac

# Preflight package metadata inspection
pkg_name=
new_ver=
new_arch=

case "$kind" in
    deb)
        command -v dpkg-deb >/dev/null 2>&1 || fail 'dpkg-deb required for deb packages'
        command -v dpkg >/dev/null 2>&1 || fail 'dpkg required for deb packages'
        pkg_name=$(dpkg-deb -f "$pkg" Package 2>/dev/null || :)
        new_ver=$(dpkg-deb -f "$pkg" Version 2>/dev/null || :)
        new_arch=$(dpkg-deb -f "$pkg" Architecture 2>/dev/null || :)
        ;;
    rpm)
        command -v rpm >/dev/null 2>&1 || fail 'rpm required for rpm packages'
        pkg_name=$(rpm -qp --queryformat '%{NAME}' "$pkg" 2>/dev/null || :)
        new_ver=$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null || :)
        new_arch=$(rpm -qp --queryformat '%{ARCH}' "$pkg" 2>/dev/null || :)
        ;;
    apk)
        command -v apk >/dev/null 2>&1 || fail 'apk required for apk packages'
        pkg_name=$(apk info --name -p "$pkg" 2>/dev/null || :)
        new_ver=$(apk info -p "$pkg" 2>/dev/null | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p' || :)
        new_arch=$(apk info --arch -p "$pkg" 2>/dev/null || :)
        ;;
esac

[ "$pkg_name" = tayga-managed ] || [ "$pkg_name" = tayga ] || fail "Invalid package identity: '$pkg_name'; expected tayga-managed"
[ -n "$new_ver" ] || fail "Cannot read package version from $pkg"

# Check installed package version
inst_ver=
case "$kind" in
    deb) inst_ver=$(dpkg-query -W -f='${Version}' tayga-managed 2>/dev/null || :) ;;
    rpm) inst_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' tayga-managed 2>/dev/null || :) ;;
    apk) inst_ver=$(apk info -v tayga-managed 2>/dev/null | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p' || :) ;;
esac

if [ -n "$inst_ver" ] && [ "$allow_downgrade" != yes ]; then
    case "$kind" in
        deb)
            if dpkg --compare-versions "$new_ver" lt "$inst_ver" 2>/dev/null; then
                fail "Refusing package downgrade from $inst_ver to $new_ver (use --allow-downgrade)"
            fi
            ;;
        apk)
            if [ "$(apk version -t "$new_ver" "$inst_ver" 2>/dev/null || :)" = "<" ]; then
                fail "Refusing package downgrade from $inst_ver to $new_ver (use --allow-downgrade)"
            fi
            ;;
    esac
fi

# Preflight dependency simulation
trust_flag=
if [ "$allow_untrusted" = yes ] || [ "${TAYGA_ALLOW_UNTRUSTED:-0}" = 1 ]; then
    trust_flag="--allow-untrusted"
fi

case "$kind" in
    deb) dpkg --simulate -i "$pkg" >/dev/null 2>&1 || fail 'Package dependency preflight failed' ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install --assumeno "$pkg" >/dev/null 2>&1 || rpm -U --test "$pkg" >/dev/null 2>&1 || fail 'Package dependency preflight failed'
        else
            rpm -U --test "$pkg" >/dev/null 2>&1 || fail 'Package dependency preflight failed'
        fi
        ;;
    apk) apk add --simulate $trust_flag --force-non-repository "$pkg" >/dev/null 2>&1 || fail 'Package dependency preflight failed' ;;
esac

# Identify active profile and init system
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
init_type=none

if [ -n "$active" ]; then
    if [ -d "$root/run/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
        init_type=systemd
        if systemctl is-active "tayga-managed@$active" >/dev/null 2>&1; then was_active=yes; fi
    elif [ -d "$root/run/openrc" ] && command -v rc-service >/dev/null 2>&1; then
        init_type=openrc
        if rc-service tayga-managed status >/dev/null 2>&1; then was_active=yes; fi
    fi
fi

apk_locked=no
if [ "$kind" = apk ] && apk info -e .tayga-managed-profile >/dev/null 2>&1; then
    apk_locked=yes
fi

# Locate old package archive for rollback if available
old_pkg_archive=
if [ -n "$old_pkg_explicit" ] && [ -f "$old_pkg_explicit" ]; then
    old_pkg_archive=$old_pkg_explicit
elif [ -n "$inst_ver" ]; then
    case "$kind" in
        deb)
            c=$(find /var/cache/apt/archives -name "tayga-managed_${inst_ver}*.deb" 2>/dev/null | head -n 1 || :)
            [ -n "$c" ] && old_pkg_archive=$c
            ;;
        apk)
            c=$(find /var/cache/apk -name "tayga-managed-${inst_ver}*.apk" 2>/dev/null | head -n 1 || :)
            [ -n "$c" ] && old_pkg_archive=$c
            ;;
    esac
fi

# Create persistent journal
rm -rf "$journal"
mkdir -p "$journal/backup" "$journal/data"
echo "$kind" > "$journal/kind"
echo "$pkg" > "$journal/target_pkg"
echo "$new_ver" > "$journal/target_ver"
echo "${inst_ver:-none}" > "$journal/inst_ver"
echo "${active:-none}" > "$journal/active_profile"
echo "$was_active" > "$journal/was_active"
echo "$init_type" > "$journal/init_type"
echo "$apk_locked" > "$journal/apk_locked"
echo "staged" > "$journal/status"

if [ -n "$active" ] && [ -f "$state/$active.conf" ]; then
    cp -p "$state/$active.conf" "$journal/accepted.conf"
fi

for bin in tayga pref64-discover tayga-ctl; do
    if [ -f "$root/usr/sbin/$bin" ]; then cp -p "$root/usr/sbin/$bin" "$journal/backup/$bin"; fi
done
if [ -d "$lib" ]; then
    mkdir -p "$journal/backup/libexec"
    cp -rp "$lib/"* "$journal/backup/libexec/" 2>/dev/null || :
fi
if [ -n "$old_pkg_archive" ] && [ -f "$old_pkg_archive" ]; then
    cp -p "$old_pkg_archive" "$journal/old_pkg.archive"
fi

# Stop writer before data snapshot
if [ "$was_active" = yes ] && [ -n "$active" ]; then
    if [ "$init_type" = systemd ]; then
        systemctl stop "tayga-managed@$active" || :
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed stop || :
    fi
    for _ in $(seq 1 15); do
        if pidof tayga >/dev/null 2>&1; then sleep 1; else break; fi
    done
fi

if [ -d "$root/var/lib/tayga" ]; then
    cp -rp "$root/var/lib/tayga/"* "$journal/data/" 2>/dev/null || :
fi

rollback() {
    reason=${1:-unknown}
    echo "WARNING: Upgrade failed ($reason); rolling back..." >&2
    echo "rolling-back" > "$journal/status"

    if [ "$init_type" = systemd ] && [ -n "$active" ]; then
        systemctl stop "tayga-managed@$active" 2>/dev/null || :
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed stop 2>/dev/null || :
    fi

    if [ -f "$journal/old_pkg.archive" ]; then
        case "$kind" in
            deb) dpkg --force-confold -i "$journal/old_pkg.archive" 2>/dev/null || : ;;
            rpm) rpm -U --replacepkgs --oldpackage "$journal/old_pkg.archive" 2>/dev/null || : ;;
            apk) apk add --allow-untrusted --force-non-repository "$journal/old_pkg.archive" 2>/dev/null || : ;;
        esac
    fi
    for b in tayga pref64-discover tayga-ctl; do
        if [ -f "$journal/backup/$b" ]; then cp -p "$journal/backup/$b" "$root/usr/sbin/$b" 2>/dev/null || :; fi
    done
    if [ -d "$journal/backup/libexec" ]; then
        mkdir -p "$lib"
        cp -rp "$journal/backup/libexec/"* "$lib/" 2>/dev/null || :
    fi
    if [ -f "$journal/accepted.conf" ] && [ -n "$active" ]; then
        cp -p "$journal/accepted.conf" "$state/$active.conf"
    fi
    if [ -d "$journal/data" ] && [ -d "$root/var/lib/tayga" ]; then
        cp -rp "$journal/data/"* "$root/var/lib/tayga/" 2>/dev/null || :
    fi

    if [ "$was_active" = yes ] && [ -n "$active" ]; then
        if [ "$init_type" = systemd ]; then
            systemctl daemon-reload 2>/dev/null || :
            systemctl start "tayga-managed@$active" 2>/dev/null || :
        elif [ "$init_type" = openrc ]; then
            rc-service tayga-managed start 2>/dev/null || :
        fi
    fi
    if [ "$apk_locked" = yes ] && [ -f "$lib/package-lock.sh" ]; then
        sh "$lib/package-lock.sh" lock 2>/dev/null || :
    fi

    rm -rf "$journal"
    lock_held=0
    rm -rf "$gate"
    fail "Live package upgrade failed ($reason); successfully rolled back to previous state"
}

# Perform installation
echo "installing" > "$journal/status"
if [ "$kind" = apk ] && [ -f "$lib/package-lock.sh" ]; then
    sh "$lib/package-lock.sh" unlock || :
fi

install_ok=yes
case "$kind" in
    deb) dpkg --force-confold -i "$pkg" || install_ok=no ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$pkg" || install_ok=no
        else
            rpm -U --replacepkgs "$pkg" || install_ok=no
        fi
        ;;
    apk) apk add $trust_flag --force-non-repository "$pkg" || install_ok=no ;;
esac

[ "$install_ok" = yes ] || rollback "Package manager failed to install $pkg"

# Post-install readiness verification
echo "verifying" > "$journal/status"
if [ "$was_active" = yes ] && [ -n "$active" ] && [ -f "$state/$active.conf" ]; then
    echo "Restarting active profile $active after package upgrade..."
    start_ok=yes
    if [ "$init_type" = systemd ]; then
        systemctl daemon-reload || :
        systemctl start "tayga-managed@$active" || start_ok=no
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed start || start_ok=no
    fi
    [ "$start_ok" = yes ] || rollback "Failed to start tayga-managed@$active with new package"

    verify_helper="$lib/tayga-verify"
    [ -x "$verify_helper" ] || verify_helper="$lib/tayga-verify.sh"
    [ -e "$verify_helper" ] || rollback 'Readiness verification helper missing after upgrade'
    "$verify_helper" "$state/$active.conf" || rollback "Readiness verification failed for $active"
fi

if [ "$kind" = apk ] && [ -f "$lib/package-lock.sh" ] && [ -n "$active" ]; then
    sh "$lib/package-lock.sh" lock || :
fi

echo "committed" > "$journal/status"
rm -rf "$journal"
lock_held=0
rm -rf "$gate"

echo "PASS: Coordinated live package upgrade successful ($pkg)"
