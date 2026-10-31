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

get_boot_id() {
    if [ -r /proc/sys/kernel/random/boot_id ]; then
        cat /proc/sys/kernel/random/boot_id
    elif [ "$(uname -s 2>/dev/null || :)" = FreeBSD ] && command -v sysctl >/dev/null 2>&1; then
        sysctl -n kern.boottime 2>/dev/null | awk '{print $4,$7}'
    elif [ -r /proc/uptime ]; then
        awk '{print $1}' /proc/uptime
    else
        echo "boot-unknown"
    fi
}

acquire_gate() {
    mkdir -p "$state"
    current_boot=$(get_boot_id)
    retries=0
    while [ "$retries" -lt 5 ]; do
        if mkdir "$gate" 2>/dev/null; then
            echo "$$" > "$gate/pid"
            echo "$current_boot" > "$gate/boot_id"
            touch "$gate/package-upgrade"
            date -u +%s 2>/dev/null > "$gate/start" || echo 0 > "$gate/start"
            lock_held=1
            return 0
        fi
        active_pid=$(cat "$gate/pid" 2>/dev/null || :)
        active_boot=$(cat "$gate/boot_id" 2>/dev/null || :)
        stale=no
        if [ -n "$active_boot" ] && [ "$active_boot" != "$current_boot" ]; then
            stale=yes
        elif [ -n "$active_pid" ]; then
            if ! kill -0 "$active_pid" 2>/dev/null; then
                stale=yes
            fi
        else
            stale=yes
        fi
        if [ "$stale" = yes ]; then
            echo "WARNING: Breaking stale operation lock from PID ${active_pid:-empty}" >&2
            rm -rf "$gate" 2>/dev/null || :
        else
            fail "Another operation is currently in progress (PID $active_pid)"
        fi
        retries=$((retries + 1))
    done
    fail "Failed to acquire exclusive operation lock at $gate"
}

release_gate() {
    if [ "$lock_held" = 1 ]; then
        owner_pid=$(cat "$gate/pid" 2>/dev/null || :)
        if [ "$owner_pid" = "$$" ]; then
            rm -rf "$gate" || :
        fi
        lock_held=0
    fi
}

cleanup_lock() {
    rc=$?
    release_gate
    rm -f "$worker" || :
    exit "$rc"
}
trap cleanup_lock EXIT
trap 'exit 1' HUP INT TERM

if [ "$action" = recover ]; then
    [ -d "$journal" ] || { echo 'No pending package upgrade journal'; exit 0; }
    acquire_gate
    status=$(cat "$journal/status" 2>/dev/null || echo unknown)
    if [ "$status" = committed ] || [ "$status" = recovered ]; then
        rm -rf "$journal"
        release_gate
        echo 'Package upgrade already committed/recovered; cleaned up'
        exit 0
    fi

    # Validate journal integrity and schema
    journal_valid=yes
    for required in status kind inst_ver target_ver old_pkg.archive; do
        if [ ! -f "$journal/$required" ] || [ ! -s "$journal/$required" ]; then
            echo "ERROR: Journal schema violation: missing or empty $required" >&2
            journal_valid=no
        fi
    done
    if [ ! -d "$journal/backup" ]; then
        echo "ERROR: Journal schema violation: missing backup directory" >&2
        journal_valid=no
    fi
    if [ "$journal_valid" != yes ]; then
        echo "recovery-failed" > "$journal/status" 2>/dev/null || :
        release_gate
        fail "Cannot recover: journal at $journal is corrupt or incomplete; state preserved"
    fi

    kind=$(cat "$journal/kind")
    inst_ver=$(cat "$journal/inst_ver")
    target_ver=$(cat "$journal/target_ver")
    active=$(cat "$journal/active_profile" 2>/dev/null || echo none)
    was_active=$(cat "$journal/was_active" 2>/dev/null || echo no)
    init_type=$(cat "$journal/init_type" 2>/dev/null || echo none)
    apk_locked=$(cat "$journal/apk_locked" 2>/dev/null || echo no)

    echo "Recovering pending package upgrade (status: $status)..."
    recovery_ok=yes

    if [ "$init_type" = systemd ] && [ "$active" != none ]; then
        systemctl stop "tayga-managed@$active" 2>/dev/null || :
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed stop 2>/dev/null || :
    fi

    trust_arg=
    if [ "$kind" = apk ]; then
        trust_arg="--allow-untrusted"
    fi
    case "$kind" in
        deb) dpkg --force-confold -i "$journal/old_pkg.archive" || recovery_ok=no ;;
        rpm) rpm -U --replacepkgs --oldpackage "$journal/old_pkg.archive" || recovery_ok=no ;;
        apk) apk add $trust_arg --force-non-repository "$journal/old_pkg.archive" || recovery_ok=no ;;
    esac

    # Verify package manager reports the recovered version
    pkg_ver_now=
    case "$kind" in
        deb) pkg_ver_now=$(dpkg-query -W -f='${Version}' tayga-managed 2>/dev/null || :) ;;
        rpm) pkg_ver_now=$(rpm -q --qf '%{VERSION}-%{RELEASE}' tayga-managed 2>/dev/null || :) ;;
        apk) pkg_ver_now=$(apk info -v tayga-managed 2>/dev/null | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p' || :) ;;
    esac
    if [ "$pkg_ver_now" != "$inst_ver" ]; then
        echo "ERROR: Package rollback verification failed: installed version is '$pkg_ver_now', expected '$inst_ver'" >&2
        recovery_ok=no
    fi

    if [ -d "$journal/backup" ]; then
        for b in tayga pref64-discover tayga-ctl; do
            if [ -f "$journal/backup/$b" ]; then
                cp -p "$journal/backup/$b" "$root/usr/sbin/$b" 2>/dev/null || recovery_ok=no
            fi
        done
        if [ -d "$journal/backup/libexec" ]; then
            mkdir -p "$lib"
            cp -rp "$journal/backup/libexec/"* "$lib/" 2>/dev/null || recovery_ok=no
        fi
    fi

    if [ -f "$journal/accepted.conf" ] && [ "$active" != none ]; then
        cp -p "$journal/accepted.conf" "$state/$active.conf" || recovery_ok=no
    fi

    # Exact data restoration: clean target files and restore snapshot
    if [ -d "$journal/data" ]; then
        rm -rf "$root/var/lib/tayga"
        mkdir -p "$root/var/lib/tayga"
        cp -a "$journal/data/." "$root/var/lib/tayga/" 2>/dev/null || recovery_ok=no
    fi

    if [ "$was_active" = yes ] && [ "$active" != none ]; then
        if [ "$init_type" = systemd ]; then
            systemctl daemon-reload 2>/dev/null || :
            systemctl start "tayga-managed@$active" || recovery_ok=no
        elif [ "$init_type" = openrc ]; then
            rc-service tayga-managed start || recovery_ok=no
        fi
        verify_helper="$lib/tayga-verify"
        [ -x "$verify_helper" ] || verify_helper="$lib/tayga-verify.sh"
        if [ -x "$verify_helper" ]; then
            "$verify_helper" "$state/$active.conf" || recovery_ok=no
        else
            echo "ERROR: Missing readiness verify helper: $verify_helper" >&2
            recovery_ok=no
        fi
    fi

    if [ "$apk_locked" = yes ] && [ -f "$lib/package-lock.sh" ]; then
        sh "$lib/package-lock.sh" lock 2>/dev/null || recovery_ok=no
    fi

    if [ "$recovery_ok" = yes ]; then
        echo "recovered" > "$journal/status"
        rm -rf "$journal"
        release_gate
        echo 'PASS: Package upgrade recovery complete'
        exit 0
    else
        echo "recovery-failed" > "$journal/status"
        release_gate
        fail "Package upgrade recovery failed; journal preserved at $journal"
    fi
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

# Check for existing uncommitted journal
if [ -d "$journal" ]; then
    prev_status=$(cat "$journal/status" 2>/dev/null || echo unknown)
    if [ "$prev_status" != committed ] && [ "$prev_status" != recovered ]; then
        fail "A pending package upgrade journal exists (status: $prev_status); run 'tayga-ctl recover' first"
    fi
    rm -rf "$journal"
fi

# Acquire exclusive operation lock (check stale PID if gate exists)
acquire_gate

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
        pkg_info=$(tar -zxOf "$pkg" .PKGINFO 2>/dev/null || tar -xf "$pkg" -O .PKGINFO 2>/dev/null || :)
        pkg_name=$(printf '%s\n' "$pkg_info" | sed -n 's/^pkgname = //p' | head -n1 || :)
        new_ver=$(printf '%s\n' "$pkg_info" | sed -n 's/^pkgver = //p' | head -n1 || :)
        new_arch=$(printf '%s\n' "$pkg_info" | sed -n 's/^arch = //p' | head -n1 || :)
        ;;
esac

[ "$pkg_name" = tayga-managed ] || fail "Invalid package identity: '$pkg_name'; expected tayga-managed"
[ -n "$new_ver" ] || fail "Cannot read package version from $pkg"

# Validate package ownership matches installer kind if installed
if [ -f "$lib/package-owner" ]; then
    installed_owner=$(cat "$lib/package-owner" 2>/dev/null || :)
    if [ -n "$installed_owner" ] && [ "$installed_owner" != "$kind" ]; then
        fail "Package manager mismatch: system installed via $installed_owner, refusing upgrade via $kind"
    fi
fi

# Validate architecture compatibility
host_arch=
case "$kind" in
    deb) host_arch=$(dpkg --print-architecture 2>/dev/null || :) ;;
    rpm) host_arch=$(rpm -E '%{_arch}' 2>/dev/null || :) ;;
    apk) host_arch=$(apk --print-arch 2>/dev/null || :) ;;
esac
[ -n "$host_arch" ] || host_arch=$(uname -m 2>/dev/null || echo unknown)
[ "${TAYGA_TESTING:-0}" != 1 ] || host_arch=${TEST_HOST_ARCH:-$host_arch}

norm_arch() {
    case "$1" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        armhf|armv7|armv7l|armv7hl) echo armv7 ;;
        armv6|armv6l) echo armv6 ;;
        riscv64) echo riscv64 ;;
        ppc64le) echo ppc64le ;;
        s390x) echo s390x ;;
        all|noarch) echo all ;;
        *) echo "$1" ;;
    esac
}

n_pkg=$(norm_arch "$new_arch")
n_host=$(norm_arch "$host_arch")
arch_compat=no
if [ "$n_pkg" = all ] || [ "$n_pkg" = "$n_host" ]; then
    arch_compat=yes
fi
[ "$arch_compat" = yes ] || fail "Package architecture '$new_arch' is incompatible with host architecture '$host_arch'"

# Check installed package version and prevent downgrade
inst_ver=
case "$kind" in
    deb) inst_ver=$(dpkg-query -W -f='${Version}' tayga-managed 2>/dev/null || :) ;;
    rpm) inst_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' tayga-managed 2>/dev/null || :) ;;
    apk) inst_ver=$(apk info -v 2>/dev/null | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p' || :) ;;
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
        rpm)
            if command -v rpmdev-vercmp >/dev/null 2>&1; then
                if [ "$(rpmdev-vercmp "$new_ver" "$inst_ver" 2>/dev/null || echo 0)" = 12 ]; then
                    fail "Refusing package downgrade from $inst_ver to $new_ver (use --allow-downgrade)"
                fi
            elif command -v python3 >/dev/null 2>&1; then
                is_rpm_downgrade=$(python3 -c '
import sys
try:
    import rpm
    rc = rpm.labelCompare(("0", sys.argv[1], "1"), ("0", sys.argv[2], "1"))
    print("yes" if rc < 0 else "no")
except Exception:
    v1 = [int(x) if x.isdigit() else x for x in sys.argv[1].replace("-", ".").split(".")]
    v2 = [int(x) if x.isdigit() else x for x in sys.argv[2].replace("-", ".").split(".")]
    print("yes" if v1 < v2 else "no")
' "$new_ver" "$inst_ver" 2>/dev/null || echo no)
                if [ "$is_rpm_downgrade" = yes ]; then
                    fail "Refusing package downgrade from $inst_ver to $new_ver (use --allow-downgrade)"
                fi
            fi
            ;;
    esac
fi

# Preflight dependency simulation
apk_locked=no
if [ "$kind" = apk ] && apk info -e .tayga-managed-profile >/dev/null 2>&1; then
    apk_locked=yes
    if [ -f "$lib/package-lock.sh" ]; then
        sh "$lib/package-lock.sh" unlock || :
    fi
fi

trust_flag=
if [ "$allow_untrusted" = yes ] || [ "${TAYGA_ALLOW_UNTRUSTED:-0}" = 1 ] || [ "${TAYGA_TESTING:-0}" = 1 ]; then
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
    apk)
        if ! apk add --simulate $trust_flag --force-non-repository "$pkg" >/dev/null 2>&1; then
            if [ "$apk_locked" = yes ] && [ -f "$lib/package-lock.sh" ]; then
                sh "$lib/package-lock.sh" lock 2>/dev/null || :
            fi
            fail 'Package dependency preflight failed'
        fi
        ;;
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

# Locate old package archive for rollback if previous package was installed
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
        rpm)
            c=$(find /var/cache/dnf /var/cache/yum -name "tayga-managed-${inst_ver}*.rpm" 2>/dev/null | head -n 1 || :)
            [ -n "$c" ] && old_pkg_archive=$c
            ;;
    esac
fi

if [ -n "$inst_ver" ]; then
    [ -n "$old_pkg_archive" ] && [ -f "$old_pkg_archive" ] || \
        fail "Old package archive for installed version ($inst_ver) is required for rollback protection (specify via --old-package or ensure it exists in package cache)"

    old_pkg_name=
    old_pkg_ver=
    case "$kind" in
        deb)
            old_pkg_name=$(dpkg-deb -f "$old_pkg_archive" Package 2>/dev/null || :)
            old_pkg_ver=$(dpkg-deb -f "$old_pkg_archive" Version 2>/dev/null || :)
            ;;
        rpm)
            old_pkg_name=$(rpm -qp --queryformat '%{NAME}' "$old_pkg_archive" 2>/dev/null || :)
            old_pkg_ver=$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}' "$old_pkg_archive" 2>/dev/null || :)
            ;;
        apk)
            old_info=$(tar -zxOf "$old_pkg_archive" .PKGINFO 2>/dev/null || tar -xf "$old_pkg_archive" -O .PKGINFO 2>/dev/null || :)
            old_pkg_name=$(printf '%s\n' "$old_info" | sed -n 's/^pkgname = //p' | head -n1 || :)
            old_pkg_ver=$(printf '%s\n' "$old_info" | sed -n 's/^pkgver = //p' | head -n1 || :)
            ;;
    esac
    [ "$old_pkg_name" = tayga-managed ] || fail "Old package identity mismatch: '$old_pkg_name'; expected tayga-managed"
    [ "$old_pkg_ver" = "$inst_ver" ] || fail "Old package version mismatch: $old_pkg_archive has '$old_pkg_ver', expected '$inst_ver'"
fi

# Create persistent journal and stage immutable package copy
mkdir -p "$journal/backup" "$journal/data"
staged_pkg="$journal/staged_pkg.$kind"
cp -p "$pkg" "$staged_pkg"
chmod 600 "$staged_pkg"

# Save recovery worker in journal for independent boot recovery
cp -p "$worker" "$journal/worker.sh"
chmod 700 "$journal/worker.sh"

echo "$kind" > "$journal/kind"
echo "$staged_pkg" > "$journal/target_pkg"
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

# Stop active service and bounded wait
if [ "$was_active" = yes ] && [ -n "$active" ]; then
    echo "Stopping active profile $active for upgrade..."
    if [ "$init_type" = systemd ]; then
        systemctl stop "tayga-managed@$active" || fail "Failed to stop tayga-managed@$active"
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed stop || fail 'Failed to stop tayga-managed'
    fi
    stopped=no
    for _ in $(seq 1 15); do
        if [ "$init_type" = systemd ]; then
            if ! systemctl is-active "tayga-managed@$active" >/dev/null 2>&1; then stopped=yes; break; fi
        elif [ "$init_type" = openrc ]; then
            if ! rc-service tayga-managed status >/dev/null 2>&1; then stopped=yes; break; fi
        else
            stopped=yes; break
        fi
        sleep 1
    done
    [ "$stopped" = yes ] || fail "Service tayga-managed@$active did not stop within 15s"
fi

# Snapshot dynamic data including dotfiles
if [ -d "$root/var/lib/tayga" ]; then
    cp -a "$root/var/lib/tayga/." "$journal/data/" 2>/dev/null || fail 'Failed to snapshot dynamic data'
fi

rollback() {
    reason=${1:-unknown}
    echo "WARNING: Upgrade failed ($reason); rolling back..." >&2
    echo "rolling-back" > "$journal/status"
    rollback_ok=yes

    if [ "$init_type" = systemd ] && [ -n "$active" ]; then
        systemctl stop "tayga-managed@$active" 2>/dev/null || :
    elif [ "$init_type" = openrc ]; then
        rc-service tayga-managed stop 2>/dev/null || :
    fi

    if [ -f "$journal/old_pkg.archive" ]; then
        trust_arg=
        if [ "$kind" = apk ]; then
            trust_arg="--allow-untrusted"
        fi
        case "$kind" in
            deb) dpkg --force-confold -i "$journal/old_pkg.archive" || rollback_ok=no ;;
            rpm) rpm -U --replacepkgs --oldpackage "$journal/old_pkg.archive" || rollback_ok=no ;;
            apk) apk add $trust_arg --force-non-repository "$journal/old_pkg.archive" || rollback_ok=no ;;
        esac

        # Verify package manager reports the recovered version
        pkg_ver_now=
        case "$kind" in
            deb) pkg_ver_now=$(dpkg-query -W -f='${Version}' tayga-managed 2>/dev/null || :) ;;
            rpm) pkg_ver_now=$(rpm -q --qf '%{VERSION}-%{RELEASE}' tayga-managed 2>/dev/null || :) ;;
            apk) pkg_ver_now=$(apk info -v tayga-managed 2>/dev/null | sed -n 's/^tayga-managed-\([0-9].*\)$/\1/p' || :) ;;
        esac
        if [ "$pkg_ver_now" != "$inst_ver" ]; then
            echo "ERROR: Package rollback verification failed: installed version is '$pkg_ver_now', expected '$inst_ver'" >&2
            rollback_ok=no
        fi
    fi

    for b in tayga pref64-discover tayga-ctl; do
        if [ -f "$journal/backup/$b" ]; then
            cp -p "$journal/backup/$b" "$root/usr/sbin/$b" 2>/dev/null || rollback_ok=no
        fi
    done
    if [ -d "$journal/backup/libexec" ]; then
        mkdir -p "$lib"
        cp -rp "$journal/backup/libexec/"* "$lib/" 2>/dev/null || rollback_ok=no
    fi
    if [ -f "$journal/accepted.conf" ] && [ -n "$active" ]; then
        cp -p "$journal/accepted.conf" "$state/$active.conf" || rollback_ok=no
    fi
    # Exact data restoration: clean target files and restore snapshot
    if [ -d "$journal/data" ]; then
        rm -rf "$root/var/lib/tayga"
        mkdir -p "$root/var/lib/tayga"
        cp -a "$journal/data/." "$root/var/lib/tayga/" 2>/dev/null || rollback_ok=no
    fi

    if [ "$was_active" = yes ] && [ -n "$active" ]; then
        if [ "$init_type" = systemd ]; then
            systemctl daemon-reload 2>/dev/null || :
            systemctl start "tayga-managed@$active" || rollback_ok=no
        elif [ "$init_type" = openrc ]; then
            rc-service tayga-managed start || rollback_ok=no
        fi
        verify_helper="$lib/tayga-verify"
        [ -x "$verify_helper" ] || verify_helper="$lib/tayga-verify.sh"
        if [ -x "$verify_helper" ]; then
            "$verify_helper" "$state/$active.conf" || rollback_ok=no
        else
            echo "ERROR: Missing readiness verify helper: $verify_helper" >&2
            rollback_ok=no
        fi
    fi
    if [ "$apk_locked" = yes ] && [ -f "$lib/package-lock.sh" ]; then
        sh "$lib/package-lock.sh" lock 2>/dev/null || rollback_ok=no
    fi

    if [ "$rollback_ok" = yes ]; then
        echo "recovered" > "$journal/status"
        rm -rf "$journal"
        release_gate
        fail "Live package upgrade failed ($reason); successfully rolled back to previous state"
    else
        echo "rollback-failed" > "$journal/status"
        release_gate
        fail "CRITICAL: Upgrade failed ($reason) AND rollback encountered errors; journal preserved at $journal"
    fi
}

# Perform installation from immutable staged copy
echo "installing" > "$journal/status"
if [ "$kind" = apk ] && [ -f "$lib/package-lock.sh" ]; then
    sh "$lib/package-lock.sh" unlock || :
fi

install_ok=yes
case "$kind" in
    deb) dpkg --force-confold -i "$staged_pkg" || install_ok=no ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$staged_pkg" || install_ok=no
        else
            rpm -U --replacepkgs "$staged_pkg" || install_ok=no
        fi
        ;;
    apk) apk add $trust_flag --force-non-repository "$staged_pkg" || install_ok=no ;;
esac

[ "$install_ok" = yes ] || rollback "Package manager failed to install $staged_pkg"

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
    sh "$lib/package-lock.sh" lock || rollback 'Failed to restore APK solver pin'
fi

echo "committed" > "$journal/status"
rm -rf "$journal"
release_gate

echo "PASS: Coordinated live package upgrade successful ($pkg)"
