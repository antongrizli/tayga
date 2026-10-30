#!/bin/sh
# Transactional profile activation; binaries are installed by the SFX header.
set -eu
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/sbin:/bin:/usr/sbin:/usr/bin}:/usr/local/sbin:/usr/local/bin"; export PATH ;; esac
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'Profile management requires root'
[ "$#" -ge 1 ] || fail 'Usage: tayga-lifecycle apply CONFIG | uninstall PROFILE'
action=$1
shift
# The mutating runner owns its process group; the wrapper only waits for it.
if [ "$action" = apply ] && [ "${TAYGA_SESSION_RUNNER:-}" != yes ]; then
    command -v setsid >/dev/null || fail 'setsid is required for independent rollback'
    TAYGA_SESSION_RUNNER=yes setsid sh "$0" "$action" "$@" &
    runner=$!
    trap 'kill -TERM "-$runner" 2>/dev/null || :' HUP INT TERM
    set +e
    wait "$runner"
    result=$?
    trap - HUP INT TERM
    exit "$result"
fi
root=${TAYGA_TEST_ROOT:-}
[ -z "$root" ] || [ "${TAYGA_TESTING:-}" = 1 ] || fail 'Test root requires TAYGA_TESTING=1'
state=$root/var/lib/tayga-installer
etc=$root/etc/tayga
lib=$root/usr/local/libexec/tayga
mkdir -p "$state" "$etc"
umask 077
gate=$state/operation.lock
mkdir "$gate" 2>/dev/null || fail 'Another profile operation is in progress'
lock=$gate
trap 'rm -rf "$gate"' 0
extra=
if [ -d "$root/run/systemd/system" ]; then
    init=systemd
    command -v systemctl >/dev/null || fail 'systemctl is required'
    unit=$root/etc/systemd/system/tayga-managed@.service
    template=$lib/tayga-managed@.service
    unit_mode=644
    mkdir -p "$root/etc/systemd/system"
elif [ -d "$root/run/openrc" ]; then
    init=openrc
    command -v rc-service >/dev/null || fail 'rc-service is required'
    command -v rc-update >/dev/null || fail 'rc-update is required'
    unit=$root/etc/init.d/tayga-managed
    template=$lib/tayga-managed.openrc
    unit_mode=755
    extra=$root/etc/conf.d/tayga-managed
    mkdir -p "$root/etc/init.d" "$root/etc/conf.d"
elif [ "$(uname -s)" = FreeBSD ] || { [ "${TAYGA_TESTING:-}" = 1 ] && [ -n "$root" ] && [ -d "$root/etc/rc.d" ]; }; then
    init=freebsd_rc
    command -v service >/dev/null || fail 'service is required'
    command -v sysrc >/dev/null || fail 'sysrc is required'
    unit=$root/usr/local/etc/rc.d/tayga-managed
    template=$lib/freebsd-rc.in
    unit_mode=755
    extra=$root/etc/rc.conf.d/tayga_managed
    mkdir -p "$root/usr/local/etc/rc.d" "$root/etc/rc.conf.d"
else fail 'Automatic activation requires systemd, OpenRC or FreeBSD rc.d'
fi
reload() { if [ "$init" = systemd ]; then systemctl daemon-reload; fi; }
service() {
    if [ "$init" = systemd ]; then systemctl "$1" "tayga-managed@$2.service"
    elif [ "$init" = openrc ]; then
        case "$1" in
            enable) rc-update add tayga-managed default ;;
            disable) rc-update del tayga-managed default ;;
            is-active) rc-service tayga-managed status ;;
            is-enabled) rc-update show default | awk '$1=="tayga-managed" {found=1} END {exit !found}' ;;
            *) rc-service tayga-managed "$1" ;;
        esac
    else
        case "$1" in
            enable) sysrc -f "$extra" tayga_managed_enable=YES ;;
            disable) sysrc -f "$extra" tayga_managed_enable=NO ;;
            is-active) command service tayga-managed onestatus ;;
            is-enabled)
                val=$(sysrc -f "$extra" -n tayga_managed_enable 2>/dev/null || echo NO)
                case "$val" in [Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac ;;
            *) command service tayga-managed "one$1" ;;
        esac
    fi
}
recovery_service() {
    if [ "$init" = systemd ]; then systemctl "$1" tayga-recovery.service
    elif [ "$init" = openrc ]; then
        case "$1" in
            enable) rc-update add tayga-recovery boot ;;
            disable) rc-update del tayga-recovery boot ;;
            is-enabled) rc-update show boot | awk '$1=="tayga-recovery" {found=1} END {exit !found}' ;;
        esac
    else
        case "$1" in
            enable) sysrc -f "$root/etc/rc.conf.d/tayga_recovery" tayga_recovery_enable=YES ;;
            disable) sysrc -f "$root/etc/rc.conf.d/tayga_recovery" tayga_recovery_enable=NO ;;
            is-enabled)
                val=$(sysrc -f "$root/etc/rc.conf.d/tayga_recovery" -n tayga_recovery_enable 2>/dev/null || echo NO)
                case "$val" in [Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac ;;
        esac
    fi
}
if [ "$init" = systemd ]; then
    recovery_unit=$root/etc/systemd/system/tayga-recovery.service
    recovery_template=$lib/tayga-recovery.service
elif [ "$init" = openrc ]; then
    recovery_unit=$root/etc/init.d/tayga-recovery
    recovery_template=$lib/tayga-recovery.openrc
else
    recovery_unit=$root/usr/local/etc/rc.d/tayga-recovery
    recovery_template=$lib/freebsd-recovery-rc.in
fi
old=
[ ! -f "$state/current" ] || old=$(cat "$state/current")
case "$old" in ''|clat|nat64|siit) ;; *) fail 'Invalid saved profile' ;; esac
case "$action" in
    apply)
        [ "$#" -eq 1 ] || fail 'apply requires a candidate configuration'
        candidate=$1
        profile=$(awk '$1=="#" && $2=="installer-mode" {print $3}' "$candidate")
        if [ -z "$profile" ]; then
            profile=$(awk '$1=="tun-device" {print $2}' "$candidate")
        fi
        case "$profile" in clat|nat64|siit) ;; *) fail 'Managed activation supports clat, nat64 or siit' ;; esac
        command -v curl >/dev/null || fail 'curl is required for readiness verification'
        if [ "$init" = freebsd_rc ]; then
            for tool in ifconfig route sysctl pfctl; do command -v "$tool" >/dev/null || fail "$tool is required"; done
        else
            for tool in ip sysctl; do command -v "$tool" >/dev/null || fail "$tool is required"; done
        fi
        if [ "$(awk '$1=="#" && $2=="installer-dns64" {print $3}' "$candidate")" = yes ]; then
            for tool in unbound unbound-checkconf pref64-discover; do command -v "$tool" >/dev/null || fail "$tool is required"; done
            sh "$lib/tayga-dns64" render "$candidate" "$lock/unbound.conf"
            unbound-checkconf "$lock/unbound.conf"
        fi
        case "$(awk '$1=="#" && $2=="installer-host-dns" {print $3}' "$candidate")" in
            public|public-nm|public-file|public-resolvconf) sh "$lib/tayga-host-dns" prepare "$candidate" ;;
        esac
        # Refuse to claim administrator-owned configurations and units.
        target=$etc/$profile.conf
        if [ -e "$target" ] || [ -L "$target" ]; then
            [ -f "$state/$profile.conf" ] || fail "Existing unmanaged configuration: $target"
            cmp -s "$target" "$state/$profile.conf" || fail "Configuration was edited; preserve it before reconfiguring: $target"
            cp -p "$target" "$lock/config.old"
        fi
        if [ -e "$unit" ] || [ -L "$unit" ]; then
            if ! cmp -s "$unit" "$template"; then
                cmp -s "$unit" "$state/unit" || fail "Existing differing service unit: $unit"
            fi
            cp -p "$unit" "$lock/unit.old"
        fi
        if [ -n "$extra" ] && { [ -e "$extra" ] || [ -L "$extra" ]; }; then
            if [ "$init" = openrc ]; then
                cmp -s "$extra" "$state/openrc-env" || fail "Existing differing OpenRC configuration: $extra"
            fi
            if [ "$init" = freebsd_rc ]; then
                cmp -s "$extra" "$state/rc-conf-d" || fail "Existing differing FreeBSD rc.conf.d configuration: $extra"
            fi
            cp -p "$extra" "$lock/extra.old"
        fi
        if [ -e "$recovery_unit" ] || [ -L "$recovery_unit" ]; then
            cmp -s "$recovery_unit" "$state/recovery-unit" || fail "Existing differing recovery service: $recovery_unit"
            cp -p "$recovery_unit" "$lock/recovery.old"
        fi
        recovery_enabled=no
        if recovery_service is-enabled >/dev/null 2>&1; then recovery_enabled=yes; fi
        printf '%s\n' "$recovery_enabled" > "$lock/recovery.enabled"
        mkdir "$lock/metadata"
        for saved in current clat.conf nat64.conf siit.conf unit openrc-env rc-conf-d recovery-unit; do
            [ ! -f "$state/$saved" ] || cp -p "$state/$saved" "$lock/metadata/$saved"
        done
        cp "$candidate" "$lock/candidate"
        if [ -d "$state/files-transaction" ]; then
            if [ -z "${TAYGA_FILES_TRANSACTION:-}" ] || [ "$(cat "$state/files-transaction/id")" != "$TAYGA_FILES_TRANSACTION" ]; then
                fail 'Another file installation is pending'
            fi
            printf '%s\n' "$TAYGA_FILES_TRANSACTION" > "$lock/files.id"
        fi
        was_active=no
        was_enabled=no
        if [ -n "$old" ]; then
            if service is-active "$old" >/dev/null 2>&1; then was_active=yes; fi
            if service is-enabled "$old" >/dev/null 2>&1; then was_enabled=yes; fi
        fi
        for tool in setsid nohup timeout ps; do command -v "$tool" >/dev/null || fail "$tool is required for watchdog recovery"; done
        if ! command -v flock >/dev/null && ! command -v lockf >/dev/null; then
            fail 'flock or lockf is required for watchdog recovery'
        fi
        seconds=${TAYGA_WATCHDOG_SECONDS:-120}
        case "$seconds" in ''|*[!0-9]*|????*) fail 'Invalid watchdog deadline' ;; esac
        minimum=30
        [ "${TAYGA_TESTING:-}" != 1 ] || minimum=1
        if [ "$seconds" -lt "$minimum" ] || [ "$seconds" -gt 600 ]; then fail 'Watchdog deadline must be 30..600 seconds'; fi
        if [ -r "/proc/$$/stat" ]; then group=$(awk '{print $5}' "/proc/$$/stat")
        else group=$(ps -p "$$" -o pgid= | tr -d ' ')
        fi
        [ "$group" = "$$" ] || fail 'Activation runner must own its process group'
        token=$(mktemp "$lock/token.XXXXXXXX")
        transaction=${token##*/}
        rm -f "$token"
        session=$gate/session.$transaction
        mkdir "$session"
        for saved in candidate config.old unit.old extra.old recovery.old recovery.enabled metadata unbound.conf files.id; do
            if [ -e "$gate/$saved" ]; then mv "$gate/$saved" "$session/$saved"; fi
        done
        printf '%s\n' "${session##*/}" > "$gate/transaction"
        lock=$session
        printf '%s\n' "$transaction" > "$lock/id"
        printf '%s\n' "$profile" > "$lock/profile"
        printf '%s\n' "$old" > "$lock/old"
        printf '%s\n' "$init" > "$lock/init"
        printf '%s\n' "$was_active" > "$lock/was_active"
        printf '%s\n' "$was_enabled" > "$lock/was_enabled"
        printf '%s\n' "$$" > "$lock/runner.pid"
        if [ -r "/proc/$$/stat" ]; then started=$(awk '{print $22}' "/proc/$$/stat")
        else started=$(LC_ALL=C ps -p "$$" -o lstart=)
        fi
        printf '%s\n' "$started" > "$lock/runner.start"
        if [ -d /proc/self ]; then
            cat /proc/sys/kernel/random/boot_id > "$lock/boot.id"
            identity=$root/etc/machine-id
            if [ ! -s "$identity" ]; then
                identity=$state/host.id
                if [ ! -s "$identity" ]; then cat /proc/sys/kernel/random/uuid > "$identity"; fi
            fi
            cp "$identity" "$lock/machine.id"
            readlink /proc/self/ns/pid > "$lock/pid.namespace"
            readlink /proc/self/ns/net > "$lock/net.namespace"
        elif [ "$(uname -s)" = FreeBSD ]; then
            sysctl -n kern.boottime 2>/dev/null | awk '{print $4,$7}' > "$lock/boot.id"
            identity=$root/etc/hostid
            if [ ! -s "$identity" ]; then
                identity=$state/host.id
                if [ ! -s "$identity" ]; then sysctl -n kern.hostuuid 2>/dev/null > "$identity" || :; fi
            fi
            [ ! -s "$identity" ] || cp "$identity" "$lock/machine.id"
        fi
        printf 'commit\n' > "$lock/commit.intent"
        printf 'parent\n' > "$lock/parent.intent"
        printf 'watchdog\n' > "$lock/watchdog.intent"
        # Immutable copies survive rollback/removal of the installed helpers.
        cp "$lib/tayga-watchdog.sh" "$lock/watchdog.sh"
        cp "$lib/tayga-recover.sh" "$lock/recover.sh"
        cp "$lib/tayga-files.sh" "$lock/files.sh"
        cp "$lib/tayga-net-ctl" "$lock/net.sh"
        cp "$lib/tayga-dns64" "$lock/dns64.sh"
        cp "$lib/tayga-host-dns" "$lock/host-dns.sh"
        if [ -f "$lib/package-owner" ] && [ "$(cat "$lib/package-owner")" = apk ]; then
            cp "$lib/package-lock.sh" "$lock/package-lock.sh"
        fi
        committed=no
        rollback() {
            if [ "$committed" = no ] && ln "$lock/parent.intent" "$lock/decision" 2>/dev/null; then
                sh "$lock/recover.sh" "$lock" "$transaction" || echo 'Recovery incomplete; run tayga-ctl recover' >&2
            fi
        }
        trap rollback 0
        trap 'exit 1' HUP INT TERM
        nohup setsid sh "$lock/watchdog.sh" "$lock" "$transaction" "$seconds" "$$" "$started" \
            </dev/null >> "$state/watchdog.log" 2>&1 &
        watcher=$!
        for _ in 1 2 3; do
            [ ! -f "$lock/armed" ] || break
            kill -0 "$watcher" 2>/dev/null || fail 'Watchdog exited before arming'
            sleep 1
        done
        [ -f "$lock/armed" ] || fail 'Watchdog did not acknowledge arming'
        if [ -f "$lock/package-lock.sh" ]; then
            sync
            timeout -k 2 30 sh "$lock/package-lock.sh" lock
        fi
        # Persist a complete snapshot and recovery registration before touching profiles.
        : > "$lock/mutating"
        sync
        install -m "$unit_mode" "$recovery_template" "$recovery_unit"
        cp "$recovery_template" "$state/recovery-unit"
        reload
        recovery_service enable
        sync
        if [ -n "$old" ]; then service stop "$old"; fi
        install -m 600 "$lock/candidate" "$target"
        install -m "$unit_mode" "$template" "$unit"
        if [ -n "$extra" ]; then
            if [ "$init" = openrc ]; then printf 'profile=%s\n' "$profile" > "$extra"; fi
            if [ "$init" = freebsd_rc ]; then printf 'tayga_managed_profile="%s"\n' "$profile" > "$extra"; fi
        fi
        reload
        service start "$profile"
        service enable "$profile"
        if [ "$init" = systemd ] && [ -n "$old" ] && [ "$old" != "$profile" ]; then service disable "$old"; fi
        cp "$lock/candidate" "$state/$profile.conf"
        cp "$template" "$state/unit"
        if [ -n "$extra" ]; then
            if [ "$init" = openrc ]; then cp "$extra" "$state/openrc-env"; fi
            if [ "$init" = freebsd_rc ]; then cp "$extra" "$state/rc-conf-d"; fi
        fi
        printf '%s\n' "$profile" > "$state/current"
        sync
        ln "$lock/commit.intent" "$lock/decision" 2>/dev/null || fail 'Watchdog already claimed recovery'
        committed=yes
        sync
        sh "$lock/recover.sh" "$lock" "$transaction"
        echo "Activated $profile; readiness verification passed"
        ;;
    uninstall)
        [ "$#" -eq 1 ] || fail 'uninstall requires a profile'
        profile=$1
        case "$profile" in clat|nat64|siit) ;; *) fail 'Unsupported profile' ;; esac
        [ -f "$state/$profile.conf" ] || fail 'Profile is not owned by this installer'
        target=$etc/$profile.conf
        [ ! -e "$target" ] || cmp -s "$target" "$state/$profile.conf" || fail "Modified configuration preserved: $target"
        extra_owned=no
        if [ -n "$extra" ]; then
            if [ "$init" = openrc ] && cmp -s "$extra" "$state/openrc-env"; then extra_owned=yes; fi
            if [ "$init" = freebsd_rc ] && cmp -s "$extra" "$state/rc-conf-d"; then extra_owned=yes; fi
        fi
        if [ "$init" = systemd ] || [ "$old" = "$profile" ]; then
            service stop "$profile"
            service disable "$profile"
        fi
        rm -f "$target" "$state/$profile.conf"
        if [ "$old" = "$profile" ]; then rm -f "$state/current"; fi
        if [ ! -f "$state/clat.conf" ] && [ ! -f "$state/nat64.conf" ] && [ ! -f "$state/siit.conf" ]; then
            recovery_service disable
            if cmp -s "$recovery_unit" "$state/recovery-unit"; then rm -f "$recovery_unit"; fi
            rm -f "$state/recovery-unit"
            if cmp -s "$unit" "$state/unit"; then rm -f "$unit"; fi
            rm -f "$state/unit"
            if [ "$extra_owned" = yes ]; then rm -f "$extra"; fi
            if [ "$init" = freebsd_rc ]; then rm -f "$root/etc/rc.conf.d/tayga_recovery"; fi
            rm -f "$state/openrc-env" "$state/rc-conf-d"
            reload
            if [ -f "$lib/tayga-files.sh" ] && [ -d "$state/files" ]; then sh "$lib/tayga-files.sh" uninstall; fi
        fi
        if [ -f "$lib/package-owner" ] && [ "$(cat "$lib/package-owner")" = apk ]; then
            timeout -k 2 30 sh "$lib/package-lock.sh" unlock
        fi
        echo "Removed managed $profile configuration and service registration; persistent data retained"
        ;;
    *) fail 'Unknown lifecycle operation' ;;
esac
