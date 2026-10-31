#!/bin/sh
# Dedicated disposable Debian/systemd or Alpine/OpenRC VM. The host performs the hard power cut.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
[ "$#" -eq 3 ] || exit 2
case "$2" in *.apk) kind=apk ;; *.deb) kind=deb ;; *.rpm) kind=rpm ;; *) exit 2 ;; esac
phase=$1; baseline=$2; target=$3
profile_state=${TAYGA_TEST_PROFILE_STATE:-active}
state=/var/lib/tayga-installer
fixture=/var/lib/tayga-native-upgrade-test
lib=/usr/libexec/tayga
trust=
[ "$kind" != apk ] || trust=--allow-untrusted
version() {
    if [ "$kind" = apk ]; then apk info -v | sed -n 's/^tayga-managed-//p';
    elif [ "$kind" = rpm ]; then rpm -q --qf '%{VERSION}-%{RELEASE}' tayga-managed;
    else dpkg-query -W -f='${Version}' tayga-managed; fi
}
pid() {
    if [ "$kind" = apk ]; then cat /run/tayga-managed.pid;
    else systemctl show -p MainPID --value tayga-managed@siit; fi
}
active() {
    if [ "$kind" = apk ]; then rc-service tayga-managed status;
    else systemctl is-active --quiet tayga-managed@siit; fi
    [ "$(pid)" -gt 0 ]
    "$lib/tayga-verify" "$state/siit.conf"
}
ready() {
    if [ "$profile_state" = active ]; then active; else
        if systemctl is-active --quiet tayga-managed@siit; then return 1; fi
        if [ "$profile_state" = unconfigured ]; then [ ! -e "$state/current" ]; fi
    fi
}
case "$phase" in
    setup)
        [ ! -e "$fixture" ] || exit 2
        [ ! -e "$state/current" ] || exit 2
        mkdir -p "$fixture"
        if [ "$kind" = rpm ]; then
            # Fedora's cloud image has no IPv6 default route. Supply an owned,
            # boot-persistent native endpoint route for SIIT route readiness.
            ip_bin=$(command -v ip)
            cat > /etc/systemd/system/tayga-native-testnet.service <<EOF
[Unit]
Description=Disposable TAYGA native upgrade fixture network
Before=tayga-managed@siit.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ip_bin link add tnative type dummy
ExecStart=$ip_bin link set tnative up
ExecStart=$ip_bin -6 addr add fd64:200::2/64 dev tnative
ExecStop=$ip_bin link delete tnative
EOF
            mkdir -p /etc/systemd/system/tayga-managed@siit.service.d
            printf '[Unit]\nRequires=tayga-native-testnet.service\nAfter=tayga-native-testnet.service\n' > /etc/systemd/system/tayga-managed@siit.service.d/native-testnet.conf
            systemctl daemon-reload
            systemctl start tayga-native-testnet.service
        fi
        if [ "$kind" = apk ]; then apk add --allow-untrusted "$baseline";
        elif [ "$kind" = rpm ]; then dnf install -y "$baseline";
        else dpkg -i "$baseline"; fi
        if [ "$profile_state" != unconfigured ]; then
        sh "$lib/configure.sh" --mode=siit --pref64=fd64:100::/96 \
            --map-ipv4=198.18.10.1 --map-ipv6=fd64:200::1 --offload=off \
            --workers=1 --firewall=nft --output="$fixture/siit.conf"
        tayga-ctl apply "$fixture/siit.conf"
        active
            if [ "$profile_state" = stopped ]; then
                systemctl disable --now tayga-managed@siit
            fi
        fi
        ready
        mkdir -p /var/lib/tayga
        printf 'accepted data\n' > /var/lib/tayga/.native-upgrade-proof
        version > "$fixture/baseline.version"
        ;;
    upgrade)
        ready
        if [ "$profile_state" = active ]; then pid > "$fixture/old.pid"; fi
        tayga-ctl upgrade "$target" --old-package "$baseline" $trust
        ready
        [ "$(version)" != "$(cat "$fixture/baseline.version")" ]
        if [ "$profile_state" = active ]; then
            [ "$(pid)" != "$(cat "$fixture/old.pid")" ]
        fi
        [ ! -d "$state/package-upgrade" ]
        grep -Fx 'accepted data' /var/lib/tayga/.native-upgrade-proof
        version > "$fixture/accepted.version"
        ;;
    arm-powercut)
        ready
        [ ! -d "$state/package-upgrade" ]
        mkdir -p "$fixture/bin"
        # Test-only manager interposer: execute real dpkg, then pause immediately
        # after it installs the staged target. No production hook is modified.
        cat > "$fixture/bin/dpkg" <<'EOF'
#!/bin/sh
/usr/bin/dpkg "$@"
rc=$?
[ "$rc" -eq 0 ] || exit "$rc"
case "$*" in
    *-i*staged_pkg.deb*)
        echo target-installed > /var/lib/tayga-native-upgrade-test/powercut.ready
        echo target-data > /var/lib/tayga/.native-upgrade-proof
        echo target-only > /var/lib/tayga/native-upgrade-target-only
        sync
        while :; do sleep 1; done
        ;;
esac
EOF
        if [ "$kind" = apk ]; then
            sed 's@/usr/bin/dpkg@/sbin/apk@g; s@\*-i\*staged_pkg.deb\*@*staged_pkg.apk*@' "$fixture/bin/dpkg" > "$fixture/bin/apk"
            rm "$fixture/bin/dpkg"
            chmod 755 "$fixture/bin/apk"
        elif [ "$kind" = rpm ]; then
            sed 's@/usr/bin/dpkg@/usr/bin/dnf@g; s@\*-i\*staged_pkg.deb\*@*staged_pkg.rpm*@' "$fixture/bin/dpkg" > "$fixture/bin/dnf"
            rm "$fixture/bin/dpkg"
            chmod 755 "$fixture/bin/dnf"
        else
            chmod 755 "$fixture/bin/dpkg"
        fi
        # Downgrade fixture deliberately: recovery must restore the accepted
        # higher revision in the package DB, not merely restore its executable.
        PATH="$fixture/bin:$PATH" nohup tayga-ctl upgrade "$baseline" \
            --old-package "$target" --allow-downgrade $trust \
            > "$fixture/interrupted.log" 2>&1 </dev/null &
        for _ in $(seq 1 60); do
            if [ -f "$fixture/powercut.ready" ]; then
                [ "$(version)" = "$(cat "$fixture/baseline.version")" ]
                sync
                echo 'READY: host must hard-stop this VM now'
                exit 0
            fi
            sleep 1
        done
        cat "$fixture/interrupted.log"
        exit 1
        ;;
    check-recovery)
        for _ in $(seq 1 90); do
            if [ ! -d "$state/package-upgrade" ]; then break; fi
            sleep 1
        done
        [ ! -d "$state/package-upgrade" ]
        [ "$(version)" = "$(cat "$fixture/accepted.version")" ]
        ready
        grep -Fx 'accepted data' /var/lib/tayga/.native-upgrade-proof
        [ ! -e /var/lib/tayga/native-upgrade-target-only ]
        ;;
    cleanup)
        if [ "$profile_state" != unconfigured ]; then tayga-ctl uninstall siit; fi
        if [ "$kind" = apk ]; then apk del tayga-managed;
        elif [ "$kind" = rpm ]; then rpm -e tayga-managed;
        else dpkg --remove tayga-managed; fi
        rm -f /var/lib/tayga/.native-upgrade-proof /var/lib/tayga/native-upgrade-target-only
        if [ "$kind" = rpm ]; then
            systemctl stop tayga-native-testnet.service
            rm -f /etc/systemd/system/tayga-native-testnet.service /etc/systemd/system/tayga-managed@siit.service.d/native-testnet.conf
            systemctl daemon-reload
        fi
        rm -rf "$fixture"
        ;;
    *) exit 2 ;;
esac
echo "PASS: native Linux VM $phase"
