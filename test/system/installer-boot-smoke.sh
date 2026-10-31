#!/bin/sh
# Multi-phase test: run ONLY inside a dedicated disposable VM. Between phases,
# reboot (install -> check) or force power off (arm -> check-recovery).
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${2:-/opt/tayga-source}
state=/var/lib/tayga-boot-test
lib=/usr/local/libexec/tayga
phase=${1:-}
check() {
    [ "$(cat /var/lib/tayga-installer/current)" = siit ]
    [ ! -e /var/lib/tayga-installer/operation.lock ]
    [ ! -e "$state/stale-cleanup-ran" ]
    ip link show siit >/dev/null
    if ip link show nat64 >/dev/null 2>&1; then exit 1; fi
    cmp /etc/tayga/siit.conf "$state/siit.before"
    "$lib/tayga-verify.real" /etc/tayga/siit.conf
    if [ -d /run/systemd/system ]; then
        systemctl is-active tayga-managed@siit.service
        systemctl is-enabled tayga-managed@siit.service
        if systemctl is-enabled tayga-managed@nat64.service; then exit 1; fi
    else
        rc-service tayga-managed status
        rc-update show default | awk '$1=="tayga-managed" {ok=1} END {exit !ok}'
    fi
}
case "$phase" in
    install)
        mkdir -p "$state"
        # Local IPv6 uplink fixture; the VM's SSH/default IPv4 route stays usable.
        cat > "$state/uplink.sh" <<'EOF'
#!/bin/sh
set -eu
ip link add boot-uplink type dummy
ip link set boot-uplink up
ip -6 addr add fd64:ffff::1/64 dev boot-uplink nodad
ip -6 route add default dev boot-uplink
EOF
        chmod 755 "$state/uplink.sh"
        if [ -d /run/systemd/system ]; then
            cat > /etc/systemd/system/tayga-boot-fixture.service <<'EOF'
[Unit]
After=network-online.target
Before=tayga-managed@siit.service tayga-managed@nat64.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/var/lib/tayga-boot-test/uplink.sh
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable --now tayga-boot-fixture.service
        else
            cat > /etc/init.d/tayga-boot-fixture <<'EOF'
#!/sbin/openrc-run
depend() { need net; before tayga-managed; }
start() { /var/lib/tayga-boot-test/uplink.sh; }
EOF
            chmod 755 /etc/init.d/tayga-boot-fixture
            rc-update add tayga-boot-fixture default
            rc-service tayga-boot-fixture start
        fi
        cat /proc/sys/kernel/random/boot_id > "$state/initial.boot"
        sh "$base/build/tayga-installer.sh" --yes --mode=siit --pref64=fd64:100::/96 \
            --map-ipv4=198.18.10.1 --map-ipv6=fd64:200::1 --workers=1 --offload=off --firewall=iptables
        cp /etc/tayga/siit.conf "$state/siit.before"
        cp "$lib/tayga-verify" "$lib/tayga-verify.real"
        check
        echo 'PASS: native init activation; reboot this VM, then run check'
        ;;
    check)
        [ "$(cat "$state/initial.boot")" != "$(cat /proc/sys/kernel/random/boot_id)" ]
        check
        echo 'PASS: enabled profile starts after a real reboot'
        ;;
    arm|arm-first)
        file_id=
        if [ "$phase" = arm-first ]; then
            [ ! -e /usr/local/sbin/tayga ]
            sh "$base/build/tayga-installer.sh" --extract-only "$state/first-payload"
            file_id=$(sh "$state/first-payload/installer/tayga-files.sh" stage "$state/first-payload" "linux-$(uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/amd64/ -e s/armv7l/armv7/)")
            cp "$lib/tayga-verify" "$lib/tayga-verify.real"
        else check
        fi
        cat /proc/sys/kernel/random/boot_id > "$state/interrupted.boot"
        cat > "$lib/tayga-verify" <<'EOF'
#!/bin/sh
: > /run/tayga-boot-test-ready
while :; do sleep 1; done
EOF
        sh "$lib/configure.sh" --mode=nat64 --pref64=fd64:100::/96 --workers=1 --offload=off \
            --firewall=iptables --output="$state/candidate"
        TAYGA_FILES_TRANSACTION="$file_id" TAYGA_WATCHDOG_SECONDS=600 nohup sh "$lib/tayga-lifecycle.sh" apply "$state/candidate" \
            > "$state/interrupted.log" 2>&1 </dev/null &
        ready=no
        for _ in $(seq 1 40); do
            if [ -f /run/tayga-boot-test-ready ]; then ready=yes; break; fi
            sleep 1
        done
        [ "$ready" = yes ] || { cat "$state/interrupted.log"; exit 1; }
        gate=/var/lib/tayga-installer/operation.lock
        session=$gate/$(cat "$gate/transaction")
        # Fail loudly if boot recovery replays cleanup from the previous kernel.
        for helper in net dns64 host-dns; do
            printf '#!/bin/sh\ntouch %s/stale-cleanup-ran\nexit 1\n' "$state" > "$session/$helper.sh"
        done
        if [ -d /run/systemd/system ]; then systemctl enable tayga-managed@nat64.service; fi
        cp "$lib/tayga-verify.real" "$lib/tayga-verify"
        # The pending service start already invoked the blocking shell above.
        sync
        echo 'PASS: activation interrupted after real TUN/routes; force power off this VM now'
        ;;
    check-recovery)
        [ "$(cat "$state/interrupted.boot")" != "$(cat /proc/sys/kernel/random/boot_id)" ]
        ready=no
        for _ in $(seq 1 40); do
            if [ ! -e /var/lib/tayga-installer/operation.lock ] && ip link show siit >/dev/null 2>&1; then ready=yes; break; fi
            sleep 1
        done
        [ "$ready" = yes ]
        check
        [ ! -e /etc/tayga/nat64.conf ]
        echo 'PASS: early boot restored previous enabled profile without old-kernel cleanup'
        ;;
    check-first-recovery)
        [ "$(cat "$state/interrupted.boot")" != "$(cat /proc/sys/kernel/random/boot_id)" ]
        [ ! -e /var/lib/tayga-installer/operation.lock ]
        [ ! -e /var/lib/tayga-installer/files-transaction ]
        [ ! -e /var/lib/tayga-installer/current ]
        [ ! -e /usr/local/sbin/tayga ]
        [ ! -e /etc/tayga/nat64.conf ]
        [ ! -e "$state/stale-cleanup-ran" ]
        [ ! -e /etc/systemd/system/tayga-recovery.service ]
        [ ! -e /etc/init.d/tayga-recovery ]
        if ip link show nat64 >/dev/null 2>&1; then exit 1; fi
        if iptables-save | grep -q TAYGA_SFX; then exit 1; fi
        echo 'PASS: interrupted first installation restored pre-install files and registration'
        ;;
    uninstall)
        /usr/local/sbin/tayga-ctl uninstall siit
        if ip link show siit >/dev/null 2>&1; then exit 1; fi
        [ ! -e /usr/local/sbin/tayga ]
        [ ! -e /etc/systemd/system/tayga-recovery.service ]
        [ ! -e /etc/init.d/tayga-recovery ]
        if iptables-save | grep -q TAYGA_SFX; then exit 1; fi
        rm -f "$lib/tayga-verify.real"
        echo 'PASS: native init uninstall and firewall cleanup'
        ;;
    *) echo 'Expected install|check|arm|check-recovery|uninstall|arm-first|check-first-recovery' >&2; exit 2 ;;
esac
