#!/bin/sh
# Multi-phase test ONLY inside a disposable, booted OpenWrt VM.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ -f /etc/openwrt_release ] && [ "$(cat /proc/1/comm)" = procd ] || exit 2
state=/etc/tayga-procd-test
service=/etc/init.d/tayga-managed
phase=${1:-}
if command -v opkg >/dev/null 2>&1; then
    package_ext=ipk
    package_install() { opkg install "$@"; }
    package_remove() { opkg remove "$@"; }
else
    command -v apk >/dev/null 2>&1 || exit 2
    package_ext=apk
    # Local unsigned fixtures without persistent package cache; hooks run normally.
    package_install() { apk --no-network --allow-untrusted --force-non-repository add "$@"; }
    package_remove() { apk --no-network del "$@"; }
fi
pid() {
    ubus call service list '{"name":"tayga-managed"}' | jsonfilter -e '@["tayga-managed"].instances.main.pid'
}
running() {
    current=$(pid)
    case "$current" in ''|*[!0-9]*) return 1 ;; esac
    [ -d "/proc/$current" ] || return 1
    [ "$(cat "/proc/$current/comm")" = tayga ] || return 1
    [ "$(ubus call service list '{"name":"tayga-managed"}' | jsonfilter -e '@["tayga-managed"].instances.main.running')" = true ]
}
dhcp_ping() {
    for _ in $(seq 1 25); do
        if ping -6 -c 1 -W 1 -I eth2 "$1"; then return 0; fi
        sleep 1
    done
    return 1
}
dhcp_client_pid() {
    parent=$(pidof netifd)
    for client in $(pidof odhcp6c || :); do
        [ "$(awk '{print $4}' "/proc/$client/stat" 2>/dev/null || :)" = "$parent" ] || continue
        command=$(tr '\000' ' ' < "/proc/$client/cmdline" 2>/dev/null || :)
        case " $command " in *' eth2 '*) echo "$client"; return 0 ;; esac
    done
    return 1
}
wait_running() {
    for _ in $(seq 1 30); do
        if running; then return 0; fi
        sleep 1
    done
    logread -e tayga >&2
    return 1
}
one_owner() {
    running
    # Validation helpers have the same comm but do not own packet I/O.
    owners=0; owner=
    for process in $(pidof tayga || :); do
        cmd=$(tr '\000' ' ' < "/proc/$process/cmdline" 2>/dev/null || :)
        [ -n "$cmd" ] || continue
        case " $cmd " in
            *' --check-config '*|*' --mktun '*|*' --rmtun '*|*' --check-offload '*|*' --help '*) continue ;;
        esac
        owners=$((owners+1)); owner=$process
    done
    [ "$owners" = 1 ] && [ "$owner" = "$(pid)" ]
}
wait_dhcp_owner() {
    # DHCP state, RA routes and procd updates arrive independently. Require
    # repeated agreement instead of asserting ownership between two restarts.
    last_pid=; last_facts=; stable=0
    # Cover the 120-second test lease plus supervisor recovery and stable samples.
    for _ in $(seq 1 240); do
        facts=$(/usr/libexec/tayga/openwrt-uplink tayga_testwan 2>/dev/null || :)
        candidate=$(pid || :)
        if [ "$facts" != "$last_facts" ]; then
            ubus call network.interface.tayga_testwan status >&2 || :
        fi
        if [ -n "$facts" ] && running && one_owner &&
           [ "$candidate" = "$(pid)" ] && [ "$candidate" = "$last_pid" ] &&
           [ "$facts" = "$last_facts" ]; then
            stable=$((stable+1))
            [ "$stable" -lt 3 ] || return 0
        else stable=0; fi
        last_pid=$candidate; last_facts=$facts
        sleep 1
    done
    return 1
}
stopped() {
    for _ in $(seq 1 20); do
        if ! pidof tayga >/dev/null; then return 0; fi
        sleep 1
    done
    return 1
}
wait_new() {
    for _ in $(seq 1 60); do
        if running && [ "$(pid)" != "$1" ]; then
            if [ "$#" -gt 1 ] && [ "$(cat /var/run/tayga-managed/network/wan 2>/dev/null || :)" != "$2" ]; then
                sleep 1
                continue
            fi
            one_owner; return
        fi
        sleep 1
    done
    logread -e tayga >&2
    return 1
}
check_boot() {
    [ "$(cat "$state/boot.before")" != "$(cat /proc/sys/kernel/random/boot_id)" ]
    if [ "$(uci -q get tayga_managed.main.uplink || :)" = tayga_testwan ]; then
        if ! ubus call network.interface.tayga_testwan status | jsonfilter -e '@.up' | grep -qx true; then
            for _ in $(seq 1 30); do
                [ ! -f /var/run/tayga-managed/armed ] || break
                sleep 1
            done
            [ -f /var/run/tayga-managed/armed ]
            stopped
            ifup tayga_testwan
        fi
    fi
    wait_running
    one_owner
    cmp "$state/accepted.conf" /etc/tayga-managed/active.conf
    [ ! -e /etc/tayga-managed/pending ]
    [ ! -e /var/run/tayga-managed/before-reboot ]
    grep -q retained /etc/tayga-managed/data/test-retained
    grep -q invalid /etc/tayga/managed.conf
    grep -q ' /overlay ext4 ' /proc/mounts
    [ -f /sys/class/net/tun64/tun_flags ]
    "$service" status
}
upgrade() {
    if [ "$package_ext" = apk ]; then
        /usr/libexec/tayga/openwrt-upgrade apply "$1" "$2" --allow-untrusted
    else /usr/libexec/tayga/openwrt-upgrade apply "$1" "$2"; fi
}
check_versions() {
    if [ "$package_ext" = apk ]; then
        version=$(apk adbdump "$1/base.apk" | awk '$1=="version:" {print $2; exit}')
        for pkg in tayga-managed-openwrt tayga-managed-openwrt-procd tayga-managed-openwrt-network; do
            apk info --exists "$pkg=$version"
        done
    else
        version=$(tar -xzOf "$1/base.ipk" ./control.tar.gz | tar -xzOf - ./control | awk '$1=="Version:" {print $2; exit}')
        for pkg in tayga-managed-openwrt tayga-managed-openwrt-procd tayga-managed-openwrt-network; do
            [ "$(opkg status "$pkg" | awk '$1=="Version:" {print $2; exit}')" = "$version" ]
        done
    fi
}
wrap_manager() {
    if [ "$package_ext" = apk ]; then manager_path=$(command -v apk); else manager_path=$(command -v opkg); fi
    echo "$manager_path" > "$state/upgrade-manager.path"
    cp "$manager_path" "$state/upgrade-manager.real"
    cat > "$manager_path" <<'EOF'
#!/bin/sh
case "$*" in *--simulate*|*--noaction*)
    mode=$(cat /etc/tayga-procd-test/upgrade-fault 2>/dev/null || :)
    case "$mode" in
        plan-apk) echo '(1/1) Upgrading busybox (1 -> 2)' ;;
        plan-ipk) echo 'Upgrading busybox on root from 1 to 2...' ;;
        *) mode= ;;
    esac
    if [ -n "$mode" ]; then rm /etc/tayga-procd-test/upgrade-fault; exit 0; fi
    ;;
esac
case "$*" in *'/package-upgrade/new/base.'*)
    mode=$(cat /etc/tayga-procd-test/upgrade-fault 2>/dev/null || :)
    if [ -n "$mode" ]; then
        /etc/tayga-procd-test/upgrade-manager.real "$@" || exit $?
        rm /etc/tayga-procd-test/upgrade-fault
        if [ "$mode" = fail ]; then exit 1; fi
        if [ "$mode" = verify ]; then
            cp /usr/libexec/tayga/openwrt-network /etc/tayga-procd-test/upgrade-network.real
            cat > /usr/libexec/tayga/openwrt-network <<'VERIFY_EOF'
#!/bin/sh
if [ "${TAYGA_NETWORK_LIBRARY:-}" = 1 ]; then
    . /etc/tayga-procd-test/upgrade-network.real
    return
fi
[ "$1" != verify ] || exit 1
exec /etc/tayga-procd-test/upgrade-network.real "$@"
VERIFY_EOF
            exit 0
        fi
        # Emulate missing core files during an interrupted unpack. The independent
        # recovery package must repair them before the main init can run.
        rm -f /etc/init.d/tayga-managed /usr/libexec/tayga/openwrt-state /usr/sbin/tayga
        touch /etc/tayga-procd-test/upgrade-cut-ready
        sync
        while :; do sleep 10; done
    fi
    ;;
esac
exec /etc/tayga-procd-test/upgrade-manager.real "$@"
EOF
    chmod 755 "$manager_path"
}
restore_manager() { cp "$state/upgrade-manager.real" "$(cat "$state/upgrade-manager.path")"; }
case "$phase" in
    install)
        packages=${2:?Package directory required}
        [ ! -e "$state" ] && [ ! -e /usr/sbin/tayga ] || exit 2
        mkdir -p "$state"
        cp "$0" "$state/test.sh"
        sha256sum /etc/config/network /etc/config/firewall /etc/config/dhcp > "$state/network.before"
        package_install "$packages/kmod-tun.$package_ext" "$packages/flock.$package_ext"
        if [ -f "$packages/extra-0.$package_ext" ]; then package_install "$packages"/extra-*.$package_ext; fi
        package_install "$packages/base.$package_ext" "$packages/procd.$package_ext"
        if [ -f "$packages/network.$package_ext" ]; then package_install "$packages/network.$package_ext"; fi
        if [ -f "$packages/upgrader.$package_ext" ]; then
            package_install "$packages/upgrader.$package_ext"
            /etc/init.d/tayga-package-recovery enabled
        fi
        if [ -f "$packages/next-base.$package_ext" ]; then
            mkdir "$state/upgrade-old" "$state/upgrade-new"
            for role in base procd network; do
                cp "$packages/$role.$package_ext" "$state/upgrade-old/$role.$package_ext"
                cp "$packages/next-$role.$package_ext" "$state/upgrade-new/$role.$package_ext"
            done
        fi
        [ "$(uci -q get tayga_managed.main.enabled)" = 0 ]
        stopped
        mkdir -p "$state/data"
        cat > "$state/network.conf" <<'EOF'
tun-device tun64
ipv4-addr 192.0.2.1
ipv6-addr fd64::1
prefix fd64:100::/96
dynamic-pool 192.168.240.0/20
data-dir /etc/tayga-procd-test/data
workers 0
tun-offload off
EOF
        cp "$state/network.conf" /etc/tayga/managed.conf
        for device in twan0 twan1; do
            sed "s/tun-device tun64/tun-device $device/" "$state/network.conf" > "$state/$device.conf"
        done
        cat > /etc/init.d/tayga-test-tun <<'EOF'
#!/bin/sh /etc/rc.common
START=90
STOP=15
start() {
    modprobe tun || return 1
    for device in tun64 twan0 twan1; do
        config=/etc/tayga-procd-test/$device.conf
        [ "$device" != tun64 ] || config=/etc/tayga-procd-test/network.conf
        if [ ! -e "/sys/class/net/$device" ]; then
            /usr/sbin/tayga --mktun --config "$config" || return 1
        fi
        ip link set "$device" up || return 1
    done
}
stop() {
    for device in tun64 twan0 twan1; do
        config=/etc/tayga-procd-test/$device.conf
        [ "$device" != tun64 ] || config=/etc/tayga-procd-test/network.conf
        /usr/sbin/tayga --rmtun --config "$config" || return 1
    done
}
EOF
        chmod 755 /etc/init.d/tayga-test-tun
        /etc/init.d/tayga-test-tun enable
        /etc/init.d/tayga-test-tun start
        uci set tayga_managed.main.enabled=1
        uci commit tayga_managed
        "$service" enable
        "$service" start
        wait_running
        one_owner
        cp /etc/tayga-managed/active.conf "$state/accepted.conf"
        echo retained > /etc/tayga-managed/data/test-retained
        echo 'PASS: disabled package install and explicit procd start'
        ;;
    lifecycle)
        one_owner
        first=$(pid)
        "$service" start
        sleep 2
        [ "$(pid)" = "$first" ]
        "$service" stop
        stopped
        [ -f /sys/class/net/tun64/tun_flags ]
        "$service" start
        wait_running
        [ "$(pid)" != "$first" ]
        first=$(pid)
        "$service" restart
        wait_running
        [ "$(pid)" != "$first" ]
        one_owner
        first=$(pid)
        echo invalid >> /etc/tayga/managed.conf
        if "$service" reload; then echo 'Invalid reload unexpectedly succeeded' >&2; exit 1; fi
        sleep 2
        [ "$(pid)" = "$first" ]
        cmp "$state/accepted.conf" /etc/tayga-managed/active.conf
        # rc.common still closes a start message after a rejected candidate.
        "$service" start
        sleep 2
        [ "$(pid)" = "$first" ]
        cp "$state/network.conf" /etc/tayga/managed.conf
        echo '# valid reload' >> /etc/tayga/managed.conf
        "$service" reload
        for _ in $(seq 1 20); do
            if running && [ "$(pid)" != "$first" ]; then break; fi
            sleep 1
        done
        [ "$(pid)" != "$first" ]
        one_owner
        cp /etc/tayga-managed/active.conf "$state/accepted.conf"
        first=$(pid)
        kill -KILL "$first"
        for _ in $(seq 1 20); do
            if running && [ "$(pid)" != "$first" ]; then break; fi
            sleep 1
        done
        [ "$(pid)" != "$first" ]
        one_owner
        echo 'PASS: start/stop/restart, rejected/valid reload and procd respawn'
        ;;
    uplink-facts)
        mkdir -p "$state/mockbin"
        cat > "$state/mockbin/ubus" <<'EOF'
#!/bin/sh
cat /etc/tayga-procd-test/status.json
EOF
        chmod 755 "$state/mockbin/ubus"
        cat > "$state/status.json" <<'EOF'
{"up":true,"l3_device":"twan0","uptime":1,"ipv6-address":[{"address":"fd64:aaaa::1","mask":64,"preferred":100,"valid":200},{"address":"fd64:aaaa::2","mask":64}],"ipv6-prefix":[{"address":"fd64:aa00::","mask":56,"preferred":100,"valid":200}],"route":[{"target":"::","mask":0,"nexthop":"fd64:aaaa::ff","metric":10}]}
EOF
        first=$(PATH="$state/mockbin:$PATH" /usr/libexec/tayga/openwrt-uplink tayga_testwan)
        cat > "$state/status.json" <<'EOF'
{"up":true,"l3_device":"twan0","uptime":900,"ipv6-address":[{"address":"fd64:aaaa::2","mask":64},{"address":"fd64:aaaa::1","mask":64,"preferred":90,"valid":190}],"ipv6-prefix":[{"address":"fd64:aa00::","mask":56,"preferred":90,"valid":190}],"route":[{"target":"::","mask":0,"nexthop":"fd64:aaaa::ff","metric":10}]}
EOF
        second=$(PATH="$state/mockbin:$PATH" /usr/libexec/tayga/openwrt-uplink tayga_testwan)
        [ "$first" = "$second" ]
        sed 's/aaaa::ff/aaaa::fe/' "$state/status.json" > "$state/status.new"
        mv "$state/status.new" "$state/status.json"
        second=$(PATH="$state/mockbin:$PATH" /usr/libexec/tayga/openwrt-uplink tayga_testwan)
        [ "$first" != "$second" ]
        echo '{"up":false}' > "$state/status.json"
        result=0
        PATH="$state/mockbin:$PATH" /usr/libexec/tayga/openwrt-uplink tayga_testwan || result=$?
        [ "$result" = 3 ]
        echo 'PASS: stable uplink fingerprint ignores order/lifetimes and detects gateway changes'
        ;;
    wan)
        [ -x /usr/libexec/tayga/openwrt-uplink ]
        one_owner
        uci set network.tayga_testwan=interface
        uci set network.tayga_testwan.proto=static
        uci set network.tayga_testwan.device=twan0
        uci set network.tayga_testwan.force_link=1
        uci set network.tayga_testwan.auto=0
        uci set network.tayga_testwan.ip6addr='fd64:aaaa::1/64'
        uci set network.tayga_testwan.ip6prefix='fd64:aa00::/56'
        uci commit network
        ubus call network reload
        uci set tayga_managed.main.uplink=tayga_testwan
        uci commit tayga_managed
        "$service" reload
        stopped
        [ -f /var/run/tayga-managed/armed ]
        ifup tayga_testwan
        wait_running
        one_owner
        first=$(pid)
        ACTION=ifupdate INTERFACE=tayga_testwan IFUPDATE_ADDRESSES=1 /sbin/hotplug-call iface
        ACTION=ifupdate INTERFACE=lan IFUPDATE_ADDRESSES=1 /sbin/hotplug-call iface
        sleep 2
        [ "$(pid)" = "$first" ]
        ifdown tayga_testwan
        stopped
        [ -f /sys/class/net/tun64/tun_flags ]
        [ -f /var/run/tayga-managed/armed ]
        echo invalid >> /etc/tayga/managed.conf
        ifup tayga_testwan
        wait_new "$first"
        cmp "$state/accepted.conf" /etc/tayga-managed/active.conf
        first=$(pid)
        uci set network.tayga_testwan.ip6addr='fd64:bbbb::1/64'
        uci set network.tayga_testwan.ip6prefix='fd64:bb00::/56'
        uci commit network
        ubus call network reload
        wait_new "$first"
        first=$(pid)
        uci set network.tayga_testwan.device=twan1
        uci commit network
        ubus call network reload
        wait_new "$first"
        [ "$(ubus call network.interface.tayga_testwan status | jsonfilter -e '@.l3_device')" = twan1 ]
        "$service" stop
        stopped
        [ ! -e /var/run/tayga-managed/armed ]
        ifdown tayga_testwan
        ifup tayga_testwan
        sleep 2
        stopped
        cp "$state/accepted.conf" /etc/tayga/managed.conf
        "$service" start
        wait_running
        one_owner
        cmp "$state/accepted.conf" /etc/tayga-managed/active.conf
        echo 'PASS: real netifd down/up, IPv6 renumber, device handover, duplicate events and manual stop'
        ;;
    arm-reboot|arm-powercut)
        one_owner
        cat /proc/sys/kernel/random/boot_id > "$state/boot.before"
        touch /var/run/tayga-managed/before-reboot
        echo invalid >> /etc/tayga/managed.conf
        if [ "$phase" = arm-powercut ]; then
            "$service" stop
            stopped
            mkdir /etc/tayga-managed/pending
            cp "$state/accepted.conf" /etc/tayga-managed/pending/old.conf
            echo yes > /etc/tayga-managed/pending/previous
            echo v1 > /etc/tayga-managed/pending/ready
            echo interrupted > /etc/tayga-managed/active.conf
        fi
        sync
        echo "PASS: $phase armed"
        ;;
    check-boot)
        check_boot
        echo 'PASS: real boot restored accepted snapshot and persistent data'
        ;;
    upgrade-failure)
        "$service" stop
        stopped
        uci set network.tayga_testwan.device=eth1
        uci set network.tayga_testwan.ipaddr=10.0.3.15
        uci set network.tayga_testwan.netmask=255.255.255.0
        uci set network.tayga_testwan.ip6addr='fd42:3::15/64'
        uci -q delete network.tayga_testwan.ip6prefix || :
        uci commit network
        ubus call network reload
        ifup tayga_testwan
        sh /usr/libexec/tayga/configure.sh --mode=nat64 --pref64=fd64:100::/96 \
            --tayga-ipv6=fd64::2 --tun-ipv6=fd64::1 --offload=off --workers=0 \
            --output=/etc/tayga/upgrade.conf
        uci set tayga_managed.main.network_mode=managed
        uci set tayga_managed.main.inside=lan
        uci set tayga_managed.main.config=/etc/tayga/upgrade.conf
        uci commit tayga_managed
        "$service" start
        wait_running
        one_owner
        cp /etc/tayga-managed/active.conf "$state/upgrade.accepted"
        echo upgrade-retained > /etc/tayga-managed/data/upgrade-retained
        ping -6 -c 1 -W 3 -I fd64::1 fd64:100::a00:302
        first=$(pid)
        mkdir "$state/upgrade-bad"
        cp "$state/upgrade-new/"* "$state/upgrade-bad/"
        echo corrupt > "$state/upgrade-bad/procd.$package_ext"
        if upgrade "$state/upgrade-old" "$state/upgrade-bad"; then exit 1; fi
        [ "$(pid)" = "$first" ]
        [ ! -e /etc/tayga-managed/package-upgrade ]
        wrap_manager
        echo "plan-$package_ext" > "$state/upgrade-fault"
        if upgrade "$state/upgrade-old" "$state/upgrade-new"; then exit 1; fi
        [ ! -f "$state/upgrade-fault" ]
        [ "$(pid)" = "$first" ]
        [ ! -e /etc/tayga-managed/package-upgrade ]
        restore_manager
        wrap_manager
        echo fail > "$state/upgrade-fault"
        if upgrade "$state/upgrade-old" "$state/upgrade-new"; then exit 1; fi
        [ ! -f "$state/upgrade-fault" ]
        restore_manager
        check_versions "$state/upgrade-old"
        wait_running
        one_owner
        cmp "$state/upgrade.accepted" /etc/tayga-managed/active.conf
        grep -q upgrade-retained /etc/tayga-managed/data/upgrade-retained
        [ ! -e /etc/tayga-managed/package-upgrade ]
        ping -6 -c 1 -W 3 -I fd64::1 fd64:100::a00:302
        first=$(pid)
        /usr/libexec/tayga/openwrt-upgrade recover
        [ "$(pid)" = "$first" ]
        echo 'PASS: malformed upgrade preflight preserves service; manager failure restores old packages and traffic'
        ;;
    upgrade-readiness-failure)
        wrap_manager
        echo verify > "$state/upgrade-fault"
        if upgrade "$state/upgrade-old" "$state/upgrade-new"; then exit 1; fi
        [ ! -f "$state/upgrade-fault" ]
        restore_manager
        check_versions "$state/upgrade-old"
        wait_running
        one_owner
        [ ! -e /etc/tayga-managed/package-upgrade ]
        cmp "$state/upgrade.accepted" /etc/tayga-managed/active.conf
        ping -6 -c 1 -W 3 -I fd64::1 fd64:100::a00:302
        echo 'PASS: failed target readiness restores previous packages and managed traffic'
        ;;
    arm-upgrade-powercut)
        rm -f "$state/upgrade-cut-ready"
        wrap_manager
        echo cut > "$state/upgrade-fault"
        cat /proc/sys/kernel/random/boot_id > "$state/upgrade.boot.before"
        # The manager wrapper pauses only after the new packages are installed.
        TAYGA_ISOLATED_TEST=yes sh "$0" run-upgrade > "$state/upgrade-background.log" 2>&1 </dev/null &
        for _ in $(seq 1 120); do
            if [ -f "$state/upgrade-cut-ready" ]; then
                [ -d /etc/tayga-managed/package-upgrade ]
                sync
                echo 'PASS: power cut armed after target package installation, before confirmation'
                exit 0
            fi
            sleep 1
        done
        cat "$state/upgrade-background.log" >&2
        exit 1
        ;;
    run-upgrade) upgrade "$state/upgrade-old" "$state/upgrade-new" ;;
    check-upgrade-recovery)
        [ "$(cat "$state/upgrade.boot.before")" != "$(cat /proc/sys/kernel/random/boot_id)" ]
        for _ in $(seq 1 90); do
            [ -d /etc/tayga-managed/package-upgrade ] || break
            sleep 1
        done
        [ ! -e /etc/tayga-managed/package-upgrade ]
        restore_manager
        check_versions "$state/upgrade-old"
        # START=90 could not create test-only external TUNs while tayga was absent.
        /etc/init.d/tayga-test-tun start
        ifup tayga_testwan
        wait_running
        one_owner
        cmp "$state/upgrade.accepted" /etc/tayga-managed/active.conf
        grep -q upgrade-retained /etc/tayga-managed/data/upgrade-retained
        ping -6 -c 1 -W 3 -I fd64::1 fd64:100::a00:302
        echo 'PASS: reboot recovered previous package set, accepted config, data and managed traffic'
        ;;
    upgrade-success)
        echo invalid >> /etc/tayga/upgrade.conf
        upgrade "$state/upgrade-old" "$state/upgrade-new"
        check_versions "$state/upgrade-new"
        wait_running
        one_owner
        cmp "$state/upgrade.accepted" /etc/tayga-managed/active.conf
        grep -q upgrade-retained /etc/tayga-managed/data/upgrade-retained
        ping -6 -c 1 -W 3 -I fd64::1 fd64:100::a00:302
        "$service" stop
        upgrade "$state/upgrade-new" "$state/upgrade-new"
        sleep 2
        stopped
        [ ! -f /var/run/tayga-managed/armed ]
        "$service" boot
        wait_running
        "$service" stop
        uci set tayga_managed.main.network_mode=external
        uci set tayga_managed.main.config=/etc/tayga/managed.conf
        uci commit tayga_managed
        cp "$state/accepted.conf" /etc/tayga/managed.conf
        "$service" start
        wait_running
        echo 'PASS: active upgrade and stopped reinstall preserve activation policy and accepted snapshot'
        ;;
    dhcpv6-start)
        # This third NIC is outside the stock WAN firewall zone. Keep test-only
        # input rules across fw4 hotplug reloads, without editing firewall UCI.
        mkdir -p /usr/share/nftables.d/chain-pre/input
        cat > /usr/share/nftables.d/chain-pre/input/95-tayga-dhcpv6-test.nft <<'EOF'
iifname "eth2" meta l4proto ipv6-icmp accept
iifname "eth2" udp dport 546 accept
EOF
        fw4 reload
        "$service" stop
        stopped
        ifdown tayga_testwan
        # Hold the physical link up before starting the DHCPv6-only interface,
        # just as a separate lower-layer WAN interface would on a router.
        uci set network.tayga_lease_link=interface
        uci set network.tayga_lease_link.proto=none
        uci set network.tayga_lease_link.device=eth2
        uci commit network
        ubus call network reload
        ifup tayga_lease_link
        for _ in $(seq 1 25); do
            if ip -6 addr show dev eth2 scope link | grep -q 'inet6 fe80:' &&
               ! ip -6 addr show dev eth2 scope link | grep -q tentative; then break; fi
            sleep 1
        done
        ip -6 addr show dev eth2 scope link | grep 'inet6 fe80:'
        uci set network.tayga_testwan.device=@tayga_lease_link
        uci set network.tayga_testwan.proto=dhcpv6
        for option in ipaddr netmask ip6addr ip6prefix; do
            uci -q delete "network.tayga_testwan.$option" || :
        done
        uci set network.tayga_testwan.reqaddress=force
        uci set network.tayga_testwan.reqprefix=62
        uci set network.tayga_testwan.peerdns=0
        uci set network.tayga_testwan.defaultroute=0
        uci commit network
        ubus call network reload
        ifup tayga_testwan
        for _ in $(seq 1 90); do
            status=$(ubus call network.interface.tayga_testwan status)
            if printf '%s' "$status" | jsonfilter -e '@["ipv6-address"][0].address' | grep -q '^fd62:100:' &&
               printf '%s' "$status" | jsonfilter -e '@["ipv6-prefix"][0].address' | grep -q '^fd62:100:'; then break; fi
            sleep 1
        done
        printf '%s\n' "$status" > "$state/dhcpv6-initial.json"
        printf '%s' "$status" | jsonfilter -e '@["ipv6-address"][0].address' | grep -q '^fd62:100:'
        [ "$(printf '%s' "$status" | jsonfilter -e '@["ipv6-prefix"][0].mask')" = 62 ]
        cp /etc/tayga-managed/active.conf "$state/dhcpv6-accepted.conf"
        "$service" boot
        wait_dhcp_owner
        /usr/libexec/tayga/openwrt-uplink tayga_testwan > "$state/dhcpv6-initial.facts"
        pid > "$state/dhcpv6-initial.pid"
        dhcp_client_pid > "$state/dhcpv6-client.pid"
        dhcp_ping fd62:100::1
        echo 'PASS: stateful DHCPv6 IA_NA and IA_PD /62 received from odhcpd; SLAAC disabled'
        ;;
    dhcpv6-renew)
        # A lifetime-only renew must not change the supervisor's stable facts.
        first=$(pid)
        ubus call network.interface.tayga_testwan renew
        sleep 8
        /usr/libexec/tayga/openwrt-uplink tayga_testwan > "$state/dhcpv6-renew.facts"
        cmp "$state/dhcpv6-initial.facts" "$state/dhcpv6-renew.facts"
        [ "$(dhcp_client_pid)" = "$(cat "$state/dhcpv6-client.pid")" ]
        [ "$(pid)" = "$first" ]
        one_owner
        echo 'PASS: DHCPv6 renew retains stable facts and the supervised PID'
        ;;
    dhcpv6-renumber)
        first=$(cat "$state/dhcpv6-initial.pid")
        # Keep odhcp6c alive: odhcpd reconfigure / normal lease renewal must
        # deliver the replacement address and delegated prefix without ifup.
        for _ in $(seq 1 150); do
            status=$(ubus call network.interface.tayga_testwan status)
            addresses=$(printf '%s' "$status" | jsonfilter -e '@["ipv6-address"][*].address' || :)
            prefixes=$(printf '%s' "$status" | jsonfilter -e '@["ipv6-prefix"][*].address' || :)
            if printf '%s\n' "$addresses" | grep -q '^fd62:200:' &&
               printf '%s\n' "$prefixes" | grep -q '^fd62:200:'; then break; fi
            sleep 1
        done
        printf '%s\n' "$status" > "$state/dhcpv6-renumbered.json"
        printf '%s\n' "$addresses" | grep -q '^fd62:200:'
        printf '%s\n' "$prefixes" | grep -q '^fd62:200:'
        wait_dhcp_owner
        [ "$(pid)" != "$first" ]
        [ "$(dhcp_client_pid)" = "$(cat "$state/dhcpv6-client.pid")" ]
        /usr/libexec/tayga/openwrt-uplink tayga_testwan > "$state/dhcpv6-renumbered.facts"
        if cmp -s "$state/dhcpv6-initial.facts" "$state/dhcpv6-renumbered.facts"; then exit 1; fi
        cmp "$state/dhcpv6-accepted.conf" /etc/tayga-managed/active.conf
        dhcp_ping fd62:200::1
        echo 'PASS: DHCPv6 renumber changes IA_NA/IA_PD and supervised PID, preserving the accepted config'
        ;;
    dhcpv6-retire)
        for _ in $(seq 1 150); do
            status=$(ubus call network.interface.tayga_testwan status)
            addresses=$(printf '%s' "$status" | jsonfilter -e '@["ipv6-address"][*].address' || :)
            prefixes=$(printf '%s' "$status" | jsonfilter -e '@["ipv6-prefix"][*].address' || :)
            if printf '%s\n' "$addresses" | grep -q '^fd62:200:' &&
               printf '%s\n' "$prefixes" | grep -q '^fd62:200:' &&
               ! printf '%s\n' "$addresses" "$prefixes" | grep -q '^fd62:100:'; then break; fi
            sleep 1
        done
        printf '%s\n' "$addresses" | grep -q '^fd62:200:'
        printf '%s\n' "$prefixes" | grep -q '^fd62:200:'
        if printf '%s\n' "$addresses" "$prefixes" | grep -q '^fd62:100:'; then exit 1; fi
        [ "$(dhcp_client_pid)" = "$(cat "$state/dhcpv6-client.pid")" ]
        wait_dhcp_owner
        cmp "$state/dhcpv6-accepted.conf" /etc/tayga-managed/active.conf
        dhcp_ping fd62:200::1
        echo 'PASS: retired DHCPv6 prefix removed; replacement lease and accepted config retained'
        ;;
    dhcpv6-stop)
        rm -f /usr/share/nftables.d/chain-pre/input/95-tayga-dhcpv6-test.nft
        fw4 reload
        "$service" stop
        stopped
        ifdown tayga_testwan
        ifdown tayga_lease_link
        uci delete network.tayga_lease_link
        for option in reqaddress reqprefix peerdns defaultroute; do
            uci -q delete "network.tayga_testwan.$option" || :
        done
        uci set network.tayga_testwan.proto=static
        uci commit network
        ;;
    managed)
        "$service" stop
        stopped
        uci set network.tayga_testwan.device=eth1
        uci set network.tayga_testwan.ipaddr=10.0.3.15
        uci set network.tayga_testwan.netmask=255.255.255.0
        uci set network.tayga_testwan.ip6addr='fd42:3::15/64'
        uci -q delete network.tayga_testwan.ip6prefix || :
        uci commit network
        ubus call network reload
        ifup tayga_testwan
        for _ in $(seq 1 20); do
            if ubus call network.interface.tayga_testwan status | jsonfilter -e '@.up' | grep -qx true; then break; fi
            sleep 1
        done
        echo '10.0.3.2 v4gw.nat64.internal v4gw.nat64.internal.lan' > /tmp/tayga-dns64.hosts
        sh /usr/libexec/tayga/configure.sh --mode=nat64 --pref64=fd64:100::/96 \
            --tayga-ipv6=fd64::2 --tun-ipv6=fd64::1 --dns64=yes --dns64-upstream=127.0.0.1@5399 \
            --offload=off --workers=0 --output=/etc/tayga/managed-nat64.conf
        uci set tayga_managed.main.network_mode=managed
        uci set tayga_managed.main.inside=lan
        uci set tayga_managed.main.config=/etc/tayga/managed-nat64.conf
        uci commit tayga_managed
        # Reject a pre-existing foreign TUN without claiming or deleting it.
        sed 's/tun-device nat64/tun-device tmg0/' /etc/tayga/managed-nat64.conf > "$state/foreign.conf"
        tayga --mktun --config "$state/foreign.conf"
        echo administrator > /sys/class/net/tmg0/ifalias
        if "$service" start; then echo 'Foreign TUN start unexpectedly succeeded' >&2; exit 1; fi
        stopped
        [ "$(cat /sys/class/net/tmg0/ifalias)" = administrator ]
        [ ! -e /var/run/tayga-managed/network ]
        "$service" stop
        ip link delete dev tmg0
        # Inject a single fw4 failure after TUN creation, then verify rollback.
        cp /sbin/fw4 "$state/fw4.original"
        touch "$state/fail-fw4"
        cat > /sbin/fw4 <<'EOF'
#!/bin/sh
if [ "$1" = check ] && [ -e /sys/class/net/tmg0 ] && [ -f /etc/tayga-procd-test/fail-fw4 ]; then
    rm /etc/tayga-procd-test/fail-fw4
    exit 1
fi
exec /etc/tayga-procd-test/fw4.original "$@"
EOF
        chmod 755 /sbin/fw4
        if "$service" start; then echo 'Injected fw4 failure unexpectedly succeeded' >&2; exit 1; fi
        stopped
        "$service" stop
        [ ! -e /sys/class/net/tmg0 ]
        [ ! -e /var/run/tayga-managed/network ]
        [ ! -e "$state/fail-fw4" ]
        cp "$state/fw4.original" /sbin/fw4
        "$service" start
        wait_running
        one_owner
        [ -e /sys/class/net/tmg0/tun_flags ]
        ip -6 route show exact fd64:100::/96 | grep 'dev tmg0'
        ip -4 route show exact 192.168.240.0/20 | grep 'dev tmg0'
        nft list chain inet fw4 srcnat | grep 'tayga-managed NAT64'
        ping -6 -c 3 -W 3 -I fd64::1 fd64:100::a00:302
        # Verify DNS64 + dnsmasq runtime drop-in end-to-end.
        pref64-discover -s 127.0.0.1 -t 2 | grep -Fx 'fd64:100::/96'
        nslookup -type=AAAA v4gw.nat64.internal 127.0.0.1 | grep -i 'fd64:100::a00:302'
        ping -6 -c 2 -W 3 -I fd64::1 v4gw.nat64.internal
        fw4 reload
        nft list chain inet fw4 srcnat | grep 'tayga-managed NAT64'
        first=$(pid)
        uci set network.tayga_testwan.device=twan0
        uci commit network
        ubus call network reload
        wait_new "$first" twan0
        [ "$(cat /var/run/tayga-managed/network/wan)" = twan0 ]
        first=$(pid)
        uci set network.tayga_testwan.device=eth1
        uci commit network
        ubus call network reload
        wait_new "$first" eth1
        [ "$(cat /var/run/tayga-managed/network/wan)" = eth1 ]
        ping -6 -c 2 -W 3 -I fd64::1 fd64:100::a00:302
        first=$(pid)
        uci set network.tayga_testinside=interface
        uci set network.tayga_testinside.proto=static
        uci set network.tayga_testinside.device=twan1
        uci set network.tayga_testinside.force_link=1
        uci set network.tayga_testinside.ipaddr=198.19.0.1
        uci set network.tayga_testinside.netmask=255.255.255.0
        uci set network.tayga_testinside.ip6addr='fd99:19::1/64'
        uci commit network
        ubus call network reload
        ifup tayga_testinside
        for _ in $(seq 1 20); do
            if ubus call network.interface.tayga_testinside status | jsonfilter -e '@.up' | grep -qx true; then break; fi
            sleep 1
        done
        uci set tayga_managed.main.inside=tayga_testinside
        uci commit tayga_managed
        "$service" reload
        wait_new "$first"
        [ "$(cat /var/run/tayga-managed/network/inside)" = twan1 ]
        ping -6 -c 2 -W 3 -I fd64::1 fd64:100::a00:302
        # Verify forwarded LAN-client traffic through NAT64 on inside interface twan1.
        pref64-discover --tun-client6 twan1 fd99:19::2 fd64:100::a00:302
        nft list chain inet fw4 forward | grep 'iifname "twan1" oifname "tmg0".*packets [1-9]'
        # Direct manual state prepare without service coordination remains fenced.
        cp /etc/tayga-managed/active.conf "$state/nat64.accepted"
        cp /etc/tayga/managed-nat64.conf "$state/managed-nat64.good"
        echo '# fenced direct prepare' >> /etc/tayga/managed-nat64.conf
        if /usr/libexec/tayga/openwrt-state prepare /etc/tayga/managed-nat64.conf managed; then
            echo 'Direct uncoordinated state prepare must be refused' >&2
            exit 1
        fi
        cmp "$state/nat64.accepted" /etc/tayga-managed/active.conf
        # Readiness failure triggers automatic rollback to previous working NAT64 profile.
        cp "$state/managed-nat64.good" /etc/tayga/managed-nat64.conf
        echo '# installer-verify-target 10.0.3.250' >> /etc/tayga/managed-nat64.conf
        if "$service" reload; then
            echo 'Readiness failure reload unexpectedly succeeded' >&2
            exit 1
        fi
        wait_running
        one_owner
        cmp "$state/nat64.accepted" /etc/tayga-managed/active.conf
        ping -6 -c 2 -W 3 -I fd64::1 fd64:100::a00:302
        cp "$state/managed-nat64.good" /etc/tayga/managed-nat64.conf
        # Test real DHCPv6/RA dynamic uplink via odhcp6c on eth1 (QEMU slirp RA responder).
        first=$(pid)
        # The stock image also runs wan6 on eth1. Use a single DHCPv6 client
        # on this link; newer netifd rejects the competing client setup.
        default6=$(ubus -t 5 call network.interface.wan6 status 2>/dev/null | jsonfilter -e '@.l3_device' || :)
        if [ "$default6" = eth1 ]; then ifdown wan6; fi
        uci delete network.tayga_testwan.ip6addr
        uci set network.tayga_testwan.proto=dhcpv6
        uci set network.tayga_testwan.reqaddress=try
        uci set network.tayga_testwan.reqprefix=no
        uci commit network
        ubus call network reload
        ifup tayga_testwan
        for _ in $(seq 1 25); do
            if ubus call network.interface.tayga_testwan status | jsonfilter -e '@["ipv6-address"][0].address' | grep -q '^fd42:3:'; then
                break
            fi
            sleep 1
        done
        ubus call network.interface.tayga_testwan status | jsonfilter -e '@["ipv6-address"][0].address' | grep -q '^fd42:3:'
        wait_dhcp_owner
        [ "$(cat /var/run/tayga-managed/network/wan)" = eth1 ]
        # Switch tayga_testwan to twan0 with an active IPv6 responder for SIIT and CLAT data-path tests.
        uci set network.tayga_testwan.proto=static
        uci set network.tayga_testwan.device=twan0
        uci set network.tayga_testwan.ipaddr=10.0.3.15
        uci set network.tayga_testwan.netmask=255.255.255.0
        uci set network.tayga_testwan.ip6addr='fd42:3::15/64'
        uci commit network
        ubus call network reload
        ifup tayga_testwan
        for _ in $(seq 1 20); do
            if [ "$(ubus call network.interface.tayga_testwan status | jsonfilter -e '@.l3_device')" = twan0 ]; then break; fi
            sleep 1
        done
        pref64-discover --tun-echo6 twan0 >/dev/null 2>&1 &
        echo_pid=$!
        sh /usr/libexec/tayga/configure.sh --mode=siit --pref64=fd64:100::/96 \
            --map-ipv4=198.18.0.1 --map-ipv6=fd42:3::2 --tayga-ipv6=fd64::2 \
            --offload=off --workers=0 --output=/etc/tayga/managed-siit.conf
        uci set tayga_managed.main.config=/etc/tayga/managed-siit.conf
        uci commit tayga_managed
        "$service" reload
        wait_running
        one_owner
        ip -4 route show exact 198.18.0.1/32 | grep 'dev tmg0'
        nft list chain inet fw4 forward | grep 'tayga-managed SIIT'
        if nft list chain inet fw4 srcnat | grep -q 'tayga-managed NAT64'; then kill "$echo_pid" || :; exit 1; fi
        if ls /tmp/dnsmasq*.d/95-tayga-managed.conf >/dev/null 2>&1; then kill "$echo_pid" || :; exit 1; fi
        # Real SIIT packet translation (router-local and forwarded LAN client on twan1).
        ping -4 -I 198.19.0.1 -c 2 -W 3 198.18.0.1
        pref64-discover --tun-client4 twan1 198.19.0.2 198.18.0.1
        nft list chain inet fw4 forward | grep 'iifname "twan1" oifname "tmg0" ip daddr 198.18.0.1.*packets [1-9]'
        # Managed CLAT routing, DNS drop-in, router-local and forwarded LAN client translation.
        ip -6 route replace fd64:100::/96 dev twan0 metric 128
        sh /usr/libexec/tayga/configure.sh --mode=clat --pref64=fd64:100::/96 \
            --tayga-ipv6=fd42:3::16 --clat-ipv6=fd42:3::17 --host-dns=public \
            --offload=off --workers=0 --output=/etc/tayga/managed-clat.conf
        uci set tayga_managed.main.config=/etc/tayga/managed-clat.conf
        uci commit tayga_managed
        "$service" reload
        wait_running
        one_owner
        ip -4 route show exact 0.0.0.0/1 | grep 'dev tmg0'
        ip -4 route show exact 128.0.0.0/1 | grep 'dev tmg0'
        ip -6 route show exact fd42:3::17 | grep 'dev tmg0'
        grep -Fx 'server=1.1.1.1' /tmp/dnsmasq.d/95-tayga-managed.conf
        ping -4 -c 2 -W 3 198.51.100.1
        pref64-discover --tun-client4 twan1 198.19.0.2 198.51.100.1
        nft list chain inet fw4 srcnat | grep 'counter packets [1-9].*tayga-managed CLAT LAN masq'
        kill "$echo_pid" 2>/dev/null || :
        wait "$echo_pid" 2>/dev/null || :
        ip -6 route del fd64:100::/96 dev twan0 metric 128 2>/dev/null || :
        rm -f /tmp/tayga-dns64.hosts
        if [ -f /usr/libexec/tayga/package-upgrade-api ]; then package_remove tayga-managed-openwrt-upgrade; fi
        package_remove tayga-managed-openwrt-network
        stopped
        [ ! -e /sys/class/net/tmg0 ]
        [ ! -e /var/run/tayga-managed/network ]
        if ls /tmp/dnsmasq*.d/95-tayga-managed.conf >/dev/null 2>&1; then exit 1; fi
        if nft list ruleset | grep -q 'tayga-managed'; then exit 1; fi
        uci set tayga_managed.main.network_mode=external
        uci set tayga_managed.main.config=/etc/tayga/managed.conf
        uci commit tayga_managed
        cp "$state/accepted.conf" /etc/tayga/managed.conf
        "$service" start
        wait_running
        one_owner
        echo invalid >> /etc/tayga/managed.conf
        echo 'PASS: managed NAT64/DNS64/SIIT/CLAT, forwarded LAN traffic, readiness rollback, DHCPv6/RA and active removal'
        ;;
    remove)
        check_boot
        "$service" stop
        stopped
        [ -f /sys/class/net/tun64/tun_flags ]
        if [ -f /usr/libexec/tayga/package-upgrade-api ]; then package_remove tayga-managed-openwrt-upgrade; fi
        package_remove tayga-managed-openwrt-procd
        [ "$(uci -q get tayga_managed.main.enabled)" = 1 ]
        [ -f /etc/tayga-managed/active.conf ]
        grep -q retained /etc/tayga-managed/data/test-retained
        if uci -q get network.tayga_testwan >/dev/null; then
            ifdown tayga_testwan
            uci delete network.tayga_testwan
            uci commit network
            ubus call network reload
        fi
        if uci -q get network.tayga_testinside >/dev/null; then
            ifdown tayga_testinside
            uci delete network.tayga_testinside
            uci commit network
            ubus call network reload
        fi
        /etc/init.d/tayga-test-tun disable
        /etc/init.d/tayga-test-tun stop
        [ ! -e /sys/class/net/tun64 ]
        package_remove tayga-managed-openwrt
        [ ! -e /usr/sbin/tayga ]
        stopped
        sha256sum /etc/config/network /etc/config/firewall /etc/config/dhcp > "$state/network.after"
        cmp "$state/network.before" "$state/network.after"
        echo 'PASS: remove retains state/UCI; LAN/firewall/DHCP unchanged'
        ;;
    *) exit 2 ;;
esac
