#!/bin/sh
# Runs only in the disposable peer VM; eth1 is a private QEMU socket link.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ -f /etc/openwrt_release ] && [ "$(cat /proc/1/comm)" = procd ] || exit 2
case "${1:-}" in
    setup)
        /etc/init.d/firewall stop
        /etc/init.d/dnsmasq stop
        ifdown wan6 || :
        ifdown wan || :
        uci set network.wan.auto=0
        uci set network.wan6.auto=0
        uci -q delete network.globals.ula_prefix || :
        uci set network.lease_pool=interface
        uci set network.lease_pool.proto=static
        uci set network.lease_pool.device=lo
        uci add_list network.lease_pool.ip6prefix='fd62:100::/48'
        uci -q delete network.lan.ip6assign || :
        uci set network.lease=interface
        uci set network.lease.proto=static
        uci set network.lease.device=eth1
        uci set network.lease.ip6assign=60
        uci set network.lease.ip6class=lease_pool
        uci set network.lease.ip6hint=0
        uci set network.lease.ip6ifaceid='::1'
        uci set dhcp.lan.ra=disabled
        uci set dhcp.lan.dhcpv6=disabled
        uci set dhcp.lease=dhcp
        uci set dhcp.lease.interface=lease
        uci set dhcp.lease.ra=server
        uci set dhcp.lease.dhcpv6=server
        uci set dhcp.lease.ra_slaac=0
        uci set dhcp.lease.ra_default=2
        uci add_list dhcp.lease.ra_flags=managed-config
        uci set dhcp.lease.ra_mininterval=3
        uci set dhcp.lease.ra_maxinterval=4
        uci set dhcp.lease.leasetime=120s
        uci commit network
        uci commit dhcp
        ubus call network reload
        ifup lease
        /etc/init.d/odhcpd restart
        ;;
    renumber)
        # Make-before-break renumbering: keep the old lease valid while the
        # client learns the replacement prefix through a normal renewal.
        uci add_list network.lease_pool.ip6prefix='fd62:200::/48'
        uci commit network
        ubus call network reload
        /etc/init.d/odhcpd reload
        ;;
    retire-old)
        uci del_list network.lease_pool.ip6prefix='fd62:100::/48'
        uci commit network
        ubus call network reload
        /etc/init.d/odhcpd reload
        ;;
    leases)
        ubus call network.interface.lease status
        leases=$(ubus call dhcp ipv6leases)
        printf '%s\n' "$leases"
        printf '%s\n' "$leases" | jsonfilter -e '@.device.eth1.leases[*]["ipv6-addr"][*].address' | grep -q "^$2"
        printf '%s\n' "$leases" | jsonfilter -e '@.device.eth1.leases[*]["ipv6-prefix"][*].address' | grep -q "^$2"
        printf '%s\n' "$leases" | jsonfilter -e '@.device.eth1.leases[*]["ipv6-prefix"][*]["prefix-length"]' | grep -qx 62
        echo 'PASS: odhcpd reports a real DHCPv6 lease'
        ;;
    *) exit 2 ;;
esac
