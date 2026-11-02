#!/bin/sh
# Read netifd state only. Stable facts exclude DHCP/RA lifetime counters.
set -e
[ "$#" -eq 1 ] || exit 2
uplink=$1
case "$uplink" in ''|*[!a-zA-Z0-9_]*) echo 'Invalid logical uplink name' >&2; exit 1 ;; esac
status=$(ubus -t 5 call "network.interface.$uplink" status 2>/dev/null) || exit 3
# shellcheck source=/dev/null
. /usr/share/libubox/jshn.sh
json_load "$status" || exit 1
json_get_var up up || up=0
case "$up" in 1|true) ;; *) exit 3 ;; esac
device=
json_get_var device l3_device || exit 3
case "$device" in ''|*[!a-zA-Z0-9_.:-]*|????????????????*) exit 1 ;; esac
facts() {
    # jshn provides numeric array keys, not shell words from status values.
    json_select "$1" || return 0
    json_get_keys keys || keys=
    for key in $keys; do
        json_select "$key" || continue
        printf '%s:' "$1"
        for field in address mask target nexthop source metric table class; do
            json_get_var value "$field" || value=
            printf '%s=%s;' "$field" "$value"
        done
        printf '\n'
        json_select ..
    done
    json_select ..
}
digest=$({
    printf 'uplink=%s;device=%s\n' "$uplink" "$device"
    facts ipv4-address
    facts ipv6-address
    facts ipv6-prefix
    facts ipv6-prefix-assignment
    facts route
} | LC_ALL=C sort -u | sha256sum)
printf '%s %s\n' "$device" "${digest%% *}"
