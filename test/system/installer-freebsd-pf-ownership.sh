#!/bin/sh
# Destructive PF fixture: only in a dedicated disposable FreeBSD VM.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(uname -s)" = FreeBSD ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
controller=${1:?controller script}
config=${2:?SIIT config}
work=${3:?persistent evidence directory}
mkdir -p "$work"
TAYGA_NET_STATE=$work/network-state
export TAYGA_NET_STATE
cleanup() {
    rc=$?
    sh "$controller" down "$config" || rc=1
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
kldload pf 2>/dev/null || :
pfctl -e 2>/dev/null || :
snapshot() {
    pfctl -t admin_peers -T show > "$1.table"
    pfctl -a admin/leaf -sr > "$1.child"
    pfctl -sn > "$1.nat"
    pfctl -sr > "$1.rules"
    pfctl -sm > "$1.limits"
}
wan=$(route -n get default | awk '$1=="interface:" {print $2}')
case "$wan" in ''|*[!a-zA-Z0-9_.:-]*) exit 2 ;; esac
for anchors in none nat filter both; do
    cat > "$work/root.pf" <<'EOF'
set skip on lo0
set limit states 12345
table <admin_peers> persist { 192.0.2.10 }
EOF
    printf 'nat on %s inet from 203.0.113.0/24 to any -> (%s)\n' "$wan" "$wan" >> "$work/root.pf"
    if [ "$anchors" = nat ] || [ "$anchors" = both ]; then printf 'nat-anchor "tayga_sfx/*"\n' >> "$work/root.pf"; fi
    printf 'anchor "admin/*"\npass all\n' >> "$work/root.pf"
    if [ "$anchors" = filter ] || [ "$anchors" = both ]; then printf 'anchor "tayga_sfx/*"\n' >> "$work/root.pf"; fi
    pfctl -nf "$work/root.pf"
    pfctl -f "$work/root.pf"
    printf 'pass quick inet proto tcp to any port 65000 label "admin-leaf"\n' > "$work/child.pf"
    pfctl -a admin/leaf -f "$work/child.pf"
    snapshot "$work/$anchors.before"
    if [ "$anchors" != both ]; then
        if sh "$controller" up "$config" > "$work/$anchors.rejected.log" 2>&1; then exit 1; fi
        grep -F 'Configure PF root' "$work/$anchors.rejected.log"
        snapshot "$work/$anchors.rejected"
        for part in table child nat rules limits; do
            cmp "$work/$anchors.before.$part" "$work/$anchors.rejected.$part"
        done
        continue
    fi
    sh "$controller" up "$config"
    snapshot "$work/$anchors.active"
    for part in table child nat rules limits; do
        cmp "$work/$anchors.before.$part" "$work/$anchors.active.$part"
    done
    # Administrative table updates made while TAYGA runs must survive stop.
    pfctl -t admin_peers -T add 192.0.2.11
    snapshot "$work/$anchors.changed"
    sh "$controller" down "$config"
    snapshot "$work/$anchors.after"
    for part in table child nat rules limits; do
        cmp "$work/$anchors.changed.$part" "$work/$anchors.after.$part"
    done
    if [ "$anchors" = nat ] || [ "$anchors" = both ]; then pfctl -sn | grep -F 'nat-anchor "tayga_sfx/*"'; fi
    if [ "$anchors" = filter ] || [ "$anchors" = both ]; then pfctl -sr | grep -F 'anchor "tayga_sfx/*"'; fi
done
echo 'PASS: PF foreign rules, persistent table edits, child anchor and limits preserved'
