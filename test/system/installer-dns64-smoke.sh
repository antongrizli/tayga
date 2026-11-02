#!/bin/sh
# Run inside installer-network-smoke's disposable NAT64 lab.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${1:-/work}
work=$(mktemp -d)
upstream=
cleanup() {
    TAYGA_DNS64_RUNTIME="$work/runtime" sh "$base/packaging/installer/tayga-dns64.sh" down "$work/profile.conf" || :
    [ -z "$upstream" ] || kill "$upstream" 2>/dev/null || :
    rm -f /etc/netns/upstream/resolv.conf
    rmdir /etc/netns/upstream 2>/dev/null || :
    rm -rf "$work"
}
trap cleanup 0
python3 "$base/test/system/dns64-upstream.py" &
upstream=$!
sh "$base/packaging/installer/configure.sh" --mode=nat64 --pref64=2001:db8:64::/96 \
    --dns64=yes --dns64-listen=2001:db8:1::2 --dns64-allow=2001:db8:1::/64 \
    --dns64-upstream=127.0.0.1@5300 --dns64-dnssec=off --output="$work/profile.conf"
# Check the validating configuration too; the unsigned offline fixture requires
# explicit DNSSEC=off for the live resolver, not a production default downgrade.
sed 's/installer-dns64-dnssec off/installer-dns64-dnssec validate/' "$work/profile.conf" > "$work/validated.conf"
sh "$base/packaging/installer/tayga-dns64.sh" render "$work/validated.conf" "$work/validated-unbound.conf"
unbound-checkconf "$work/validated-unbound.conf"
TAYGA_DNS64_RUNTIME="$work/runtime" sh "$base/packaging/installer/tayga-dns64.sh" prepare "$work/profile.conf"
TAYGA_DNS64_RUNTIME="$work/runtime" sh "$base/packaging/installer/tayga-dns64.sh" up "$work/profile.conf"
[ "$(ip netns exec upstream pref64-discover -s 2001:db8:1::2)" = '2001:db8:64::/96' ]
mkdir -p /etc/netns/upstream
printf 'nameserver 2001:db8:1::2\n' > /etc/netns/upstream/resolv.conf
ip netns exec upstream curl -6 --noproxy '*' -sS --max-time 15 http://service.example.com/large.bin > "$work/download"
dd if=/dev/zero of="$work/expected" bs=4096 count=256 2>/dev/null
cmp "$work/expected" "$work/download"
TAYGA_DNS64_RUNTIME="$work/runtime" sh "$base/packaging/installer/tayga-dns64.sh" down "$work/profile.conf"
[ ! -f "$work/runtime/dns64.identity" ]
if pref64-discover -s 2001:db8:1::2; then echo 'DNS64 listener survived cleanup' >&2; exit 1; fi
echo 'PASS: Unbound DNS64 synthesis, RFC 7050, DNS-resolved NAT64 HTTP and owned process cleanup'
