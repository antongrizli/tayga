#!/bin/sh
# Changes /etc/resolv.conf: run only in a dedicated disposable VM.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
base=${1:-/opt/tayga-source}
work=$(mktemp -d)
cp -a /etc/resolv.conf "$work/resolv.original"
export TAYGA_HOST_DNS_RUNTIME="$work/runtime" TAYGA_HOST_DNS_STATE="$work/persistent"
unset TAYGA_TEST_RESOLV_CONF
cleanup() {
    sh "$base/packaging/installer/tayga-host-dns.sh" down "$work/profile" 2>/dev/null || :
    resolvconf -d tayga-fixture.test 2>/dev/null || :
    rm -f /etc/resolv.conf
    cp -a "$work/resolv.original" /etc/resolv.conf
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# Explicit direct-file policy: preserve and restore the original resolver bytes.
cp -L /etc/resolv.conf "$work/before"
rm /etc/resolv.conf
cp "$work/before" /etc/resolv.conf
printf 'tun-device clat\n# installer-host-dns public-file\n' > "$work/profile"
sh "$base/packaging/installer/tayga-host-dns.sh" prepare "$work/profile"
sh "$base/packaging/installer/tayga-host-dns.sh" up "$work/profile"
grep -Fx 'nameserver 1.1.1.1' /etc/resolv.conf
getent ahostsv4 cloudflare.com >/dev/null
# Model /run loss, then ensure administrator edits are preserved.
rm "$work/runtime/host-dns"
printf '# administrator change\n' >> /etc/resolv.conf
if sh "$base/packaging/installer/tayga-host-dns.sh" down "$work/profile"; then exit 1; fi
[ -f "$work/persistent/original" ]
cp "$work/persistent/expected" /etc/resolv.conf
sh "$base/packaging/installer/tayga-host-dns.sh" down "$work/profile"
cmp "$work/before" /etc/resolv.conf
# Real openresolv, including another record that must survive cleanup.
printf 'nameserver 9.9.9.9\n' | resolvconf -a tayga-fixture.test
resolvconf -l tayga-fixture.test > "$work/other.before"
printf 'tun-device clat\n# installer-host-dns public-resolvconf\n' > "$work/profile"
sh "$base/packaging/installer/tayga-host-dns.sh" prepare "$work/profile"
sh "$base/packaging/installer/tayga-host-dns.sh" up "$work/profile"
resolvconf -l clat.tayga | grep -Fx 'nameserver 1.1.1.1'
getent ahostsv4 cloudflare.com >/dev/null
sh "$base/packaging/installer/tayga-host-dns.sh" down "$work/profile"
if resolvconf -l clat.tayga | grep -q 'nameserver'; then exit 1; fi
resolvconf -l tayga-fixture.test > "$work/other.after"
cmp "$work/other.before" "$work/other.after"
echo 'PASS: native direct-file and openresolv DNS queries, edit protection and scoped cleanup'
