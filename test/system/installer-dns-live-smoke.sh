#!/bin/sh
# Run only in a dedicated disposable systemd VM with network access.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${1:-/opt/tayga-source}
work=$(mktemp -d)
server=
cleanup() {
    sh "$base/packaging/installer/tayga-host-dns.sh" down "$work/clat.conf" 2>/dev/null || :
    sh "$base/packaging/installer/tayga-dns64.sh" down "$work/nat64.conf" 2>/dev/null || :
    [ -z "$server" ] || kill "$server" 2>/dev/null || :
    ip netns del dns-fixture 2>/dev/null || :
    ip link del clat 2>/dev/null || :
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
export PATH="$base/build:$PATH" TAYGA_HOST_DNS_RUNTIME="$work/host" TAYGA_DNS64_RUNTIME="$work/dns64"
chmod 755 "$work"
cat > "$work/clat.conf" <<'EOF'
tun-device clat
# installer-host-dns public
EOF
ip netns add dns-fixture
ip link add clat type veth peer name dns-peer
ip link set dns-peer netns dns-fixture
ip addr add 198.18.100.1/30 dev clat
ip link set clat up
ip netns exec dns-fixture ip link set lo up
ip netns exec dns-fixture ip addr add 198.18.100.2/30 dev dns-peer
ip netns exec dns-fixture ip addr add 1.1.1.1/32 dev dns-peer
ip netns exec dns-fixture ip addr add 8.8.8.8/32 dev dns-peer
ip netns exec dns-fixture ip link set dns-peer up
ip route add 1.1.1.1/32 dev clat
ip route add 8.8.8.8/32 dev clat
sed "s/server.bind(('127.0.0.1', 5300))/server.bind(('1.1.1.1', 53))/" "$base/test/system/dns64-upstream.py" > "$work/upstream.py"
ip netns exec dns-fixture python3 "$work/upstream.py" &
server=$!
sh "$base/packaging/installer/tayga-host-dns.sh" prepare "$work/clat.conf"
sh "$base/packaging/installer/tayga-host-dns.sh" up "$work/clat.conf"
resolvectl dns clat | grep '1.1.1.1' >/dev/null
resolvectl domain clat | grep '~\.' >/dev/null
resolvectl --interface=clat --type=A query service.example.com | grep '1.1.1.1' >/dev/null
sh "$base/packaging/installer/tayga-host-dns.sh" down "$work/clat.conf"
if resolvectl dns clat | grep -q '1.1.1.1'; then exit 1; fi
echo 'PASS: real resolved link assignment, DNS query and scoped cleanup'
# Remove fixture routes so validation uses the real network.
ip link del clat
ip netns del dns-fixture
kill "$server" 2>/dev/null || :
server=
sh "$base/packaging/installer/configure.sh" --mode=nat64 --pref64=64:ff9b::/96 --dns64=yes --dns64-listen=127.0.0.2 --dns64-allow=127.0.0.0/8 --dns64-upstream=1.1.1.1 --dns64-dnssec=validate --output="$work/nat64.conf"
sh "$base/packaging/installer/tayga-dns64.sh" prepare "$work/nat64.conf"
sh "$base/packaging/installer/tayga-dns64.sh" up "$work/nat64.conf"
dig @127.0.0.2 cloudflare.com A +dnssec +time=5 +tries=1 > "$work/signed"
grep 'status: NOERROR' "$work/signed" >/dev/null
grep 'flags:.* ad[ ;]' "$work/signed" >/dev/null
dig @127.0.0.2 dnssec-failed.org A +dnssec +time=5 +tries=1 > "$work/bogus"
grep 'status: SERVFAIL' "$work/bogus" >/dev/null
sh "$base/packaging/installer/tayga-dns64.sh" down "$work/nat64.conf"
echo 'PASS: live DNSSEC signed answer accepted and bogus answer rejected'
