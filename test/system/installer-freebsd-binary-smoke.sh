#!/bin/sh
# Only for a dedicated disposable FreeBSD VM with no managed TAYGA installation.
set -eu
if [ "${TAYGA_ISOLATED_TEST:-}" != yes ] || [ "$(uname -s)" != FreeBSD ] || [ "$(id -u)" -ne 0 ]; then exit 2; fi
bundle=${1:?installer path required}
if ifconfig tun64 >/dev/null 2>&1; then echo 'tun64 already exists' >&2; exit 1; fi
work=$(mktemp -d)
tun_owned=no
for path in /usr/local/sbin/tayga /usr/local/sbin/tayga-ctl /usr/local/sbin/pref64-discover /var/lib/tayga-installer/files; do
    if [ -e "$path" ] || [ -L "$path" ]; then echo 'Expected a clean disposable VM' >&2; exit 1; fi
done
mkdir -p /usr/local/sbin
printf 'pre-existing administrator file\n' > /usr/local/sbin/tayga
cleanup() {
    if [ "$tun_owned" = yes ]; then ifconfig tun64 destroy || :; fi
    rm -rf "$work"
    if [ -x /usr/local/sbin/tayga-ctl ] && [ -d /var/lib/tayga-installer/files ]; then
        /usr/local/sbin/tayga-ctl uninstall || :
    fi
    if [ "$(cat /usr/local/sbin/tayga 2>/dev/null || :)" = 'pre-existing administrator file' ]; then rm -f /usr/local/sbin/tayga; fi
}
trap cleanup EXIT HUP INT TERM
sh "$bundle" --mode=binary-only --yes
/usr/local/sbin/tayga --help | grep '^TAYGA version ' >/dev/null
/usr/local/sbin/pref64-discover --check 64:ff9b::192.0.0.170 | grep -Fx '64:ff9b::/96' >/dev/null
cat > "$work/profile.conf" <<'EOF'
tun-device tun64
ipv4-addr 192.0.0.2
ipv6-addr 2001:db8::2
prefix 64:ff9b::/96
map 192.0.0.1 2001:db8::1
tun-offload off
EOF
/usr/local/sbin/tayga --config "$work/profile.conf" --mktun
tun_owned=yes
ifconfig tun64 >/dev/null
/usr/local/sbin/tayga --config "$work/profile.conf" --rmtun
tun_owned=no
if ifconfig tun64 >/dev/null 2>&1; then exit 1; fi
/usr/local/sbin/tayga-ctl uninstall
[ "$(cat /usr/local/sbin/tayga)" = 'pre-existing administrator file' ]
[ ! -e /usr/local/sbin/tayga-ctl ]
echo 'PASS: FreeBSD TUN lifecycle, binary installation and restoration of a pre-existing file'
