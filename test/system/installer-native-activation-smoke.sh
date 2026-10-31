#!/bin/sh
# Dedicated Linux VM with a native package installed and real systemd/OpenRC.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
lib=/usr/libexec/tayga
state=/var/lib/tayga-installer
[ -f "$lib/package-owner" ] || exit 2
for profile in clat nat64 siit; do [ ! -f "$state/$profile.conf" ] || exit 2; done
work=$(mktemp -d)
cp -p "$lib/tayga-verify" "$work/verify.original"
cleanup() {
    cp -p "$work/verify.original" "$lib/tayga-verify"
    for profile in nat64 siit; do
        if [ -f "$state/$profile.conf" ]; then /usr/sbin/tayga-ctl uninstall "$profile" || :; fi
    done
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
sh "$lib/configure.sh" --mode=siit --pref64=fd64:100::/96 --map-ipv4=198.18.10.1 --map-ipv6=fd64:200::1 --offload=off --workers=1 --firewall=nft --output="$work/siit.conf"
/usr/sbin/tayga-ctl apply "$work/siit.conf"
[ "$(cat "$state/current")" = siit ]
ip link show siit >/dev/null
if [ "$(cat "$lib/package-owner")" = apk ]; then apk info -e .tayga-managed-profile; fi
# A readiness failure must restore the previous active profile and keep its pin.
cat > "$lib/tayga-verify" <<EOF
#!/bin/sh
if grep -q '^tun-device nat64$' "\$1"; then exit 1; fi
exec sh "$work/verify.original" "\$@"
EOF
sh "$lib/configure.sh" --mode=nat64 --pref64=fd64:100::/96 --offload=off --workers=1 --firewall=nft --output="$work/nat64.conf"
if /usr/sbin/tayga-ctl apply "$work/nat64.conf"; then exit 1; fi
cp -p "$work/verify.original" "$lib/tayga-verify"
[ "$(cat "$state/current")" = siit ]
ip link show siit >/dev/null
if ip link show nat64 >/dev/null 2>&1; then exit 1; fi
if [ "$(cat "$lib/package-owner")" = apk ]; then apk info -e .tayga-managed-profile; fi
/usr/sbin/tayga-ctl uninstall siit
if [ "$(cat "$lib/package-owner")" = apk ] && apk info -e .tayga-managed-profile >/dev/null 2>&1; then exit 1; fi
if nft list tables | grep -q tayga_sfx_; then exit 1; fi
echo 'PASS: native prefix activation, failed readiness rollback, package pin lifecycle and cleanup'
