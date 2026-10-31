#!/bin/sh
# Save the current SDK packages, then build a next-patch test fixture.
set -eu
[ "$#" = 2 ] || exit 2
sdk=$(realpath "$1")
baseline=$2
repo=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
[ ! -e "$baseline" ] || { echo 'Baseline directory already exists' >&2; exit 1; }
version=$(cat "$repo/VERSION")
if grep -qx CONFIG_USE_APK=y "$sdk/.config"; then ext=apk; else ext=ipk; fi
mkdir -p "$baseline"
for role in base procd network upgrader; do
    case "$role" in base) name=tayga-managed-openwrt ;; upgrader) name=tayga-managed-openwrt-upgrade ;; *) name=tayga-managed-openwrt-$role ;; esac
    if [ "$ext" = apk ]; then pattern=$name-$version-r\*.apk
    else pattern=$name"_"$version-r\*_aarch64_generic.ipk; fi
    # Preparer currently tests armsr/armv8 aarch64_generic in these CI jobs.
    archive=$(find "$sdk/bin/packages" -name "$pattern")
    [ -f "$archive" ] || { echo "Expected one baseline $role archive" >&2; exit 1; }
    cp "$archive" "$baseline/$role.$ext"
done
cp "$sdk/package/tayga-managed-openwrt/source-manifest.json" "$baseline/"
next_version=$(python3 -c 'import sys; a,b,c=map(int,sys.argv[1].split(".")); print(f"{a}.{b}.{c+1}")' "$version")
make -C "$sdk" package/tayga-managed-openwrt/clean V=s
rm -rf "$sdk/package/tayga-managed-openwrt"
python3 "$repo/scripts/prepare-openwrt-package.py" --sdk "$sdk" \
    --target armsr --subtarget armv8 --architecture aarch64_generic --version "$next_version"
make -C "$sdk" package/tayga-managed-openwrt/compile V=s -j2
