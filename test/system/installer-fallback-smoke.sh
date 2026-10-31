#!/bin/sh
# Native build fallback; installs only into an isolated test root.
set -eu
base=${1:-/opt/tayga-source}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in aarch64|arm64) arch=arm64; foreign=amd64 ;; x86_64|amd64) arch=amd64; foreign=arm64 ;; *) exit 2 ;; esac
version=$(cat "$base/VERSION")
python3 "$base/scripts/build-installer.py" --version "$version" --platform "$os-$foreign" "$base/build/tayga" "$base/build/pref64-discover" --output "$work/foreign.sh"
sh "$work/foreign.sh" --fallback=build --extract-only "$work/extracted"
[ "$("$work/extracted/bin/$os-$arch/tayga" --help | head -n 1)" = "TAYGA version $version" ]
"$work/extracted/bin/$os-$arch/pref64-discover" --check 64:ff9b::192.0.0.170 | grep -Fx '64:ff9b::/96'
# Root privileges are required only for the existing transactional file helper.
[ "$(id -u)" -eq 0 ] || exit 2
export TAYGA_TESTING=1 TAYGA_TEST_ROOT="$work/root"
id=$(sh "$work/extracted/installer/tayga-files.sh" stage "$work/extracted" "$os-$arch")
sh "$work/extracted/installer/tayga-files.sh" commit "$id"
"$work/root/usr/local/sbin/tayga" --help | grep -Fx "TAYGA version $version"
sh "$work/extracted/installer/tayga-files.sh" uninstall
[ ! -e "$work/root/usr/local/sbin/tayga" ]
echo 'PASS: embedded source fallback, native execution, staged installation and uninstall'
