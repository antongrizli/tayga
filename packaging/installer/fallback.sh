#!/bin/sh
# Explicit architecture fallback. Runs before installed files are changed.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 8 ] || exit 2
mode=$1; os=$2; arch=$3; version=$4; payload=$5; url=$6; daemon_hash=$7; helper_hash=$8
case "$os-$arch" in linux-amd64|linux-arm64|linux-armv7|linux-armv6|linux-riscv64|linux-ppc64le|linux-s390x|freebsd-amd64|freebsd-arm64) ;; *) fail 'Unsupported fallback platform' ;; esac
bin=$payload/bin/$os-$arch
mkdir -p "$bin"
hash() {
    if command -v sha256sum >/dev/null 2>&1; then value=$(sha256sum "$1"); printf '%s\n' "${value%% *}"
    elif command -v sha256 >/dev/null 2>&1; then sha256 -q "$1"
    else value=$(shasum -a 256 "$1"); printf '%s\n' "${value%% *}"
    fi
}
case "$mode" in
 build)
    command -v cc >/dev/null || fail 'Install a native C compiler for source fallback'
    if command -v gmake >/dev/null; then make_tool=gmake
    elif [ "$os" = linux ] && command -v make >/dev/null; then make_tool="make"
    else fail 'Install GNU make for source fallback'
    fi
    [ -f "$payload/source/Makefile" ] || fail 'Bundle has no embedded build sources'
    (cd "$payload/source" && "$make_tool" CC=cc CFLAGS='-Wall -O2' LDFLAGS=-static VERSION="$version" BRANCH=installer-source COMMIT=embedded static pref64-discover) >&2
    cp "$payload/source/build/tayga" "$bin/tayga"
    cp "$payload/source/build/pref64-discover" "$bin/pref64-discover"
    ;;
 download)
    case "$url" in https://*) ;; *) fail 'Fallback download requires an explicit HTTPS base URL' ;; esac
    for digest in "$daemon_hash" "$helper_hash"; do
        case "$digest" in ''|*[!0-9a-f]*) fail 'Two SHA-256 digests are required' ;; esac
        [ "${#digest}" -eq 64 ] || fail 'Invalid SHA-256 length'
    done
    command -v curl >/dev/null || fail 'curl is required for download fallback'
    for name in tayga pref64-discover; do
        curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --connect-timeout 10 --max-time 120 \
            --output "$bin/$name" "${url%/}/$name-$os-$arch"
    done
    [ "$(hash "$bin/tayga")" = "$daemon_hash" ] || fail 'Fallback TAYGA checksum mismatch'
    [ "$(hash "$bin/pref64-discover")" = "$helper_hash" ] || fail 'Fallback helper checksum mismatch'
    ;;
 *) fail 'Select --fallback=build or --fallback=download' ;;
esac
chmod 755 "$bin/tayga" "$bin/pref64-discover"
# Verify the daemon's exact version and the helper's RFC 7050 behavior before staging.
"$bin/tayga" --help > "$bin/help"
[ "$(head -n 1 "$bin/help")" = "TAYGA version $version" ] || fail 'Fallback daemon version mismatch'
[ "$("$bin/pref64-discover" --check 64:ff9b::192.0.0.170)" = '64:ff9b::/96' ] || fail 'Fallback helper smoke check failed'
echo "Verified $mode fallback for $os/$arch ($version)" >&2
