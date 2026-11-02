#!/bin/sh
# TAYGA self-extracting binary installer. Generated payload follows below.
set -eu
version='@VERSION@'
checksum='@CHECKSUM@'
usage() {
    cat <<USAGE
TAYGA installer $version
Usage: sh tayga-installer.sh [--help|--version|--extract-only DIR|--mode=binary-only]

--check-deps       Check selected profile dependencies without changing the host.
--install-deps     Explicitly install missing dependencies (requires --mode).
--fallback=build|download
                   Explicit fallback when a native binary is absent (default none).
--fallback-url=URL  HTTPS base URL; download also requires --fallback-tayga-sha256
                   and --fallback-helper-sha256 (both pinned SHA-256 values).
--extract-only DIR  Extract the payload into an empty directory (no root needed).
--mode=binary-only Install binaries and manual pages under /usr/local.
--configure-only=FILE --mode=clat|nat64|siit
                   Generate a profile for review without activating it.
--wizard          Run the interactive wizard (default without arguments).
--mode=clat|nat64|siit
                  Install and activate a managed Linux profile.
--host-dns=keep|public|public-nm|public-resolvconf|public-file
                  Select CLAT host DNS policy (default keep).
--clat-address-mode=routed|proxy-ndp|nat66
                  Linux CLAT IPv6 delivery (default routed).
--nat66-address=IP Existing uplink IPv6 source for nat66 (ULA CLAT addresses required).
--yes             Accept unattended configuration; explicit CLAT address required.
--watchdog-seconds=N
                  Activation rollback deadline, 30..600 seconds (default 120).
--diagnose|--reconfigure|--uninstall|--recover
                  Manage the installed profile (optionally select --mode).
USAGE
}
dependencies=none
deps_firewall=${FIREWALL:-auto}
deps_dns64=${ENABLE_DNS64:-no}
deps_dnssec=${DNS64_DNSSEC:-validate}
deps_host_dns=${HOST_DNS:-keep}
fallback=none
fallback_url=
fallback_daemon_hash=
fallback_helper_hash=
mode=
requested_profile=${MODE:-}
profile_requested=no
wizard=no
noninteractive=no
dest=
profile=
install_requested=no
management_action=
extract_requested=no
configure_requested=no
parse_args() {
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --check-deps) dependencies=check ;;
        --install-deps) dependencies=install ;;
        --firewall=*) deps_firewall=${1#*=} ;;
        --dns64=*) deps_dns64=${1#*=} ;;
        --dns64-dnssec=*) deps_dnssec=${1#*=} ;;
        --host-dns=*) deps_host_dns=${1#*=} ;;
        --fallback=none|--fallback=build|--fallback=download) fallback=${1#*=} ;;
        --fallback-url=*) fallback_url=${1#*=} ;;
        --fallback-tayga-sha256=*) fallback_daemon_hash=${1#*=} ;;
        --fallback-helper-sha256=*) fallback_helper_hash=${1#*=} ;;
        --version) echo "$version"; exit 0 ;;
        --extract-only) [ "$#" -ge 2 ] || { echo 'Missing extraction directory' >&2; exit 2; }; mode=extract; extract_requested=yes; dest=$2; shift ;;
        --mode=binary-only) mode=install; requested_profile=binary-only; install_requested=yes; profile_requested=yes ;;
        --mode=clat|--mode=nat64|--mode=siit) requested_profile=${1#*=}; profile_requested=yes ;;
        --wizard) wizard=yes ;;
        --diagnose) mode=manage; management_action=status ;;
        --reconfigure) mode=manage; management_action=reconfigure ;;
        --uninstall) mode=manage; management_action=uninstall ;;
        --recover) mode=manage; management_action=recover ;;
        --watchdog-seconds=*)
            TAYGA_WATCHDOG_SECONDS=${1#*=}
            case "$TAYGA_WATCHDOG_SECONDS" in ''|*[!0-9]*|????*) echo 'Invalid watchdog deadline' >&2; exit 2 ;; esac
            if [ "$TAYGA_WATCHDOG_SECONDS" -lt 30 ] || [ "$TAYGA_WATCHDOG_SECONDS" -gt 600 ]; then echo 'Watchdog deadline must be 30..600 seconds' >&2; exit 2; fi
            export TAYGA_WATCHDOG_SECONDS
            ;;
        --configure-only=*) configure_requested=yes; profile=${1#*=}; mode=configure ;;
        --clat-address-mode=*|--nat66-address=*|--pref64=*|--dns64-server=*|--pool4=*|--tayga-ipv4=*|--tayga-ipv6=*|--tun-ipv6=*|--clat-ipv6=*|--map-ipv4=*|--map-ipv6=*|--mtu=*|--workers=*|--offload=*|--dns64-listen=*|--dns64-allow=*|--dns64-upstream=*) ;;
        --yes|-y|--non-interactive|--defaults) noninteractive=yes ;;
        *) echo "Unsupported argument: $1" >&2; exit 2 ;;
    esac
    shift
done
}
parse_args "$@"
if [ "$extract_requested" = yes ]; then
    if [ "$configure_requested" = yes ] || [ "$install_requested" = yes ] || [ -n "$management_action" ] || [ "$wizard" = yes ] || [ "$profile_requested" = yes ]; then
        echo 'Conflicting extraction flags' >&2; exit 2
    fi
    mode=extract
elif [ -n "$management_action" ]; then
    if [ "$configure_requested" = yes ] || [ "$wizard" = yes ]; then echo 'Conflicting management flags' >&2; exit 2; fi
    mode=manage
elif [ "$configure_requested" = yes ]; then
    [ "$install_requested" != yes ] || { echo 'binary-only has no profile' >&2; exit 2; }
    mode=configure
elif [ "$install_requested" = yes ] || [ "$requested_profile" = binary-only ]; then
    mode=install
elif [ -n "$requested_profile" ]; then mode=activate
elif [ "$noninteractive" = yes ]; then echo 'Unattended installation requires --mode' >&2; exit 2
else wizard=yes; mode=activate
fi
if [ "$wizard" = yes ] && { [ "$mode" = install ] || [ "$noninteractive" = yes ]; }; then echo 'Conflicting wizard operation flags' >&2; exit 2; fi
case "$(uname -s)" in Linux) os=linux ;; FreeBSD) os=freebsd ;; *) echo 'Unsupported operating system' >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; armv7|armv7l|armhf) arch=armv7 ;; armv6|armv6l) arch=armv6 ;; riscv64|ppc64le|s390x) arch=$(uname -m) ;; *) echo 'Unsupported architecture' >&2; exit 1 ;; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/tayga-installer.XXXXXXXX") || exit 1
file_pending=no
cleanup() {
    if [ "$file_pending" = yes ]; then
        if [ -f /var/lib/tayga-installer/operation.lock/transaction ]; then
            echo 'Activation watchdog owns recovery; backups retained in /var/lib/tayga-installer' >&2
        else
            sh "$work/files/installer/tayga-files.sh" rollback "$file_transaction" || echo 'File rollback needs attention' >&2
        fi
    fi
    rm -rf "$work"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
# The here-document works both from a file and when the script is piped to sh.
base64 -d > "$work/payload.tar.gz" <<'__TAYGA_PAYLOAD__'
@PAYLOAD@
__TAYGA_PAYLOAD__
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$work/payload.tar.gz"); actual=${actual%% *}
elif command -v sha256 >/dev/null 2>&1; then
    actual=$(sha256 -q "$work/payload.tar.gz")
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$work/payload.tar.gz"); actual=${actual%% *}
else
    echo 'A SHA-256 utility is required' >&2; exit 1
fi
[ "$actual" = "$checksum" ] || { echo 'Payload checksum mismatch' >&2; exit 1; }
mkdir "$work/files"
tar -xzf "$work/payload.tar.gz" -C "$work/files"
if [ "$dependencies" != none ]; then
    build_deps=no
    if [ "$fallback" = build ] && [ ! -f "$work/files/bin/$os-$arch/tayga" ]; then build_deps=yes; fi
    sh "$work/files/installer/dependencies.sh" "$dependencies" "$requested_profile" "$deps_firewall" "$deps_dns64" "$deps_host_dns" "$build_deps" "$deps_dnssec"
    if [ "$dependencies" = check ]; then exit 0; fi
fi
if [ -f /etc/openwrt_release ] && { [ "$mode" = install ] || [ "$mode" = activate ]; }; then
    echo 'Use the target-matched OpenWrt SDK package; SFX activation/install is unsupported on OpenWrt' >&2
    exit 2
fi
if [ ! -f "$work/files/bin/$os-$arch/tayga" ] || [ ! -f "$work/files/bin/$os-$arch/pref64-discover" ]; then
    if [ "$fallback" = none ]; then
        echo "No binaries for $os/$arch; select --fallback=build or --fallback=download" >&2; exit 1
    fi
    sh "$work/files/installer/fallback.sh" "$fallback" "$os" "$arch" "$version" "$work/files" "$fallback_url" "$fallback_daemon_hash" "$fallback_helper_hash"
fi
# Fallback flags belong to the installer, not the profile generator.
arg_count=$#
while [ "$arg_count" -gt 0 ]; do
    argument=$1; shift
    case "$argument" in --check-deps|--install-deps|--fallback=*|--fallback-url=*|--fallback-tayga-sha256=*|--fallback-helper-sha256=*) ;; *) set -- "$@" "$argument" ;; esac
    arg_count=$((arg_count - 1))
done
if [ "$wizard" = yes ]; then
    candidate=$work/profile.conf
    if [ "$mode" = configure ]; then candidate=$profile; fi
    if MODE="$requested_profile" PREF64_HELPER="$work/files/bin/$os-$arch/pref64-discover" sh "$work/files/installer/wizard.sh" "$candidate" "$@"; then
        requested_profile=$(awk '$1=="tun-device" {print $2}' "$candidate")
        [ "$mode" = configure ] || mode=activate
    else
        result=$?
        [ "$result" = 3 ] || exit "$result"
        [ "$mode" != configure ] || { echo 'binary-only has no configuration' >&2; exit 2; }
        mode=install
    fi
elif [ "$mode" = activate ]; then
    if [ "$os" = linux ]; then
        if [ ! -d /run/systemd/system ] && [ ! -d /run/openrc ]; then
            echo 'Automatic activation currently requires Linux with systemd or OpenRC' >&2; exit 2
        fi
    elif [ "$os" = freebsd ]; then
        if [ ! -d /etc/rc.d ]; then
            echo 'Automatic activation requires FreeBSD rc.d' >&2; exit 2
        fi
    else
        echo 'Automatic activation unsupported on this operating system' >&2; exit 2
    fi
    candidate=$work/profile.conf
    PREF64_HELPER="$work/files/bin/$os-$arch/pref64-discover" sh "$work/files/installer/configure.sh" "$@" --output="$candidate"
fi
if [ "$mode" = activate ]; then
    command -v curl >/dev/null || { echo 'Required tool missing: curl' >&2; exit 2; }
    if [ "$os" = freebsd ]; then
        for tool in ifconfig route sysctl pfctl; do
            command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 2; }
        done
    else
        for tool in ip sysctl; do
            command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 2; }
        done
    fi
fi
if [ "$mode" = configure ]; then
    if [ "$wizard" != yes ]; then
        PREF64_HELPER="$work/files/bin/$os-$arch/pref64-discover" sh "$work/files/installer/configure.sh" "$@" --output="$profile"
    fi
    echo "Generated profile: $profile"
elif [ "$mode" = extract ]; then
    [ -d "$dest" ] || mkdir -p "$dest"
    [ -z "$(ls -A "$dest")" ] || { echo 'Extraction directory must be empty' >&2; exit 1; }
    cp -R "$work/files/." "$dest/"
    echo "Extracted payload to $dest"
elif [ "$mode" = manage ]; then
    sh "$work/files/installer/tayga-ctl.sh" "$management_action" "$requested_profile"
else
    [ "$(id -u)" -eq 0 ] || { echo 'Installation requires root' >&2; exit 1; }
    if [ -d /var/lib/tayga-installer/files-transaction ]; then
        echo 'Interrupted file installation detected; recovering previous transaction' >&2
        if [ -f /var/lib/tayga-installer/files-transaction/files.sh ]; then
            sh /var/lib/tayga-installer/files-transaction/files.sh rollback || exit 1
        elif [ -f "$work/files/installer/tayga-files.sh" ]; then
            sh "$work/files/installer/tayga-files.sh" rollback || exit 1
        fi
    fi
    file_transaction=$(sh "$work/files/installer/tayga-files.sh" stage "$work/files" "$os-$arch")
    file_pending=yes
    if [ "$mode" = activate ]; then
        TAYGA_FILES_TRANSACTION="$file_transaction" sh /usr/local/libexec/tayga/tayga-lifecycle.sh apply "$candidate"
        echo "=== TAYGA $requested_profile active and verified ==="
    else
        echo 'Installed binaries and manuals.'
    fi
    sh "$work/files/installer/tayga-files.sh" commit "$file_transaction"
    file_pending=no
fi
