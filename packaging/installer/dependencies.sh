#!/bin/sh
# Explicit dependency planning/installation. Never performs a distribution upgrade.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$#" -eq 7 ] || exit 2
action=$1; mode=$2; firewall=$3; dns64=$4; host_dns=$5; build=$6; dnssec=$7
case "$action" in check|install) ;; *) exit 2 ;; esac
case "$mode" in binary-only|clat|nat64|siit) ;; *) fail 'An explicit --mode is required for dependencies' ;; esac
release=/etc/os-release
if [ -n "${TAYGA_TEST_OS_RELEASE:-}" ]; then
    [ "${TAYGA_TESTING:-}" = 1 ] || exit 2
    release=$TAYGA_TEST_OS_RELEASE
fi
[ -r "$release" ] || fail 'Cannot identify distribution'
distro=$(awk -F= '$1=="ID" {gsub(/"/,"",$2); print $2}' "$release")
like=$(awk -F= '$1=="ID_LIKE" {gsub(/"/,"",$2); print $2}' "$release")
case "$distro" in
 openwrt)
    # Never treat OpenWrt apk as Alpine: package names and services differ.
    if [ "$mode" != binary-only ] || [ "$build" != no ]; then
        fail 'OpenWrt activation requires procd/netifd/fw4 integration; build packages with the OpenWrt SDK'
    fi
    if command -v apk >/dev/null 2>&1; then manager=apk
    elif command -v opkg >/dev/null 2>&1; then manager=opkg
    else fail 'OpenWrt package manager missing: apk or opkg'; fi
    printf 'Distribution: OpenWrt\nDependency manager: %s\n' "$manager"
    if command -v install >/dev/null 2>&1; then echo 'Dependencies satisfied'; exit 0; fi
    echo 'Required packages: coreutils-install'
    [ "$action" = install ] || exit 1
    [ "$(id -u)" -eq 0 ] || fail 'Dependency installation requires root'
    case "$manager" in apk) apk add coreutils-install ;; opkg) opkg update; opkg install coreutils-install ;; esac
    exec sh "$0" check "$mode" "$firewall" "$dns64" "$host_dns" "$build" "$dnssec"
    ;;
 alpine) manager=apk; family=apk ;;
 debian|ubuntu) manager=apt-get; family=deb ;;
 fedora|rhel|centos|rocky|almalinux) family=rpm; if command -v dnf >/dev/null; then manager=dnf; else manager=yum; fi ;;
 *) case " $like " in
     *' debian '*) manager=apt-get; family=deb ;;
     *' rhel '*|*' fedora '*) family=rpm; if command -v dnf >/dev/null; then manager=dnf; else manager=yum; fi ;;
     *) fail "Unsupported dependency distribution: $distro" ;;
    esac ;;
esac
command -v "$manager" >/dev/null || fail "Package manager missing: $manager"
packages=
add() { case " $packages " in *" $1 "*) ;; *) packages="${packages:+$packages }$1" ;; esac; }
need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        case "$family" in apk) add "$2" ;; deb) add "$3" ;; rpm) add "$4" ;; esac
    fi
}
ensure_package() {
    case "$family" in
        apk) apk info -e "$1" >/dev/null 2>&1 || add "$1" ;;
        deb) [ "$(dpkg-query -W -f='${db:Status-Status}' "$2" 2>/dev/null || :)" = installed ] || add "$2" ;;
        rpm) rpm -q "$3" >/dev/null 2>&1 || add "$3" ;;
    esac
}
need install coreutils coreutils coreutils
if [ "$mode" != binary-only ]; then
    if [ "$mode" != clat ] && [ "$host_dns" != keep ]; then fail 'Host DNS policies require CLAT'; fi
    if [ "$mode" != nat64 ] && [ "$dns64" = yes ]; then fail 'DNS64 dependencies require NAT64'; fi
    need curl curl curl curl
    # BusyBox ip is not the full iproute2 required by the controller.
    if ! ip -Version 2>/dev/null | grep -q iproute2; then
        case "$family" in apk|deb) add iproute2 ;; rpm) add iproute ;; esac
    fi
    need sysctl procps procps procps-ng
    need setsid util-linux util-linux util-linux
    need flock flock util-linux util-linux
    need timeout coreutils coreutils coreutils
    need nohup coreutils coreutils coreutils
    need ps procps procps procps-ng
    need cmp diffutils diffutils diffutils
    if [ "$firewall" = auto ]; then
        if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then firewall=firewalld
        elif command -v iptables >/dev/null && command -v ip6tables >/dev/null; then firewall=iptables
        else firewall=nft
        fi
    fi
    case "$firewall" in
      iptables) need iptables iptables iptables iptables; need ip6tables ip6tables iptables iptables ;;
      nft) need nft nftables nftables nftables ;;
      firewalld) need firewall-cmd firewalld firewalld firewalld ;;
      *) fail 'Unknown dependency firewall backend' ;;
    esac
    case "$dns64" in yes)
        need unbound unbound unbound unbound
        need unbound-checkconf unbound unbound unbound
        case "$dnssec" in validate) ensure_package dnssec-root dns-root-data unbound-anchor ;; off) ;; *) fail 'Invalid DNSSEC dependency selection' ;; esac
        ;; no) ;; *) fail 'Invalid DNS64 dependency selection' ;; esac
    case "$host_dns" in
        keep|public-file) ;;
        public)
            if [ "$family" = apk ] && ! command -v resolvectl >/dev/null; then fail 'Use public-resolvconf or public-file on Alpine without systemd-resolved'; fi
            need resolvectl systemd-resolved systemd-resolved systemd-resolved
            ;;
        public-resolvconf) need resolvconf openresolv openresolv openresolv ;;
        public-nm)
            if [ "$family" = apk ] && ! command -v busctl >/dev/null; then fail 'NetworkManager mode requires preinstalled busctl on Alpine'; fi
            need nmcli networkmanager network-manager NetworkManager
            need busctl systemd systemd systemd
            ;;
        *) fail 'Unknown host DNS policy' ;;
    esac
fi
if [ "$build" = yes ]; then
    ensure_package build-base build-essential gcc
    ensure_package linux-headers linux-libc-dev kernel-headers
    if [ "$family" = rpm ]; then ensure_package make make make; ensure_package musl-dev libc6-dev glibc-static; fi
elif [ "$build" != no ]; then fail 'Invalid build dependency selection'
fi
printf 'Dependency manager: %s\n' "$manager"
if [ -z "$packages" ]; then echo 'Dependencies satisfied'; exit 0; fi
printf 'Required packages: %s\n' "$packages"
[ "$action" = install ] || exit 1
[ "$(id -u)" -eq 0 ] || fail 'Dependency installation requires root'
# Tokens come exclusively from the fixed package map above.
# shellcheck disable=SC2086
set -- $packages
case "$manager" in
 apk) apk add --no-cache "$@" ;;
 apt-get) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
 dnf|yum) "$manager" install -y "$@" ;;
esac
exec sh "$0" check "$mode" "$firewall" "$dns64" "$host_dns" "$build" "$dnssec"
