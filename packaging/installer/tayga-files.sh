#!/bin/sh
# Owned file installation with rollback and restoration of pre-install files.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'File installation requires root'
root=${TAYGA_TEST_ROOT:-}
[ -z "$root" ] || [ "${TAYGA_TESTING:-}" = 1 ] || fail 'Invalid test root'
state=$root/var/lib/tayga-installer
files=$state/files
tx=$state/files-transaction
paths() {
    printf '%s\n' /usr/local/sbin/tayga /usr/local/sbin/pref64-discover /usr/local/sbin/tayga-ctl \
        /usr/local/share/man/man8/tayga.8 /usr/local/share/man/man5/tayga.conf.5
    for helper in tayga-net-ctl tayga-verify tayga-dns64 tayga-host-dns configure.sh wizard.sh tayga-lifecycle.sh tayga-files.sh tayga-watchdog.sh tayga-recover.sh tayga-boot-recover.sh tayga-recovery.service tayga-recovery.openrc tayga-managed@.service tayga-managed.openrc freebsd-rc.in freebsd-recovery-rc.in; do
        printf '/usr/local/libexec/tayga/%s\n' "$helper"
    done
}
package_owned() {
    if command -v dpkg-query >/dev/null && dpkg-query -S "$1" >/dev/null 2>&1; then return 0; fi
    if command -v rpm >/dev/null && rpm -qf "$1" >/dev/null 2>&1; then return 0; fi
    if command -v apk >/dev/null && apk info --who-owns "$1" >/dev/null 2>&1; then return 0; fi
    # opkg search can exit successfully with no matches: inspect its output.
    if command -v opkg >/dev/null && opkg search "$1" 2>/dev/null | awk -v path="$1" '$2=="-" && $3==path {found=1} END {exit !found}'; then return 0; fi
    if [ "$(uname -s)" = FreeBSD ] && command -v pkg >/dev/null && pkg which "$1" >/dev/null 2>&1; then return 0; fi
    return 1
}
rollback() {
    [ -d "$tx" ] || return 0
    if [ -n "${1:-}" ] && { [ ! -f "$tx/id" ] || [ "$(cat "$tx/id")" != "$1" ]; }; then return 0; fi
    for path in $(paths); do
        if [ -e "$tx/current$path" ] || [ -L "$tx/current$path" ]; then
            rm -f "$root$path"
            cp -pP "$tx/current$path" "$root$path"
        elif [ -f "$tx/missing$path" ]; then rm -f "$root$path"
        fi
    done
    rm -rf "$files"
    if [ -d "$tx/metadata" ]; then cp -Rp "$tx/metadata" "$files"; fi
    complete=$(mktemp -d "$state/files-rollback.XXXXXXXX")
    rmdir "$complete"
    mv "$tx" "$complete"
    rm -rf "$complete"
}
action=${1:-}
mkdir -p "$state"
umask 077
case "$action" in
    stage)
        [ "$#" -eq 3 ] || fail 'Usage: tayga-files stage PAYLOAD OS-ARCH'
        if [ -f "$root/usr/libexec/tayga/package-owner" ]; then fail 'Native package installation detected; use the package manager'; fi
        payload=$2
        platform=$3
        case "$platform" in linux-amd64|linux-arm64|linux-armv7|linux-armv6|linux-riscv64|linux-ppc64le|linux-s390x|freebsd-amd64|freebsd-arm64) ;; *) fail 'Invalid platform' ;; esac
        [ ! -d "$state/operation.lock" ] || fail 'A profile activation is in progress'
        for path in $(paths); do
            if { [ -e "$root$path" ] || [ -L "$root$path" ]; } && package_owned "$root$path"; then
                fail "Package-managed file preserved: $path; use the package manager"
            fi
        done
        mkdir "$tx" 2>/dev/null || fail 'A file transaction is already pending'
        token=$(mktemp "$tx/token.XXXXXXXX")
        file_id=${token##*/}
        rm -f "$token"
        printf '%s\n' "$file_id" > "$tx/id"
        cp -p "$payload/installer/tayga-files.sh" "$tx/files.sh"
        if [ -d "$files" ]; then
            if ! cp -Rp "$files" "$tx/metadata"; then rm -rf "$tx"; fail 'Unable to snapshot file ownership'; fi
        fi
        trap 'rollback "$file_id"' 0
        trap 'exit 1' HUP INT TERM
        for path in $(paths); do
            parent=$(dirname "$path")
            mkdir -p "$root$parent" "$tx/current$parent" "$tx/missing$parent" "$files/original$parent" "$files/expected$parent"
            if [ -e "$root$path" ] || [ -L "$root$path" ]; then
                if [ -f "$files/expected$path" ]; then
                    if [ -L "$root$path" ] || ! cmp -s "$root$path" "$files/expected$path"; then fail "Modified file preserved: $path"; fi
                fi
                cp -pP "$root$path" "$tx/current$path"
                if [ ! -f "$files/expected$path" ]; then cp -pP "$root$path" "$files/original$path"; fi
            else : > "$tx/missing$path"
            fi
            case "$path" in
                */sbin/tayga) source=$payload/bin/$platform/tayga; mode=755 ;;
                */sbin/pref64-discover) source=$payload/bin/$platform/pref64-discover; mode=755 ;;
                */sbin/tayga-ctl) source=$payload/installer/tayga-ctl.sh; mode=755 ;;
                */man8/*|*/man5/*) source=$payload/man/${path##*/}; mode=644 ;;
                *)
                    name=${path##*/}
                    case "$name" in tayga-net-ctl|tayga-verify|tayga-dns64|tayga-host-dns) name=$name.sh ;; esac
                    source=$payload/installer/$name
                    case "$name" in *.service) mode=644 ;; *) mode=755 ;; esac
                    ;;
            esac
            install -m "$mode" "$source" "$root$path"
            cp -p "$root$path" "$files/expected$path"
        done
        trap - 0 HUP INT TERM
        printf '%s\n' "$file_id"
        ;;
    commit)
        if [ -d "$tx" ]; then
            if [ -n "${2:-}" ] && { [ ! -f "$tx/id" ] || [ "$(cat "$tx/id")" != "$2" ]; }; then exit 0; fi
            complete=$(mktemp -d "$state/files-commit.XXXXXXXX")
            rmdir "$complete"
            mv "$tx" "$complete"
            rm -rf "$complete"
        fi
        ;;
    rollback) rollback "${2:-}" ;;
    uninstall)
        [ ! -d "$tx" ] || fail 'A file transaction is pending'
        [ -d "$files" ] || fail 'No owned file installation'
        for path in $(paths); do
            if [ -e "$root$path" ] || [ -L "$root$path" ]; then
                if [ -L "$root$path" ] || ! cmp -s "$root$path" "$files/expected$path"; then fail "Modified file preserved: $path"; fi
            fi
        done
        for path in $(paths); do
            rm -f "$root$path"
            if [ -e "$files/original$path" ] || [ -L "$files/original$path" ]; then cp -pP "$files/original$path" "$root$path"; fi
        done
        rm -rf "$files"
        ;;
    *) fail 'Expected stage, commit, rollback or uninstall' ;;
esac
