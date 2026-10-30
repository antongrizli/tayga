#!/bin/sh
# Isolated Unbound sidecar; never edits the system Unbound or resolv.conf.
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$#" -ge 2 ] || fail 'Usage: tayga-dns64 prepare|up|down CONFIG | render CONFIG OUTPUT'
action=$1
config=$2
meta() { awk -v key="$1" '$1=="#" && $2==key {if(NF!=3 || seen++)exit 1;value=$3} END {print value}' "$config"; }
profile=$(meta installer-mode)
if [ -z "$profile" ]; then
    profile=$(awk '$1=="tun-device" {print $2}' "$config")
fi
case "$profile" in clat|nat64|siit) ;; *) fail 'Invalid DNS64 profile' ;; esac
runtime=${TAYGA_DNS64_RUNTIME:-/run/tayga-managed-$profile}
case "$runtime" in /*) ;; *) fail 'Runtime path must be absolute' ;; esac
identity=$runtime/dns64.identity
config_dir=${TAYGA_DNS64_CONFIG_DIR:-/etc/unbound/tayga-installer-$profile}
case "$config_dir" in /*) ;; *) fail 'Configuration directory must be absolute' ;; esac
unbound_config=$config_dir/unbound.conf
# Check PID, start time and config argument before sending signals.
owned_process() {
    [ -f "$identity" ] || return 1
    read -r pid started < "$identity"
    case "$pid:$started" in *[!0-9:]*|:|*:) return 1 ;; esac
    [ -r "/proc/$pid/stat" ] || return 1
    [ "$(awk '{print $22}' "/proc/$pid/stat")" = "$started" ] || return 1
    tr '\000' '\n' < "/proc/$pid/cmdline" | grep -Fx "$unbound_config" >/dev/null
}
stop_owned() {
    if owned_process; then
        kill -TERM "$pid"
        for _ in 1 2 3 4 5; do
            if ! owned_process; then break; fi
            sleep 1
        done
        if owned_process; then fail 'Unbound did not stop; identity retained'; fi
    fi
    rm -f "$identity"
    if [ -f "$config_dir/.tayga-owned" ] && [ ! -L "$config_dir" ]; then
        rm -f "$unbound_config" "$config_dir/.tayga-owned"
        rmdir "$config_dir" 2>/dev/null || :
    fi
}
if [ "$action" = down ]; then
    [ "$(id -u)" -eq 0 ] || fail 'DNS64 management requires root'
    stop_owned
    exit
fi
enabled=$(meta installer-dns64)
case "${enabled:-no}" in no) exit ;; yes) ;; *) fail 'Invalid DNS64 selection' ;; esac
[ "$profile" = nat64 ] || fail 'DNS64 provisioning requires NAT64'
prefix=$(awk '$1=="prefix" {print $2}' "$config")
listen=$(meta installer-dns64-listen)
allow=$(meta installer-dns64-allow)
upstream=$(meta installer-dns64-upstream)
dnssec=$(meta installer-dns64-dnssec)
listen=${listen:-::1}
allow=${allow:-::1/128}
upstream=${upstream:-1.1.1.1}
dnssec=${dnssec:-validate}
for value in "$prefix" "$listen" "$allow" "$upstream"; do
    case "$value" in ''|*[!0-9a-fA-F:./@]*) fail 'Invalid DNS64 address token' ;; esac
done
case "$listen" in *[/@]*) fail 'Listener must be a single IP address' ;; esac
case "$prefix" in *::/96) ;; *) fail 'DNS64 readiness currently requires a canonical /96 prefix ending in ::' ;; esac
case "$dnssec" in validate) modules='dns64 validator iterator' ;; off) modules='dns64 iterator' ;; *) fail 'Invalid DNSSEC policy' ;; esac
anchor=
if [ "$dnssec" = validate ]; then
    for candidate in /usr/share/dnssec-root/trusted-key.key /var/lib/unbound/root.key /etc/unbound/root.key; do
        if [ -r "$candidate" ]; then anchor=$candidate; break; fi
    done
    [ -n "$anchor" ] || fail 'Install the distribution DNSSEC root trust anchor (dnssec-root/unbound)'
fi
render() {
    cat <<CONF
server:
    interface: $listen
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: $allow allow
    username: "unbound"
    chroot: ""
    directory: "/"
    pidfile: ""
    use-syslog: no
    logfile: ""
    module-config: "$modules"
    dns64-prefix: $prefix
    edns-buffer-size: 1232
    harden-dnssec-stripped: yes
CONF
    case "$listen" in *:*) printf '    access-control: %s/128 allow\n' "$listen" ;; *) printf '    access-control: %s/32 allow\n' "$listen" ;; esac
    if [ -n "$anchor" ]; then printf '    trust-anchor-file: "%s"\n' "$anchor"; fi
    case "$upstream" in 127.*|::1|::1@*) printf '    do-not-query-localhost: no\n' ;; esac
    printf 'forward-zone:\n    name: "."\n    forward-addr: %s\n' "$upstream"
}
if [ "$action" = render ]; then
    [ "$#" -eq 3 ] || fail 'render requires an output file'
    render > "$3"
    exit
fi
[ "$(id -u)" -eq 0 ] || fail 'DNS64 management requires root'
case "$action" in prepare|up) ;; *) fail 'Unknown DNS64 operation' ;; esac
for tool in unbound unbound-checkconf pref64-discover; do command -v "$tool" >/dev/null || fail "$tool is required"; done
id unbound >/dev/null 2>&1 || fail 'The unbound service account is required'
umask 077
mkdir -p "$runtime"
[ ! -L "$runtime" ] || fail 'Runtime directory must not be a symlink'
[ ! -f "$identity" ] || fail 'DNS64 identity already exists; stop the profile first'
if [ -e "$config_dir" ] || [ -L "$config_dir" ]; then
    if [ ! -d "$config_dir" ] || [ -L "$config_dir" ] || [ ! -f "$config_dir/.tayga-owned" ] || [ -L "$config_dir/.tayga-owned" ]; then
        fail 'Unmanaged DNS64 configuration directory exists'
    fi
else
    mkdir -p "$(dirname "$config_dir")"
    mkdir "$config_dir"
    : > "$config_dir/.tayga-owned"
fi
chmod 755 "$config_dir"
render > "$unbound_config"
chmod 644 "$unbound_config"
unbound-checkconf "$unbound_config"
[ "$action" = up ] || exit 0
expected=$(pref64-discover --check "${prefix%/96}192.0.0.170")
unbound -d -c "$unbound_config" > "$runtime/unbound.log" 2>&1 &
pid=$!
if ! started=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null); then
    cat "$runtime/unbound.log" >&2
    fail 'Unbound exited before readiness'
fi
printf '%s %s\n' "$pid" "$started" > "$identity"
ready=no
trap 'if [ "$ready" != yes ]; then stop_owned; fi' 0
trap 'exit 1' HUP INT TERM
for _ in 1 2 3; do
    if discovered=$(pref64-discover -s "$listen") && [ "$discovered" = "$expected" ] && owned_process; then
        ready=yes
        echo '[PASS] DNS64 RFC 7050 synthesis matches the translation prefix'
        exit 0
    fi
    sleep 1
done
cat "$runtime/unbound.log" >&2
fail 'DNS64 readiness failed'
