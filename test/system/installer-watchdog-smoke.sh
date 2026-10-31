#!/bin/sh
# Real route/firewall recovery after SIGKILL, only in a disposable container.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
base=${1:-/work}
work=$(mktemp -d)
export TAYGA_TEST_ROOT="$work/root" TAYGA_TESTING=1 TAYGA_NET_STATE="$work/network"
export TEST_GUARD_WORK="$work" TEST_GUARD_BASE="$base"
gate=$TAYGA_TEST_ROOT/var/lib/tayga-installer/operation.lock
lock=$gate
cleanup() {
    if [ -f "$gate/transaction" ]; then lock=$gate/$(cat "$gate/transaction"); fi
    if [ -f "$lock/armed" ]; then
        setsid sh "$lock/watchdog.sh" "$lock" "$(cat "$lock/id")" 0 "$(cat "$lock/runner.pid")" "$(cat "$lock/runner.start")" &
        wait "$!" || :
    fi
    ip link del guard6 2>/dev/null || :
    rm -rf "$work"
}
trap cleanup 0
ip link add guard6 type dummy
ip link set dev guard6 addrgenmode none
ip -6 addr add 2001:db8:99::1/64 dev guard6 nodad
ip link set guard6 up
ip -6 route add default dev guard6
ip -4 route show table main | sort > "$work/routes4.before"
ip -6 route show table main | sort > "$work/routes6.before"
lib=$TAYGA_TEST_ROOT/usr/local/libexec/tayga
mkdir -p "$lib" "$work/bin" "$TAYGA_TEST_ROOT/run/systemd/system" /var/lib/tayga/clat
for name in tayga-lifecycle.sh tayga-watchdog.sh tayga-recover.sh tayga-files.sh tayga-boot-recover.sh tayga-recovery.service; do cp "$base/packaging/installer/$name" "$lib/$name"; done
for name in tayga-net-ctl tayga-dns64 tayga-host-dns; do cp "$base/packaging/installer/$name.sh" "$lib/$name"; done
cp "$base/packaging/installer/tayga-managed@.service" "$lib/"
cat > "$work/bin/systemctl" <<'MOCK'
#!/bin/sh
set -eu
case "$1" in
    is-active|is-enabled) exit 1 ;;
    start)
        sh "$TEST_GUARD_BASE/packaging/installer/tayga-net-ctl.sh" up "$TAYGA_TEST_ROOT/etc/tayga/clat.conf"
        : > "$TEST_GUARD_WORK/routes.applied"
        trap '' TERM
        sleep 60 &
        wait
        ;;
    stop)
        sh "$TEST_GUARD_BASE/packaging/installer/tayga-net-ctl.sh" down "$TAYGA_TEST_ROOT/etc/tayga/clat.conf"
        ;;
esac
MOCK
chmod 755 "$work/bin/systemctl"
export PATH="$work/bin:$PATH"
sh "$base/packaging/installer/configure.sh" --mode=clat --pref64=64:ff9b::/96 \
    --clat-ipv6=2001:db8:3::464 --tayga-ipv6=2001:db8:3::465 --offload=off \
    --firewall="${TAYGA_TEST_FIREWALL:-iptables}" --output="$work/candidate"
TAYGA_WATCHDOG_SECONDS=6 sh "$lib/tayga-lifecycle.sh" apply "$work/candidate" > "$work/activation.log" 2>&1 &
installer=$!
applied=no
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$work/routes.applied" ]; then applied=yes; break; fi
    sleep 1
done
[ "$applied" = yes ] || { cat "$work/activation.log"; exit 1; }
lock=$gate/$(cat "$gate/transaction")
ip -4 route show exact 0.0.0.0/1 | grep 'dev clat'
# The launcher is gone; only the detached activation session and guard remain.
kill -KILL "$installer"
wait "$installer" 2>/dev/null || :
recovered=no
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if [ ! -d "$lock" ]; then recovered=yes; break; fi
    sleep 1
done
[ "$recovered" = yes ] || { cat "$TAYGA_TEST_ROOT/var/lib/tayga-installer/watchdog.log"; exit 1; }
cat "$TAYGA_TEST_ROOT/var/lib/tayga-installer/watchdog.log"
ip -4 route show table main | sort > "$work/routes4.after"
ip -6 route show table main | sort > "$work/routes6.after"
diff "$work/routes4.before" "$work/routes4.after"
diff "$work/routes6.before" "$work/routes6.after"
if ip link show dev clat >/dev/null 2>&1; then exit 1; fi
if iptables-save | grep -q TAYGA_SFX; then exit 1; fi
if ip6tables-save | grep -q TAYGA_SFX; then exit 1; fi
if command -v nft >/dev/null && nft list tables | grep -q tayga_sfx_; then exit 1; fi
[ ! -f "$TAYGA_TEST_ROOT/etc/tayga/clat.conf" ]
echo 'PASS: independent watchdog survives installer SIGKILL and restores real routes/firewall/TUN'
