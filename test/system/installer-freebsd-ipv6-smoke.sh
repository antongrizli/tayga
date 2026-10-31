#!/bin/sh
# Dedicated disposable VM: root CLAT -> VNET jail IPv6 HTTP, UDP, PMTUD and ownership fixture.
set -eu
[ "${TAYGA_ISOLATED_TEST:-}" = yes ] || exit 2
[ "$(uname -s)" = FreeBSD ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
base=${1:?source directory}
work=${2:?evidence directory}
if ifconfig tun64 >/dev/null 2>&1 || jls -j tayga-clat-upstream >/dev/null 2>&1; then exit 2; fi
mkdir -p "$work"
TAYGA_NET_STATE=$work/network-state
export TAYGA_NET_STATE
old_gateway=$(route -n get -inet6 default | awk '$1=="gateway:" {print $2}')
case "$old_gateway" in ''|*[!a-zA-Z0-9_.:%-]*) exit 2 ;; esac
epair=; config=; daemon=; server=; udp_server=; capture=; tun_capture=; changed_default=no; root_owned=no
cleanup() {
    rc=$?
    [ -z "$daemon" ] || { kill "$daemon" 2>/dev/null || :; wait "$daemon" 2>/dev/null || :; }
    [ -z "$tun_capture" ] || { kill "$tun_capture" 2>/dev/null || :; wait "$tun_capture" 2>/dev/null || :; }
    [ -z "$capture" ] || { kill "$capture" 2>/dev/null || :; wait "$capture" 2>/dev/null || :; }
    [ -z "$server" ] || { kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :; }
    [ -z "$udp_server" ] || { kill "$udp_server" 2>/dev/null || :; wait "$udp_server" 2>/dev/null || :; }
    if [ -n "$config" ]; then sh "$base/packaging/installer/tayga-net-ctl.sh" down "$config" || rc=1; fi
    if [ "$changed_default" = yes ]; then
        route delete -inet6 default || :
        route add -inet6 default "$old_gateway" || rc=1
    fi
    jail -r tayga-clat-upstream 2>/dev/null || :
    ndp -d 2001:db8:2::99 2>/dev/null || :
    if [ -n "$epair" ]; then ifconfig "$epair" inet6 2001:db8:2::88/64 -alias 2>/dev/null || :; fi
    pfctl -a tayga_sfx/foreign -F rules 2>/dev/null || :
    [ -z "$epair" ] || ifconfig "$epair" destroy 2>/dev/null || :
    if [ "$root_owned" = yes ]; then pfctl -F nat; pfctl -F rules; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
kldload pf 2>/dev/null || :
if pfctl -sn | grep -q . || pfctl -sr | grep -q .; then
    echo 'Requires a clean PF root in a disposable VM' >&2
    exit 2
fi
printf 'nat-anchor "tayga_sfx/*"\nanchor "tayga_sfx/*"\npass all\n' > "$work/root.pf"
pfctl -f "$work/root.pf"
root_owned=yes
epair=$(ifconfig epair create)
peer=${epair%a}b
jail -c name=tayga-clat-upstream persist vnet path=/ host.hostname=tayga-clat-upstream allow.raw_sockets=1
ifconfig "$peer" vnet tayga-clat-upstream
ifconfig "$epair" inet6 2001:db8:2::2/64 -ifdisabled no_dad up
jexec tayga-clat-upstream ifconfig "$peer" inet6 2001:db8:2::1/64 -ifdisabled no_dad up
jexec tayga-clat-upstream ifconfig lo0 inet6 fd64:100::101:101/128 alias up
route delete -inet6 default
changed_default=yes
route add -inet6 default 2001:db8:2::1

# Add foreign NDP entry, IPv6 alias, and PF child rule to verify ownership isolation
ndp -s 2001:db8:2::99 52:54:00:12:34:56
ifconfig "$epair" inet6 2001:db8:2::88/64 alias
printf 'pass in quick inet proto tcp to any port 64999 label "foreign-rule"\n' > "$work/foreign.pf"
pfctl -a tayga_sfx/foreign -f "$work/foreign.pf"

ndp -an | grep '2001:db8:2::99' > "$work/foreign.ndp.expected"
ifconfig "$epair" | grep '2001:db8:2::88' > "$work/foreign.if.expected"
pfctl -a tayga_sfx/foreign -sr > "$work/foreign.pf.expected"

printf 'freebsd-translated-proof\n' > "$work/proof"
dd if=/dev/zero of="$work/large" bs=4096 count=256 2>/dev/null

cat > "$work/udp_server.py" <<'EOF'
import socket, sys, select, struct

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('fd64:100::101:101', 18080))

raw_icmp6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)

ready_file = sys.argv[1]
peer_log = sys.argv[2]
with open(ready_file, 'w') as f:
    f.write('ready\n')

while True:
    r, _, _ = select.select([sock], [], [], 1.0)
    if r:
        try:
            data, addr = sock.recvfrom(65535)
        except Exception:
            break
        with open(peer_log, 'a') as f:
            f.write(f'{addr[0]}:{addr[1]}:{len(data)}\n')

        if data.startswith(b"PTB_TRIGGER_"):
            peer_ip, peer_port = addr[0], addr[1]
            reported_mtu = 1280
            ip6_hdr = struct.pack("!IHBB16s16s",
                0x60000000,
                len(data) + 8,
                17,
                64,
                socket.inet_pton(socket.AF_INET6, peer_ip),
                socket.inet_pton(socket.AF_INET6, "fd64:100::101:101")
            )
            udp_hdr = struct.pack("!HHHH", peer_port, 18080, len(data) + 8, 0)
            icmp6_pkt = struct.pack("!BBHI", 2, 0, 0, reported_mtu) + ip6_hdr + udp_hdr + data
            try:
                raw_icmp6.sendto(icmp6_pkt, (peer_ip, 0))
                with open(peer_log + ".ptb", "a") as f:
                    f.write(f"SENT_PTB:{peer_ip}:{peer_port}:{reported_mtu}\n")
            except Exception as e:
                with open(peer_log + ".ptb", "a") as f:
                    f.write(f"ERROR_PTB:{e}\n")
        else:
            try:
                sock.sendto(data, addr)
            except Exception:
                pass
EOF

cat > "$work/udp_client.py" <<'EOF'
import socket, sys, time, os

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
expected_peer_ip = sys.argv[3]
peer_log = sys.argv[4]

sizes = [1, 7, 32, 511, 1200]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3.0)

for size in sizes:
    success = False
    for attempt in range(1, 4):
        token = f"TAYGA_{size}_{attempt}_".encode()
        if len(token) < size:
            payload = token + bytes([(i + attempt) % 256 for i in range(size - len(token))])
        else:
            payload = token[:size]
        t0 = time.monotonic()
        sock.sendto(payload, (target_ip, target_port))
        try:
            resp, _ = sock.recvfrom(65535)
            if resp == payload:
                success = True
                print(f"UDP payload {size} bytes: OK (attempt {attempt}, elapsed {time.monotonic()-t0:.3f}s)")
                break
            else:
                print(f"UDP payload {size} bytes mismatch: got {len(resp)} bytes, expected {len(payload)}")
        except socket.timeout:
            print(f"UDP payload {size} bytes timeout on attempt {attempt}, retrying...")
            time.sleep(0.2)
    if not success:
        print(f"UDP payload {size} bytes failed after 3 attempts!", file=sys.stderr)
        sys.exit(1)

if not os.path.exists(peer_log):
    print(f"Peer log {peer_log} does not exist!", file=sys.stderr)
    sys.exit(1)

with open(peer_log, 'r') as f:
    lines = [line.strip() for line in f if line.strip()]

if not lines:
    print("Peer log is empty!", file=sys.stderr)
    sys.exit(1)

for line in lines:
    parts = line.split(':')
    peer_ip = ':'.join(parts[:-2])
    if peer_ip != expected_peer_ip:
        print(f"Peer IP mismatch: got {peer_ip}, expected {expected_peer_ip}", file=sys.stderr)
        sys.exit(1)

print(f"Verified {len(lines)} UDP datagrams received by server from expected source {expected_peer_ip}")
EOF

cat > "$work/test_ptb.py" <<'EOF'
import socket, struct, sys, time

raw_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
raw_icmp.settimeout(5.0)

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(('0.0.0.0', 55555))

probe_data = b"PTB_TRIGGER_PAYLOAD_TEST_1234567890"
udp_sock.sendto(probe_data, ("1.1.1.1", 18080))

t0 = time.monotonic()
found = False
while time.monotonic() - t0 < 5.0:
    try:
        pkt, _ = raw_icmp.recvfrom(65535)
    except socket.timeout:
        break
    ihl = (pkt[0] & 0x0f) * 4
    if len(pkt) < ihl + 8:
        continue
    icmp_type = pkt[ihl]
    icmp_code = pkt[ihl + 1]
    if icmp_type == 3 and icmp_code == 4:
        next_hop_mtu = (pkt[ihl + 6] << 8) | pkt[ihl + 7]
        quoted = pkt[ihl + 8:]
        if len(quoted) >= 28:
            q_src = socket.inet_ntoa(quoted[12:16])
            q_dst = socket.inet_ntoa(quoted[16:20])
            q_proto = quoted[9]
            q_ihl = (quoted[0] & 0x0f) * 4
            if len(quoted) >= q_ihl + 4:
                q_sport = (quoted[q_ihl] << 8) | quoted[q_ihl + 1]
                q_dport = (quoted[q_ihl + 2] << 8) | quoted[q_ihl + 3]
                if q_proto == 17 and q_sport == 55555 and q_dport == 18080:
                    print(f"ICMPv4 Frag-Needed received: MTU={next_hop_mtu}, quoted {q_src}:{q_sport} -> {q_dst}:{q_dport}")
                    if next_hop_mtu == 1260:
                        found = True
                        break
                    else:
                        print(f"MTU mismatch: got {next_hop_mtu}, expected 1260", file=sys.stderr)
                        sys.exit(1)

if not found:
    print("Did not receive translated ICMPv4 Frag-Needed for PTB trigger!", file=sys.stderr)
    sys.exit(1)

print("PASS: Reverse path ICMPv6 Packet Too Big correctly translated to ICMPv4 Fragmentation Needed")
EOF

cat > "$work/test_forward_ptb.py" <<'EOF'
import socket, sys, errno

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# IP_DONTFRAG = 67 on FreeBSD
s.setsockopt(socket.IPPROTO_IP, 67, 1)

payload = b"X" * 1420
try:
    s.sendto(payload, ("1.1.1.1", 18080))
    print("Unexpected: packet > interface MTU was sent without error!", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    if e.errno == errno.EMSGSIZE:
        print("PASS: Forward path interface MTU 1400 enforced with EMSGSIZE for 1448-byte packet")
    else:
        raise
EOF

for mode in nat66 proxy-ndp; do
    clat6=2001:db8:2::464; daemon6=2001:db8:2::465; external=
    if [ "$mode" = nat66 ]; then clat6=fd64:2::464; daemon6=fd64:2::465; external=2001:db8:2::2; fi
    config=$work/$mode.conf
    NAT66_ADDRESS=$external sh "$base/packaging/installer/configure.sh" --mode=clat \
        --pref64=fd64:100::/96 --clat-ipv6="$clat6" --tayga-ipv6="$daemon6" \
        --clat-address-mode="$mode" --firewall=pf --output="$config"

    # Execute two full lifecycle cycles (up -> traffic -> down) to prove idempotency and clean teardown
    for cycle in 1 2; do
        echo "=== Mode: $mode, Cycle: $cycle ==="
        capture=; tun_capture=
        if [ "$cycle" -eq 1 ]; then
            tcpdump -ni "$epair" -U -w "$work/$mode.pcap" > "$work/$mode.capture.log" 2>&1 &
            capture=$!
        fi

        sh "$base/packaging/installer/tayga-net-ctl.sh" up "$config"

        if [ "$cycle" -eq 1 ]; then
            tcpdump -ni tun64 -U -w "$work/$mode.tun.pcap" > "$work/$mode.tun-capture.log" 2>&1 &
            tun_capture=$!
        fi

        mkdir -p "$work/runtime-$mode-c$cycle"
        tayga --config "$config" --runtime-dir "$work/runtime-$mode-c$cycle" --nodetach > "$work/$mode.daemon.c$cycle.log" 2>&1 &
        daemon=$!

        jexec tayga-clat-upstream python3 -m http.server 80 --bind fd64:100::101:101 --directory "$work" > "$work/$mode.http.c$cycle.log" 2>&1 &
        server=$!

        jexec tayga-clat-upstream python3 "$work/udp_server.py" "$work/$mode.udp-ready.c$cycle" "$work/$mode.udp-peers.c$cycle.log" > "$work/$mode.udp-server.c$cycle.log" 2>&1 &
        udp_server=$!

        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if [ -f "$work/$mode.udp-ready.c$cycle" ] && curl -4 -fsS --noproxy '*' --connect-timeout 2 --max-time 4 http://1.1.1.1/proof > "$work/$mode.result.c$cycle"; then break; fi
            sleep 1
        done
        grep -Fx 'freebsd-translated-proof' "$work/$mode.result.c$cycle"

        # UDP Echo verification: 1, 7, 32, 511, 1200 byte payloads with token validation
        expected_peer=$clat6
        if [ "$mode" = nat66 ]; then expected_peer=$external; fi
        python3 "$work/udp_client.py" 1.1.1.1 18080 "$expected_peer" "$work/$mode.udp-peers.c$cycle.log"

        if [ "$cycle" -eq 1 ]; then
            # Full 1 MiB transfer and ping on cycle 1
            curl -4 -fsS --noproxy '*' --max-time 20 http://1.1.1.1/large > "$work/$mode.large"
            cmp "$work/large" "$work/$mode.large"
            ping -c 2 -W 3000 1.1.1.1

            # Path MTU & ICMPv6 Packet Too Big Translation Test
            # 1. Host forward path check (oversized DF packet rejected with EMSGSIZE)
            python3 "$work/test_forward_ptb.py" > "$work/$mode.forward_ptb.log"
            grep -F 'PASS: Forward path interface MTU' "$work/$mode.forward_ptb.log"

            # 2. Reverse path check (ICMPv6 PTB from server translated to ICMPv4 Frag-Needed with quoted packet)
            python3 "$work/test_ptb.py" > "$work/$mode.verify_ptb.log"
            grep -F 'PASS: Reverse path ICMPv6 Packet Too Big' "$work/$mode.verify_ptb.log"

            pfctl -a tayga_sfx/tun64 -sn > "$work/$mode.nat"
            ndp -an > "$work/$mode.ndp"
            netstat -rn -f inet6 > "$work/$mode.routes"
        fi

        kill "$daemon" "$server" "$udp_server"
        wait "$daemon" 2>/dev/null || :; wait "$server" 2>/dev/null || :; wait "$udp_server" 2>/dev/null || :
        daemon=; server=; udp_server=

        if [ -n "$capture" ]; then
            kill "$capture"
            wait "$capture" 2>/dev/null || :
            capture=
        fi
        if [ -n "$tun_capture" ]; then
            kill "$tun_capture"
            wait "$tun_capture" 2>/dev/null || :
            tun_capture=
        fi

        sh "$base/packaging/installer/tayga-net-ctl.sh" down "$config"

        # Verify owned interface and state cleanup
        if ifconfig tun64 >/dev/null 2>&1; then echo 'TUN leaked after down' >&2; exit 1; fi
        if [ "$mode" = proxy-ndp ]; then
            ndp -an > "$work/$mode.after.c$cycle.ndp"
            ifconfig "$epair" > "$work/$mode.after.c$cycle.interface"
            if ndp -n "$clat6" >/dev/null 2>&1; then echo 'Proxy entry leaked after down' >&2; exit 1; fi
            if ifconfig "$epair" inet6 | awk '$1=="inet6" {print $2}' | grep -Fx "$daemon6"; then
                echo 'Daemon identity leaked after down' >&2; exit 1
            fi
        fi

        # Verify foreign entries survived down completely intact
        ndp -an | grep '2001:db8:2::99' | cmp - "$work/foreign.ndp.expected"
        ifconfig "$epair" | grep '2001:db8:2::88' | cmp - "$work/foreign.if.expected"
        pfctl -a tayga_sfx/foreign -sr | cmp - "$work/foreign.pf.expected"
    done
done

echo 'PASS: FreeBSD NAT66 and proxy NDP HTTP, 1 MiB TCP, ICMP, UDP echo, PMTUD PTB translation, and ownership preservation'
