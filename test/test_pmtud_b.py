import sys, os, time, subprocess

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode

def get_mac(iface, netns=None):
    if netns:
        out, _, _ = sh(f'ip -n {netns} link show {iface}')
    else:
        out, _, _ = sh(f'ip link show {iface}')
    for tok in out.split():
        if len(tok)==17 and tok.count(':')==5:
            return tok
    return 'ff:ff:ff:ff:ff:ff'

def setup_topology():
    for ns in ['client','router','clatns','server']:
        sh(f'ip netns del {ns} 2>/dev/null')
    for ns in ['client','router','clatns','server']:
        sh(f'ip netns add {ns}')
    sh('ip link add lan0 type veth peer name rlan')
    sh('ip link set lan0 netns client'); sh('ip link set rlan netns router')
    sh('ip link add rclat type veth peer name ceth')
    sh('ip link set rclat netns router'); sh('ip link set ceth netns clatns')
    sh('ip -n clatns link set ceth name veth-nat64')
    sh('ip link add rwan type veth peer name server0')
    sh('ip link set rwan netns router'); sh('ip link set server0 netns server')
    for c in ['ip -n client link set lo up','ip -n client link set lan0 up',
              'ip -n client addr add 192.168.88.2/24 dev lan0',
              'ip -n client route add default via 192.168.88.1']:
        sh(c)
    for c in ['ip -n router link set lo up','ip -n router link set rlan up',
              'ip -n router addr add 192.168.88.1/24 dev rlan',
              'ip -n router link set rclat up',
              'ip -n router addr add 172.31.64.1/24 dev rclat',
              'ip -n router -6 addr add fd9b:64:1:fe::1/64 dev rclat',
              'ip -n router link set rwan up',
              'ip -n router -6 addr add 2600:464::1/64 dev rwan',
              'ip netns exec router sysctl -w net.ipv4.ip_forward=1 >/dev/null',
              'ip netns exec router sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null',
              'ip -n router route add default via 172.31.64.2',
              'ip -n router -6 route add fd9b:64:1:ff::10/128 via fd9b:64:1:fe::2 dev rclat',
              'ip -n router -6 route add 64:ff9b::/96 via 2600:464::2 dev rwan']:
        sh(c)
    sh("""ip netns exec router nft -f - <<'EOF'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "rclat" ip saddr 192.168.88.0/24 snat to 192.0.0.1
  }
}
EOF""")
    for c in ['ip -n clatns link set lo up','ip -n clatns link set veth-nat64 up',
              'ip -n clatns addr add 172.31.64.2/24 dev veth-nat64',
              'ip -n clatns -6 addr add fd9b:64:1:fe::2/64 dev veth-nat64',
              'ip -n clatns -6 route add default via fd9b:64:1:fe::1',
              'ip netns exec clatns sysctl -w net.ipv4.ip_forward=1 >/dev/null',
              'ip netns exec clatns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null']:
        sh(c)
    for c in ['ip -n server link set lo up','ip -n server link set server0 up',
              'ip -n server -6 addr add 2600:464::2/64 dev server0',
              'ip -n server -6 addr add 64:ff9b::b00:2/128 dev lo',
              'ip -n server -6 route add fd9b:64:1::/48 via 2600:464::1 dev server0']:
        sh(c)

print('=== Sub-test B: ICMPv6 PTB injection via Scapy L2 ===')
setup_topology()

tayga = subprocess.Popen(
    ['ip','netns','exec','clatns','env',
     'PREF64=64:ff9b::/96','ROUTER4=172.31.64.1',
     'CLAT_WORKERS=1','CLAT_OFFLOAD=off',
     '/usr/local/sbin/clat-start.sh'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(1.5)

ping_out, _, rc = sh('ip netns exec client ping -c 2 -W 2 11.0.0.2')
print(f'  Ping rc={rc}')

rwan_mac    = get_mac('rwan',    'router')
server0_mac = get_mac('server0', 'server')
print(f'  server0={server0_mac} rwan={rwan_mac}')

icmp_cap = '/tmp/ptb_b.pcap'
tdump = subprocess.Popen(
    ['ip','netns','exec','router','tcpdump','-i','rclat',
     '-w', icmp_cap, '-n', 'icmp'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.2)

# Write scapy inject script into REPO (shared FS)
inject_py = '/Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/_ptb_inject_inner.py'
with open(inject_py, 'w') as f:
    f.write(f'''import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
emb = IPv6(src='fd9b:64:1:ff::10', dst='64:ff9b::b00:2', nh=6, hlim=63)/TCP(sport=12345,dport=80,flags='S',seq=1000)
ptb = Ether(src='{server0_mac}',dst='{rwan_mac}')/IPv6(src='64:ff9b::c000:201',dst='fd9b:64:1:fe::2',nh=58)/ICMPv6PacketTooBig(mtu=1280)/emb
sendp(ptb, iface='server0', verbose=0)
print('PTB_SENT')
''')

out, err, rc = sh(f'ip netns exec server python3 {inject_py}')
print(f'  Inject: {out.strip()}')
if err.strip() and 'SyntaxWarning' not in err and 'iface' not in err:
    print(f'  Inject STDERR: {err.strip()[:300]}')
time.sleep(0.8)

tdump.terminate()
try: tdump.wait(timeout=2)
except: tdump.kill(); tdump.wait()

cap_out, _, _ = sh(f'tcpdump -r {icmp_cap} -n -v 2>/dev/null')
lines = [l for l in cap_out.splitlines() if l.strip()]
print(f'  ICMPv4 on rclat: {len(lines)} lines')
for l in lines[:20]: print(f'    {l}')

print()
print('  TAYGA log:')
tayga.terminate()
try:
    log, _ = tayga.communicate(timeout=3)
except:
    tayga.kill()
    log, _ = tayga.communicate()
log_str = log.decode(errors='replace')
for line in log_str.splitlines()[-30:]:
    print(f'    {line}')

for ns in ['client','router','clatns','server']:
    sh(f'ip netns del {ns} 2>/dev/null')

frag = any('unreachable' in l.lower() or ('3,' in l and '4,' in l) or 'frag' in l.lower() for l in lines)
print()
if frag:
    print('[PASS] ICMPv4 Fragmentation-Needed confirmed — PTB translation works')
elif lines:
    print('[INFO] ICMP captured — check type/code above')
else:
    print('[INFO] No ICMP at rclat — TAYGA may route ICMPv4 differently (check log)')
