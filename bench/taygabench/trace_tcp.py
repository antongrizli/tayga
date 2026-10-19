"""Run a command under bounded, multi-stage kernel TCP tracing (diagnostic only).

Requires root, bpftrace, BTF, and the explicitly checked kernel symbols. TUN
copy is observed inside tun_do_read, not advertised as successful read return.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


PROBES = [('kprobe:ip_finish_output2', 'arg2', 'ip_output'),
          ('kprobe:ip6_finish_output2', 'arg2', 'ip_output'),
          ('tracepoint:net:net_dev_start_xmit', 'args->skbaddr', 'dev_xmit'),
          ('kprobe:tun_net_xmit', 'arg0', 'tun_enqueue'),
          ('kprobe:skb_copy_datagram_iter /@reading[tid]/', 'arg0', 'tun_read_copy'),
          ('kprobe:tcp_v4_rcv', 'arg0', 'tcp_receive'),
          ('kprobe:tcp_v6_rcv', 'arg0', 'tcp_receive')]

# Optional Linux ingress probes: separate stages preserve each handoff boundary.
INGRESS_PROBES = [('kprobe:veth_xmit', 'arg0', 'veth_xmit'),
                  ('tracepoint:net:netif_rx', 'args->skbaddr', 'netif_rx'),
                  ('kprobe:enqueue_to_backlog', 'arg0', 'backlog_enqueue'),
                  ('kprobe:__netif_receive_skb', 'arg0', 'backlog_receive'),
                  ('tracepoint:net:napi_gro_receive_entry', 'args->skbaddr', 'gro_receive'),
                  ('kprobe:ip_rcv', 'arg0', 'ip_receive'),
                  ('kprobe:ipv6_rcv', 'arg0', 'ip_receive')]


def reported_loss(text):
    """bpftrace versions report lost events on stdout as well as stderr."""
    total = 0
    for line in text.splitlines():
        values = re.findall(r'lost\s+(\d+)\s+events', line, re.I)
        if re.search(r'\b(lost|dropped|ERROR)\b', line, re.I) and not values:
            return None
        total += sum(map(int, values))
    return total


def cpu_masks(namespace):
    """Read namespace-local queue steering masks without modifying them."""
    script = '''import json
from pathlib import Path
result = {}
for dev in Path('/sys/class/net').iterdir():
    values = {}
    for pattern in ('queues/rx-*/rps_cpus', 'queues/rx-*/rps_flow_cnt',
                    'queues/tx-*/xps_cpus', 'queues/tx-*/xps_rxqs'):
        for path in dev.glob(pattern):
            try: values[str(path.relative_to(dev))] = path.read_text().strip()
            except OSError as exc: values[str(path.relative_to(dev))] = {'error': str(exc)}
    result[dev.name] = values
print(json.dumps(result))'''
    result = subprocess.run(['ip', 'netns', 'exec', namespace, 'python3', '-c', script],
                            capture_output=True, text=True, timeout=5)
    return json.loads(result.stdout) if result.returncode == 0 else dict(error=result.stderr.strip())


def program(ports, limit, window_ms=0, ingress=False):
    if not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('invalid TCP ports')
    if type(limit) is not int or not 1 <= limit <= 1000000:
        raise ValueError('invalid per-stage/CPU event budget')
    if type(window_ms) is not int or not 0 <= window_ms <= 10000:
        raise ValueError('invalid trace window')
    port_filter = ' || '.join(f'$sp=={p} || $dp=={p}' for p in sorted(set(ports)))
    out = ['BEGIN { printf("READY\\n"); }',
           'kprobe:tun_do_read { @reading[tid]=1; }',
           'kretprobe:tun_do_read { delete(@reading[tid]); }']
    for probe, skb, stage in PROBES + (INGRESS_PROBES if ingress else []):
        body = r'''
{
 $skb=(struct sk_buff *)SKB;
 $ip=(uint8 *)($skb->head+$skb->network_header);
 $linear=(uint8 *)($skb->head+$skb->tail);
 if ($ip+20 <= $linear) {
  $v=(*$ip)>>4; $l3=(uint64)0; $len=(uint64)0;
  if ($v==4 && (*($ip+9))==6 && (bswap(*(uint16 *)($ip+6)) & 0x3fff)==0) {
   $l3=(*$ip & 15)*4; $len=(uint64)bswap(*(uint16 *)($ip+2));
  }
  if ($v==6 && $ip+40 <= $linear && (*($ip+6))==6) {
   $l3=(uint64)40; $len=40+bswap(*(uint16 *)($ip+4));
  }
  if ($l3>=20 && $ip+$l3+20 <= $linear) {
   $tcp=$ip+$l3; $l4=(*($tcp+12)>>4)*4;
   $sp=bswap(*(uint16 *)$tcp); $dp=bswap(*(uint16 *)($tcp+2));
   if ((PORTS) && $l4>=20 && $ip+$l3+$l4 <= $linear && $len >= $l3+$l4) {
    WINDOW_START
    if (WINDOW_FILTER) {
    @seen["STAGE",cpu]=count();
    if (@count["STAGE",cpu] < LIMIT) {
     @count["STAGE",cpu]=@count["STAGE",cpu]+1;
     $src=ntop(2, *(uint32 *)($ip+12)); $dst=ntop(2, *(uint32 *)($ip+16));
     if ($v==6) { $src=ntop(10, *(uint8[16] *)($ip+8)); $dst=ntop(10, *(uint8[16] *)($ip+24)); }
     $dev=$skb->dev; $ns=(uint32)0; $idx=(int32)0;
     if ($dev) { $ns=$dev->nd_net.net->ns.inum; $idx=$dev->ifindex; }
     $sh=(struct skb_shared_info *)($skb->head+$skb->end);
     printf("{\"stage\":\"STAGE\",\"timestamp_ns\":%llu,\"cpu\":%u,\"pid\":%u,\"tid\":%u,\"netns\":%u,\"ifindex\":%u,\"queue\":%u,\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,\"seq\":%u,\"ack\":%u,\"payload_len\":%u,\"syn\":%u,\"fin\":%u,\"gso_size\":%u,\"gso_type\":%u,\"gso_segs\":%u,\"checksum_state\":%u,\"skb_addr\":\"0x%llx\",\"skb_hash\":%u,\"ingress_ifindex\":%u,\"target_cpu\":%d}\n", nsecs,cpu,pid,tid,$ns,$idx,$skb->queue_mapping,$src,$dst,$sp,$dp,bswap(*(uint32 *)($tcp+4)),bswap(*(uint32 *)($tcp+8)),$len-$l3-$l4,((*($tcp+13))&2)>>1,(*($tcp+13))&1,$sh->gso_size,$sh->gso_type,$sh->gso_segs,$skb->ip_summed,(uint64)$skb,$skb->hash,$skb->skb_iif,TARGET_CPU);
    } else { @capped=count(); }
    }
   }
  }
 }
}
'''
        trigger = ('if (!@window_start && $len-$l3-$l4>=10000) { @window_start=nsecs; }'
                   if stage == 'ip_output' and window_ms else '')
        out.append(probe + body.replace('SKB', skb).replace('PORTS', port_filter)
                   .replace('STAGE', stage).replace('LIMIT', str(limit))
                   .replace('TARGET_CPU', '(int32)arg1' if stage == 'backlog_enqueue' else '-1')
                   .replace('WINDOW_START', trigger).replace('WINDOW_FILTER',
                    f'@window_start && nsecs>=@window_start && nsecs-@window_start<{window_ms*1000000}'
                    if window_ms else '1'))
    out.append('END { clear(@reading); clear(@count); }')
    return '\n'.join(out)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--ports', type=int, nargs='+', default=[5201, 5202, 5203, 5204])
    p.add_argument('--limit', type=int, default=10000, help='per-stage/CPU bound')
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--max-events', type=int, default=500000, help='normalized JSONL event budget')
    p.add_argument('--ring-pages', type=int, default=256, help='perf ring pages per CPU, power of two, max 16384')
    p.add_argument('--ingress', action='store_true', help='also observe veth, backlog enqueue/dequeue and IP ingress')
    p.add_argument('--window-ms', type=int, default=0,
                   help='capture a short window triggered by the first >=10KB TCP IP output; 0=whole command')
    p.add_argument('--aliases', type=Path, help='explicit JSON IPv6/IPv4 address aliases')
    p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args()
    if a.command and a.command[0] == '--': a.command.pop(0)
    if not a.command or a.timeout < 1 or not 1 <= a.max_events <= 5000000:
        p.error('a bounded workload command is required')
    if not 1 <= a.ring_pages <= 16384 or a.ring_pages & (a.ring_pages-1):
        p.error('--ring-pages must be a power of two in 1..16384')
    text = program(a.ports, a.limit, a.window_ms, a.ingress)
    # Do not truncate previous evidence, even when invocation later fails.
    a.output.mkdir(parents=True, exist_ok=False)
    source = a.output/'trace.bt'; source.write_text(text)
    metadata = dict(schema_version=1, purpose='diagnostic-only', complete=False,
                    lost_events=None, capped_events=None, command=a.command, ports=a.ports,
                    event_budget_per_stage_cpu=a.limit, clock='bpf_ktime_get_ns',
                    normalization_budget=a.max_events,
                    perf_ring_pages_per_cpu=a.ring_pages,
                    ingress_probes=a.ingress,
                    window_ms=a.window_ms, capture_scope='triggered-window' if a.window_ms else 'whole-command',
                    source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                    collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    address_aliases=json.loads(a.aliases.read_text()) if a.aliases else {},
                    limitations=['Basic IPv4/IPv6 TCP only; fragments/IPv6 extension headers are excluded.',
                                 'tun_read_copy is skb_copy_datagram_iter inside tun_do_read, before read return.',
                                 'ip_output is kernel IP egress, including forwarding/TSQ/softirq contexts.',
                                 'No userspace post-translation write probe; downstream IP output is observed.',
                                 'Concurrent CPUs do not define a global FIFO; no capacity acceptance.'])
    if a.ingress:
        metadata['limitations'].extend([
            'backlog_receive observes __netif_receive_skb, not every list/GRO receive path.',
            'skb addresses can be reused; match tuple/sequence/time and never equate pointer identity with packet lifetime.',
            'backlog_enqueue target_cpu is the enqueue_to_backlog argument, before queue insertion/return.'])
    trace = workload = None
    lock = None
    try:
        if os.geteuid() != 0: raise RuntimeError('root required')
        lock = os.open('/tmp/tayga-perf-workflow.lock', os.O_RDONLY | os.O_CREAT, 0o644)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        metadata['kernel'] = subprocess.check_output(['uname', '-a'], text=True).strip()
        metadata['bpftrace_version'] = subprocess.check_output(['bpftrace', '--version'], text=True).strip()
        with (a.output/'raw.stdout').open('w') as stdout, (a.output/'raw.stderr').open('w') as stderr:
            trace = subprocess.Popen(['bpftrace', '-q', '-B', 'line', str(source)], stdout=stdout, stderr=stderr,
                                     env=dict(os.environ, BPFTRACE_PERF_RB_PAGES=str(a.ring_pages)))
            deadline = time.monotonic()+20
            while 'READY\n' not in (a.output/'raw.stdout').read_text():
                if trace.poll() is not None: raise RuntimeError('tracer failed before READY; see raw.stderr')
                if time.monotonic() > deadline: raise RuntimeError('tracer readiness timeout')
                time.sleep(.05)
            with (a.output/'workload.stdout').open('w') as wo, (a.output/'workload.stderr').open('w') as we:
                workload = subprocess.Popen(a.command, stdout=wo, stderr=we, start_new_session=True)
                deadline = time.monotonic()+a.timeout
                topology = {}
                ready_names = set()
                expected_links = dict(client={'lan0'}, router={'rlan', 'rclat', 'rwan'},
                                      clatns={'veth-nat64', 'clat'}, server={'server0'})
                while workload.poll() is None:
                    for name in ('client', 'router', 'clatns', 'server'):
                        if name in ready_names: continue
                        netpath = Path('/var/run/netns')/name
                        if not netpath.exists(): continue
                        info = dict(netns=netpath.stat().st_ino)
                        links = subprocess.run(['ip', '-j', '-n', name, 'address', 'show'],
                                               capture_output=True, text=True)
                        if links.returncode == 0:
                            info['interfaces'] = json.loads(links.stdout)
                            topology[name] = info
                            up = {link['ifname'] for link in info['interfaces']
                                  if 'UP' in link.get('flags', []) and link.get('addr_info')}
                            if expected_links[name] <= up:
                                ready_names.add(name)
                                if a.ingress:
                                    topology[name]['queue_cpu_masks'] = cpu_masks(name)
                    if time.monotonic() > deadline: raise RuntimeError('workload timeout')
                    time.sleep(.1)
                metadata['workload_exit'] = workload.returncode
                metadata['topology'] = topology
                metadata['topology_ready'] = len(ready_names) == 4
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        metadata['error'] = str(exc)
    finally:
        if workload and workload.poll() is None:
            os.killpg(workload.pid, signal.SIGTERM)
            try: workload.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(workload.pid, signal.SIGKILL); workload.wait()
        if trace and trace.poll() is None:
            trace.send_signal(signal.SIGINT)
            try: trace.wait(timeout=10)
            except subprocess.TimeoutExpired: trace.kill(); trace.wait()
        errors = (a.output/'raw.stderr').read_text() if (a.output/'raw.stderr').exists() else ''
        count = omitted = 0
        stdout_loss = 0
        metadata['capped_events'] = 0
        metadata['window_start_ns'] = None
        with (a.output/'events.jsonl').open('w') as output:
            if (a.output/'raw.stdout').exists():
                with (a.output/'raw.stdout').open() as raw:
                    for line in raw:
                        loss = reported_loss(line)
                        if loss is None: stdout_loss = None
                        elif stdout_loss is not None: stdout_loss += loss
                        if line.startswith('{'):
                            try:
                                event = json.loads(line)
                                if count < a.max_events:
                                    output.write(json.dumps(event)+'\n'); count += 1
                                else: omitted += 1
                            except ValueError as exc: metadata['error'] = f'malformed event: {exc}'
                        cap = re.search(r'@capped:\s*(\d+)', line)
                        if cap: metadata['capped_events'] = int(cap[1])
                        window = re.search(r'@window_start:\s*(\d+)', line)
                        if window: metadata['window_start_ns'] = int(window[1])
        stderr_loss = reported_loss(errors)
        metadata['stdout_lost_events'] = stdout_loss
        metadata['stderr_lost_events'] = stderr_loss
        metadata['lost_events'] = stdout_loss + stderr_loss if stdout_loss is not None and stderr_loss is not None else None
        metadata['events'] = count
        metadata['normalization_omitted_events'] = omitted
        metadata['tracer_exit'] = trace.returncode if trace else None
        metadata['complete'] = (not metadata.get('error') and metadata.get('workload_exit') == 0 and
                                metadata['tracer_exit'] == 0 and count > 0 and omitted == 0 and
                                metadata['lost_events'] == 0 and metadata['capped_events'] == 0)
        (a.output/'capture.json').write_text(json.dumps(metadata, indent=2)+'\n')
        if lock is not None: os.close(lock)
    print(json.dumps({k: v for k, v in metadata.items() if k != 'topology'}, indent=2))
    return int(not metadata['complete'])


if __name__ == '__main__':
    raise SystemExit(main())
