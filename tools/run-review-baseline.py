#!/usr/bin/env python3
"""Frozen Linux baseline: inline CLAT, reloadable CLAT and dynamic NAT64.

Each case has a fresh network namespace, local socket endpoints and real TUN
translation. This synthetic driver measures its own workload, not hardware capacity.
Rejected UDP runs remain in the ledger. Profiling is a separate campaign.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import sys
import threading
import time


def run_case(a):
    out = Path(a.output); out.mkdir(parents=True, exist_ok=False)
    def ip(*args):
        subprocess.run(['ip', *args], check=True, capture_output=True)
    subprocess.run(['sysctl','-qw','net.ipv6.conf.default.addr_gen_mode=1','net.ipv6.conf.default.router_solicitations=0','net.ipv6.conf.default.accept_ra=0'], check=True)
    ip('link', 'set', 'lo', 'up')
    runtime = out/'runtime'; runtime.mkdir()
    cfg = out/'tayga.conf'
    base = f'tun-device reviewtun\nipv4-addr 192.0.2.254\nipv6-addr 2001:db8::fe\nprefix fd64::/96\nworkers {a.workers}\ntun-up yes\ntun-offload {a.offload}\n'
    dynamic = a.mapping == 'dynamic'
    if dynamic:
        base += 'dynamic-pool 198.18.0.0/24\n'
        client_family, server_family = socket.AF_INET6, socket.AF_INET
        client_addr, server_addr, remote = '2001:db8::1', '192.0.2.2', 'fd64::c000:202'
        ip('-6', 'addr', 'add', client_addr+'/128', 'dev', 'lo', 'nodad')
        ip('addr', 'add', server_addr+'/32', 'dev', 'lo')
    else:
        mapping = 'map 192.0.2.1 2001:db8::1\n'
        if a.mapping == 'map-file':
            (out/'maps').write_text(mapping); base += f'map-file {out / "maps"}\n'
        else:
            base += mapping
        client_family, server_family = socket.AF_INET, socket.AF_INET6
        client_addr, server_addr, remote = '192.0.2.1', 'fd64::c000:202', '192.0.2.2'
        ip('addr', 'add', client_addr+'/32', 'dev', 'lo')
        ip('-6', 'addr', 'add', server_addr+'/128', 'dev', 'lo', 'nodad')
    cfg.write_text(base)
    log = (out/'tayga.log').open('w')
    help_result = subprocess.run([a.binary, '--help'], capture_output=True, text=True, timeout=5)
    modern_runtime = '--runtime-dir' in help_result.stdout+help_result.stderr
    launch = [a.binary, '-d', '-c', str(cfg)]
    if modern_runtime: launch += ['--runtime-dir', str(runtime)]
    daemon = subprocess.Popen(launch, stdout=log, stderr=subprocess.STDOUT)
    profile = None
    try:
        status_file = runtime/'tayga-status.json' if modern_runtime else Path('/run/tayga-status.json')
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if daemon.poll() is not None: raise RuntimeError((out/'tayga.log').read_text())
            if status_file.exists():
                status = json.loads(status_file.read_text())
                if status.get('pid') == daemon.pid: break
            time.sleep(.02)
        else: raise RuntimeError('readiness timeout')
        if dynamic:
            ip('-6','route','add','fd64::/96','dev','reviewtun')
            ip('route','add','198.18.0.0/24','dev','reviewtun')
        else:
            ip('route','add','192.0.2.2/32','dev','reviewtun')
            ip('-6','route','add','2001:db8::1/128','dev','reviewtun')
        def snapshot():
            previous = json.loads(status_file.read_text())['snapshot_sequence']
            daemon.send_signal(signal.SIGUSR2)
            deadline = time.monotonic()+2
            while time.monotonic() < deadline:
                status = json.loads(status_file.read_text())
                if status['pid'] == daemon.pid and status['snapshot_sequence'] > previous:
                    return status
                time.sleep(.01)
            raise RuntimeError('statistics snapshot timeout')
        def cpu_ticks():
            fields = Path(f'/proc/{daemon.pid}/stat').read_text().rsplit(')',1)[1].split()
            return int(fields[11])+int(fields[12])
        before = snapshot()
        (out/'tayga-status.before.json').write_text(json.dumps(before, indent=2)+'\n')
        if a.profile:
            profile = subprocess.Popen(['perf','stat','-x,','-o',str(out/'perf-stat.csv'),'-e','task-clock,cycles,instructions,context-switches','-p',str(daemon.pid),'--','sleep',str(a.duration+2)])
        kind = socket.SOCK_STREAM if a.protocol == 'tcp' else socket.SOCK_DGRAM
        server = socket.socket(server_family, kind); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(5); server.bind((server_addr, 49011))
        client = socket.socket(client_family, kind); client.settimeout(5); client.bind((client_addr, 49012))
        if kind == socket.SOCK_STREAM:
            server.listen(1); client.connect((remote, 49011)); connected, _ = server.accept(); server.close(); server = connected
        else:
            client.sendto(b'ready', (remote, 49011)); _, peer = server.recvfrom(64); server.connect(peer); client.connect((remote, 49011))
        sender, receiver = (client, server) if a.direction == 'upload' else (server, client)
        receiver.settimeout(.25)
        chunk = bytes(range(256)) * (256 if kind == socket.SOCK_STREAM else 4)
        sent_hash, received_hash = hashlib.sha256(), hashlib.sha256()
        counts = {'sent_bytes': 0, 'received_bytes': 0, 'sent_frames': 0, 'received_frames': 0, 'invalid_frames': 0}
        done = threading.Event(); errors = []; seen = set()
        def receive():
            try:
                idle_deadline = None
                while True:
                    try: data = receiver.recv(65536)
                    except socket.timeout:
                        if done.is_set():
                            if idle_deadline is None: idle_deadline = time.monotonic()+1
                            if time.monotonic() >= idle_deadline: break
                        continue
                    if not data: break
                    counts['received_bytes'] += len(data); counts['received_frames'] += 1
                    received_hash.update(data)
                    if kind == socket.SOCK_DGRAM:
                        if len(data) != len(chunk)+8 or data[8:] != chunk: counts['invalid_frames'] += 1
                        else:
                            seq = struct.unpack('!Q', data[:8])[0]
                            if seq in seen: counts['invalid_frames'] += 1
                            seen.add(seq)
            except Exception as exc: errors.append(str(exc))
        thread = threading.Thread(target=receive, daemon=True); thread.start()
        ticks_before = cpu_ticks()
        start = time.monotonic(); deadline = start+a.duration
        while time.monotonic() < deadline:
            data = chunk if kind == socket.SOCK_STREAM else struct.pack('!Q', counts['sent_frames'])+chunk
            if kind == socket.SOCK_STREAM: sender.sendall(data)
            else: assert sender.send(data) == len(data)
            counts['sent_bytes'] += len(data); counts['sent_frames'] += 1; sent_hash.update(data)
        elapsed = time.monotonic()-start
        done.set()
        if kind == socket.SOCK_STREAM: sender.shutdown(socket.SHUT_WR)
        thread.join(timeout=7); assert not thread.is_alive(), 'receiver did not drain'
        sender.close(); receiver.close()
        status = snapshot()
        cpu_seconds = (cpu_ticks()-ticks_before)/os.sysconf("SC_CLK_TCK")
        (out/'tayga-status.after.json').write_text(json.dumps(status, indent=2)+'\n')
        links = json.loads(subprocess.check_output(['ip','-s','-j','link','show','dev','reviewtun'], text=True))
        (out/'link.after.json').write_text(json.dumps(links, indent=2)+'\n')
        rejected = bool(errors or counts['invalid_frames'] or counts['sent_bytes'] != counts['received_bytes'] or status.get('tx_failed_frames',0)-before.get('tx_failed_frames',0) or status['traffic']['dropped_packets']-before['traffic']['dropped_packets'] or status['traffic']['errors']-before['traffic']['errors'])
        if kind == socket.SOCK_STREAM: rejected |= sent_hash.digest() != received_hash.digest()
        else: rejected |= len(seen) != counts['sent_frames']
        for directions in links[0].get('stats64', links[0].get('stats', {})).values():
            if isinstance(directions, dict): rejected |= bool(directions.get('dropped', 0) or directions.get('errors', 0))
        if profile and profile.wait(timeout=8): errors.append('perf stat failed; inspect perf-stat.csv')
        result = dict(mapping=a.mapping, workers=a.workers, protocol=a.protocol, direction=a.direction, mtu=links[0]['mtu'], tayga_cpu_seconds=cpu_seconds,
                      cpu_seconds_per_gib_received=cpu_seconds/(counts['received_bytes']/2**30) if counts['received_bytes'] else None,
                      config_sha256=hashlib.sha256(cfg.read_bytes()).hexdigest(), reason_counters_available='tx_failed_frames' in status,
                      elapsed_sec=elapsed, received_mbps=counts['received_bytes']*8/elapsed/1e6,
                      acceptance_pass=not rejected and not errors, capture_valid=not errors and status['workers_synced'], errors=errors,
                      sender_sha256=sent_hash.hexdigest(), receiver_sha256=received_hash.hexdigest(),
                      offload_effective=status['offload_effective'], workers_synced=status['workers_synced'],
                      profiled=a.profile, **counts)
        (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    finally:
        if profile:
            profile.wait(timeout=8)
        if daemon.poll() is None: daemon.terminate()
        daemon.wait(timeout=5); log.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True)
    p.add_argument('--reference-binary')
    p.add_argument('--reference-source-sha')
    p.add_argument('--reference-build-flags', default='unknown')
    p.add_argument('--output', required=True)
    p.add_argument('--duration', type=float, default=10)
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--build-flags', default=os.environ.get('TAYGA_BUILD_FLAGS', 'unknown'))
    p.add_argument('--offload', choices=('auto','off','tcp','udp'), default='auto')
    p.add_argument('--profile', action='store_true')
    p.add_argument('--case', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--mapping', choices=('inline','map-file','dynamic'))
    p.add_argument('--workers', type=int, default=0)
    p.add_argument('--protocol', choices=('tcp','udp'))
    p.add_argument('--direction', choices=('upload','download'))
    a = p.parse_args(); a.binary = str(Path(a.binary).resolve()); a.output = str(Path(a.output).resolve())
    if a.duration <= 0 or a.repeats < 1: p.error('positive duration and repeats required')
    if a.reference_binary:
        a.reference_binary = str(Path(a.reference_binary).resolve())
        if not a.reference_source_sha or len(a.reference_source_sha) != 64 or any(c not in '0123456789abcdef' for c in a.reference_source_sha):
            p.error('--reference-binary requires its verified --reference-source-sha')
    if a.case:
        if not (a.mapping and a.protocol and a.direction): p.error('--case needs mapping, protocol and direction')
        run_case(a); return
    out = Path(a.output); out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    source_hash = hashlib.sha256()
    for source in sorted(list(root.glob('*.c'))+list(root.glob('*.h'))):
        source_hash.update(source.name.encode()+b'\0'+source.read_bytes())
    metadata = dict(binary_sha256=hashlib.sha256(Path(a.binary).read_bytes()).hexdigest(),
                    source_sha256=source_hash.hexdigest(), runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    kernel=platform.uname()._asdict(), cpus=os.cpu_count(), cpu_affinity=sorted(os.sched_getaffinity(0)), settings=vars(a),
                    workload='local socket endpoints over real TUN in disposable netns; unrestricted sender; one flow',
                    qualification='profiling' if a.profile else ('smoke' if a.duration < 10 or a.repeats < 3 else 'synthetic baseline'),
                    rate_unit='received bytes / sender active duration; includes separately drained tail')
    binaries = {'candidate': a.binary}
    if a.reference_binary: binaries['reference'] = a.reference_binary
    metadata['binary_hashes'] = {name: hashlib.sha256(Path(binary).read_bytes()).hexdigest() for name, binary in binaries.items()}
    metadata['reference_source_sha256'] = a.reference_source_sha
    (out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    ledger = []
    with open('/tmp/tayga-perf-workflow.lock','a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        for repeat in range(a.repeats):
            for mapping in ('inline','map-file','dynamic'):
                for workers in (0,1,2,4):
                    for protocol in ('tcp','udp'):
                        for direction in ('upload','download'):
                            arms = list(binaries.items())
                            if repeat % 2: arms.reverse()
                            for arm, binary in arms:
                                name = f'{arm}-{repeat+1}-{mapping}-w{workers}-{protocol}-{direction}'
                                command = ['unshare','-n',sys.executable,str(Path(__file__).resolve()),'--case','--binary',binary,'--output',str(out/name),'--mapping',mapping,'--workers',str(workers),'--protocol',protocol,'--direction',direction,'--duration',str(a.duration),'--offload',a.offload]
                                if a.profile: command.append('--profile')
                                child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                                try:
                                    stdout, stderr = child.communicate(timeout=a.duration+30)
                                except subprocess.TimeoutExpired:
                                    os.killpg(child.pid, signal.SIGTERM)
                                    try: stdout, stderr = child.communicate(timeout=5)
                                    except subprocess.TimeoutExpired:
                                        os.killpg(child.pid, signal.SIGKILL); stdout, stderr = child.communicate()
                                    stderr += '\nCase timed out; process group terminated\n'
                                except BaseException:
                                    os.killpg(child.pid, signal.SIGKILL); child.wait(); raise
                                completed = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
                                (out/(name+'.log')).write_text(completed.stdout+completed.stderr)
                                path = out/name/'result.json'
                                result = json.loads(path.read_text()) if path.exists() else dict(capture_valid=False, acceptance_pass=False, failure=completed.stderr)
                                result.update(case=name, repeat=repeat+1, arm=arm); ledger.append(result)
                                (out/'ledger.json').write_text(json.dumps(ledger, indent=2)+'\n')
                                print(name, 'PASS' if result['acceptance_pass'] else 'REJECTED', flush=True)
    for arm, binary in binaries.items():
        if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != metadata['binary_hashes'][arm]:
            raise RuntimeError('binary changed during campaign; captures invalid')
    raise SystemExit(any(not row['capture_valid'] for row in ledger))
if __name__ == '__main__': main()
