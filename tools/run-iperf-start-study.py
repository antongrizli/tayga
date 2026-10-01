#!/usr/bin/env python3
"""Linux root: compare benchmark start synchronization, preserving invalid runs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--benchmark',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--git-revision',required=True)
    p.add_argument('--source-tree-sha256',required=True,help='source identity of the unchanged installed TAYGA ELF')
    p.add_argument('--duration',type=int,default=10)
    p.add_argument('--pairs',type=int,default=3)
    p.add_argument('--clients',type=int,default=4)
    p.add_argument('--validation-only',action='store_true')
    a=p.parse_args()
    if os.geteuid()!=0 or not 1<=a.duration<=300 or not 1<=a.pairs<=6 or not 1<=a.clients<=4:p.error('Linux root; duration 1..300, pairs 1..6, clients 1..4')
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=a.output.resolve();root.mkdir(parents=True,exist_ok=False)
    benchmark=root/'measured-benchmark.sh';benchmark.write_bytes(a.benchmark.read_bytes());benchmark.chmod(0o755)
    paths=[Path('/usr/sbin/tayga'),Path('/usr/local/sbin/clat-start.sh'),benchmark,Path('/usr/local/lib/tayga-perf/iperf-start-gate.so'),Path('/usr/local/libexec/tayga-perf/iperf-start-control'),Path(__file__).resolve()]
    identity={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    (root/'identity.json').write_text(json.dumps(identity,indent=2)+'\n')
    (root/'measured-runner.py').write_bytes(Path(__file__).read_bytes())
    (root/'settings.json').write_text(json.dumps(vars(a),default=str,indent=2)+'\n')
    rows=[]
    def run(label,protocol,gate,mode='none',scope='process',drain='0.5',warmup='0'):
        folder=root/label
        env=dict(os.environ,ARTIFACT_DIR=str(folder),DURATION=str(a.duration),WARMUP=warmup,RATE='0',CLIENTS=str(a.clients),FLOWS='1',WORKERS='1',
                 DIRECTIONS='upload download',PROTOCOL=protocol,IPERF_START_GATE=gate,CLAT_OFFLOAD='auto',FORWARDING_GRO='on',PERF_MODE=mode,PERF_SCOPE=scope,
                 RECEIVER_DRAIN_SECONDS=drain,CLAT_OFFLINK_MTU='1280',DATAGRAM_SIZE='1200',SOCKET_BUFFER_BYTES='0',TUN_TXQLEN='1000',
                 TAYGA_CPUSET='all',CLIENT_CPUSET='all',SERVER_CPUSET='all',SENDER_FQ='off',FQ_RATE='0',VETH_QUEUES='0',SOCKET_SAMPLE_INTERVAL='1',
                 MAX_UDP_LOSS_PERCENT='0',MAX_TUN_DROPS='0',MAX_PING_LOSS_PERCENT='0',GIT_REVISION=a.git_revision,SOURCE_TREE_SHA256=a.source_tree_sha256)
        print(label,flush=True)
        with (root/f'{label}.log').open('w') as log:
            child=subprocess.Popen([str(benchmark)],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:status=child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:child.kill();child.wait()
                raise RuntimeError('benchmark timeout; inspect retained diagnostics')
        current=[]
        for direction in ('upload','download'):
            path=folder/direction/'result.json';result=json.loads(path.read_text()) if path.exists() else {}
            row=dict(case=label,protocol=protocol,gate=gate,mode=mode,scope=scope,direction=direction,status=status,path=str(path),result=result)
            rows.append(row);current.append(row)
        (root/'ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
        if gate=='on' and protocol=='udp' and drain!='0' and not all(r['result'].get('capture_valid') and r['result'].get('workload_valid') for r in current):
            raise RuntimeError('gated workload incomplete; stop and investigate')
    if not a.validation_only:
        for pair in range(1,a.pairs+1):
            for gate in (('off','on') if pair%2 else ('on','off')):run(f'pair{pair}-{gate}','udp',gate)
    run('no-drain-on','udp','on',drain='0')
    run('warmup-on','udp','on',warmup='2')
    run('tcp-regression','tcp','on')
    for scope in ('process','system'):run(f'profile-{scope}-on','udp','on',mode='record',scope=scope)
    for path,digest in identity.items():
        if path in ('/usr/sbin/tayga','/usr/local/sbin/clat-start.sh') and hashlib.sha256(Path(path).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('installed daemon/startup changed during study')
    print(f'Completed {len(rows)} directional cases',flush=True)

if __name__=='__main__':main()
