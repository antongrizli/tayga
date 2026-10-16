#!/usr/bin/env python3
"""Linux root: matched TCP harness A/B and balanced-order worker study."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess


def schedule(rounds):
    cases=[]
    for n in range(1,rounds+1):
        for arm in (('before','after') if n%2 else ('after','before')):
            cases.append(dict(label=f'ab-pair{n}-{arm}',stage='ab',round=n,arm=arm,workers=1,mode='none',scope='process'))
    orders=((1,2,3),(3,1,2),(2,3,1))
    for n in range(1,rounds+1):
        for workers in orders[(n-1)%3]:
            cases.append(dict(label=f'workers-round{n}-w{workers}',stage='workers',round=n,arm='after',workers=workers,mode='none',scope='process'))
    for workers in (1,3):
        for scope in ('process','system'):
            cases.append(dict(label=f'profile-w{workers}-{scope}',stage='profile',round=0,arm='after',workers=workers,mode='record',scope=scope))
    return cases


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--before',required=True,type=Path)
    p.add_argument('--after',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--git-revision',required=True)
    p.add_argument('--source-tree-sha256',required=True)
    p.add_argument('--duration',type=int,default=10)
    p.add_argument('--rounds',type=int,default=3)
    a=p.parse_args()
    if os.geteuid()!=0 or not 1<=a.duration<=300 or not 3<=a.rounds<=6:p.error('root; duration 1..300 and rounds 3..6 required')
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=a.output.resolve();root.mkdir(parents=True,exist_ok=False)
    binaries=[Path('/usr/sbin/tayga'),Path('/usr/local/sbin/clat-start.sh')]
    identity={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in binaries}
    for arm,path in [('before',a.before),('after',a.after)]:
        frozen=root/f'{arm}-benchmark.sh';frozen.write_bytes(path.read_bytes());frozen.chmod(0o755)
        identity[str(frozen)]=hashlib.sha256(frozen.read_bytes()).hexdigest()
    (root/'identity.json').write_text(json.dumps(identity,indent=2)+'\n')
    (root/'settings.json').write_text(json.dumps(vars(a),default=str,indent=2)+'\n')
    (root/'measured-runner.py').write_bytes(Path(__file__).read_bytes())
    cases=schedule(a.rounds);(root/'schedule.json').write_text(json.dumps(cases,indent=2)+'\n')
    rows=[]
    for case in cases:
        label=case['label'];folder=root/label
        print(label,flush=True)
        env=dict(os.environ,ARTIFACT_DIR=str(folder),DURATION=str(a.duration),WARMUP='2',CLIENTS='4',FLOWS='1',WORKERS=str(case['workers']),
            PROTOCOL='tcp',RATE='0',DIRECTIONS='upload download',CLAT_OFFLOAD='auto',FORWARDING_GRO='on',CLAT_OFFLINK_MTU='1280',
            PERF_MODE=case['mode'],PERF_SCOPE=case['scope'],SOCKET_BUFFER_BYTES='0',TUN_TXQLEN='1000',TAYGA_CPUSET='all',CLIENT_CPUSET='all',SERVER_CPUSET='all',
            SENDER_FQ='off',FQ_RATE='0',VETH_QUEUES='0',RECEIVER_DRAIN_SECONDS='0.5',IPERF_START_GATE='on',SOCKET_SAMPLE_INTERVAL='1',
            MAX_UDP_LOSS_PERCENT='0',MAX_TUN_DROPS='0',MAX_PING_LOSS_PERCENT='0',GIT_REVISION=a.git_revision,SOURCE_TREE_SHA256=a.source_tree_sha256)
        # Diagnostic preload must never carry over into capacity measurements.
        for key in ('LD_PRELOAD','IPERF_READ_DIAGNOSTIC','IPERF_DIAGNOSTIC_CONTROL_ONLY'):
            env.pop(key,None)
        with (root/f'{label}.log').open('w') as log:
            child=subprocess.Popen([str(root/f"{case['arm']}-benchmark.sh")],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:status=child.wait(timeout=2*a.duration+120)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:child.kill();child.wait()
                raise RuntimeError('timeout: stop and inspect cleanup')
        passed=status==0
        for direction in ('upload','download'):
            path=folder/direction/'result.json';r=json.loads(path.read_text()) if path.exists() else {}
            tuples=[]
            for client in sorted((folder/direction).glob('client-*.json')):
                report=json.loads(client.read_text());tuples.extend(report.get('start',{}).get('connected',[]))
            row=dict(**case,direction=direction,status=status,path=str(path),flow_tuples=tuples,result=r)
            rows.append(row)
            passed=passed and all(r.get(k) for k in ('capture_valid','workload_valid','acceptance_pass'))
            if case['mode']=='record' and r.get('capture_valid'):
                target=folder/direction
                for kind,opts in [('self',['--no-children','--call-graph','none','--sort','symbol,dso']),('caller',['--children','--call-graph','graph,0.5,caller'])]:
                    with (target/f'perf-report-{kind}.txt').open('w') as out,(target/f'perf-report-{kind}.stderr').open('w') as err:
                        subprocess.run(['perf','report','--stdio',*opts,'-i',str(target/'perf.data')],stdout=out,stderr=err,check=True)
        (root/'ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
        if not passed:raise RuntimeError(f'{label}: capture/workload/acceptance failure; artifacts retained')
        for path in binaries:
            if hashlib.sha256(path.read_bytes()).hexdigest()!=identity[str(path)]:raise RuntimeError('installed executable changed')
    print(f'Completed {len(rows)} directions',flush=True)

if __name__=='__main__':main()
