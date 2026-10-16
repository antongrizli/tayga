#!/usr/bin/env python3
"""Linux root: alternate four versus sixteen streams with fixed worker counts."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess


def schedule(rounds):
    cases=[]
    for workers in (2,3):
        for n in range(1,rounds+1):
            for flows in ((1,4) if n%2 else (4,1)):
                cases.append(dict(label=f'flows-w{workers}-pair{n}-f{flows}',stage='flows',round=n,arm='after',workers=workers,flows=flows,mode='none',scope='process'))
    return cases


def placement_schedule(rounds):
    cases = []
    for workers in (2, 3):
        for n in range(1, rounds + 1):
            for placement in (('scheduler', 'partitioned') if n % 2 else ('partitioned', 'scheduler')):
                cases.append(dict(label=f'placement-w{workers}-pair{n}-{placement}', stage='placement', round=n,
                    arm='after', workers=workers, flows=4, mode='none', scope='process', placement=placement))
        for placement in ('scheduler', 'partitioned'):
            for scope in ('process', 'system'):
                cases.append(dict(label=f'profile-w{workers}-{placement}-{scope}', stage='profile', round=0,
                    arm='after', workers=workers, flows=4, mode='record', scope=scope, placement=placement))
    return cases


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--after',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--git-revision',required=True)
    p.add_argument('--source-tree-sha256',required=True)
    p.add_argument('--duration',type=int,default=10)
    p.add_argument('--rounds',type=int,default=3)
    p.add_argument('--placement-study', action='store_true', help='Sixteen streams; alternate scheduler and partitioned CPU masks, then capture separate profiles')
    p.add_argument('--resume', action='store_true', help='Resume an existing frozen campaign; retain degraded profiles as diagnostics')
    a=p.parse_args()
    if os.geteuid()!=0 or not 1<=a.duration<=300 or not 3<=a.rounds<=6:p.error('root; duration 1..300 and rounds 3..6 required')
    if a.placement_study and set(os.sched_getaffinity(0)) != {0, 1, 2, 3}:
        p.error('placement study requires the complete four-vCPU affinity set 0..3')
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=a.output.resolve()
    binaries=[Path('/usr/sbin/tayga'),Path('/usr/local/sbin/clat-start.sh')]
    identity={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in binaries}
    rows=[]
    if a.resume:
        saved=json.loads((root/'identity.json').read_text())
        for name,digest in saved.items():
            if hashlib.sha256(Path(name).read_bytes()).hexdigest()!=digest:raise RuntimeError('frozen campaign identity changed')
        settings=json.loads((root/'settings.json').read_text())
        for key in ('git_revision','source_tree_sha256','duration','rounds','placement_study'):
            if settings.get(key,False)!=getattr(a,key):raise RuntimeError('resume settings mismatch')
        rows=json.loads((root/'ledger.json').read_text())
        # Capacity failure needs investigation rather than silent retry. A
        # complete, valid profile with loss is retained as a degraded diagnostic.
        for row in rows:
            gates=('capture_valid','workload_valid') if row['mode']=='record' else ('capture_valid','workload_valid','acceptance_pass')
            if row['status']!=0 or not all(row['result'].get(k) for k in gates):raise RuntimeError('cannot resume past incomplete or rejected capacity case')
        count=len(list(root.glob('resume-runner-*.py')))+1
        (root/f'resume-runner-{count}.py').write_bytes(Path(__file__).read_bytes())
    else:
        root.mkdir(parents=True,exist_ok=False)
        frozen=root/'after-benchmark.sh';frozen.write_bytes(a.after.read_bytes());frozen.chmod(0o755)
        identity[str(frozen)]=hashlib.sha256(frozen.read_bytes()).hexdigest()
        (root/'identity.json').write_text(json.dumps(identity,indent=2)+'\n')
        (root/'settings.json').write_text(json.dumps(vars(a),default=str,indent=2)+'\n')
        (root/'measured-runner.py').write_bytes(Path(__file__).read_bytes())
    cases=placement_schedule(a.rounds) if a.placement_study else schedule(a.rounds)
    (root/'schedule.json').write_text(json.dumps(cases,indent=2)+'\n')
    for case in cases:
        label=case['label'];folder=root/label
        completed=[r for r in rows if r['label']==label]
        if completed:
            if len(completed)!=2 or {r['direction'] for r in completed}!={'upload','download'}:raise RuntimeError('partial case in resume ledger')
            continue
        if folder.exists():raise RuntimeError('unrecorded case folder exists; inspect rather than overwrite')
        print(label,flush=True)
        env=dict(os.environ,ARTIFACT_DIR=str(folder),DURATION=str(a.duration),WARMUP='2',CLIENTS='4',FLOWS=str(case['flows']),WORKERS=str(case['workers']),
            PROTOCOL='tcp',RATE='0',DIRECTIONS='upload download',CLAT_OFFLOAD='auto',FORWARDING_GRO='on',CLAT_OFFLINK_MTU='1280',
            PERF_MODE=case['mode'],PERF_SCOPE=case['scope'],SOCKET_BUFFER_BYTES='0',TUN_TXQLEN='1000',TAYGA_CPUSET='all',CLIENT_CPUSET='all',SERVER_CPUSET='all',
            SENDER_FQ='off',FQ_RATE='0',VETH_QUEUES='0',RECEIVER_DRAIN_SECONDS='0.5',IPERF_START_GATE='on',SOCKET_SAMPLE_INTERVAL='1',
            MAX_UDP_LOSS_PERCENT='0',MAX_TUN_DROPS='0',MAX_PING_LOSS_PERCENT='0',GIT_REVISION=a.git_revision,SOURCE_TREE_SHA256=a.source_tree_sha256)
        if case.get('placement') == 'partitioned':
            # Four-vCPU VM experiment. Three workers leave one CPU shared by
            # endpoints; explicitly measure this trade-off rather than assume
            # affinity improves capacity or configures kernel steering.
            env.update(TAYGA_CPUSET='0,1' if case['workers'] == 2 else '0,1,2',
                       CLIENT_CPUSET='2' if case['workers'] == 2 else '3', SERVER_CPUSET='3')
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
            gates=('capture_valid','workload_valid') if case['mode']=='record' else ('capture_valid','workload_valid','acceptance_pass')
            passed=passed and all(r.get(k) for k in gates)
            if case['mode']=='record' and not r.get('acceptance_pass'):
                print(f'{label}/{direction}: degraded profile retained: {r.get("degraded_reasons")}',flush=True)
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
