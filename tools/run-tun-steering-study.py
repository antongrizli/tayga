#!/usr/bin/env python3
"""Linux root: reversible reference/steering A/B, unrestricted TCP/UDP and perf."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import signal
import tempfile


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def install(source, target):
    # Replace the inode atomically; never truncate an executable still mapped
    # by a process during failure cleanup.
    fd, name = tempfile.mkstemp(prefix='.tayga-study-',dir=target.parent)
    os.close(fd)
    temporary=Path(name)
    try:
        shutil.copy2(source,temporary)
        os.replace(temporary,target)
    finally:
        temporary.unlink(missing_ok=True)

def startup(source):
    before='/usr/sbin/tayga -c /run/clat.conf --mktun'
    after='exec /usr/sbin/tayga -c /run/clat.conf -d'
    if source.count(before)!=1 or source.count(after)!=1:raise ValueError('unknown startup structure')
    launch="""parent=$$
(
trap 'status=$?; if [ "$status" -ne 0 ]; then kill -TERM "$parent"; fi' EXIT
ready=0
while ! grep -q 'TUN offload negotiated:' "$ARTIFACT_DIR/clat.log"; do
  kill -0 "$parent" || exit 1
  ready=$((ready+1))
  [ "$ready" -lt 200 ] || exit 1
  sleep 0.05
done"""
    finish=""") &
if [ "${TAYGA_STEERING_MODE:-kernel}" = groups ]; then
  exec /usr/sbin/tayga -c /run/clat.conf -d --tun-steering=groups
else
  exec /usr/sbin/tayga -c /run/clat.conf -d
fi"""
    return source.replace(before,launch).replace(after,finish)



def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--source-sha',required=True)
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--reference-only',action='store_true',help='Three sixteen-stream TCP pairs, no profiles')
    parser.add_argument('--verification-only',action='store_true',help='Final candidate kernel/groups TCP/UDP maximum-rate checks')
    parser.add_argument('--profiles-only',action='store_true',help='Separate post-fix profiles (sixteen TCP streams, four UDP streams)')
    parser.add_argument('--kernel-only',action='store_true',help='Limit profiles to the production steering policy')
    a=parser.parse_args()
    if os.geteuid()!=0:parser.error('Linux root required')
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=a.output.resolve()
    daemon=Path('/usr/sbin/tayga'); start=Path('/usr/local/sbin/clat-start.sh')
    bench=Path('/usr/local/sbin/benchmark-clat.sh')
    if not a.resume:
        root.mkdir(exist_ok=False)
        for path,name in ((daemon,'baseline-tayga'),(start,'original-startup.sh'),(bench,'benchmark.sh'),(a.candidate,'candidate-tayga')):
            shutil.copy2(path,root/name)
        (root/'experimental-startup.sh').write_text(startup(start.read_text()))
    identity={name:digest(root/name) for name in ('baseline-tayga','candidate-tayga','original-startup.sh','benchmark.sh','experimental-startup.sh')}
    if a.resume:
        if identity!=json.loads((root/'identity.json').read_text()):raise RuntimeError('frozen artifacts changed')
        if digest(daemon)!=identity['baseline-tayga'] or digest(start)!=identity['original-startup.sh'] or digest(a.candidate)!=identity['candidate-tayga']:raise RuntimeError('installation/candidate changed')
        settings=json.loads((root/'settings.json').read_text())
        if any(settings[k]!=getattr(a,k) for k in ('revision','source_sha')):raise RuntimeError('source identity changed')
        if any(settings.get(k,False)!=getattr(a,k) for k in ('reference_only','verification_only','profiles_only','kernel_only')):raise RuntimeError('campaign selection changed')
        (root/f'resume-runner-{len(list(root.glob("resume-runner-*.py")))+1}.py').write_bytes(Path(__file__).read_bytes())
    else:
        (root/'identity.json').write_text(json.dumps(identity,indent=2))
        (root/'runner.py').write_bytes(Path(__file__).read_bytes())
        (root/'settings.json').write_text(json.dumps(vars(a),default=str,indent=2))
    cases=[]
    for pair in range(1,4):
        for binary in (('baseline','candidate') if pair%2 else ('candidate','baseline')):
            cases.append(dict(stage='reference',pair=pair,binary=binary,policy='kernel',protocol='tcp',mode='none',scope='process'))
    for protocol in ('tcp','udp'):
        for pair in range(1,4):
            for policy in (('kernel','groups') if pair%2 else ('groups','kernel')):
                cases.append(dict(stage='steering',pair=pair,binary='candidate',policy=policy,protocol=protocol,mode='none',scope='process'))
        for policy in ('kernel','groups'):
            for scope in ('process','system'):
                cases.append(dict(stage='profile',pair=0,binary='candidate',policy=policy,protocol=protocol,mode='record',scope=scope))
    if sum((a.reference_only,a.verification_only,a.profiles_only))>1:parser.error('choose one restricted campaign')
    if a.kernel_only and not a.profiles_only:parser.error('--kernel-only requires --profiles-only')
    if a.reference_only:cases=cases[:6]
    if a.verification_only:cases=[dict(stage='verification',pair=0,binary='candidate',policy=policy,protocol=protocol,mode='none',scope='process') for protocol in ('tcp','udp') for policy in ('kernel','groups')]
    if a.profiles_only:cases=[c for c in cases if c['stage']=='profile' and (not a.kernel_only or c['policy']=='kernel')]
    (root/'schedule.json').write_text(json.dumps(cases,indent=2))
    rows=json.loads((root/'ledger.json').read_text()) if a.resume else []
    def interrupted(signum,frame):raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM,interrupted)
    try:
        install(root/'experimental-startup.sh',start);start.chmod(0o755)
        for index,case in enumerate(cases):
            label=f'{index:02d}-{case["stage"]}-{case["protocol"]}-{case["binary"]}-{case["policy"]}-{case["scope"]}'
            completed=[r for r in rows if r['label']==label]
            if completed:
                if len(completed)!=2 or {r['direction'] for r in completed}!={'upload','download'}:raise RuntimeError('partial ledger case')
                if any(not r['result']['capture_valid'] or not r['result']['workload_valid'] or r['effective']!=case['policy'] for r in completed):raise RuntimeError('rejected prior case')
                if case['protocol']=='tcp' and case['mode']=='none' and any(not r['result']['acceptance_pass'] for r in completed):raise RuntimeError('rejected prior TCP capacity')
                continue
            if (root/label).exists():
                abandoned=root/('interrupted-'+label)
                if abandoned.exists():raise RuntimeError('multiple interrupted attempts require inspection')
                (root/label).rename(abandoned)
                (root/(label+'.log')).rename(root/('interrupted-'+label+'.log'))
            print(label,flush=True)
            install(root/(case['binary']+'-tayga'),daemon)
            folder=root/label
            flows='4' if a.reference_only or (a.profiles_only and case['protocol']=='tcp') else '1'
            env=dict(os.environ,ARTIFACT_DIR=str(folder),DURATION='10',WARMUP='2',CLIENTS='4',FLOWS=flows,WORKERS='2',
                PROTOCOL=case['protocol'],RATE='0',DIRECTIONS='upload download',CLAT_OFFLOAD='auto',FORWARDING_GRO='on',
                CLAT_OFFLINK_MTU='1280',PERF_MODE=case['mode'],PERF_SCOPE=case['scope'],DATAGRAM_SIZE='1200',
                SOCKET_BUFFER_BYTES='0',TUN_TXQLEN='1000',TAYGA_CPUSET='all',CLIENT_CPUSET='all',SERVER_CPUSET='all',
                SENDER_FQ='off',FQ_RATE='0',VETH_QUEUES='0',RECEIVER_DRAIN_SECONDS='0.5',IPERF_START_GATE='on',
                SOCKET_SAMPLE_INTERVAL='1',MAX_UDP_LOSS_PERCENT='0',MAX_TUN_DROPS='0',MAX_PING_LOSS_PERCENT='0',
                GIT_REVISION=a.revision if case['binary']=='candidate' else '84e394c73ac148d02e2e5c2a4701b0e91839643a21ebf692',
                SOURCE_TREE_SHA256=a.source_sha if case['binary']=='candidate' else 'db4e3bdf909a9df98c492f97f84c849e65768a86b3d309e0afb14d3343f7b8bd',
                TAYGA_STEERING_MODE=case['policy'])
            for key in ('LD_PRELOAD','IPERF_READ_DIAGNOSTIC','IPERF_DIAGNOSTIC_CONTROL_ONLY'):env.pop(key,None)
            with (root/(label+'.log')).open('w') as log:
                child=subprocess.Popen(['bash',str(root/'benchmark.sh')],env=env,stdout=log,stderr=subprocess.STDOUT)
                try: status=child.wait(timeout=160)
                except BaseException:
                    child.terminate()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                    raise
            for direction in ('upload','download'):
                target=folder/direction
                result=json.loads((target/'result.json').read_text())
                state=json.loads((target/'tayga-status.after.json').read_text())
                effective=state.get('steering_effective','kernel')
                rows.append(dict(**case,label=label,direction=direction,status=status,effective=effective,result=result))
                (root/'ledger.json').write_text(json.dumps(rows,indent=2))
                if not result['capture_valid'] or not result['workload_valid'] or effective!=case['policy']:raise RuntimeError('invalid capture/workload or unexpected steering fallback')
                if case['protocol']=='tcp' and case['mode']=='none' and not result['acceptance_pass']:raise RuntimeError('TCP capacity acceptance failure')
                if case['mode']=='record':
                    for kind,opts in [('self',['--no-children','--call-graph','none','--sort','symbol,dso']),('caller',['--children','--call-graph','graph,0.5,caller'])]:
                        with (target/f'perf-report-{kind}.txt').open('w') as output,(target/f'perf-report-{kind}.stderr').open('w') as err:
                            subprocess.run(['perf','report','--stdio',*opts,'-i',str(target/'perf.data')],stdout=output,stderr=err,check=True)
            if digest(daemon)!=identity[case['binary']+'-tayga']:raise RuntimeError('daemon identity changed')
    finally:
        install(root/'baseline-tayga',daemon)
        install(root/'original-startup.sh',start)
        (root/'restored.json').write_text(json.dumps(dict(daemon=digest(daemon),startup=digest(start)),indent=2))
    print(f'Completed {len(rows)} directions; original installation restored',flush=True)

if __name__=='__main__':main()
