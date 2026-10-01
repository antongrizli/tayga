#!/usr/bin/env python3
"""Reversible maximum-rate TCP/UDP experiment; failed gates remain evidence."""
import argparse,fcntl,hashlib,importlib.util,json,os,shutil,signal,subprocess
from pathlib import Path
spec=importlib.util.spec_from_file_location('steering',Path(__file__).with_name('run-tun-steering-study.py'))
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--protocols',nargs='+',choices=('tcp','udp'),default=['tcp','udp'])
    p.add_argument('--pairs',type=int,default=3);p.add_argument('--profiles-only',action='store_true')
    p.add_argument('--integrity-only',action='store_true');p.add_argument('--reference-only',action='store_true')
    p.add_argument('--policies',nargs='+',choices=('kernel-sync','flows-sync','kernel-uring','flows-uring'),default=['kernel-sync','flows-sync','kernel-uring','flows-uring'])
    a=p.parse_args()
    if os.geteuid()!=0 or a.pairs<1:p.error('root and positive pairs required')
    root=a.output.resolve();root.mkdir(exist_ok=False)
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    daemon=Path('/usr/sbin/tayga');start=Path('/usr/local/sbin/clat-start.sh');bench=Path('/usr/local/sbin/benchmark-clat.sh')
    for src,name in ((daemon,'original-tayga'),(start,'original-startup.sh'),(bench,'benchmark.sh'),(a.binary,'candidate-tayga')):shutil.copy2(src,root/name)
    generated=study.startup(start.read_text())
    # Both arms use the same fresh TUN topology. Only candidate receives new flags.
    old='exec /usr/sbin/tayga -c /run/clat.conf -d\n'
    assert generated.count(old)==1
    generated=generated.replace(old,'exec /usr/sbin/tayga -c /run/clat.conf -d ${TAYGA_EXPERIMENT_FLAGS:-}\n')
    if a.integrity_only:
        generated=generated.replace('while ! grep -q \'TUN offload negotiated:\' "$ARTIFACT_DIR/clat.log"; do', 'while ! python3 -c \'import json,sys; d=json.load(open("/run/tayga-status.json")); sys.exit(not(d.get("pid")==int(sys.argv[1]) and d.get("offload_negotiation_complete")))\' "$parent" 2>/dev/null; do')
    (root/'experimental-startup.sh').write_text(generated)
    (root/'experimental-startup.sh').chmod(0o755)
    (root/'runner.py').write_bytes(Path(__file__).read_bytes())
    (root/'settings.json').write_text(json.dumps(vars(a),default=str,indent=2))
    identity={p.name:study.digest(p) for p in root.iterdir() if p.is_file()};(root/'identity.json').write_text(json.dumps(identity,indent=2))
    def interrupt(sig,frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupt)
    rows=[]
    def run(argv,env,log,timeout=180):
        with log.open('w') as out:
            child=subprocess.Popen(argv,env=env,stdout=out,stderr=subprocess.STDOUT)
            try:return child.wait(timeout=timeout)
            except BaseException:
                child.terminate()
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:child.kill();child.wait()
                raise
    try:
        study.install(root/'experimental-startup.sh',start)
        if a.integrity_only:
            study.install(root/'candidate-tayga',daemon)
            for policy in a.policies:
                dispatch,io=policy.split('-')
                for name in ('test_correctness.py','test_pmtud.py'):
                    env=dict(os.environ,TEST_SIZE_MB='4',TAYGA_EXPERIMENT_FLAGS=f'--dispatch={dispatch} --packet-io={io}')
                    source=Path(__file__).resolve().parents[1]/'test'/name
                    diagnostic=root/(policy+'-'+name+'.daemon.log')
                    script=root/(policy+'-'+name)
                    script.write_text(source.read_text().replace('stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)', 'stdout=open('+repr(str(diagnostic))+', \"w\"), stderr=subprocess.STDOUT)'))
                    status=run(['python3',str(script)],env,root/(policy+'-'+name+'.log'))
                    if status:raise RuntimeError(f'{policy}/{name} failed')
                    state=json.load(open('/run/tayga-status.json'));assert state['dispatch_mode']==dispatch and state['packet_io']==io
                    (root/(policy+'-'+name+'.status.json')).write_text(json.dumps(state,indent=2));print('PASS',policy,name,flush=True)
            return
        cases=[]
        for protocol in a.protocols:
            for pair in range(1,(1 if a.profiles_only else a.pairs)+1):
                policies=a.policies if pair%2 else list(reversed(a.policies))
                for policy in policies:
                    for scope in (('process','system') if a.profiles_only else ('process',)):
                        for binary in (('candidate','original') if pair%2 else ('original','candidate')) if a.reference_only else ('candidate',):
                            cases.append((protocol,pair,policy,scope,binary))
        for protocol,pair,policy,scope,binary in cases:
            label=f'{protocol}-pair{pair}-{policy}-{scope}-{binary}';folder=root/label
            dispatch,io=policy.split('-');study.install(root/(binary+'-tayga'),daemon)
            env=dict(os.environ,ARTIFACT_DIR=str(folder),DURATION='10',WARMUP='2',CLIENTS='4',FLOWS='4' if a.reference_only and protocol=='tcp' else '1',WORKERS='2',PROTOCOL=protocol,RATE='0',DIRECTIONS='upload download',CLAT_OFFLOAD='auto',FORWARDING_GRO='on',CLAT_OFFLINK_MTU='1280',PERF_MODE='record' if a.profiles_only else 'none',PERF_SCOPE=scope,DATAGRAM_SIZE='1200',SOCKET_BUFFER_BYTES='0',TUN_TXQLEN='1000',TAYGA_CPUSET='all',CLIENT_CPUSET='all',SERVER_CPUSET='all',SENDER_FQ='off',FQ_RATE='0',VETH_QUEUES='0',RECEIVER_DRAIN_SECONDS='0.5',IPERF_START_GATE='on',SOCKET_SAMPLE_INTERVAL='1',MAX_UDP_LOSS_PERCENT='0',MAX_TUN_DROPS='0',MAX_PING_LOSS_PERCENT='0',TAYGA_STEERING_MODE='kernel',TAYGA_EXPERIMENT_FLAGS='' if binary=='original' else f'--dispatch={dispatch} --packet-io={io}')
            if binary=='original':
                env.update(GIT_REVISION='84e394c73ac148d02e2e5c2a4701b0e91839643a21ebf692', SOURCE_TREE_SHA256='db4e3bdf909a9df98c492f97f84c849e65768a86b3d309e0afb14d3343f7b8bd')
            for key in ('LD_PRELOAD','IPERF_READ_DIAGNOSTIC','IPERF_DIAGNOSTIC_CONTROL_ONLY'):env.pop(key,None)
            print(label,flush=True);status=run(['bash',str(root/'benchmark.sh')],env,root/(label+'.log'))
            for direction in ('upload','download'):
                target=folder/direction;r=json.load(open(target/'result.json'));state=json.load(open(target/'tayga-status.after.json'))
                assert r['tayga_sha256']==identity[binary+'-tayga']
                assert r['clat_start_sha256']==identity['experimental-startup.sh']
                if binary=='candidate':assert state['dispatch_mode']==dispatch and state['packet_io']==io
                assert r['capture_valid'] and r['workload_valid'],(label,r.get('degraded_reasons'))
                rows.append(dict(label=label,protocol=protocol,pair=pair,policy=policy,scope=scope,binary=binary,direction=direction,status=status,result=r,state=state))
                (root/'ledger.json').write_text(json.dumps(rows,indent=2))
                if a.profiles_only:
                    for kind,args in [('self',['--no-children','--call-graph','none','--sort','symbol,dso']),('caller',['--children','--call-graph','graph,0.5,caller'])]:
                        with (target/f'perf-report-{kind}.txt').open('w') as out:subprocess.run(['perf','report','--stdio',*args,'-i',str(target/'perf.data')],stdout=out,stderr=subprocess.STDOUT,check=True)
            assert study.digest(daemon)==identity[binary+'-tayga']
    finally:
        for ns in ('client','router','clatns','server'):
            for pid in subprocess.run(['ip','netns','pids',ns],capture_output=True,text=True).stdout.split():
                try:os.kill(int(pid),signal.SIGTERM)
                except ProcessLookupError:pass
            subprocess.run(['ip','netns','del',ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        study.install(root/'original-tayga',daemon);study.install(root/'original-startup.sh',start)
        (root/'restored.json').write_text(json.dumps(dict(daemon=study.digest(daemon),startup=study.digest(start)),indent=2))
if __name__=='__main__':main()
