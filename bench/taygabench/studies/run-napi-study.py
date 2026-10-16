#!/usr/bin/env python3
"""Linux root: bounded paired NAPI experiment using already validated frozen ELFs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tarfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',required=True)
    p.add_argument('--candidate',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--source-snapshot',required=True)
    p.add_argument('--git-revision',required=True,help='revision used to build both frozen ELFs')
    p.add_argument('--duration',type=int,default=20)
    p.add_argument('--pairs',type=int,default=3)
    p.add_argument('--protocol',choices=('tcp','udp'),nargs='+',default=['tcp','udp'])
    p.add_argument('--profiles-only',action='store_true')
    args=p.parse_args()
    if os.geteuid()!=0 or not 1<=args.duration<=300 or args.pairs<1: p.error('Linux root; positive pairs and duration 1..300 required')
    lock=os.open('/tmp/tayga-perf-workflow.lock',os.O_RDONLY|os.O_CREAT,0o644)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False)
    installed=Path('/usr/sbin/tayga');original=output/'original-tayga';shutil.copy2(installed,original)
    binaries={arm:Path(getattr(args,arm)).resolve() for arm in ('baseline','candidate')}
    for arm,path in binaries.items():
        shutil.copy2(path,output/f'{arm}-tayga')
        binaries[arm]=output/f'{arm}-tayga'
    snapshot=Path(args.source_snapshot).resolve();shutil.copy2(snapshot,output/'source-snapshot.tar.gz')
    tree=hashlib.sha256()
    manifest=[]
    with tarfile.open(snapshot, 'r:gz') as archive:
        entries=sorted((member for member in archive.getmembers() if member.isfile()), key=lambda member: member.name.removeprefix('./'))
        for member in entries:
            relative=member.name.removeprefix('./')
            digest=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            manifest.append(f'{digest}  {relative}')
            tree.update(relative.encode()+b'\0'+bytes.fromhex(digest))
    identity=tree.hexdigest()
    (output/'source-manifest.sha256').write_text('\n'.join(manifest)+'\n')
    (output/'source-tree.sha256').write_text(identity+'\n')
    (output/'source-snapshot.sha256').write_text(sha(snapshot)+'\n')
    rows=[]
    def run_case(protocol,pair,attempt,arm,mode,scope="process"):
        folder=output/f'{protocol}-pair{pair}-attempt{attempt}-{arm}-{mode}-{scope}'
        env=dict(os.environ,ARTIFACT_DIR=str(folder),PERF_MODE=mode,PERF_SCOPE=scope,
                 CLIENTS='2',FLOWS='1',WORKERS='1',RATE='0',WARMUP='0',DURATION=str(args.duration),
                 DIRECTIONS='upload download',PROTOCOL=protocol,CLAT_OFFLOAD='auto',
                 FORWARDING_GRO='on',CLAT_OFFLINK_MTU='1280',DATAGRAM_SIZE='1200',
                 TAYGA_CPUSET='all',CLIENT_CPUSET='all',SERVER_CPUSET='all',
                 SOCKET_BUFFER_BYTES='0',TUN_TXQLEN='1000',SENDER_FQ='off',FQ_RATE='0',
                 MAX_UDP_LOSS_PERCENT='0',MAX_TUN_DROPS='0',MAX_PING_LOSS_PERCENT='0',
                 GIT_REVISION=args.git_revision,SOURCE_TREE_SHA256=identity,
                 VETH_QUEUES='0',SOCKET_SAMPLE_INTERVAL='1',PACING_TIMER_US='1000',
                 RECEIVER_DRAIN_SECONDS='0.5',BLOCK_SIZE='',SENDER_FQ_TOPOLOGY='auto')
        subprocess.run(['install','-m','0755',str(binaries[arm]),str(installed)],check=True)
        print(f'{protocol} pair{pair} attempt{attempt} {arm} {mode}',flush=True)
        with (output/f'{folder.name}.log').open('w') as log:
            status=subprocess.run(['/usr/local/sbin/benchmark-clat.sh'],env=env,stdout=log,stderr=subprocess.STDOUT).returncode
        current=[]
        for direction in ('upload','download'):
            path=folder/direction/'result.json';result=json.loads(path.read_text()) if path.exists() else {}
            row=dict(protocol=protocol,pair=pair,attempt=attempt,arm=arm,mode=mode,direction=direction,
                     exit_status=status,result=result,selected=False,path=str(path),scope=scope)
            rows.append(row);current.append(row)
        valid=all(r['result'].get('capture_valid') and r['result'].get('workload_valid') and r['result'].get('tayga_sha256')==sha(binaries[arm]) for r in current)
        if arm=='candidate' and valid:
            startup=(folder/'clat.log').read_text()
            assert 'Experimental TUN NAPI verified on queue -1' in startup and 'Experimental TUN NAPI verified on queue 0' in startup
        (output/'ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
        return valid,current
    try:
        for protocol in args.protocol:
            if not args.profiles_only:
                for pair in range(1,args.pairs+1):
                    for attempt in (1,2):
                        selected=[];valid=True
                        for arm in (('baseline','candidate') if pair%2 else ('candidate','baseline')):
                            ok,current=run_case(protocol,pair,attempt,arm,'none');selected+=current
                            if not ok: valid=False;break
                        if valid:
                            for row in selected: row['selected']=True
                            break
                    else: raise RuntimeError('two incomplete pair attempts; retained failures, stop')
            for scope in (('process','system') if protocol=='udp' else ('process',)):
                for arm in ('baseline','candidate'):
                    for attempt in (1,2):
                        ok,current=run_case(protocol,0,attempt,arm,'record',scope)
                        if ok:
                            for row in current: row['selected']=True
                            for row in current:
                                folder=Path(row['path']).parent
                                export=subprocess.run(['perf','report','--stdio','--no-children','--percent-limit','0.5','--sort','symbol,dso','-i',str(folder/'perf.data')],capture_output=True,text=True,check=True)
                                (folder/'perf-report.txt').write_text(export.stdout+export.stderr)
                            break
                    else: raise RuntimeError('two incomplete profile attempts; retained failures, stop')
        if args.profiles_only:
            return
        lines=['# NAPI paired capacity','','| Protocol/direction | Baseline Gbit/s | NAPI Gbit/s | Median paired change |','|---|---:|---:|---:|']
        for protocol in args.protocol:
            for direction in ('upload','download'):
                key='received_active_window_mbps' if protocol=='udp' else 'received_mbps'
                g={a:{r['pair']:r['result'][key] for r in rows if r['selected'] and r['mode']=='none' and r['protocol']==protocol and r['direction']==direction and r['arm']==a} for a in ('baseline','candidate')}
                a,b=g.values();change=statistics.median((b[p]/a[p]-1)*100 for p in a)
                lines.append(f'| {protocol}/{direction} | {statistics.median(a.values())/1000:.4f} | {statistics.median(b.values())/1000:.4f} | {change:+.2f}% |')
        (output/'summary.md').write_text('\n'.join(lines)+'\n')
    finally:
        shutil.copy2(original,installed)
        assert sha(installed)==sha(original),'installed ELF restoration failed'
        (output/'ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
        os.close(lock)


if __name__=='__main__': main()
