#!/usr/bin/env python3
"""Linux root: bounded diagnostic runs, never pool with capacity results."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',required=True)
p.add_argument('--library',required=True)
p.add_argument('--duration',type=int,default=10)
p.add_argument('--pairs',type=int,default=3)
p.add_argument('--clients',type=int,default=2)
p.add_argument('--start-gate',choices=('on','off'),default='off')
a=p.parse_args()
if os.geteuid()!=0 or not 1<=a.duration<=300 or not 1<=a.pairs<=6 or not 1<=a.clients<=4: p.error('root, duration 1..300, pairs 1..6 and clients 1..4 required')
lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
root=Path(a.output).resolve();root.mkdir(parents=True,exist_ok=False)
(root/'identity.json').write_text(json.dumps({str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in (Path(a.library).resolve(),Path('/usr/sbin/tayga'),Path('/usr/bin/iperf3'),Path('/usr/local/sbin/benchmark-clat.sh'),Path(__file__).resolve())},indent=2)+'\n')
(root/'settings.json').write_text(json.dumps(vars(a),indent=2)+'\n')
(root/'measured-runner.py').write_bytes(Path(__file__).read_bytes())
wrapper=root/'bin';wrapper.mkdir()
# Environment arguments avoid inserting paths into shell source.
(wrapper/'iperf3').write_text('#!/bin/sh\nLD_PRELOAD="$IPERF_READ_DIAGNOSTIC${LD_PRELOAD:+:$LD_PRELOAD}"\nexport LD_PRELOAD\nexec /usr/bin/iperf3 "$@"\n')
(wrapper/'iperf3').chmod(0o755)
rows=[]
for pair in range(1,a.pairs+1):
    for drain in ((.5,0) if pair%2 else (0,.5)):
        folder=root/f'pair{pair}-drain{drain}'
        env=dict(os.environ,PATH=str(wrapper)+':'+os.environ['PATH'],IPERF_READ_DIAGNOSTIC=str(Path(a.library).resolve()),
                 ARTIFACT_DIR=str(folder),DURATION=str(a.duration),WARMUP='0',RATE='0',CLIENTS=str(a.clients),FLOWS='1',WORKERS='1',
                 IPERF_START_GATE=a.start_gate,DIRECTIONS='upload download',PROTOCOL='udp',CLAT_OFFLOAD='auto',FORWARDING_GRO='on',PERF_MODE='none',
                 RECEIVER_DRAIN_SECONDS=str(drain),CLAT_OFFLINK_MTU='1280',DATAGRAM_SIZE='1200')
        print(folder.name,flush=True)
        with (root/f'{folder.name}.log').open('w') as log:
            child=subprocess.Popen(['/usr/local/sbin/benchmark-clat.sh'],env=env,stdout=log,stderr=subprocess.STDOUT)
            try: status=child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                child.terminate()
                try: child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill();child.wait()
                raise RuntimeError('diagnostic timeout; stop campaign and inspect cleanup')
        rows.append(dict(pair=pair,drain=drain,status=status,path=str(folder)))
        (root/'ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
