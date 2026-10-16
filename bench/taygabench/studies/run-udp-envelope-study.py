#!/usr/bin/env python3
"""Separate paced operating points from unrestricted native UDP capacity."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import statistics
import shutil
from importlib.util import spec_from_file_location, module_from_spec

spec=spec_from_file_location('native_study',Path(__file__).with_name('run-udp-batch-study.py'))
native=module_from_spec(spec);spec.loader.exec_module(native)

def summarize(rows,rates,pairs):
    output=[]
    if len({r["case"] for r in rows})!=len(rows):raise ValueError("duplicate case")
    for direction in ('upload','download'):
        for rate in rates:
            selected=[r for r in rows if not r['finite'] and not r.get('profile',False) and r['direction']==direction and r['requested_rate_mbps']==rate]
            if len(selected)!=pairs:raise ValueError('incomplete operating point')
            if any(r['sender'].get('rate_mbps')!=rate or r['rate']!=('paced' if rate else 'unrestricted') for r in selected):raise ValueError('rate metadata mismatch')
            complete=all(r['capture_valid'] and r['workload_valid'] for r in selected)
            reached=rate==0 or all(.95*rate<=r['offered_mbps']<=1.05*rate for r in selected)
            output.append(dict(direction=direction,rate_mbps=rate,unrestricted=rate==0,runs=len(selected),
                offered_median_mbps=statistics.median(r['offered_mbps'] for r in selected),
                received_median_mbps=statistics.median(r['received_mbps'] for r in selected),
                loss_max_percent=max(r['loss_percent'] for r in selected),
                operating_point_pass=complete and reached and all(r['acceptance_pass'] and not r['pressure_deltas'] and r['sender']['packets']==r['receiver']['packets'] and r['sender']['bytes']==r['receiver']['bytes'] and not r['receiver']['invalid'] and not r['receiver']['duplicates'] for r in selected),
                reached_requested_rate=reached,pressure=[r['pressure_deltas'] for r in selected]))
    return output

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',required=True);p.add_argument('--endpoint',required=True)
    p.add_argument('--receive-buffers',type=int,nargs='+',help='Alternate explicit receiver buffer treatments')
    p.add_argument('--receive-buffer',type=int,default=0,help='SO_RCVBUF request, 0 preserves kernel default')
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--force-receive-buffer',action='store_true',help='Explicit diagnostic SO_RCVBUFFORCE; requires CAP_NET_ADMIN')
    p.add_argument('--profiles-only',action='store_true',help='Separate unrestricted process/system profiles; no capacity summary')
    p.add_argument('--rates',type=int,nargs='+',default=[1000,8000,16000,0])
    p.add_argument('--duration',type=int,default=10);p.add_argument('--pairs',type=int,default=3)
    a=p.parse_args()
    if not 0<=a.receive_buffer<=1073741824 or os.geteuid()!=0 or not 1<=a.duration<=300 or not 1<=a.pairs<=20 or 0 not in a.rates or len(set(a.rates))!=len(a.rates) or any(not 0<=r<=1000000 for r in a.rates):p.error('root, valid unique rates including unrestricted 0, duration 1..300, pairs 1..20 required')
    def interrupted(signum,frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    buffers=a.receive_buffers or [a.receive_buffer]
    if len(set(buffers))!=len(buffers) or any(not 0<=b<=1073741824 for b in buffers):p.error('invalid buffer treatments')
    os.environ['UDP_ENDPOINT_OFFLOAD']='strict'
    os.environ['UDP_ENDPOINT_RCVBUF']=str(a.receive_buffer)
    os.environ['UDP_ENDPOINT_RCVBUF_FORCE']='1' if a.force_receive_buffer else '0'
    root=a.output.resolve();root.mkdir(parents=True,exist_ok=False)
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    for field in ('binary','endpoint'):
        path=Path(getattr(a,field)).resolve();setattr(a,field,str(path));setattr(a,field+'_hash',hashlib.sha256(path.read_bytes()).hexdigest())
    for field in ('binary','endpoint'):shutil.copy2(getattr(a,field),root/('measured-'+field))
    (root/'settings.json').write_text(json.dumps(vars(a),default=str,indent=2))
    for path in (Path(__file__),Path(__file__).with_name('run-udp-batch-study.py'),Path(__file__).with_name('udp-batch-endpoint.c')):
        (root/path.name).write_bytes(path.read_bytes())
    rows=[]
    try:
        for buffer in buffers:
            os.environ['UDP_ENDPOINT_RCVBUF']=str(buffer)
            for direction in ('upload','download'):
                for batch,gro in ((1,0),(32,0),(1,1),(32,1)):
                    rows.append(native.run_case(a,root,direction,batch,gro,f'finite-buffer{buffer}-{direction}-{batch}-{gro}',finite=True))
        if a.profiles_only:
            a.rate_mbps=0
            for buffer in buffers:
                os.environ['UDP_ENDPOINT_RCVBUF']=str(buffer)
                for scope in ('process','system'):
                    a.profile_scope=scope
                    for direction in ('upload','download'):
                        rows.append(native.run_case(a,root,direction,32,1,f'profile-buffer{buffer}-{scope}-{direction}',profile=True))
            (root/'profile-summary.json').write_text(json.dumps([r for r in rows if r['profile']],indent=2))
            return
        for pair in range(1,a.pairs+1):
            rates=a.rates if pair%2 else list(reversed(a.rates))
            for rate in rates:
                a.rate_mbps=rate
                for buffer in (buffers if pair%2 else list(reversed(buffers))):
                    os.environ['UDP_ENDPOINT_RCVBUF']=str(buffer)
                    for direction in ('upload','download'):
                        rows.append(native.run_case(a,root,direction,32,1,f'pair{pair}-{direction}-rate{rate}-buffer{buffer}'))
        result={str(buffer):summarize([r for r in rows if r['receiver']['requested_rcvbuf']==buffer],a.rates,a.pairs) for buffer in buffers}
        (root/'summary.json').write_text(json.dumps(result if a.receive_buffers else result[str(buffers[0])],indent=2))
    finally:
        (root/'ledger.json').write_text(json.dumps(rows,indent=2))
        lock.close()
if __name__=='__main__':main()
