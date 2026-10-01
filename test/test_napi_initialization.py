#!/usr/bin/env python3
"""Linux root: experimental NAPI must fail closed on every queue attachment."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',required=True)
p.add_argument('--output',required=True)
a=p.parse_args()
with open('/tmp/tayga-perf-workflow.lock') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=False)
    rows=[]
    with tempfile.TemporaryDirectory() as name:
        root=Path(name);shim=root/'fault.so'
        subprocess.run(['cc','-Wall','-Wextra','-Werror','-shared','-fPIC',str(Path(__file__).with_name('napi_ioctl_fault.c')),'-o',str(shim),'-ldl'],check=True)
        for mode in ('auto','tcp','off'):
            for workers in (0,3):
                for fault in ('unsupported-main','unsupported-worker','unverified-main','unverified-worker'):
                    if workers==0 and 'worker' in fault: continue
                    cfg=root/'tayga.conf';cfg.write_text(f'tun-device napitest\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\nworkers {workers}\ntun-offload {mode}\n')
                    env=dict(os.environ,LD_PRELOAD=str(shim),TAYGA_TEST_NAPI_FAIL=fault)
                    case=f'{mode}-w{workers}-{fault}'
                    proc=subprocess.run(['unshare','-n',str(Path(a.binary).resolve()),'-d','-c',str(cfg)],env=env,capture_output=True,text=True,timeout=5)
                    (out/f'{case}.log').write_text(proc.stdout+proc.stderr)
                    assert proc.returncode!=0,case
                    assert 'Unable to attach tun' in proc.stdout+proc.stderr or 'could not be verified' in proc.stdout+proc.stderr,case
                    rows.append(dict(case=case,passed=True,exit_status=proc.returncode));print('PASS',case,flush=True)
    (out/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
