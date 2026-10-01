#!/usr/bin/env python3
"""Run finite integrity/PMTU tests with reversible experimental installation."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

spec=importlib.util.spec_from_file_location('study',Path(__file__).with_name('run-tun-steering-study.py'))
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    if os.geteuid()!=0:p.error('Linux root required')
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=a.output;root.mkdir(exist_ok=False)
    daemon=Path('/usr/sbin/tayga');start=Path('/usr/local/sbin/clat-start.sh')
    shutil.copy2(daemon,root/'original-tayga');shutil.copy2(start,root/'original-startup.sh')
    generated=study.startup(start.read_text())
    before="while ! grep -q 'TUN offload negotiated:' \"$ARTIFACT_DIR/clat.log\"; do"
    after='''while ! python3 -c 'import json,sys; d=json.load(open("/run/tayga-status.json")); sys.exit(not(d.get("pid")==int(sys.argv[1]) and d.get("offload_negotiation_complete")))' "$parent" 2>/dev/null; do'''
    assert before in generated
    (root/'experimental-startup.sh').write_text(generated.replace(before,after))
    def interrupted(signum,frame):raise KeyboardInterrupt(signum)
    signal.signal(signal.SIGTERM,interrupted)
    try:
        study.install(a.binary,daemon);study.install(root/'experimental-startup.sh',start);start.chmod(0o755)
        env=dict(os.environ,TAYGA_STEERING_MODE='groups',TEST_SIZE_MB='4')
        for name in ('test_correctness.py','test_pmtud.py'):
            test=Path(__file__).resolve().parents[1]/'test'/name
            (root/name).write_bytes(test.read_bytes())
            with (root/(name+'.log')).open('w') as log:
                child=subprocess.Popen(['python3',str(test)],env=env,stdout=log,stderr=subprocess.STDOUT)
                try:status=child.wait(timeout=180)
                except BaseException:
                    child.terminate()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                    raise
            if status:raise RuntimeError(f'{name} failed; see retained log')
            snapshot=json.loads(Path('/run/tayga-status.json').read_text())
            assert snapshot['steering_effective']=='groups',snapshot
            (root/(name+'.status.json')).write_text(json.dumps(snapshot,indent=2))
            print(f'PASS {name}',flush=True)
    finally:
        # Existing suites own their test namespaces; terminate remaining test
        # daemons before restoring paths if a suite was interrupted.
        for ns in ('client','router','clatns','server'):
            ids=subprocess.run(['ip','netns','pids',ns],capture_output=True,text=True).stdout.split()
            for pid in ids:
                try:os.kill(int(pid),signal.SIGTERM)
                except ProcessLookupError:pass
            subprocess.run(['ip','netns','del',ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        study.install(root/'original-tayga',daemon);study.install(root/'original-startup.sh',start)
        (root/'restored.json').write_text(json.dumps(dict(daemon=study.digest(daemon),startup=study.digest(start)),indent=2))

if __name__=='__main__':main()
