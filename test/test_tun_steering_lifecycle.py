#!/usr/bin/env python3
"""Linux root: disposable daemon lifecycle, existing-device guard and fallback."""
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import json


def main():
    binary=Path(sys.argv[1]).resolve()
    lock=open('/tmp/tayga-perf-workflow.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    ns='tayga-lifecycle-'+str(os.getpid())
    def run(*args,**kwargs):
        return subprocess.run(['ip','netns','exec',ns,*args],**kwargs)
    subprocess.run(['ip','netns','add',ns],check=True)
    try:
        with tempfile.TemporaryDirectory(prefix='tayga-lifecycle-') as folder:
            conf=Path(folder)/'config'
            conf.write_text('tun-device tgdaemon\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\nmap 198.18.0.2 2001:db8:1::2\nworkers 3\ntun-up yes\ntun-offload auto\n')
            for ending in (signal.SIGTERM,signal.SIGKILL):
                log=Path(folder)/str(ending)
                with log.open('w') as output:
                    child=subprocess.Popen(['ip','netns','exec',ns,str(binary),'-c',str(conf),'-d','--tun-steering=groups'],stdout=output,stderr=subprocess.STDOUT)
                    try:
                        for _ in range(100):
                            if 'requested=groups effective=groups' in log.read_text():break
                            assert child.poll() is None,log.read_text()
                            time.sleep(.05)
                        else: raise AssertionError(log.read_text())
                        run('ip','link','set','lo','up',check=True)
                        run('ip','addr','replace','198.18.0.2/32','dev','lo',check=True)
                        run('ip','route','replace','11.0.0.2/32','dev','tgdaemon',check=True)
                        def snapshot():
                            path=Path('/run/tayga-status.json')
                            prior=json.loads(path.read_text()) if path.exists() else {}
                            previous=prior.get('snapshot_sequence',0) if prior.get('pid')==child.pid else 0
                            child.send_signal(signal.SIGUSR2)
                            for _ in range(100):
                                data=json.loads(path.read_text()) if path.exists() else {}
                                if data.get('pid')==child.pid and data.get('snapshot_sequence',0)>previous and data.get('workers_synced'):
                                    return [w['rx_packets_v4'] for w in data['workers'] if w['slot']>0]
                                time.sleep(.05)
                            raise AssertionError('no synchronized worker snapshot')
                        sender_code='import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("198.18.0.2",6000)); [(s.sendto(bytes([i])+b"test"*16,("11.0.0.2",7000)),time.sleep(.002)) for i in range(128)]'
                        run('python3','-c',sender_code,check=True)
                        before=snapshot()
                        sender=subprocess.Popen(['ip','netns','exec',ns,'python3','-c',sender_code])
                        time.sleep(.1)
                        child.send_signal(signal.SIGHUP)
                        assert sender.wait(timeout=5)==0
                        after=snapshot()
                        delta=[b-a for a,b in zip(before,after)]
                        assert sum(delta)==128 and sum(v>0 for v in delta)==1,(before,after)
                        assert [i for i,v in enumerate(before) if v>0]==[i for i,v in enumerate(delta) if v>0],(before,delta)
                        assert child.poll() is None,log.read_text()
                        child.send_signal(ending)
                        child.wait(timeout=5)
                    finally:
                        if child.poll() is None:child.kill();child.wait()
                assert run('ip','link','show','tgdaemon',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
            assert run(str(binary),'-c',str(conf),'--mktun',stdout=subprocess.DEVNULL).returncode==0
            rejected=run(str(binary),'-c',str(conf),'-d','--tun-steering=groups',capture_output=True,text=True,timeout=5)
            assert rejected.returncode!=0 and 'fresh disposable' in rejected.stdout+rejected.stderr
            assert run('ip','link','show','tgdaemon',stdout=subprocess.DEVNULL).returncode==0
            run(str(binary),'-c',str(conf),'--rmtun',check=True,stdout=subprocess.DEVNULL)
            # Remove both privilege alternatives while retaining TUN capability.
            with (Path(folder)/'fallback').open('w') as output:
                child=subprocess.Popen(['ip','netns','exec',ns,'setpriv','--bounding-set=-bpf,-sys_admin',str(binary),'-c',str(conf),'-d','--tun-steering=groups'],stdout=output,stderr=subprocess.STDOUT)
                try:
                    for _ in range(100):
                        if 'requested=groups effective=kernel' in (Path(folder)/'fallback').read_text():break
                        assert child.poll() is None,(Path(folder)/'fallback').read_text()
                        time.sleep(.05)
                    else: raise AssertionError('fallback missing')
                    child.terminate();child.wait(timeout=5)
                finally:
                    if child.poll() is None:child.kill();child.wait()
            print('PASS: reload, TERM/KILL cleanup, existing-device rejection, capability fallback')
    finally: subprocess.run(['ip','netns','del',ns],check=True)

if __name__=='__main__':main()
