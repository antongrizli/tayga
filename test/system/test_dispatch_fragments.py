#!/usr/bin/env python3
"""Real TUN: out-of-order IPv4/IPv6 fragments retain a worker and payload."""
import fcntl,json,os,signal,socket,subprocess,sys,tempfile,time
from pathlib import Path

def inside(binary,output):
    from scapy.all import IP,IPv6,UDP,Raw,fragment,fragment6
    root=Path(output);cfg=root/'tayga.conf'
    cfg.write_text('tun-device dispatchtest\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8:64::1\nprefix 64:ff9b::/96\nwkpf-strict no\nmap 192.0.2.2 2001:db8:64::2\nworkers 3\ntun-up yes\ntun-offload auto\n')
    log=(root/'daemon.log').open('w')
    child=subprocess.Popen([binary,'-c',str(cfg),'-d','--dispatch=flows','--packet-io=uring'],stdout=log,stderr=log)
    def run(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
    def snapshot():
        path=Path('/run/tayga-status.json')
        prior=json.loads(path.read_text()) if path.exists() else {}
        sequence=prior.get('snapshot_sequence',0) if prior.get('pid')==child.pid else 0
        child.send_signal(signal.SIGUSR2)
        for _ in range(50):
            p=Path('/run/tayga-status.json')
            if p.exists():
                d=json.loads(p.read_text())
                if d.get('pid')==child.pid and d.get('snapshot_sequence',0)>sequence and d.get('workers_synced'):return d
            time.sleep(.02)
        raise AssertionError('no synchronized status')
    try:
        for _ in range(100):
            if 'Packet I/O: dispatch=flows transmit=uring' in (root/'daemon.log').read_text():break
            assert child.poll() is None,(root/'daemon.log').read_text();time.sleep(.05)
        else:raise AssertionError('startup timeout')
        run('ip','link','set','lo','up')
        run('ip','addr','add','192.0.2.2/32','dev','lo')
        run('ip','-6','addr','add','64:ff9b::c633:6402/128','dev','lo','nodad')
        run('ip','route','add','198.51.100.2/32','dev','dispatchtest')
        run('ip','-6','route','add','2001:db8:64::2/128','dev','dispatchtest')
        for family in (4,6):
            recv_family=socket.AF_INET6 if family==4 else socket.AF_INET
            recv_addr='64:ff9b::c633:6402' if family==4 else '192.0.2.2'
            with socket.socket(recv_family,socket.SOCK_DGRAM) as receiver:
                receiver.bind((recv_addr,49001));receiver.settimeout(2)
                af=socket.AF_INET if family==4 else socket.AF_INET6
                with socket.socket(af,socket.SOCK_RAW,socket.IPPROTO_RAW) as sender:
                    for iteration in range(4):
                        payload=bytes([family,iteration])+bytes(range(256))*5
                        if family==4:
                            packet=IP(src='192.0.2.2',dst='198.51.100.2',id=900+iteration)/UDP(sport=43001,dport=49001)/Raw(payload)
                            fragments=fragment(IP(bytes(packet)),fragsize=512);destination='198.51.100.2'
                        else:
                            packet=IPv6(src='64:ff9b::c633:6402',dst='2001:db8:64::2')/UDP(sport=43001,dport=49001)/Raw(payload)
                            fragments=fragment6(IPv6(bytes(packet)),560);destination='2001:db8:64::2'
                        for part in reversed(fragments[1:]):sender.sendto(bytes(part),(destination,0))
                        time.sleep(.05)
                        if iteration==2:child.send_signal(signal.SIGHUP)
                        sender.sendto(bytes(fragments[0]),(destination,0))
                        received,_=receiver.recvfrom(65536);assert received==payload,(family,iteration)
            print('PASS fragments',family,flush=True)
        time.sleep(.2);d=snapshot();assert d['dispatch_held']>=8 and d['dispatch_drops']==0,d
        assert d['async_accepted']==d['async_completed'] and d['async_errors']==0,d
        (root/'status.json').write_text(json.dumps(d,indent=2))
        child.terminate();assert child.wait(timeout=5)==0
        assert subprocess.run(['ip','link','show','dispatchtest'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
    finally:
        if child.poll() is None:child.kill();child.wait()
        log.close()

def main():
    if sys.argv[1]=='inside':inside(sys.argv[2],sys.argv[3]);return
    binary=str(Path(sys.argv[1]).resolve());root=Path(sys.argv[2]).resolve();root.mkdir(exist_ok=False)
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    ns='dispatch-fragments-'+str(os.getpid())
    subprocess.run(['ip','netns','add',ns],check=True)
    try:subprocess.run(['ip','netns','exec',ns,sys.executable,__file__,'inside',binary,str(root)],check=True)
    finally:subprocess.run(['ip','netns','del',ns],check=True)
if __name__=='__main__':main()
