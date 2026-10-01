#!/usr/bin/env python3
"""Linux root: isolated native UDP batching experiment, no NAT44/iperf pooling."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import statistics
import subprocess
import time


def command(*args, check=True):
    return subprocess.run([str(a) for a in args], check=check, text=True, capture_output=True)


def kill_child(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def run_case(args, root, direction, batch, gro, label, finite=False, profile=False):
    folder = root / label
    folder.mkdir()
    trans, recv = f'ubt{os.getpid()}', f'ubr{os.getpid()}'
    daemon = receiver = recorder = None
    log = (folder / 'tayga.log').open('w')
    receive_log = (folder / 'receive.log').open('w')
    perf_log = (folder / 'perf.log').open('w')
    def ns(name, *argv):
        return command('ip', 'netns', 'exec', name, *argv)
    try:
        for name in (trans, recv):
            command('ip', 'netns', 'add', name)
            command('ip', '-n', name, 'link', 'set', 'lo', 'up')
        ns(trans, 'ip', 'link', 'add', 'out0', 'type', 'veth', 'peer', 'name', 'ep0')
        command('ip', '-n', trans, 'link', 'set', 'ep0', 'netns', recv)
        for name, dev, a4, a6 in ((trans, 'out0', '10.23.0.1/24', 'fd23::1/64'), (recv, 'ep0', '10.23.0.2/24', 'fd23::2/64')):
            command('ip', '-n', name, 'link', 'set', dev, 'mtu', '1280', 'up')
            command('ip', '-n', name, 'addr', 'add', a4, 'dev', dev)
            command('ip', '-n', name, '-6', 'addr', 'add', a6, 'dev', dev, 'nodad')
            ns(name, 'ethtool', '-K', dev, 'gro', 'on', 'rx-udp-gro-forwarding', 'on')
            (folder / f'{dev}-features.txt').write_text(ns(name, 'ethtool', '-k', dev).stdout)
        ns(trans, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', 'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')
        cfg=folder / 'tayga.conf'
        cfg.write_text('tun-device ubtun\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8:64::1\nprefix 64:ff9b::/96\nwkpf-strict no\nmap 192.0.2.2 2001:db8:64::2\nworkers 1\ntun-offload auto\nofflink-mtu 1280\n')
        ns(trans, args.binary, '-c', cfg, '--mktun')
        command('ip', '-n', trans, 'link', 'set', 'ubtun', 'mtu', '1280', 'up')
        if direction=='upload':
            af_in, source, dest = 4, '192.0.2.2', '198.51.100.2'
            af_out, target = 6, '64:ff9b::c633:6402'
            command('ip', '-n', trans, 'addr', 'add', source+'/32', 'dev', 'lo')
            command('ip', '-n', trans, 'route', 'add', dest+'/32', 'dev', 'ubtun')
            command('ip', '-n', trans, '-6', 'route', 'add', target+'/128', 'via', 'fd23::2', 'dev', 'out0')
            command('ip', '-n', recv, '-6', 'addr', 'add', target+'/128', 'dev', 'lo', 'nodad')
            command('ip', '-n', recv, '-6', 'route', 'add', 'default', 'via', 'fd23::1')
            command('ip', '-n', trans, '-6', 'route', 'add', '2001:db8:64::2/128', 'dev', 'ubtun')
        else:
            af_in, source, dest = 6, '64:ff9b::c633:6402', '2001:db8:64::2'
            af_out, target = 4, '192.0.2.2'
            command('ip', '-n', trans, '-6', 'addr', 'add', source+'/128', 'dev', 'lo', 'nodad')
            command('ip', '-n', trans, '-6', 'route', 'add', dest+'/128', 'dev', 'ubtun')
            command('ip', '-n', trans, 'route', 'add', target+'/32', 'via', '10.23.0.2', 'dev', 'out0')
            command('ip', '-n', recv, 'addr', 'add', target+'/32', 'dev', 'lo')
            command('ip', '-n', recv, 'route', 'add', 'default', 'via', '10.23.0.1')
            command('ip', '-n', trans, 'route', 'add', '198.51.100.2/32', 'dev', 'ubtun')
        daemon=subprocess.Popen(['ip','netns','exec',trans,args.binary,'-d','-c',str(cfg)], stdout=log, stderr=log)
        time.sleep(.2)
        assert daemon.poll() is None, 'TAYGA initialization failed'
        warmup=command('ip','netns','exec',trans,'ping','-c','1','-W','3','-I',source,dest,check=False)
        (folder/'warmup.txt').write_text(warmup.stdout+warmup.stderr)
        if warmup.returncode:
            for name in (trans,recv):
                for action,argv in (('neigh',['ip','-6','neigh']),('route',['ip','-6','route']),('counters',['nstat','-az'])):
                    (folder/f'{name}-{action}.txt').write_text(command('ip','netns','exec',name,*argv,check=False).stdout)
            raise RuntimeError('warmup path failed; see counters and warmup.txt')
        cookie=str(secrets.randbits(63))
        receiver=subprocess.Popen(['ip','netns','exec',recv,args.endpoint,'receive',str(af_out),target,str(gro),cookie,str(folder/'receiver.json')], stdout=subprocess.PIPE,stderr=receive_log,text=True)
        ready,_,_=select.select([receiver.stdout],[],[],3)
        assert ready and receiver.stdout.readline().strip()=='READY', 'receiver readiness failed'
        ticks_before=Path(f'/proc/{daemon.pid}/stat').read_text().split(') ',1)[1].split()
        if profile:
            recorder=subprocess.Popen(['perf','record','-e','cpu-clock','-F','99','-g','--call-graph','fp','-p',str(daemon.pid),'-o',str(folder/'perf.data'),'--','sleep',str(args.duration+2)], stdout=perf_log,stderr=perf_log)
            time.sleep(.3)
            assert recorder.poll() is None, 'perf attachment failed'
        sender=['ip','netns','exec',trans,args.endpoint,'send',str(af_in),source,dest,str(args.duration),str(batch),cookie,str(folder/'sender.json')]
        if finite: sender += ['35','64']
        result=command(*sender,check=False)
        (folder/'sender.log').write_text(result.stdout+result.stderr)
        result.check_returncode()
        time.sleep(.5)
        kill_child(receiver)
        assert receiver.returncode==0, 'receiver rejected payload or failed'
        ticks_after=Path(f'/proc/{daemon.pid}/stat').read_text().split(') ',1)[1].split()
        daemon.send_signal(signal.SIGUSR2)
        time.sleep(.1)
        if recorder:
            recorder.wait(timeout=10)
            assert recorder.returncode==0, 'perf recording failed'
            export=command('perf','report','--stdio','--no-children','--percent-limit','0.5','--sort','symbol,dso','-i',folder/'perf.data')
            (folder/'perf-report.txt').write_text(export.stdout+export.stderr)
        sent=json.loads((folder/'sender.json').read_text()); got=json.loads((folder/'receiver.json').read_text())
        assert sent['packets']>0 and got['packets']<=sent['packets'] and got['invalid']==0 and got['duplicates']==0
        assert got['highest_sequence']<sent['packets'], 'sequence outside sender ledger'
        if finite:
            assert sent['packets']==got['packets']==35
            assert sent['bytes']==got['bytes']==34*1200+64
            assert got['short_tails']==1
        useful=got['bytes']*8/sent['elapsed_seconds']/1e6
        lost=sent['packets']-got['packets']
        cpu_ticks=sum(int(ticks_after[i])-int(ticks_before[i]) for i in (11,12))
        row=dict(case=label,direction=direction,batch=batch,gro=gro,finite=finite,profile=profile,
                 sender=sent,receiver=got,received_mbps=useful,loss_percent=100*lost/sent['packets'],
                 tayga_cpu_cores=cpu_ticks/os.sysconf('SC_CLK_TCK')/sent['elapsed_seconds'],
                 tayga_cpu_seconds=cpu_ticks/os.sysconf('SC_CLK_TCK'),
                 tayga_cpu_seconds_per_received_gib=(cpu_ticks/os.sysconf('SC_CLK_TCK'))/(got['bytes']/(1024**3)) if got['bytes'] else None,
                 offered_mbps=sent['bytes']*8/sent['elapsed_seconds']/1e6,
                 acceptance_pass=lost==0,capture_valid=True,workload_valid=True,
                 rate='unrestricted',topology='local sender -> TUN translator -> veth receiver; no NAT44',
                 binary_sha256=args.binary_hash,endpoint_sha256=args.endpoint_hash)
        (folder/'result.json').write_text(json.dumps(row,indent=2)+'\n')
        print(f'{label}: rx={useful:.1f} Mbit/s loss={row["loss_percent"]:.2f}% GRO buffers={got["aggregates"]}',flush=True)
        return row
    finally:
        for child in (recorder,receiver,daemon): kill_child(child)
        for file in (log,receive_log,perf_log): file.close()
        for name in (recv,trans): command('ip','netns','del',name,check=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',default='/usr/sbin/tayga')
    p.add_argument('--endpoint',required=True)
    p.add_argument('--offload-policy',choices=('strict','auto'),default='strict',help='strict for controlled A/B; auto permits ordinary UDP fallback')
    p.add_argument('--output',required=True)
    p.add_argument('--duration',type=int,default=15)
    p.add_argument('--pairs',type=int,default=3)
    p.add_argument('--batch-sizes',type=int,nargs='+',default=[1,32],help='capacity sweep; each batch must be 1..32')
    p.add_argument('--gro-values',type=int,nargs='+',choices=(0,1),default=[0,1],help='receiver GRO treatments')
    p.add_argument('--correctness-only',action='store_true')
    p.add_argument('--start-pair',type=int,default=1)
    args=p.parse_args()
    os.environ['UDP_ENDPOINT_OFFLOAD']=args.offload_policy
    if os.geteuid()!=0 or not 1<=args.duration<=300 or args.pairs<1 or args.start_pair<1 or any(not 1<=size<=32 for size in args.batch_sizes) or len(set(args.batch_sizes))!=len(args.batch_sizes): p.error('Linux root, positive pairs and duration 1..300 required')
    lock=os.open('/tmp/tayga-perf-workflow.lock',os.O_RDONLY|os.O_CREAT,0o644)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=Path(args.output).resolve();root.mkdir(parents=True,exist_ok=False)
    (root/'settings.json').write_text(json.dumps(vars(args),indent=2)+'\n')
    (root/'measured-runner.py').write_bytes(Path(__file__).read_bytes())
    for field in ('binary','endpoint'):
        path=Path(getattr(args,field)).resolve();setattr(args,field,str(path));setattr(args,field+'_hash',hashlib.sha256(path.read_bytes()).hexdigest())
    rows=[]
    try:
        for direction in ('upload','download'):
            for batch,gro in dict.fromkeys([(1,0),(32,0),(1,1),(32,1)]+[(b,g) for g in args.gro_values for b in args.batch_sizes]):
                rows.append(run_case(args,root,direction,batch,gro,f'correctness-{direction}-{batch}-{gro}',finite=True))
        if not args.correctness_only:
            for pair in range(args.start_pair,args.start_pair+args.pairs):
                treatments=[(batch,gro) for gro in args.gro_values for batch in args.batch_sizes]
                if pair%2==0: treatments.reverse()
                for direction in ('upload','download'):
                    for batch,gro in treatments:
                        rows.append(run_case(args,root,direction,batch,gro,f'pair{pair}-{direction}-{batch}-{gro}'))
            for direction in ('upload','download'):
                for batch,gro in dict.fromkeys([(1,0)]+[(b,g) for g in args.gro_values for b in args.batch_sizes]):
                    rows.append(run_case(args,root,direction,batch,gro,f'profile-{direction}-{batch}-{gro}',profile=True))
    finally:
        rows=[json.loads(f.read_text()) for f in sorted(root.glob('*/result.json'))]
        (root/'ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
        command('uname','-a').check_returncode()
        (root/'kernel.txt').write_text(command('uname','-a').stdout)
        os.close(lock)
    print(f'Completed {len(rows)} valid cases',flush=True)


if __name__=='__main__': main()
