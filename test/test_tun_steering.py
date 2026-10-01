#!/usr/bin/env python3
"""Linux root: real multiqueue TUN address-group ordering and framing tests."""
import ctypes
import fcntl
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import concurrent.futures
import resource

ROOT=Path(__file__).resolve().parents[1]

def sh(*args):
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL)

def inside(library):
    lib=ctypes.CDLL(library,use_errno=True)
    lib.attach.argtypes=[ctypes.c_int,ctypes.c_int]
    assert lib.attach(-1,0)==-1 and ctypes.get_errno()==22
    assert lib.attach(-1,129)==-1 and ctypes.get_errno()==22
    descriptors=[]
    try:
        for _ in range(3):
            fd=os.open('/dev/net/tun',os.O_RDWR|os.O_NONBLOCK)
            descriptors.append(fd)
            fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',b'tgtest',0x1001|0x100))
        limit=resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE,(max(descriptors)+1,limit[1]))
            assert lib.attach(descriptors[0],3)==-1 and ctypes.get_errno()==24
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE,limit)
        assert lib.attach(descriptors[0],3)==0, ctypes.get_errno()
        sh('ip','link','set','tgtest','up')
        sh('ip','addr','add','198.18.0.1/16','dev','tgtest')
        sh('ip','-6','addr','add','fd00::1/64','dev','tgtest','nodad')
        seen={}
        def receive(tag):
            for _ in range(30):
                ready,_,_=select.select(descriptors,[],[],1)
                for fd in ready:
                    packet=os.read(fd,65536)
                    if packet.endswith(tag): return descriptors.index(fd)
            raise AssertionError('packet did not reach TUN')
        for family,base in ((socket.AF_INET,'198.18.0.'),(socket.AF_INET6,'fd00::')):
            queues=[]
            for group in range(2,10):
                dst=base+str(group)
                for sequence in range(20):
                    tag=b'TGST'+struct.pack('!II',group,sequence)
                    with socket.socket(family,socket.SOCK_DGRAM) as sender:
                        sender.sendto(tag,(dst,7000+sequence))
                    q=receive(tag)
                    key=(family,group)
                    assert seen.setdefault(key,q)==q, ('queue migration',key)
                queues.append(seen[family,group])
            assert len(set(queues))==3,queues
        # Options, protocol changes and fragments retain the same address-group
        # bucket as ordinary UDP, even though no transport ports can be parsed.
        with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) as sender:
            for seq,(ihl,proto,fragment) in enumerate(((5,17,0),(6,6,0),(5,17,0x2000),(5,17,2),(5,1,0))):
                tag=b'TGST'+struct.pack('!II',22,seq)
                payload=b'\x00'*8+tag
                header=struct.pack('!BBHHHBBH4s4s',0x40|ihl,0,ihl*4+len(payload),seq,fragment,64,proto,0,
                                   socket.inet_aton('198.18.0.1'),socket.inet_aton('198.18.0.2'))
                sender.sendto(header+b'\x01'*(4*(ihl-5))+payload,('198.18.0.2',0))
                assert receive(tag)==seen[socket.AF_INET,2]
            symmetric=None
            for sequence,(src,dst) in enumerate((('198.18.0.2','198.18.0.3'),('198.18.0.3','198.18.0.2'))):
                tag=b'SYMM'+struct.pack('!II',1,sequence)
                payload=b'\x00'*8+tag
                header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),sequence,0,64,17,0,
                                   socket.inet_aton(src),socket.inet_aton(dst))
                sender.sendto(header+payload,(dst,0))
                q=receive(tag)
                if symmetric is None:symmetric=q
                assert symmetric==q
        with socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_RAW) as sender:
            sender.setsockopt(socket.IPPROTO_IPV6,36,1)  # IPV6_HDRINCL
            for seq,next_header in enumerate((60,44,58)):
                tag=b'TGST'+struct.pack('!II',33,seq)
                ext=(struct.pack('!BBHI',17,0,1,123) if next_header==44 else b'\x11\x00'+b'\x00'*6) if next_header!=58 else b'\x80\x00'+b'\x00'*6
                payload=ext+b'\x00'*8+tag
                header=struct.pack('!IHBB16s16s',6<<28,len(payload),next_header,64,
                                   socket.inet_pton(socket.AF_INET6,'fd00::1'),socket.inet_pton(socket.AF_INET6,'fd00::2'))
                sender.sendto(header+payload,('fd00::2',0))
                assert receive(tag)==seen[socket.AF_INET6,2]
        # Concurrent first arrivals contend on one previously empty bucket.
        def send_first(thread):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                for sequence in range(8):
                    sender.sendto(b'RACE'+struct.pack('!II',thread,sequence),('198.18.0.99',7100+thread))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(send_first,range(8)))
        last={}; race_queue=None
        for _ in range(64):
            ready,_,_=select.select(descriptors,[],[],2)
            assert ready,'missing concurrent packet'
            for fd in ready:
                packet=os.read(fd,65536)
                assert packet[-12:-8]==b'RACE'
                thread,sequence=struct.unpack('!II',packet[-8:])
                assert sequence==last.get(thread,-1)+1
                last[thread]=sequence
                q=descriptors.index(fd)
                if race_queue is None: race_queue=q
                assert race_queue==q
        assert len(last)==8 and all(v==7 for v in last.values())
        print('PASS: 384 UDP packets including concurrent first arrivals, IPv4 options/fragments/ICMP, IPv6 extension/fragment/ICMP queue stability',flush=True)
    finally:
        for fd in descriptors: os.close(fd)
    assert subprocess.run(['ip','link','show','tgtest'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0


def main():
    if len(os.sys.argv)>2 and os.sys.argv[1]=='inside':
        inside(os.sys.argv[2]); return
    if os.geteuid()!=0: raise SystemExit('Linux root required')
    lock=open('/tmp/tayga-perf-workflow.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    with tempfile.TemporaryDirectory(prefix='tayga-steering-') as folder:
        source=Path(folder)/'loader.c'; library=Path(folder)/'loader.so'
        source.write_text('#include <sys/ioctl.h>\n#include <linux/if_tun.h>\n#include "tun_steering.h"\nint attach(int tun,int queues){char log[16384]={0};int p=steering_program(queues,log,sizeof(log));if(p<0)return -1;int r=ioctl(tun,TUNSETSTEERINGEBPF,&p);close(p);return r;}\n')
        sh('gcc','-shared','-fPIC','-Wall','-O2','-I'+str(ROOT),str(source),'-o',str(library))
        ns='tayga-steering-'+str(os.getpid())
        sh('ip','netns','add',ns)
        try: subprocess.run(['ip','netns','exec',ns,'python3',str(Path(__file__).resolve()),'inside',str(library)],check=True)
        finally: sh('ip','netns','del',ns)

if __name__=='__main__':main()
