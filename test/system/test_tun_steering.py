#!/usr/bin/env python3
"""Linux root: real multiqueue TUN address-group ordering and framing tests."""
import argparse
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
import sys

ROOT = Path(__file__).resolve().parents[2]

def sh(*args):
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL)

def inside(library, mode):
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
        if mode == "flows":
            exercise_flows(descriptors, receive)
        else:
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
        print(f'PASS: {mode} real TUN queue stability, backlog and concurrent arrivals', flush=True)
    finally:
        for fd in descriptors: os.close(fd)
    assert subprocess.run(['ip','link','show','tgtest'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0


def exercise_flows(descriptors, receive):
    # Keep a socket/4-tuple alive across the former promotion boundary. Send
    # before reading so packets remain on their original queues under backlog.
    for family, dst in ((socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, 'fd00::2')):
        owners=[]
        for flow in range(8):
            with socket.socket(family,socket.SOCK_DGRAM) as sender:
                sender.bind(('198.18.0.1' if family==socket.AF_INET else 'fd00::1', 6000+flow))
                expected=[]
                for sequence, size in enumerate((12, 227, 228, 229, 300, 12)):
                    tag=b'FLOW'+struct.pack('!II',flow,sequence)
                    data=b'x'*size+tag
                    sender.sendto(data,(dst,7000))
                    expected.append(tag)
                queue=None
                for tag in expected:
                    q=receive(tag)
                    if queue is None: queue=q
                    assert q==queue,('flow changed queue with unread packets',flow,tag)
                owners.append(queue)
        assert len(set(owners))==3,owners
    # Concurrent first arrivals to the same new 4-tuple must publish one owner.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
        sender.bind(('198.18.0.1',6500))
        def send(thread):
            sender.sendto(b'RACE'+struct.pack('!II',thread,0)+b'x'*(thread*100),('198.18.0.99',7000))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(send,range(8)))
        queues=[]
        for _ in range(8):
            ready,_,_=select.select(descriptors,[],[],2); assert ready
            fd=ready[0]; os.read(fd,65536); queues.append(descriptors.index(fd))
        assert len(set(queues))==1,queues


def frame(family=4, proto=17, sport=6000, length=100, fragment=0, options=False):
    """Ethernet framing is required by socket-filter BPF_PROG_TEST_RUN."""
    if family==4:
        ihl=24 if options else 20
        ip=struct.pack('!BBHHHBBH4s4s',0x40+ihl//4,0,length,123,fragment,64,proto,0,
                       socket.inet_aton('198.18.0.1'),socket.inet_aton('198.18.0.2'))
        ip+=b'\x01'* (ihl-20)
        ether=b'\0'*12+b'\x08\x00'
    else:
        ihl=40
        ip=struct.pack('!IHBB16s16s',6<<28,length-40,proto,64,
                       socket.inet_pton(socket.AF_INET6,'fd00::1'),socket.inet_pton(socket.AF_INET6,'fd00::2'))
        ether=b'\0'*12+b'\x86\xdd'
    data=bytearray(length-ihl)
    struct.pack_into('!HH',data,0,sport,7000)
    return ether+ip+data



def bucket(data, mode):
    """Model the documented hash only to construct deliberate collision inputs."""
    ip=data[14:];family=ip[0]>>4
    word=lambda value:int.from_bytes(value,sys.byteorder)
    if family==4:
        h=word(ip[12:16])^word(ip[16:20])^4
        offset=(ip[0]&15)*4
        use_ports=not int.from_bytes(ip[6:8],'big')&0x3fff and ip[9] in (6,17)
    else:
        h=6
        for i in range(4):h=((h^word(ip[8+4*i:12+4*i])^word(ip[24+4*i:28+4*i]))&0xffffffff)*16777619
        offset=40;use_ports=ip[6] in (6,17)
    if mode=='flows' and use_ports:h=((h^word(ip[offset:offset+4]))&0xffffffff)*16777619
    h=(h^(h>>16))&0xffffffff;h*=0x45d9f3b
    return (h^(h>>16))&65535


def test_program(library, mode):
    lib=ctypes.CDLL(str(library),use_errno=True)
    lib.program.argtypes=[ctypes.c_int]
    lib.family_counter.argtypes=[ctypes.c_int,ctypes.c_uint]
    lib.family_counter.restype=ctypes.c_longlong
    lib.packet_queue.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint]
    def queue(fd, data):
        q=lib.packet_queue(fd,data,len(data)); assert q>=0,ctypes.get_errno(); return q
    fd=lib.program(3);assert fd>=0
    try:
        assert bucket(frame(4),mode)!=bucket(frame(6),mode)
        assert lib.family_counter(fd,0)==lib.family_counter(fd,1)==0
        queue(fd,frame(4))
        assert lib.family_counter(fd,0)==1 and lib.family_counter(fd,1)==0
        queue(fd,frame(6))
        assert lib.family_counter(fd,0)==lib.family_counter(fd,1)==1
        queue(fd,frame(4,length=300));queue(fd,frame(6,length=300))
        assert lib.family_counter(fd,0)==lib.family_counter(fd,1)==1
    finally:os.close(fd)
    for count in (1,2,3,4,8,128):
        before=len(os.listdir('/proc/self/fd'))
        fd=lib.program(count);assert fd>=0,ctypes.get_errno()
        try:
            for family in (4,6):
                owners=[]
                for flow in range(max(16,count)):
                    first=queue(fd,frame(family,sport=6000+flow))
                    assert 0<=first<count
                    for size in (255,256,257,1000,100):
                        assert queue(fd,frame(family,sport=6000+flow,length=size))==first
                    tcp=frame(family,proto=6,sport=6000+flow,length=300)
                    tcp_owner=queue(fd,tcp)
                    assert queue(fd,frame(family,proto=6,sport=6000+flow,length=100))==tcp_owner
                    owners.append(first)
                if mode=='flows' and count<=8: assert len(set(owners))==count,owners
                # Fragment fallback ignores ports, including across sizes.
                fragment_owner=queue(fd,frame(family,proto=44 if family==6 else 17,fragment=0x2000))
                for port in (6001,65535):
                    assert queue(fd,frame(family,proto=44 if family==6 else 17,
                                          sport=port,length=300,fragment=2))==fragment_owner
            # Churn must not evict or migrate previously admitted buckets.
            held=queue(fd,frame(sport=6100))
            for port in range(10000,11000): queue(fd,frame(sport=port))
            assert queue(fd,frame(sport=6100,length=300))==held
            # Concurrent executions contend on the same new bucket.
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                owners=list(executor.map(lambda n:queue(fd,frame(sport=6500,length=100+n*100)),range(8)))
            assert len(set(owners))==1,owners
        finally:os.close(fd)
        assert len(os.listdir('/proc/self/fd'))==before,'BPF descriptor leak'
    # The map is shared across families. Collisions intentionally share the
    # already published owner, even when counters/packet sizes differ.
    fd=lib.program(3);assert fd>=0
    try:
        known={};same=cross=None
        for port in range(10000,14000):
            data=bytearray(frame(sport=port))
            if mode=='groups':data[32:34]=struct.pack('!H',port)
            data=bytes(data);key=bucket(data,mode)
            if key in known and same is None:same=(known[key],data)
            known[key]=data
        for port in range(10000,14000):
            data=bytearray(frame(6,sport=port))
            if mode=='groups':data[52:54]=struct.pack('!H',port)
            data=bytes(data);key=bucket(data,mode)
            if key in known:cross=(known[key],data);break
        assert same is not None and cross is not None,'collision fixture search failed'
        for a,b in (same,cross):
            owner=queue(fd,a)
            assert queue(fd,b)==owner
    finally:os.close(fd)
    print(f'PASS: {mode} BPF load/test-run, queue limits, size stability, fragments, churn and CAS races',flush=True)


def main():
    if len(os.sys.argv)>2 and os.sys.argv[1]=='inside':
        inside(os.sys.argv[2], os.sys.argv[3]); return
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--steering',choices=('groups','flows'),default='groups')
    args=parser.parse_args()
    if sys.platform != 'linux': parser.error('Linux required')
    if os.geteuid()!=0: raise SystemExit('Linux root required')
    lock=open('/tmp/tayga-perf-workflow.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    with tempfile.TemporaryDirectory(prefix='tayga-steering-') as folder:
        source=Path(folder)/'loader.c'; library=Path(folder)/'loader.so'
        source.write_text(r'''#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include "tun_steering.h"
int program(int queues) {
 char log[65536]={0}; int p=steering_program_ext(queues, FLOW_MODE, log, sizeof(log));
 if(p<0) {int saved=errno; fprintf(stderr,"BPF verifier: %s\n%s\n",strerror(saved),log); errno=saved;}
 return p;
}
int attach(int tun,int queues) {int p=program(queues);if(p<0)return -1;
 int r=ioctl(tun,TUNSETSTEERINGEBPF,&p);int saved=errno;close(p);errno=saved;return r;}
int packet_queue(int p, void *packet, unsigned len) {
 unsigned char out[2048]; union bpf_attr a={0};a.test.prog_fd=p;
 a.test.data_in=(uintptr_t)packet;a.test.data_size_in=len;
 a.test.data_out=(uintptr_t)out;a.test.data_size_out=sizeof(out);a.test.repeat=1;
 if(steering_bpf(BPF_PROG_TEST_RUN,&a)<0)return -1;
 return a.test.retval;
}
long long family_counter(int p, unsigned family) {
 unsigned ids[4]={0};
 struct bpf_prog_info prog={.nr_map_ids=4,.map_ids=(uintptr_t)ids};
 union bpf_attr a={0};a.info.bpf_fd=p;a.info.info_len=sizeof(prog);a.info.info=(uintptr_t)&prog;
 if(steering_bpf(BPF_OBJ_GET_INFO_BY_FD,&a)<0 || prog.nr_map_ids>4)return -1;
 for(unsigned i=0;i<prog.nr_map_ids;i++) {
  memset(&a,0,sizeof(a));a.map_id=ids[i];
  int fd=steering_bpf(BPF_MAP_GET_FD_BY_ID,&a);
  if(fd<0)return -1;
  struct bpf_map_info map={0};memset(&a,0,sizeof(a));
  a.info.bpf_fd=fd;a.info.info_len=sizeof(map);a.info.info=(uintptr_t)&map;
  int ret=steering_bpf(BPF_OBJ_GET_INFO_BY_FD,&a);
  if(ret<0) {close(fd);return -1;}
  if(map.type==BPF_MAP_TYPE_ARRAY && map.max_entries==2 && map.value_size==4) {
   unsigned value=0;memset(&a,0,sizeof(a));a.map_fd=fd;
   a.key=(uintptr_t)&family;a.value=(uintptr_t)&value;
   ret=steering_bpf(BPF_MAP_LOOKUP_ELEM,&a);close(fd);
   return ret<0 ? -1 : (long long)value;
  }
  close(fd);
 }
 return -1;
}
'''.replace('FLOW_MODE', '1' if args.steering == 'flows' else '0'))
        sh('gcc','-shared','-fPIC','-Wall','-O2','-I'+str(ROOT / 'src'),'-I'+str(ROOT),str(source),'-o',str(library))
        test_program(library, args.steering)
        ns='tayga-steering-'+str(os.getpid())
        sh('ip','netns','add',ns)
        try: subprocess.run(['ip','netns','exec',ns,'python3',str(Path(__file__).resolve()),'inside',str(library),args.steering],check=True)
        finally: sh('ip','netns','del',ns)

if __name__=='__main__':main()
