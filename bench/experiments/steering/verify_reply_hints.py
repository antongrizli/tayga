"""Actual BPF hint tests; hash vectors are not capacity or TCP wire tests."""
import concurrent.futures
import ctypes
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

root,output=map(Path,sys.argv[1:]);output.mkdir(parents=True,exist_ok=True)
lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sys.path.insert(0,str(root/'test/system'))
from test_tun_steering import frame,bucket
source=output/'hints.c';library=output/'hints.so'
source.write_text(r'''#include <stdio.h>
#include "tun_steering.h"
int make(unsigned queues,int *hints) {
 char log[65536]={0};int p=steering_program_ext_hints(queues,1,log,sizeof(log),hints);
 if(p<0)fprintf(stderr,"BPF verifier: %s\n%s\n",strerror(errno),log);
 return p;
}
int publish(int fd,unsigned key,unsigned value) {
 union bpf_attr a={0};a.map_fd=fd;a.key=(uintptr_t)&key;a.value=(uintptr_t)&value;a.flags=BPF_ANY;
 return steering_bpf(BPF_MAP_UPDATE_ELEM,&a);
}
int queue(int fd,void *packet,unsigned size) {
 unsigned char out[2048];union bpf_attr a={0};a.test.prog_fd=fd;
 a.test.data_in=(uintptr_t)packet;a.test.data_size_in=size;
 a.test.data_out=(uintptr_t)out;a.test.data_size_out=sizeof(out);a.test.repeat=1;
 if(steering_bpf(BPF_PROG_TEST_RUN,&a)<0)return -1;
 return a.test.retval;
}
unsigned reply(void *packet) {
 unsigned char *ip=(unsigned char *)packet+14;
 unsigned offset=(ip[0]>>4)==4 ? (ip[0]&15)*4 : 40;
 return steering_reply_bucket(ip,ip+offset);
}
''')
subprocess.run(['gcc','-shared','-fPIC','-Wall','-O2','-I'+str(root/'src'),str(source),'-o',str(library)],check=True)
lib=ctypes.CDLL(str(library),use_errno=True)
lib.make.argtypes=[ctypes.c_uint,ctypes.POINTER(ctypes.c_int)]
lib.publish.argtypes=[ctypes.c_int,ctypes.c_uint,ctypes.c_uint]
lib.queue.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint]
lib.reply.argtypes=[ctypes.c_void_p];lib.reply.restype=ctypes.c_uint

def new(queues=3):
    hints=ctypes.c_int(-1);fd=lib.make(queues,ctypes.byref(hints))
    assert fd>=0 and hints.value>=0,ctypes.get_errno()
    return fd,hints.value

def queue(fd,data):
    q=lib.queue(fd,data,len(data));assert q>=0,ctypes.get_errno();return q

def publish(fd,key,value):assert lib.publish(fd,key,value)==0,ctypes.get_errno()

def reverse(data):
    data=bytearray(data);ip=data[14:];family=ip[0]>>4
    if family==4:
        data[26:30],data[30:34]=data[30:34],data[26:30];offset=14+(ip[0]&15)*4
    else:
        data[22:38],data[38:54]=data[38:54],data[22:38];offset=54
    data[offset:offset+2],data[offset+2:offset+4]=data[offset+2:offset+4],data[offset:offset+2]
    return bytes(data)

count_before=len(os.listdir('/proc/self/fd'));cases=[]
for family in (4,6):
    data=frame(family,proto=6,sport=6011);key=bucket(data,'flows')
    fd,hints=new()
    try:
        publish(hints,key,3);assert queue(fd,data)==2
        for value in (1,2,0,129):
            publish(hints,key,value);assert queue(fd,frame(family,proto=6,sport=6011,length=1000))==2
        cases.append(f'IPv{family}: a hint initializes an empty bucket; subsequent changes never migrate its owner')
    finally:os.close(hints);os.close(fd)
    fd,hints=new()
    try:
        first=queue(fd,data);publish(hints,key,(first+1)%3+1)
        assert queue(fd,data)==first
        cases.append(f'IPv{family}: publishing after admission cannot replace the owner')
    finally:os.close(hints);os.close(fd)
    for invalid in (0,4,0xffffffff):
        fd,hints=new()
        try:publish(hints,key,invalid);assert 0<=queue(fd,data)<3
        finally:os.close(hints);os.close(fd)
    for count in (1,2,3,4,8,128):
        fd,hints=new(count)
        try:publish(hints,key,count);assert queue(fd,data)==count-1
        finally:os.close(hints);os.close(fd)
    for port in (1,53,443,6001,6104,32768,65535):
        for options in ((False,True) if family==4 else (False,)):
            data=frame(family,proto=6,sport=port,options=options)
            assert lib.reply(data)==bucket(reverse(data),'flows')
    cases.append(f'IPv{family}: reversed full-tuple hash matches BPF key, including IPv4 options')
for repeat in range(20):
    fd,hints=new();data=frame(proto=6,sport=6400+repeat);key=bucket(data,'flows')
    try:
        def contend(n):
            publish(hints,key,n%3+1);return queue(fd,data)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            owners=list(executor.map(contend,range(32)))
        assert len(set(owners))==1 and 0<=owners[0]<3,owners
    finally:os.close(hints);os.close(fd)
assert len(os.listdir('/proc/self/fd'))==count_before,'BPF descriptor leak'
cases+=['20 concurrent hint/admission races retain one committed owner','Program/map descriptor count returns to its original value']
report=dict(passed=True,cases=cases)
(output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
