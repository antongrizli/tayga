"""Real BPF endpoint/connection striping counterexample regression."""
import ctypes
import concurrent.futures
import collections
import fcntl
import itertools
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
root,output=map(Path,sys.argv[1:]);output.mkdir(parents=True,exist_ok=True)
lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sys.path.insert(0,str(root/'test/system'))
from test_tun_steering import frame,bucket
source=output/'group.c';library=output/'group.so'
source.write_text(r'''#include <stdio.h>
#include "tun_steering.h"
int make(unsigned queues,int *hints) {
 char log[65536]={0};int fd=steering_program_ext_hints(queues,1,log,sizeof(log),hints);
 if(fd<0)fprintf(stderr,"%s\n%s\n",strerror(errno),log);
 return fd;
}
int queue(int fd,void *packet,unsigned size) {
 unsigned char out[2048];union bpf_attr a={0};a.test.prog_fd=fd;
 a.test.data_in=(uintptr_t)packet;a.test.data_size_in=size;
 a.test.data_out=(uintptr_t)out;a.test.data_size_out=sizeof(out);a.test.repeat=1;
 if(steering_bpf(BPF_PROG_TEST_RUN,&a)<0)return -1;
 return a.test.retval;
}
''')
subprocess.run(['gcc','-shared','-fPIC','-O2','-Wall','-I'+str(root/'src'),str(source),'-o',str(library)],check=True)
lib=ctypes.CDLL(str(library),use_errno=True)
lib.make.argtypes=[ctypes.c_uint,ctypes.POINTER(ctypes.c_int)];lib.queue.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint]
def queue(fd,data):
 q=lib.queue(fd,data,len(data));assert q>=0,ctypes.get_errno();return q
def packet(family,number,data=False,length=100,services=(7001,8080,443,65000)):
 raw=bytearray(frame(family,proto=6,sport=(6100 if data else 6000)+number,length=length))
 offset=14+(20 if family==4 else 40)
 struct.pack_into('!H',raw,offset+2,services[number-1]);return bytes(raw)
schedule=[(1,False),(1,True),(2,False),(2,True),(3,False),(4,False),(3,True),(4,True)]
rng=random.Random(20261018);schedules=[schedule]
while len(schedules)<32:
 order=list(itertools.product(range(1,5),(False,True)));rng.shuffle(order)
 if all(order.index((n,False))<order.index((n,True)) for n in range(1,5)) and order not in schedules:schedules.append(order)
cases=[]
for family in (4,6):
 for number,order in enumerate(schedules):
  hints=ctypes.c_int(-1);fd=lib.make(3,ctypes.byref(hints));assert fd>=0,ctypes.get_errno()
  try:
   inputs=[packet(family,n,data) for n,data in order]
   assert len({bucket(raw,'flows') for raw in inputs})==8,'test inputs must not share primary buckets'
   owners={}
   for n,data in order:owners[n,data]=queue(fd,packet(family,n,data))
   data_owners=[owners[n,True] for n in range(1,5)]
   assert len(set(data_owners))==3,(family,order,data_owners)
   for n in range(1,5):assert queue(fd,packet(family,n,True,length=1200))==owners[n,True]
   cases.append(dict(family=family,schedule=number,data_owners=data_owners))
  finally:os.close(hints.value);os.close(fd)
# Race distinct primary buckets through first initialization of one group.
# Exactly one admission per bucket must advance the group sequence once.
races=[]
for family in (4,6):
 for attempt in range(10):
  hints=ctypes.c_int(-1);fd=lib.make(3,ctypes.byref(hints));assert fd>=0
  try:
   inputs=[];keys=set()
   for port in range(10000,14000):
    raw=frame(family,proto=6,sport=port,length=100)
    key=bucket(raw,'flows')
    if key not in keys:inputs.append(raw);keys.add(key)
    if len(inputs)==96:break
   with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    owners=list(pool.map(lambda raw:queue(fd,raw),inputs))
   counts=collections.Counter(owners)
   assert sorted(counts.values())==[32,32,32],(family,attempt,counts)
   assert all(queue(fd,raw)==owner for raw,owner in zip(inputs,owners))
   races.append(dict(family=family,attempt=attempt,counts=dict(counts)))
  finally:os.close(hints.value);os.close(fd)
(output/'result.json').write_text(json.dumps(dict(passed=True,cases=cases,concurrent_group_initializations=races),indent=2)+'\n')
print('PASS: 32 deterministic valid interleavings per family use all three data queues; owners stay stable; 20 concurrent group initialization trials balanced')
