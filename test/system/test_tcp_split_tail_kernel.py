#!/usr/bin/env python3
"""Validate completed split-tail TCP checksums on a disposable veth receiver."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def receive():
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
        raw.bind(('ep0', 0)); raw.settimeout(5)
        print('READY', flush=True)
        packets = []
        for _ in range(80):
            frame = raw.recv(65536)
            if frame[12:14] != b'\x08\x00': continue
            ip = frame[14:]
            if ip[9] != 6: continue
            assert ip[12:20] == socket.inet_aton('192.0.2.2') + socket.inet_aton('198.51.100.2')
            assert ip[8] == 62
            header = (ip[0] & 15) * 4
            tcp = ip[header:struct.unpack_from('!H', ip, 2)[0]]
            if tcp[2:4] != struct.pack('!H', 7000): continue
            pseudo = ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp))
            assert checksum(ip[:header]) == 0 and checksum(pseudo + tcp) == 0, 'wire checksum'
            port, = struct.unpack_from('!H', tcp)
            sequence, = struct.unpack_from('!I', tcp, 4)
            data = tcp[(tcp[12] >> 4)*4:]
            assert data == bytes((n % 251 for n in range(sequence-1000, sequence-1000+len(data))))
            flags = struct.unpack_from('!H', ip, 6)[0]
            assert bool(flags & 0x4000) == (len(ip[:header])+len(tcp)>1260)
            print(f'wire port={port} sequence={sequence} bytes={len(data)}',flush=True)
            packets.append(dict(port=port, sequence=sequence, payload=len(data), flags=tcp[13]))
            if len(packets) == 45: break
        assert len(packets)==45,packets
        for h in range(3):
            for full in (1,2):
                for number,tail in ((1,1),(2,2),(3,(1220,1208,1180)[h])):
                    port=6000+h*100+full*10+number
                    flow=[p for p in packets if p['port']==port]
                    assert [p['payload'] for p in flow]==[1400]*full+[tail],flow
                    assert [p['sequence'] for p in flow]==[1000+1400*i for i in range(full+1)],flow
                    assert flow[0]['flags'] & 0x80 and all(not p['flags'] & 0x80 for p in flow[1:])
                    assert all(not p['flags'] & 9 for p in flow[:-1])
                    assert flow[-1]['flags'] & 9 == 9
        print(json.dumps(packets),flush=True)


def main():
    if sys.argv[1:] == ['receive']:
        receive();return
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)  # Common system runner interface.
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0: parser.error('Linux root required')
    lock=open('/tmp/tayga-perf-workflow.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    root=Path(__file__).resolve().parents[2]
    subprocess.run(['make','-C',str(root),'build/test-bin/tcp_split_tail'],check=True)
    args.output.mkdir(parents=True,exist_ok=True)
    ns=f'tgtail-{os.getpid()}';peer=ns+'r';child=receiver=None
    def run(*cmd):subprocess.run(list(map(str,cmd)),check=True,stdout=subprocess.DEVNULL)
    try:
        for name in (ns,peer):run('ip','netns','add',name)
        run('ip','-n',ns,'link','add','out0','type','veth','peer','name','ep0')
        run('ip','-n',ns,'link','set','ep0','netns',peer)
        for name,dev,addr in ((ns,'out0','10.23.0.1/24'),(peer,'ep0','10.23.0.2/24')):
            run('ip','-n',name,'link','set',dev,'up');run('ip','-n',name,'addr','add',addr,'dev',dev)
        run('ip','netns','exec',ns,'sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.default.rp_filter=0')
        run('ip','netns','exec',ns,'ethtool','-K','out0','tx','off','gso','off','tso','off')
        run('ip','netns','exec',peer,'ethtool','-K','ep0','gro','off','lro','off')
        child=subprocess.Popen(['ip','netns','exec',ns,str(root/'build/test-bin/tcp_split_tail')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        assert select.select([child.stdout],[],[],5)[0] and child.stdout.readline().strip()=='READY'
        run('ip','-n',ns,'link','set','tailtun','mtu','1500','up')
        run('ip','-n',ns,'route','add','198.51.100.2/32','via','10.23.0.2','dev','out0')
        run('ip','-n',peer,'addr','add','198.51.100.2/32','dev','lo')
        receiver=subprocess.Popen(['ip','netns','exec',peer,sys.executable,str(Path(__file__).resolve()),'receive'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert select.select([receiver.stdout],[],[],5)[0] and receiver.stdout.readline().strip()=='READY'
        child.stdin.write('G');child.stdin.flush()
        try:
            out,err=receiver.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            receiver.kill();out,err=receiver.communicate()
            (args.output/'receiver.log').write_text(out+err)
            raise
        (args.output/'receiver.log').write_text(out+err)
        assert receiver.returncode==0,(out,err)
        child.stdin.write('Q');child.stdin.flush();assert child.wait(timeout=5)==0
        print('PASS: TCP split tails, single/multiple full segments, TCP options, checksums, DF, CWR/FIN/PSH and sequence')
    finally:
        for process in (receiver,child):
            if process is not None and process.poll() is None:process.kill();process.wait()
        for name in (peer,ns):subprocess.run(['ip','netns','del',name],check=False,stderr=subprocess.DEVNULL)


if __name__=='__main__':main()
