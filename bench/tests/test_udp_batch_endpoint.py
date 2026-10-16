#!/usr/bin/env python3
"""Native Linux endpoint accounting, payload and short-tail regression checks."""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'), 'native Linux UDP options required')
class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.binary=cls.root/'endpoint'
        subprocess.run(['cc','-O3','-Wall','-Wextra','-Werror',str(Path(__file__).resolve().parents[1]/'tools/udp-batch-endpoint.c'),'-o',str(cls.binary)],check=True)

        cls.fault=cls.root/'fault.so'
        subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(Path(__file__).resolve().parent/'udp_endpoint_fault.c'),'-ldl','-o',str(cls.fault)],check=True)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def receiver(self, gro, name, env=None):
        folder=self.root/name;folder.mkdir()
        proc=subprocess.Popen([str(self.binary),'receive','4','127.0.0.1',str(gro),'123',str(folder/'receiver.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        self.addCleanup(lambda: self.finish(proc) if proc.poll() is None else None)
        ready,_,_=select.select([proc.stdout],[],[],3)
        self.assertTrue(ready);self.assertEqual(proc.stdout.readline().strip(),'READY')
        return proc,folder

    def finish(self, proc):
        proc.terminate()
        stdout,stderr=proc.communicate(timeout=3)
        return proc.returncode,stderr

    def test_short_tail_plain_and_gro(self):
        for batch,gro in ((1,0),(32,0),(1,1),(32,1)):
            proc,folder=self.receiver(gro,f'tail-{batch}-{gro}')
            subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1',str(batch),'123',str(folder/'sender.json'),'35','64'],check=True)
            time.sleep(.1);status,err=self.finish(proc);self.assertEqual(status,0,err)
            got=json.loads((folder/'receiver.json').read_text());self.assertEqual(got['packets'],35);self.assertEqual(got['bytes'],40864);self.assertEqual(got['short_tails'],1)
            if batch==32 and gro: self.assertGreater(got['aggregates'],0)

    def test_paced_payload_accounting(self):
        proc,folder=self.receiver(1,'paced')
        subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','32','123',str(folder/'sender.json'),'0','1200','100'],check=True)
        time.sleep(.1);status,err=self.finish(proc);self.assertEqual(status,0,err)
        sent=json.loads((folder/'sender.json').read_text());got=json.loads((folder/'receiver.json').read_text())
        self.assertEqual(sent['rate_mbps'],100)
        self.assertEqual(sent['packets'],got['packets'])
        self.assertEqual(sent['bytes'],got['bytes'])
        self.assertGreater(sent['elapsed_seconds'],.95)
        actual=sent['bytes']*8/sent['elapsed_seconds']/1e6
        self.assertLess(abs(actual-100),5)

    def test_explicit_receive_buffer(self):
        proc,folder=self.receiver(0,'receive-buffer',dict(os.environ,UDP_ENDPOINT_RCVBUF='1048576'))
        subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','1','123',str(folder/'sender.json'),'35','64'],check=True)
        time.sleep(.1);status,err=self.finish(proc);self.assertEqual(status,0,err)
        got=json.loads((folder/'receiver.json').read_text())
        self.assertEqual(got['requested_rcvbuf'],1048576)
        self.assertEqual(got['force_rcvbuf'],0)
        self.assertGreater(got['actual_rcvbuf'],0)
        self.assertEqual(got['packets'],35)

    def test_invalid_force_buffer(self):
        output=self.root/'invalid-force.json'
        result=subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','32','123',str(output),'0','1200','0'],env=dict(os.environ,UDP_ENDPOINT_RCVBUF_FORCE='4294967296'))
        self.assertEqual(result.returncode,2);self.assertFalse(output.exists())

    def test_invalid_rate(self):
        output=self.root/'invalid-rate.json'
        result=subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','32','123',str(output),'0','1200','1000001'])
        self.assertEqual(result.returncode,2);self.assertFalse(output.exists())

    def test_auto_unsupported_fallback(self):
        env=dict(os.environ,LD_PRELOAD=str(self.fault),UDP_ENDPOINT_FAULT='92',UDP_ENDPOINT_OFFLOAD='auto')
        proc,folder=self.receiver(1,'fallback',env)
        subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','32','123',str(folder/'sender.json'),'35','64'],env=env,check=True)
        time.sleep(.1);status,err=self.finish(proc);self.assertEqual(status,0,err)
        sent=json.loads((folder/'sender.json').read_text());got=json.loads((folder/'receiver.json').read_text())
        self.assertEqual((sent['requested_batch'],sent['batch'],sent['fallback_errno']),(32,1,92))
        self.assertEqual((got['requested_gro'],got['gro'],got['fallback_errno']),(1,0,92))
        self.assertEqual((got['packets'],got['bytes'],got['short_tails']),(35,40864,1))

    def test_auto_first_send_fallback(self):
        proc,folder=self.receiver(0,'send-fallback')
        env=dict(os.environ,LD_PRELOAD=str(self.fault),UDP_ENDPOINT_SEND_FAULT='1',UDP_ENDPOINT_OFFLOAD='auto')
        subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','32','123',str(folder/'sender.json'),'35','64'],env=env,check=True)
        time.sleep(.1);status,err=self.finish(proc);self.assertEqual(status,0,err)
        sent=json.loads((folder/'sender.json').read_text());got=json.loads((folder/'receiver.json').read_text())
        self.assertEqual((sent['batch'],sent['fallback_errno'],sent['calls']),(1,95,36))
        self.assertEqual((got['packets'],got['duplicates'],got['bytes']),(35,0,40864))

    def test_strict_and_unexpected_errors_fail(self):
        for policy,error in (('strict','92'),('auto','9')):
            env=dict(os.environ,LD_PRELOAD=str(self.fault),UDP_ENDPOINT_FAULT=error,UDP_ENDPOINT_OFFLOAD=policy)
            output=self.root/f'failed-{policy}.json'
            result=subprocess.run([str(self.binary),'send','4','127.0.0.1','127.0.0.1','1','32','123',str(output),'35','64'],env=env,capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertFalse(output.exists())

    def test_duplicates_and_reordering(self):
        proc,folder=self.receiver(0,'duplicate')
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            for seq in (2,0,2,1): udp.sendto(struct.pack('!QQ',seq,123)+b'\xa5'*48,('127.0.0.1',49153))
        time.sleep(.1);status,err=self.finish(proc);self.assertEqual(status,0,err)
        got=json.loads((folder/'receiver.json').read_text());self.assertEqual(got['packets'],3);self.assertEqual(got['duplicates'],1);self.assertEqual(got['reordered'],2)

    def test_payload_corruption_rejected(self):
        proc,folder=self.receiver(0,'invalid')
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.sendto(struct.pack('!QQ',0,123)+b'corrupted!',('127.0.0.1',49153))
        time.sleep(.1);status,_=self.finish(proc);self.assertEqual(status,1)
        got=json.loads((folder/'receiver.json').read_text());self.assertEqual(got['packets'],0);self.assertEqual(got['invalid'],1)


if __name__=='__main__': unittest.main()
