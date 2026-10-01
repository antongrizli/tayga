#!/usr/bin/env python3
"""Linux iperf regression: all streams ready before timers/data begin."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

@unittest.skipUnless(sys.platform.startswith('linux'),'Linux iperf preload required')
class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.library=cls.root/'gate.so';cls.controller=cls.root/'controller'
        source=Path(__file__).resolve().parents[1]/'tools/iperf-start-gate.c'
        subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(source),'-ldl','-o',str(cls.library)],check=True)
        subprocess.run(['cc','-DIPERF_GATE_CONTROLLER','-Wall','-Wextra','-Werror',str(source),'-o',str(cls.controller)],check=True)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def status(self,control):return json.loads(subprocess.check_output([str(self.controller),'status',str(control)]))

    def wait_arrivals(self,control,expected):
        deadline=time.monotonic()+5
        while self.status(control)['arrived']!=expected:
            if time.monotonic()>deadline:self.fail('endpoint did not reach readiness barrier')
            time.sleep(.01)

    def test_both_directions_deferred_timers(self):
        for reverse in (False,True):
            with self.subTest(reverse=reverse),tempfile.TemporaryDirectory() as temp:
                control=Path(temp)/'control';children=[]
                subprocess.run([str(self.controller),'init',str(control),'4'],check=True)
                env=dict(os.environ,LD_PRELOAD=str(self.library),TAYGA_IPERF_START_CONTROL=str(control))
                ports=[]
                for _ in range(2):
                    with socket.socket() as sock:sock.bind(('127.0.0.1',0));ports.append(str(sock.getsockname()[1]))
                try:
                    for port in ports:
                        children.append(subprocess.Popen(['iperf3','-s','-1','-p',port],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE))
                    time.sleep(.2)
                    def client(port):
                        command=['iperf3','-c','127.0.0.1','-p',port,'-u','-b','0','-t','1','-J']
                        if reverse:command.append('-R')
                        process=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(process);return process
                    first=client(ports[0]);self.wait_arrivals(control,2)
                    premature=subprocess.run([str(self.controller),'release',str(control)],capture_output=True)
                    self.assertNotEqual(premature.returncode,0)
                    time.sleep(1.2) # Longer than iperf's test duration; timer must still be unstarted.
                    self.assertIsNone(first.poll());self.assertEqual(self.status(control)['released'],0)
                    second=client(ports[1]);self.wait_arrivals(control,4)
                    subprocess.run([str(self.controller),'release',str(control)],check=True,stdout=subprocess.DEVNULL)
                    for process in (first,second):
                        output,error=process.communicate(timeout=8);self.assertEqual(process.returncode,0,error+output)
                        report=json.loads(output);self.assertNotIn('error',report)
                        self.assertGreater(report['end']['sum_sent']['bytes'],0)
                        self.assertGreater(report['end']['sum_received']['bytes'],0)
                        self.assertGreater(report['end']['sum_sent']['seconds'],.8)
                    for server in children[:2]:self.assertEqual(server.wait(timeout=3),0)
                finally:
                    for process in children:
                        if process.poll() is None:process.terminate()
                        try:process.wait(timeout=3)
                        except subprocess.TimeoutExpired:process.kill();process.wait()
                        for stream in (process.stdout,process.stderr):
                            if stream:stream.close()

    def test_invalid_or_reused_control_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'control'
            for expected in ('0','513','-1','oops'):
                result=subprocess.run([str(self.controller),'init',str(path),expected],capture_output=True)
                self.assertNotEqual(result.returncode,0);self.assertFalse(path.exists())
            subprocess.run([str(self.controller),'init',str(path),'2'],check=True)
            self.assertNotEqual(subprocess.run([str(self.controller),'init',str(path),'2']).returncode,0)
            self.assertEqual(self.status(path)['arrived'],0)
            path.write_bytes(b'bad')
            self.assertEqual(subprocess.run([str(self.controller),'status',str(path)],capture_output=True).returncode,127)

if __name__=='__main__':unittest.main()
