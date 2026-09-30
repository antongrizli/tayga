#!/usr/bin/env python3
"""Linux integration regression for the benchmark-only iperf3 write guard.
Run after make udp-drain-tools. Requires dynamically linked iperf3 (3.18 tested).
"""
import json
import os
from pathlib import Path
import socket
import sys
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / 'tools/udp-drain-control'
GUARD = ROOT / 'tools/udp-drain-guard.so'

@unittest.skipUnless(sys.platform == "linux" and GUARD.exists() and CONTROLLER.exists(),
                     "requires Linux and make udp-drain-tools")
class DrainTest(unittest.TestCase):
    def test_both_directions(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as tmp:
                control = str(Path(tmp) / 'control')
                subprocess.run([str(CONTROLLER), 'init', control], check=True)
                env = dict(os.environ, LD_PRELOAD=str(GUARD), TAYGA_UDP_DRAIN_CONTROL=control)
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); port = str(sock.getsockname()[1])
                server = subprocess.Popen(['iperf3', '-s', '-1', '-p', port], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                client = None
                try:
                    time.sleep(.3)
                    command = ['iperf3', '-c', '127.0.0.1', '-p', port, '-u', '-b', '10M', '-t', '3', '-J']
                    if reverse: command += ['-R']
                    client = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    time.sleep(1)
                    subprocess.run([str(CONTROLLER), 'stop', control], check=True, stdout=subprocess.DEVNULL)
                    output, error = client.communicate(timeout=10)
                    self.assertEqual(client.returncode, 0, error + output)
                    report = json.loads(output)
                    self.assertNotIn('error', report)
                    sent, received = report['end']['sum_sent'], report['end']['sum_received']
                    self.assertEqual(received['lost_packets'], 0)
                    self.assertEqual(sent['bytes'], received['bytes'])
                    # Only the first second produces traffic: no resumed tail.
                    self.assertLess(sent['bytes'], 2_000_000)
                    self.assertGreater(sent['bytes'], 500_000)
                    state = json.loads(subprocess.check_output([str(CONTROLLER), 'status', control]))
                    self.assertEqual(state['stopped'], 1)
                    self.assertGreater(state['blocked_writes'], 0)
                    self.assertEqual(state['attached'], 2)
                    server.wait(timeout=5)
                    self.assertEqual(server.returncode, 0)
                finally:
                    for process in (client, server):
                        if process and process.poll() is None:
                            process.kill(); process.wait()
                    server.stderr.close()

if __name__ == '__main__': unittest.main()
