#!/usr/bin/env python3
"""Run the benchmark's exact owned-child cleanup helper on Linux processes."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

text = (Path(__file__).resolve().parents[1]/'benchmark-clat.sh').read_text()
start = text.index('  python3 - $clat_pid ')
helper = text[text.index('\n', start)+1:].split('\nPY\n', 1)[0]

@unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux /proc')
class CleanupTests(unittest.TestCase):
    def invoke(self, pid):
        return subprocess.run([sys.executable, '-c', helper, str(pid)], timeout=6, check=True)

    def test_normal_exit_is_reaped(self):
        child = subprocess.Popen(['sleep', '60'])
        try:
            child.terminate()
            self.invoke(child.pid)
            self.assertEqual(child.wait(timeout=1), -signal.SIGTERM)
        finally:
            if child.poll() is None: child.kill(); child.wait()

    def test_stopped_owned_child_has_bounded_shutdown(self):
        child = subprocess.Popen(['sleep', '60'])
        try:
            os.kill(child.pid, signal.SIGSTOP)
            os.waitpid(child.pid, os.WUNTRACED)
            child.terminate()
            start = time.monotonic()
            self.invoke(child.pid)
            self.assertEqual(child.wait(timeout=1), -signal.SIGKILL)
            self.assertGreaterEqual(time.monotonic()-start, 2.9)
        finally:
            if child.poll() is None: child.kill(); child.wait()

    def test_foreign_parent_is_not_targeted(self):
        code = "import subprocess,sys; p=subprocess.Popen(['sleep','60']); print(p.pid,flush=True); sys.stdin.readline(); p.terminate(); p.wait()"
        supervisor = subprocess.Popen([sys.executable, '-u', '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            grandchild = int(supervisor.stdout.readline())
            self.invoke(grandchild)
            os.kill(grandchild, 0)
        finally:
            supervisor.communicate('stop\n', timeout=3)

if __name__ == '__main__':
    unittest.main()
