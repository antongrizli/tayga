"""Host collection must preserve rejected results and failed-copy guest data."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
MOCK = '''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
a = sys.argv[1:]
if a[0] == 'list':
    print('NAME STATUS'); print('tayga-perf Running'); sys.exit(0)
cmd = a[a.index('--')+1:]
guest = pathlib.Path(os.environ['FAKE_SESSION'])
if cmd[0] == 'env':
    guest.mkdir(); (guest/'result.json').write_text('retained workload')
    sys.exit(int(os.environ['FAKE_WORKLOAD_STATUS']))
if cmd[0] == 'tar':
    if os.environ.get('FAKE_COPY_FAIL'): sys.exit(1)
    sys.exit(subprocess.call(['tar','-C',str(guest),'-cf','-','.']))
if cmd[0] == 'rm':
    import shutil
    shutil.rmtree(guest); sys.exit(0)
sys.exit(99)
'''

class RetentionTests(unittest.TestCase):
    def run_collection(self, status=0, copy_fail=False, root_file=False):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); mock = base/'limactl'
            mock.write_text(MOCK); mock.chmod(0o755)
            root = base/'external-state'
            if root_file: root.write_text('not a directory')
            env = dict(os.environ, PATH=str(base)+os.pathsep+os.environ['PATH'],
                       REPO=str(REPO), PERF_SESSION_ROOT=str(root), SESSION_STAMP='fixture',
                       FAKE_SESSION=str(base/'guest'), FAKE_WORKLOAD_STATUS=str(status),
                       GIT_REVISION='fixture-revision')
            if copy_fail: env['FAKE_COPY_FAIL'] = 'yes'
            result = subprocess.run(['bash',str(REPO/'bench/lima/run-host.sh')],
                                    env=env, capture_output=True, text=True)
            destination = root/'fixture-lima-debian13-arm64'
            copied = (destination/'result.json').is_file() if not root_file else False
            metadata = (destination/'host-request.txt').read_text() if copied else ''
            return result.returncode, copied, (base/'guest').exists(), metadata

    def test_success_collects_outside_shared_mount(self):
        status, copied, retained, meta = self.run_collection()
        self.assertEqual((status,copied,retained), (0,True,False))
        self.assertIn('guest_exit_status=0', meta)

    def test_rejected_workload_is_collected_and_stays_rejected(self):
        status, copied, retained, meta = self.run_collection(status=23)
        self.assertEqual((status,copied,retained), (23,True,False))
        self.assertIn('guest_exit_status=23', meta)

    def test_transfer_failure_retains_guest(self):
        self.assertEqual(self.run_collection(copy_fail=True)[:3], (1,False,True))

    def test_destination_failure_retains_guest(self):
        self.assertEqual(self.run_collection(root_file=True)[:3], (1,False,True))
