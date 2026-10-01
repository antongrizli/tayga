#!/usr/bin/env python3
"""Root Linux integration: a missing gate participant aborts and cleans namespaces."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Linux root and installed benchmark helpers required')
class FailureTest(unittest.TestCase):
    def test_missing_warmup_participant_stops_and_cleans(self):
        with open('/tmp/tayga-perf-workflow.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            names={'client','router','clatns','server'}
            def namespaces():return {line.split()[0] for line in subprocess.check_output(['ip','netns','list'],text=True).splitlines()}
            self.assertFalse(names&namespaces(),'benchmark namespaces already exist')
            with tempfile.TemporaryDirectory() as temporary:
                chosen=os.environ.get('IPERF_START_FAILURE_OUTPUT')
                root=Path(chosen) if chosen else Path(temporary)/'retained';root.mkdir(parents=True,exist_ok=False)
                wrapper=root/'bin';wrapper.mkdir()
                (wrapper/'iperf3').write_text('''#!/bin/sh
previous=
for argument in "$@"; do
  if [ "$previous" = -p ] && [ "$argument" = 5204 ]; then
    case "$1" in -c) unset TAYGA_IPERF_START_CONTROL;; esac
  fi
  previous=$argument
done
exec /usr/bin/iperf3 "$@"
''');(wrapper/'iperf3').chmod(0o755)
                env=dict(os.environ,PATH=str(wrapper)+':'+os.environ['PATH'],ARTIFACT_DIR=str(root/'workload'),BENCHMARK_LOCK_DIR=str(root/'benchmark-lock'),
                         PROTOCOL='udp',CLIENTS='4',FLOWS='1',WORKERS='1',RATE='0',DURATION='1',WARMUP='1',DIRECTIONS='upload download',
                         IPERF_START_GATE='on',CLAT_OFFLOAD='auto',FORWARDING_GRO='on',PERF_MODE='none')
                start=time.monotonic()
                with (root/'benchmark.log').open('w') as log:
                    child=subprocess.Popen([str(ROOT/'benchmark-clat.sh')],env=env,stdout=log,stderr=subprocess.STDOUT)
                    try:status=child.wait(timeout=25)
                    except subprocess.TimeoutExpired:
                        child.terminate()
                        try:child.wait(timeout=6)
                        except subprocess.TimeoutExpired:child.kill();child.wait()
                        self.fail('startup failure was not bounded')
                self.assertNotEqual(status,0)
                self.assertLess(time.monotonic()-start,25)
                self.assertIn('iperf start gate readiness timeout',(root/'benchmark.log').read_text())
                self.assertFalse((root/'workload/download').exists(),'next direction must not start after fatal warmup failure')
                self.assertFalse((root/'benchmark-lock').exists())
                self.assertFalse(names&namespaces(),'owned benchmark namespaces leaked')

if __name__=='__main__':unittest.main()
