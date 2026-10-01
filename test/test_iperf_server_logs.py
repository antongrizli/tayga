#!/usr/bin/env python3
"""Server evidence must survive warmup and both measured directions."""
from pathlib import Path
import subprocess
import tempfile
import unittest

class ServerLogTest(unittest.TestCase):
    def test_phase_logs_are_retained(self):
        source=(Path(__file__).resolve().parents[1]/'benchmark-clat.sh').read_text()
        start=source.index('start_iperf_servers() {')
        function=source[start:source.index('\n}\n',start)+3]
        with tempfile.TemporaryDirectory() as temp:
            script='''set -eu
CLIENTS=2
SERVER_CPUSET=
iperf_start_library=
iperf_start_control=
udp_drain_guard=
udp_drain_control=
iperf_pids=
cleanup_iperf_servers() { for pid in $iperf_pids; do wait "$pid"; done; iperf_pids=; }
exec_with_affinity() { printf '%s\n' "$RUN_LABEL"; }
ip() { printf 'LISTEN 0 0 [::]:5201 *:*\nLISTEN 0 0 [::]:5202 *:*\n'; }
'''+function+'''
ARTIFACT_DIR=$1
for phase in warmup-upload upload warmup-download download; do
 RUN_LABEL=$phase
 start_iperf_servers "$ARTIFACT_DIR/$phase"
 cleanup_iperf_servers
done
'''
            subprocess.run(['bash','-c',script,'test',temp],check=True,capture_output=True,text=True)
            logs=list(Path(temp).glob('*/iperf-server-*.log'))
            self.assertEqual(len(logs),8)
            for log in logs:self.assertEqual(log.read_text().strip(),log.parent.name)
        self.assertIn('start_iperf_servers "$warmup_dir"',source)
        self.assertIn('start_iperf_servers "$run_dir"',source)

if __name__=='__main__': unittest.main()
