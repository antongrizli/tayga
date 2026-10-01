#!/usr/bin/env python3
"""Exercise the benchmark end sequence and exact stop-guard validation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE=(Path(__file__).resolve().parents[1]/'benchmark-clat.sh').read_text()

class CommonStopTest(unittest.TestCase):
    def test_udp_stops_before_wait_without_added_drain(self):
        start=SOURCE.index('  if [ "$PROTOCOL" = udp ]; then\n    sleep "$DURATION"')
        block=SOURCE[start:SOURCE.index('  client_pids=',start)]
        block=block.replace('/usr/local/libexec/tayga-perf/udp-drain-control','stop_control')
        with tempfile.TemporaryDirectory() as temp:
            script='''set -eu
PROTOCOL=$2
DURATION=15
drain_int=0
drain_s=0
run_dir=$1
udp_drain_control=$1/control
sleep() { printf 'sleep %s\n' "$1" >> "$run_dir/events"; }
stop_control() { printf 'stop\n' >> "$run_dir/events"; }
wait_clients() { printf 'wait\n' >> "$run_dir/events"; }
monotonic_ns() { echo 42; }
'''+block+'''
test "$monotonic_traffic_end" = "$monotonic_drain_end"
'''
            subprocess.run(['bash','-c',script,'test',temp,'udp'],check=True)
            self.assertEqual((Path(temp)/'events').read_text().splitlines(),['sleep 15','stop','sleep 0','wait'])
            (Path(temp)/'events').unlink()
            subprocess.run(['bash','-c',script,'test',temp,'tcp'],check=True)
            self.assertEqual((Path(temp)/'events').read_text().splitlines(),['wait'])

    def test_zero_drain_still_requires_stop_and_attachment(self):
        start=SOURCE.index('drain_status = None\n')
        validation=SOURCE[start:SOURCE.index('if os.path.exists(os.path.join(run_dir, "capture_errors.txt")):',start)]
        with tempfile.TemporaryDirectory() as temp:
            status=Path(temp)/'udp-drain.status.json'
            for drain,stopped,attached,blocked,valid in [('0',1,4,0,True),('0',0,4,0,False),('0',1,3,0,False),('0.5',1,4,0,False),('0.5',1,4,1,True)]:
                with self.subTest(drain=drain,stopped=stopped,attached=attached,blocked=blocked):
                    status.write_text(json.dumps(dict(stopped=stopped,attached=attached,blocked_writes=blocked)))
                    namespace=dict(protocol='udp',os=os,json=json,run_dir=temp,capture_errors=[])
                    with patch.dict(os.environ,CLIENTS='2',RECEIVER_DRAIN_SECONDS=drain):
                        exec(compile(validation,'exact stop validation','exec'),namespace)
                    self.assertEqual(not namespace['capture_errors'],valid)

if __name__=='__main__':unittest.main()
