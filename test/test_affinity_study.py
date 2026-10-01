#!/usr/bin/env python3
"""Exercise study ordering, invalid-workload handling and summary isolation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('affinity_study', Path(__file__).resolve().parents[1] / 'tools/run-affinity-study.py')
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


class StudyTests(unittest.TestCase):
    def run_study(self, root, invalid=False):
        calls = []
        def fake_run(command, env, **kwargs):
            calls.append(env)
            destination = root / 'perf-sessions' / (env['SESSION_STAMP'] + '-lima-debian13-arm64') / env['PERF_MODES']
            for direction in ('upload', 'download'):
                folder = destination / direction
                folder.mkdir(parents=True)
                speed = 100 if env['TAYGA_CPUSET'] == 'all' else 110
                if env['PERF_MODES'] == 'record':
                    speed = 999
                result = dict(capture_valid=True, workload_valid=not invalid,
                              acceptance_pass=env['PROTOCOL'] == 'tcp',
                              received_mbps=speed, received_active_window_mbps=speed, tayga_sha256='fixture')
                (folder / 'result.json').write_text(json.dumps(result))
            return subprocess.CompletedProcess(command, 1 if env['PROTOCOL'] == 'udp' else 0)
        with patch.object(study.subprocess, 'run', side_effect=fake_run), patch('sys.argv', ['study', '--repo', str(root), '--stamp', 'fixture', '--pairs', '2', '--duration', '1']):
            study.main()
        return calls

    def test_order_and_profile_exclusion(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            calls = self.run_study(root)
            self.assertEqual([x['TAYGA_CPUSET'] for x in calls[:4]], ['all', '0', '0', 'all'])
            self.assertTrue(all(x['RATE'] == '0' for x in calls))
            summary = (root / 'perf-sessions/fixture/summary.md').read_text()
            self.assertEqual(summary.count('+10.00%'), 4)
            self.assertNotIn('999', summary)
            self.assertEqual(len(json.loads((root / 'perf-sessions/fixture/ledger.json').read_text())), 24)

    def test_invalid_retained_and_stops(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaisesRegex(RuntimeError, 'invalid workload'):
                self.run_study(root, invalid=True)
            self.assertEqual(len(json.loads((root / 'perf-sessions/fixture/ledger.json').read_text())), 2)
            self.assertFalse((root / 'perf-sessions/fixture/summary.md').exists())


if __name__ == '__main__':
    unittest.main()
