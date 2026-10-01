#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('run-tcp-flow-study')
summary = load('summarize-tcp-flow-study')
placement_summary = load('summarize-tcp-placement-study')


class FlowStudyTest(unittest.TestCase):
    def fixture(self):
        rows = []
        for case in runner.schedule(3):
            for direction in ('upload', 'download'):
                rows.append(dict(**case, direction=direction, status=0, flow_tuples=[{}] * (4 * case['flows']),
                    result=dict(capture_valid=True, workload_valid=True, acceptance_pass=True,
                    workers=case['workers'], flows_per_client=case['flows'], clients=4, direction=direction,
                    workload_protocol='tcp', perf_mode='none', rate_per_flow='0', received_mbps=1000,
                    tayga_sha256='a', clat_start_sha256='b', worker_metrics=[dict(slot=1, rx_packets_v4=1, rx_packets_v6=1)])))
        return rows

    def test_schedule(self):
        self.assertEqual(len(runner.schedule(3)), 12)
        self.assertEqual([c['flows'] for c in runner.schedule(3)[:6]], [1, 4, 4, 1, 1, 4])
        cases = runner.placement_schedule(3)
        self.assertEqual(len(cases), 20)
        self.assertEqual(sum(c['mode'] == 'record' for c in cases), 8)
        self.assertTrue(all(c['flows'] == 4 for c in cases))

    def test_complete_summary(self):
        self.assertEqual(len(summary.summarize(self.fixture())['groups']), 8)

    def test_missing_duplicate_identity_and_tuple_rejected(self):
        rows = self.fixture()
        with self.assertRaises(ValueError):
            summary.summarize(rows[:-1])
        with self.assertRaises(ValueError):
            summary.summarize(rows + [rows[0]])
        for field in ('tayga_sha256', 'clat_start_sha256'):
            changed = copy.deepcopy(rows)
            changed[0]['result'][field] = 'other'
            with self.assertRaises(ValueError):
                summary.summarize(changed)
        rows[0]['flow_tuples'].pop()
        with self.assertRaises(ValueError):
            summary.summarize(rows)

    def test_invalid_rate_profile_treatment_and_settings_rejected(self):
        for key, value in [('capture_valid', False), ('rate_per_flow', '300M'), ('perf_mode', 'record'),
                           ('flows_per_client', 5), ('clients', 1), ('offlink_mtu', 1500)]:
            rows = self.fixture()
            rows[0]['result'][key] = value
            with self.assertRaises(ValueError):
                summary.summarize(rows)

    def placement_fixture(self):
        rows = []
        for case in runner.placement_schedule(3):
            for direction in ('upload', 'download'):
                masks = ('all', 'all', 'all') if case['placement'] == 'scheduler' else (('0,1', '2', '3') if case['workers'] == 2 else ('0,1,2', '3', '3'))
                rows.append(dict(**case, direction=direction, status=0, path='/test/result.json', flow_tuples=[{}] * 16,
                    result=dict(capture_valid=True, workload_valid=True, acceptance_pass=True,
                    workers=case['workers'], flows_per_client=4, clients=4, direction=direction,
                    workload_protocol='tcp', perf_mode=case['mode'], perf_scope=case['scope'],
                    rate_per_flow='0', received_mbps=1100 if case['placement'] == 'partitioned' else 1000,
                    tayga_sha256='a', clat_start_sha256='b', tayga_cpuset=masks[0], client_cpuset=masks[1], server_cpuset=masks[2],
                    worker_metrics=[dict(slot=1, rx_packets_v4=1, rx_packets_v6=1)])))
        return rows

    def test_placement_summary_separates_profiles(self):
        result = placement_summary.summarize(self.placement_fixture())
        self.assertEqual(len(result['profiles']), 16)
        self.assertEqual(len(result['groups']), 8)
        self.assertAlmostEqual(result['pairs'][0]['median_paired_change_percent'], 10)

    def test_degraded_profile_retained_but_capacity_rejected(self):
        rows = self.placement_fixture()
        profile = next(row for row in rows if row['mode'] == 'record')
        profile['result'].update(acceptance_pass=False, degraded_reasons=['TUN drops'])
        result = placement_summary.summarize(rows)
        self.assertFalse(result['profiles'][0]['acceptance_pass'])
        self.assertEqual(result['profiles'][0]['degraded_reasons'], ['TUN drops'])
        rows[0]['result']['acceptance_pass'] = False
        with self.assertRaises(ValueError):
            placement_summary.summarize(rows)

    def test_placement_rejects_missing_profiles_and_wrong_affinity(self):
        rows = self.placement_fixture()
        with self.assertRaises(ValueError):
            placement_summary.summarize(rows[:-1])
        rows[0]['result']['tayga_cpuset'] = '0'
        with self.assertRaises(ValueError):
            placement_summary.summarize(rows)

    def test_profile_evidence_rejects_loss_and_keeps_self_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'profile' / 'upload'
            folder.mkdir(parents=True)
            for name in ('perf.data', 'perf-report-caller.txt'):
                (folder / name).write_text('fixture')
            report = '# Total Lost Samples: 0\n# Samples: 1K of event cpu-clock\n  20.00% [k] __arch_copy_to_user kernel\n  3.00% [k] __pi_clear_page kernel\n'
            path = folder / 'perf-report-self.txt'
            path.write_text(report)
            profiles = [dict(label='profile', direction='upload')]
            result = placement_summary.profile_evidence(root, profiles)
            self.assertEqual(result[0]['copy_to_user_percent'], 20)
            self.assertEqual(result[0]['page_clearing_percent'], 3)
            path.write_text(report.replace('Lost Samples: 0', 'Lost Samples: 1'))
            with self.assertRaises(ValueError):
                placement_summary.profile_evidence(root, profiles)


if __name__ == '__main__':
    unittest.main()
