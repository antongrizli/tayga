import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import os
import subprocess
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from taygabench import diagnostics as d, sequence as s


class WorkerDiagnosticsTests(unittest.TestCase):
    def test_direction_bytes_and_main_slot(self):
        workers = [dict(slot=0, worker_id=0, rx_packets_v4=100000, rx_bytes_v4=100000),
                   dict(slot=1, worker_id=0, rx_packets_v4=10, rx_bytes_v4=1000),
                   dict(slot=2, worker_id=1, rx_packets_v4=10, rx_bytes_v4=9000)]
        r = d.summarize_result(dict(direction='upload', worker_metrics=workers, received_mbps=8000,
                                    tayga_cpu_cores=2, gso_stats_delta=dict(rx_pkts=10, rx_bytes=40000, split_tail=2)))
        self.assertEqual(r['packet_distribution']['shares'], [.5, .5])
        self.assertEqual(r['byte_distribution']['shares'], [.1, .9])
        self.assertEqual(r['gso']['mean_input_ip_bytes'], 4000)
        self.assertEqual(r['tayga_cpu_seconds_per_received_application_gb'], 2)

    def test_snapshot_legacy_partial_and_reset(self):
        b = dict(pid=1, snapshot_sequence=1, workers_synced=True,
                 workers=[dict(slot=1, worker_id=0, rx_packets_v4=1, rx_packets_v6=1)])
        a = copy.deepcopy(b); a['snapshot_sequence'] = 2
        rows = d.snapshot_workers(b, a)
        self.assertIsNone(rows[0]['rx_bytes_v4'])
        a['workers'][0]['rx_bytes_v4'] = 1
        with self.assertRaises(KeyError): d.snapshot_workers(b, a)
        for snap in (b, a): snap['workers'][0].update(dict.fromkeys(d.BYTE_FIELDS, 10))
        a['workers'][0]['rx_bytes_v4'] = 9
        with self.assertRaises(ValueError): d.snapshot_workers(b, a)

    def test_summary_keeps_invalid_and_separates_datapaths(self):
        rows=[]
        for steering, value in [('kernel', 100), ('flows', 200)]:
            rows.append(dict(path=steering, identity=dict(steering_effective=steering),
                             errors=[], capture_valid=True, workload_valid=True, received_mbps=value))
        bad=copy.deepcopy(rows[0]);bad.update(path='bad', errors=['counter reset'],capture_valid=False)
        rows.append(bad)
        groups=d.grouped(rows)
        self.assertEqual(len(groups),2)
        self.assertEqual(groups[0]['n'],2)
        self.assertEqual(groups[0]['evidence_errors'],1)
        self.assertEqual(groups[0]['invalid_captures'],1)
        self.assertEqual(groups[1]['metrics']['received_mbps']['median'],200)


def event(seq, size=10, **kw):
    return dict(timestamp_ns=kw.pop('timestamp_ns', seq+1), seq=seq, payload_len=size,
                cpu=0, netns=1, src='192.0.2.1', dst='192.0.2.2', sport=1, dport=2,
                stage=kw.pop('stage', 'tun_read'), **kw)


class SequenceDiagnosticsTests(unittest.TestCase):
    def run_events(self, events, **metadata):
        return s.analyze(events, dict(complete=True, lost_events=0, capped_events=0, **metadata))

    def test_gap_late_fill_and_overlap(self):
        r = self.run_events([event(100, timestamp_ns=1), event(120, timestamp_ns=2),
                             event(110, timestamp_ns=3), event(100, timestamp_ns=4)])['stages'][0]
        self.assertEqual(r['observed_sequence_ranges'], [(100, 130)])
        self.assertEqual(r['late_new_sequence_bytes'], 10)
        self.assertEqual(r['observed_overlap_sequence_bytes'], 10)
        self.assertEqual(r['unresolved_internal_ranges'], [])
        self.assertEqual(len(r['forward_gaps']), 1)

    def test_wrap_syn_fin_and_pure_ack(self):
        events = [event(s.MOD-2, 0, syn=True, timestamp_ns=1),
                  event(s.MOD-1, 3, timestamp_ns=2), event(2, 0, fin=True, timestamp_ns=3),
                  event(2000, 0, timestamp_ns=4)]
        r = self.run_events(events)['stages'][0]
        self.assertEqual(r['observed_sequence_ranges'], [(s.MOD-2, s.MOD+3)])
        self.assertEqual(r['forward_gaps'], [])

    def test_segmentation_and_explicit_translated_alias(self):
        events = [event(100, 20, timestamp_ns=1), event(100, 10, timestamp_ns=2), event(110, 10, timestamp_ns=3)]
        for e in events[1:]: e.update(stage='receiver', src='2001:db8::1')
        r = self.run_events(events, address_aliases={'2001:db8::1': '192.0.2.1'})
        self.assertEqual(len(r['stages']), 2)
        self.assertEqual(r['stages'][0]['flow'], r['stages'][1]['flow'])
        self.assertEqual(r['stages'][0]['observed_sequence_ranges'], r['stages'][1]['observed_sequence_ranges'])

    def test_incomplete_ties_and_budgets_never_prove_loss(self):
        r = self.run_events([event(100, timestamp_ns=1), event(120, timestamp_ns=1)])
        self.assertFalse(r['capture_complete'])
        self.assertFalse(r['loss_or_reordering_proven'])
        with self.assertRaises(ValueError): s.analyze([event(100), event(120)], {}, max_intervals=1)
        with self.assertRaises(ValueError): s.unwrap(s.HALF, 0)
        with self.assertRaises(ValueError): s.analyze([event(100)], {}, max_events=0)

    def test_cross_stage_does_not_confuse_segmentation_or_claim_proof(self):
        points = [dict(stage='sender', netns=1, ifindex=0), dict(stage='receiver', netns=1, ifindex=0)]
        ev = [event(100, 30, stage='sender', timestamp_ns=1),
              event(100, stage='receiver', timestamp_ns=2),
              event(120, stage='receiver', timestamp_ns=3),
              event(110, stage='receiver', timestamp_ns=4)]
        r = self.run_events(ev, observation_paths=[dict(name='test', points=points)])
        self.assertTrue(r['cross_stage'][0]['upstream_range_seen_before_gap'])
        self.assertFalse(r['cross_stage'][0]['upstream_gap_already_observed'])
        self.assertFalse(r['loss_or_reordering_proven'])

    def test_filled_upstream_gap_is_not_a_new_downstream_handoff(self):
        points = [dict(stage='sender', netns=1, ifindex=0), dict(stage='receiver', netns=1, ifindex=0)]
        ev = [event(100, stage='sender', timestamp_ns=1),
              event(120, stage='sender', timestamp_ns=2),
              event(110, stage='sender', timestamp_ns=3),
              event(100, stage='receiver', timestamp_ns=4),
              event(120, stage='receiver', timestamp_ns=5),
              event(110, stage='receiver', timestamp_ns=6)]
        r = self.run_events(ev, observation_paths=[dict(name='propagated', points=points)])['cross_stage'][0]
        self.assertTrue(r['upstream_range_seen_before_gap'])
        self.assertTrue(r['upstream_gap_already_observed'])
        self.assertIn('not a new handoff', r['attribution'])

    def test_exact_backlog_matching_wrap_ambiguity_and_incomplete_capture(self):
        a=event(s.MOD-10,stage='backlog_enqueue',timestamp_ns=1,skb_addr='0xa',target_cpu=0,ifindex=0)
        b=event(0,stage='backlog_enqueue',timestamp_ns=2,skb_addr='0xb',target_cpu=1,ifindex=0)
        rb=dict(b,stage='backlog_receive',timestamp_ns=3)
        ra=dict(a,stage='backlog_receive',timestamp_ns=4)
        result=self.run_events([a,b,rb,ra])['backlog_handoffs']
        self.assertEqual(result['matched_packets'],2)
        self.assertEqual(result['different_backlog_inversions'],1)
        self.assertTrue(result['interpretable'])
        incomplete=s.analyze([a,b,rb,ra],dict(complete=False))['backlog_handoffs']
        self.assertFalse(incomplete['interpretable'])
        ambiguous=self.run_events([a,dict(a,timestamp_ns=2),ra])['backlog_handoffs']
        self.assertEqual(ambiguous['ambiguous_matches'],1)
        self.assertEqual(ambiguous['matched_packets'],0)


class CollectorFailureTests(unittest.TestCase):
    def test_bpftrace_stdout_loss_is_not_silent_success(self):
        from taygabench.trace_tcp import reported_loss
        self.assertEqual(reported_loss('READY\nLost 52565 events\n@seen[stage, 2]: 5\n'),52565)
        self.assertEqual(reported_loss('WARNING: lost 12 events\nLost 3 events\n'),15)
        self.assertIsNone(reported_loss('WARNING: dropped output\n'))
        self.assertEqual(reported_loss(''),0)

    def test_non_root_retains_failure_without_starting_a_workload(self):
        from taygabench import trace_tcp
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'capture'
            argv=['trace', '--output', str(out), '--', 'must-not-run']
            with mock.patch('sys.argv',argv), mock.patch.object(trace_tcp.os,'geteuid',return_value=1000), \
                 mock.patch.object(trace_tcp.subprocess,'Popen') as spawn, mock.patch('builtins.print'):
                self.assertEqual(trace_tcp.main(),1)
            spawn.assert_not_called()
            metadata=json.loads((out/'capture.json').read_text())
            self.assertFalse(metadata['complete'])
            self.assertIn('root required',metadata['error'])
            self.assertEqual((out/'events.jsonl').read_text(),'')

    def test_protocol_test_restores_installed_binary_on_failure(self):
        path=Path(__file__).resolve().parents[2]/'test/system/test_protocols_e2e.py'
        spec=importlib.util.spec_from_file_location('protocol_test_fixture',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            source, installed=Path(tmp)/'candidate',Path(tmp)/'installed'
            source.write_bytes(b'candidate');installed.write_bytes(b'original');installed.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError,'simulated startup failure'):
                with module.selected_binary(source,installed):
                    self.assertEqual(installed.read_bytes(),b'candidate')
                    raise RuntimeError('simulated startup failure')
            self.assertEqual(installed.read_bytes(),b'original')
            self.assertEqual(installed.stat().st_mode & 0o777,0o700)
            installed.unlink()
            with module.selected_binary(source,installed): self.assertTrue(installed.exists())
            self.assertFalse(installed.exists())

    def test_default_recovery_reaches_evaluator_on_system_bash(self):
        repo=Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);harness=root/'harness';(harness/'bench/lima').mkdir(parents=True)
            host=harness/'bench/lima/run-host.sh';host.write_text('#!/bin/sh\nexit 0\n');host.chmod(0o755)
            package=harness/'bench/taygabench';package.mkdir()
            (package/'__init__.py').write_text('')
            (package/'acceptance.py').write_text('import json,os,sys\nfrom pathlib import Path\nPath(os.environ["RUNNER_CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n')
            output=root/'args.json'
            env=dict(os.environ,HARNESS_REPO=str(harness),REPO=str(repo),
                     BASELINE_REPO=str(repo),CANDIDATE_REPO=str(repo),
                     PERF_SESSION_ROOT=str(root/'sessions'),RUNNER_CAPTURE=str(output),
                     RECOVERY_STAMP='shell-regression',REPEATS='5',
                     BASELINE_STEERING='kernel',CANDIDATE_STEERING='flows')
            for purpose in ('acceptance','diagnostic'):
                env['RECOVERY_PURPOSE']=purpose
                proc=subprocess.run(['/bin/bash',str(repo/'bench/lima/run-recovery.sh')],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,0,proc.stderr)
                args=json.loads(output.read_text())
                self.assertEqual('--diagnostic' in args,purpose=='diagnostic')


if __name__ == '__main__': unittest.main()
