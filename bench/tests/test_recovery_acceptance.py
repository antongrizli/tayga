"""Recovery gates must reject bad evidence, not only compare aggregate medians."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import subprocess
import shutil
import tarfile
import unittest
from taygabench import acceptance, compare
from test_compare_perf_sessions import result


class RecoveryTests(unittest.TestCase):
    @staticmethod
    def archive(path,data):
        with tarfile.open(path,'w:gz') as archive:
            member=tarfile.TarInfo('./main.c');member.size=len(data)
            archive.addfile(member,io.BytesIO(data))

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        for arm,steering,retrans in (('baseline','kernel',100),('candidate','flows',40)):
            session=self.root/arm
            session.mkdir()
            (session/'compiler.txt').write_text('gcc fixture 1.0\n')
            (session/'build-flags.txt').write_text('CC=gcc\nCFLAGS=-O3 -flto -ffile-prefix-map=/tmp/fixture=.\nLDFLAGS=-flto\n')
            (session/'tayga.sha256').write_text('binary  tayga\n')
            self.archive(session/'source-snapshot.tar.gz',b'fixture source\n')
            tree=acceptance.source_identity(session/'source-snapshot.tar.gz')
            (session/'source-tree.sha256').write_text(tree+'\n')
            (session/'source-snapshot.sha256').write_text(hashlib.sha256((session/'source-snapshot.tar.gz').read_bytes()).hexdigest())
            for direction in ('download','upload'):
                path=session/'none'/direction;path.mkdir(parents=True)
                for phase in ('before','after'):
                    (path/f'kernel-network-settings.{phase}').write_text('net.core.netdev_max_backlog = 1000\nnet.core.netdev_budget = 300\nnet.core.netdev_budget_usecs = 8000\n')
                rate=78000 if arm=='baseline' else 80000
                doc=result(direction,'0','auto',rate)
                doc.update(clients=4,expected_clients=4,workers=3,duration_seconds=20,warmup_seconds=5,
                           offload_effective='udp',client_port_base=40100,source_tree_sha256=tree,
                           perf_mode='none',interface_deltas={'client':{'lan0':{way:dict(dropped=0,errors=0) for way in ('rx','tx')}}})
                (path/'result.json').write_text(json.dumps(doc))
                # Reuse the comparison loader's historical defaults, so a test
                # fixture has the same complete identity as a real result.
                doc=compare.results(session)[-1]
                (path/'result.json').write_text(json.dumps(doc))
                snap=dict(pid=42,process_start_ticks='123',network_namespace=99,tun_device='clat',
                          workers_synced=True,unacknowledged_worker_slots=[],snapshot_sequence=3,
                          steering_requested=steering,steering_effective=steering,packet_io='sync',dispatch_mode='kernel',offload_effective='udp',
                          tx_failed_frames=0,tx_short=0,tx_fatal=0,async_errors=0,dispatch_drops=0,
                          traffic=dict(dropped_packets=4,errors=0),gso=dict(invalid_packets=0,tun_write_errors=0),
                          workers=[dict(slot=i,rx_packets_v4=10,rx_packets_v6=10) for i in (1,2,3)])
                (path/'tayga-status.before.json').write_text(json.dumps(snap))
                snap['snapshot_sequence']=8
                for worker in snap['workers']:worker.update(rx_packets_v4=100,rx_packets_v6=100)
                (path/'tayga-status.after.json').write_text(json.dumps(snap))
                for n in range(1,5):
                    client={'end':{'sum_received':dict(seconds=20,bits_per_second=rate*1e6/4),
                                   'sum_sent':dict(bytes=40000000000,retransmits=retrans)}}
                    client['start']=dict(test_start=dict(protocol='TCP',num_streams=1,duration=20,target_bitrate=0,bidir=0,
                                                         reverse=1 if direction=='download' else 0),
                                         connected=[dict(local_port=40100+n+(1000 if direction=='upload' else 0))])
                    (path/f'client-{n}.json').write_text(json.dumps(client))
        self.base=self.root/'baseline';self.candidate=self.root/'candidate'
        self.path=self.candidate/'none/download'

    def tearDown(self):self.tmp.cleanup()

    def report(self,**kwargs):return acceptance.evaluate([self.base],[self.candidate],repeats=kwargs.pop('repeats',1),**kwargs)

    def change(self,name,func):
        p=self.path/name;doc=json.loads(p.read_text());func(doc);p.write_text(json.dumps(doc))

    def test_pass_uses_sent_decimal_gb_and_interval_drops(self):
        # Earlier four lifetime drops are not measurement-window drops.
        report=self.report();self.assertTrue(report['passed'],report['errors'])
        self.assertEqual(report['samples']['candidate'][0]['retransmits_per_sent_gb'],1)

    def test_insufficient_repeats_and_missing_upload_fail(self):
        self.assertFalse(self.report(repeats=5)['passed'])
        (self.candidate/'none/upload/result.json').unlink()
        self.assertTrue(any('upload' in e for e in self.report()['errors']))

    def test_repeated_paths_cannot_supply_independent_trials(self):
        report=acceptance.evaluate([self.base]*5,[self.candidate]*5,repeats=5)
        self.assertFalse(report['passed'])
        self.assertIn('duplicate samples cannot count as independent trials',report['errors'])

    def test_empty_manifest_and_missing_connection_fail_closed(self):
        p=self.candidate/'tayga.sha256';original=p.read_text()
        p.write_text('')
        self.assertFalse(self.report()['passed'])
        p.write_text(original)
        self.change('client-1.json',lambda d:d['start'].update(connected=[]))
        self.assertFalse(self.report()['passed'])

    def test_low_throughput_and_retransmission_regression_fail(self):
        self.assertFalse(self.report(download=90000)['passed'])
        self.assertFalse(self.report(reduction=.9)['passed'])

    def test_raw_and_declared_core_workload_are_both_required(self):
        for name,key,value in (('result.json','flows_per_client',2),('result.json','rate_per_flow','100M'),
                               ('result.json','offlink_mtu',1500),('result.json','client_port_base',0),
                               ('result.json','client_port_base',1023),('result.json','client_port_base',62531)):
            with self.subTest(key=key):
                p=self.path/name;original=p.read_text()
                self.change(name,lambda d:d.update({key:value}))
                self.assertFalse(self.report()['passed']);p.write_text(original)
        for key,value in (('num_streams',2),('reverse',0),('protocol','UDP')):
            with self.subTest(raw_key=key):
                p=self.path/'client-1.json';original=p.read_text()
                self.change(p.name,lambda d:d['start']['test_start'].update({key:value}))
                self.assertFalse(self.report()['passed']);p.write_text(original)
        self.change('client-1.json',lambda d:d['start']['connected'][0].update(local_port=40102))
        self.assertFalse(self.report()['passed'])

    def test_changed_or_unrecorded_kernel_network_settings_fail(self):
        p=self.path/'kernel-network-settings.after'
        original=p.read_text();changed=original.replace('1000','8192')
        p.write_text(changed)
        self.assertFalse(self.report()['passed'])
        (self.path/'kernel-network-settings.before').write_text(changed)
        self.assertTrue(any('arm mismatch kernel_network_settings' in e for e in self.report(mode='build')['errors']))
        p.unlink();self.assertFalse(self.report()['passed'])

    def test_equal_or_lower_throughput_is_not_an_improvement(self):
        for rate in (78000,77999):
            with self.subTest(rate=rate):
                self.change('result.json',lambda d:d.update(received_mbps=rate))
                for n in range(1,5):
                    self.change(f'client-{n}.json',lambda d:d['end']['sum_received'].update(bits_per_second=rate*1e6/4))
                report=self.report()
                self.assertTrue(any('no same-environment throughput improvement' in e for e in report['errors']))

    def test_old_plan_floor_cannot_pass_below_saved_initial_result(self):
        rate=76000
        self.change('result.json',lambda d:d.update(received_mbps=rate))
        for n in range(1,5):
            self.change(f'client-{n}.json',lambda d:d['end']['sum_received'].update(bits_per_second=rate*1e6/4))
        report=self.report()
        self.assertTrue(any('historical throughput threshold failed' in e for e in report['errors']))

    def test_improved_arm_median_cannot_hide_negative_paired_median(self):
        roots={'baseline':[],'candidate':[]}
        schedules={'baseline':(78000,80000,100000),'candidate':(77999,90000,99999)}
        for arm,rates in schedules.items():
            for trial,rate in enumerate(rates):
                target=self.root/f'{arm}-{trial}'
                shutil.copytree(self.root/arm,target);roots[arm].append(target)
                for direction in ('download','upload'):
                    folder=target/'none'/direction
                    p=folder/'result.json';doc=json.loads(p.read_text())
                    doc['received_mbps']=rate;p.write_text(json.dumps(doc))
                    for p in folder.glob('client-*.json'):
                        doc=json.loads(p.read_text())
                        doc['end']['sum_received']['bits_per_second']=rate*1e6/4
                        p.write_text(json.dumps(doc))
        report=acceptance.evaluate(roots['baseline'],roots['candidate'],repeats=3)
        self.assertFalse(report['passed'])
        self.assertTrue(any('no median paired throughput improvement' in e for e in report['errors']))
        self.assertFalse(any('no same-environment throughput improvement' in e for e in report['errors']))

    def test_snapshot_identity_staleness_reset_and_wrong_steering(self):
        for key,value in (('pid',43),('snapshot_sequence',3),('workers_synced',False),('steering_effective','kernel')):
            with self.subTest(key=key):
                p=self.path/'tayga-status.after.json';original=p.read_text()
                self.change(p.name,lambda d:d.update({key:value}))
                self.assertFalse(self.report()['passed']);p.write_text(original)
        self.change('tayga-status.after.json',lambda d:d['traffic'].update(dropped_packets=0))
        self.assertFalse(self.report()['passed'])

    def test_five_pairs_require_repeatable_improvement(self):
        roots={'baseline':[],'candidate':[]}
        for arm in roots:
            for trial in range(5):
                target=self.root/f'{arm}-{trial}'
                shutil.copytree(self.root/arm,target);roots[arm].append(target)
        report=acceptance.evaluate(roots['baseline'],roots['candidate'])
        self.assertTrue(report['passed'],report['errors'])
        self.assertEqual(report['groups'][0]['paired_improvement_sign_p'],1/32)
        folder=roots['candidate'][-1]/'none/download'
        p=folder/'result.json';doc=json.loads(p.read_text())
        doc['received_mbps']=77999;p.write_text(json.dumps(doc))
        for p in folder.glob('client-*.json'):
            doc=json.loads(p.read_text())
            doc['end']['sum_received']['bits_per_second']=77999*1e6/4
            p.write_text(json.dumps(doc))
        report=acceptance.evaluate(roots['baseline'],roots['candidate'])
        self.assertFalse(report['passed'])
        self.assertTrue(any('run-to-run variation' in e for e in report['errors']))

    def test_missing_worker_or_client_is_not_zero(self):
        self.change('tayga-status.after.json',lambda d:d['workers'].pop())
        self.assertFalse(self.report()['passed'])
        (self.path/'client-4.json').unlink();self.assertFalse(self.report()['passed'])

    def test_interfaces_and_content_identity_checked(self):
        self.change('result.json',lambda d:d['interface_deltas']['client']['lan0']['tx'].update(dropped=1))
        self.assertFalse(self.report()['passed'])
        (self.candidate/'source-tree.sha256').write_text('different')
        self.assertTrue(any('manifest mismatch' in e for e in self.report()['errors']))

    def test_replaced_archive_cannot_reuse_the_old_source_identity(self):
        p=self.candidate/'source-snapshot.tar.gz'
        self.archive(p,b'different source\n')
        (self.candidate/'source-snapshot.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest())
        report=self.report()
        self.assertFalse(report['passed'])
        self.assertTrue(any('source archive contents/identity mismatch' in e for e in report['errors']))

    def test_duplicate_legacy_worker_lines_ignored(self):
        (self.path/'worker-stats.after.txt').write_text('Worker 0 rx6=1\nWorker 0 rx6=99999999\n')
        self.assertTrue(self.report()['passed'])

    def test_mismatched_build_rejected_in_configuration_mode(self):
        self.change('result.json',lambda d:d.update(clat_start_sha256='different'))
        self.assertFalse(self.report()['passed'])
        self.assertTrue(self.report(mode='build')['passed'])

    def test_build_comparison_requires_same_compiler_and_optimization(self):
        p=self.candidate/'build-flags.txt';original=p.read_text()
        p.write_text(original.replace('/tmp/fixture','/tmp/another-build'))
        self.assertTrue(self.report(mode='build')['passed'])
        p.write_text(original.replace('-O3','-O2'))
        self.assertTrue(any('arm mismatch build_flags' in e for e in self.report(mode='build')['errors']))
        p.write_text(original)
        (self.candidate/'compiler.txt').write_text('gcc fixture 2.0\n')
        self.assertTrue(any('arm mismatch compiler' in e for e in self.report(mode='build')['errors']))

    def test_deterministic_ports_keep_warmup_and_directions_separate(self):
        library=Path(__file__).resolve().parents[1]/'clat/lib/iperf.sh'
        env = "CLIENTS=1 FLOWS=1 CLIENT_PORT_BASE=40100 CLIENT_CPUSET=all PROTOCOL=tcp PACING_TIMER_US=1000 FQ_RATE=0 SOCKET_BUFFER_BYTES=0 BLOCK_SIZE= RATE=0 iperf_start_library= udp_drain_guard= iperf_start_control= udp_drain_control="
        for direction, warmup, expected in (('download',False,'40101'),('upload',False,'41101'),('download',True,'42101'),('upload',True,'43101')):
            directory=self.root/('warmup-'+direction if warmup else direction);directory.mkdir()
            script=f'. "{library}"\n{env}\nexec_with_affinity() {{ printf "%s\\n" "$@"; }}\nstart_clients "{directory}" {direction} 20 no\nwait\n'
            subprocess.run(['sh','-c',script],check=True,capture_output=True,text=True)
            args=(directory/'client-1.json').read_text().splitlines()
            self.assertEqual(args[args.index('--cport')+1],expected)

    def test_different_paired_flow_schedule_fails(self):
        self.change('result.json',lambda d:d.update(client_port_base=40200))
        self.assertFalse(self.report()['passed'])


if __name__=='__main__':unittest.main()
