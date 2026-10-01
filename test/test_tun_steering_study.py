#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import unittest
import tempfile
import copy
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('study',ROOT/'tools/run-tun-steering-study.py')
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)
spec=importlib.util.spec_from_file_location('summary',ROOT/'tools/summarize-tun-steering-study.py')
summary=importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)
class StudyTest(unittest.TestCase):
 def test_startup_preserves_daemon_pid_and_waits_for_negotiation(self):
  script=study.startup((ROOT/'scripts/container/clat-start.sh').read_text())
  self.assertNotIn('--mktun',script)
  self.assertIn('parent=$$',script)
  self.assertIn('TUN offload negotiated:',script)
  self.assertIn('exec /usr/sbin/tayga -c /run/clat.conf -d --tun-steering=groups',script)
  self.assertEqual(subprocess.run(['sh','-n'],input=script,text=True,capture_output=True).returncode,0)
 def test_unknown_startup_rejected(self):
  with self.assertRaises(ValueError):study.startup('exit 0\n')
 def test_install_replaces_inode_and_preserves_mode(self):
  with tempfile.TemporaryDirectory() as folder:
   source,target=Path(folder)/'source',Path(folder)/'target'
   source.write_text('after');source.chmod(0o755);target.write_text('before')
   with target.open() as reader:
    study.install(source,target)
    self.assertEqual(reader.read(),'before')
   self.assertEqual(target.read_text(),'after')
   self.assertEqual(target.stat().st_mode & 0o777,0o755)
   self.assertEqual(len(list(Path(folder).iterdir())),2)
 def fixture(self):
  cases=[dict(stage='reference',pair=n,binary=b,policy='kernel',protocol='tcp',mode='none',scope='process') for n in (1,2,3) for b in ('baseline','candidate')]
  identity={'baseline-tayga':'old','candidate-tayga':'new','experimental-startup.sh':'startup'}
  rows=[]
  for case in cases:
   for direction in ('upload','download'):
    rows.append(dict(**case,direction=direction,effective='kernel',label='fixture',status=0,result=dict(capture_valid=True,workload_valid=True,acceptance_pass=True,
       tayga_sha256=identity[case['binary']+'-tayga'],clat_start_sha256='startup',workload_protocol='tcp',direction=direction,perf_mode='none',perf_scope='process',
       workers=2,clients=4,flows_per_client=4,rate_per_flow='0',received_mbps=1000,worker_metrics=[dict(slot=1,rx_packets_v4=1,rx_packets_v6=1)])))
  return rows,cases,identity
 def test_summary_complete_and_rejections(self):
  rows,cases,identity=self.fixture()
  result=summary.summarize(rows,cases,identity,4)
  self.assertEqual(len(result['groups']),4)
  self.assertEqual(result['pairs'][0]['median_paired_change_percent'],0)
  with self.assertRaises(ValueError):summary.summarize(rows[:-1],cases,identity,4)
  with self.assertRaises(ValueError):summary.summarize(rows+[rows[0]],cases,identity,4)
  for key,value in (('tayga_sha256','wrong'),('acceptance_pass',False),('rate_per_flow','300M'),('flows_per_client',1),('workers',3)):
   changed=copy.deepcopy(rows);changed[0]['result'][key]=value
   with self.assertRaises(ValueError):summary.summarize(changed,cases,identity,4)
  rows[0]['effective']='kernel-fallback'
  with self.assertRaises(ValueError):summary.summarize(rows,cases,identity,4)
if __name__=='__main__':unittest.main()
