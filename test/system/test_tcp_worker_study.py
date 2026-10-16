#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
def module(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/'tools'/f'{name}.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
run=module('run-tcp-worker-study');summary=module('summarize-tcp-worker-study')
class StudyTest(unittest.TestCase):
 def test_alternating_and_balanced_order(self):
  cases=run.schedule(3)
  self.assertEqual([v['arm'] for v in cases if v['stage']=='ab'],['before','after','after','before','before','after'])
  self.assertEqual([v['workers'] for v in cases if v['stage']=='workers'],[1,2,3,3,1,2,2,3,1])
  self.assertEqual(len(cases),19)
 def test_distribution(self):
  d=summary.distribution(dict(worker_metrics=[dict(slot=0,rx_packets_v4=1000),dict(slot=1,rx_packets_v4=50),dict(slot=2,rx_packets_v6=50)]))
  self.assertEqual(d['shares'],[.5,.5]);self.assertEqual(d['active_workers'],2);self.assertEqual(d['effective_workers'],2)
  self.assertEqual(summary.distribution(dict(worker_metrics=[dict(slot=1,rx_packets_v4=9,rx_packets_v6=1),dict(slot=2,rx_packets_v4=1,rx_packets_v6=9)]),'upload')['shares'],[.9,.1])
 def fixture(self):
  rows=[]
  for c in run.schedule(3):
   for d in ('upload','download'):
    rows.append(dict(**c,direction=d,result=dict(capture_valid=True,workload_valid=True,acceptance_pass=True,tayga_sha256='a',workers=c['workers'],workload_protocol='tcp',perf_mode=c['mode'],rate_per_flow='0',received_mbps=1000 if c['arm']=='before' else 1100,worker_metrics=[dict(slot=1,rx_packets_v4=1,rx_packets_v6=1)])))
  return rows
 def test_summary_and_rejections(self):
  rows=self.fixture();s=summary.summarize(rows)
  self.assertEqual(len(s['groups']),10);self.assertEqual(len(s['profile_cases']),8)
  self.assertAlmostEqual(s['pairs'][0]['median_paired_change_percent'],10)
  with self.assertRaises(ValueError):summary.summarize(rows[1:])
  rows=self.fixture();rows[0]['result']['tayga_sha256']='b'
  with self.assertRaises(ValueError):summary.summarize(rows)
  rows=self.fixture();rows[0]['result']['acceptance_pass']=False
  with self.assertRaises(ValueError):summary.summarize(rows)
 def test_treatment_rate_and_duplicate_rounds_are_rejected(self):
  for mutation in ('workers','rate','round'):
   rows=self.fixture()
   if mutation=='workers':rows[0]['result']['workers']=9
   if mutation=='rate':rows[0]['result']['rate_per_flow']='300M'
   if mutation=='round':
    for row in rows:
     if row['stage']=='ab' and row['arm']=='before' and row['round']==3:row['round']=2
   with self.assertRaises(ValueError):summary.summarize(rows)
if __name__=='__main__':unittest.main()
