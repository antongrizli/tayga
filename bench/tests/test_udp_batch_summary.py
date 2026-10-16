#!/usr/bin/env python3
"""Capacity matrix validation and separate profile reporting."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('batch_summary',Path(__file__).resolve().parents[1]/'tools/summarize-udp-batch-study.py')
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)

class SummaryTests(unittest.TestCase):
    def fixture(self,root):
        (root/'settings.json').write_text(json.dumps(dict(start_pair=1,pairs=2,batch_sizes=[3,32],gro_values=[1])))
        rows=[]
        for pair in (1,2):
            for direction in ('upload','download'):
                for batch in (3,32):
                    rows.append(dict(case=f'pair{pair}-{direction}-{batch}-1',direction=direction,batch=batch,gro=1,
                                     finite=False,profile=False,capture_valid=True,workload_valid=True,acceptance_pass=False,
                                     sender=dict(batch=batch,fallback_errno=0),receiver=dict(gro=1,fallback_errno=0),
                                     binary_sha256='fixed',endpoint_sha256='fixed',received_mbps=batch*1000,offered_mbps=batch*2000,
                                     loss_percent=50,tayga_cpu_seconds_per_received_gib=1/batch))
        profile=dict(rows[0],case='profile-upload-3-1',profile=True,received_mbps=999999)
        folder=root/profile['case'];folder.mkdir()
        (folder/'perf-report.txt').write_text('# Total Lost Samples: 0\n  12.34% [k] __pi_clear_page [kernel.kallsyms]\n')
        rows.append(profile)
        (root/'ledger.json').write_text(json.dumps(rows));return rows

    def test_profiles_do_not_enter_capacity_medians(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);result=study.summarize(root)
            self.assertEqual(result['capacity_cases'],8);self.assertEqual(result['profile_cases'],1)
            self.assertEqual(result['capacity'][0]['received_gbps'],3)
            self.assertEqual(result['profiles'][0]['self_percent']['__pi_clear_page'],12.34)
            self.assertEqual(result['profiles'][0]['lost_samples'],0)

    def test_incomplete_invalid_mixed_or_fallback_rejected(self):
        for fault in ('missing','invalid','identity','fallback','duplicate'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);rows=self.fixture(root)
                if fault=='missing':rows.pop(0)
                if fault=='invalid':rows[0]['workload_valid']=False
                if fault=='identity':rows[0]['binary_sha256']='changed'
                if fault=='fallback':rows[0]['sender']['batch']=1
                if fault=='duplicate':rows.append(rows[0])
                (root/'ledger.json').write_text(json.dumps(rows))
                with self.assertRaises(ValueError):study.summarize(root)

if __name__=='__main__':unittest.main()
