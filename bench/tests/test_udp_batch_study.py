#!/usr/bin/env python3
"""Study matrix ordering and finite/profile coverage without network side effects."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('batch_study',Path(__file__).resolve().parents[1]/'tools/run-udp-batch-study.py')
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)

class StudyTests(unittest.TestCase):
    def run_study(self,finite_only=False):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);binary=root/'binary';binary.write_text('fixture')
            argv=['study','--binary',str(binary),'--endpoint',str(binary),'--output',str(root/'output'),'--duration','1','--pairs','3','--batch-sizes','3','8','32','--gro-values','1']
            if finite_only: argv.append('--correctness-only')
            with patch('sys.argv',argv),patch.object(study.os,'geteuid',return_value=0),patch.object(study.fcntl,'flock'),patch.object(study,'run_case',return_value={}) as run,patch.object(study,'command',return_value=subprocess.CompletedProcess([],0,stdout='fixture',stderr='')):
                study.main()
            return run.call_args_list

    def test_alternating_order_and_profile_coverage(self):
        calls=self.run_study()
        finite=[c for c in calls if c.kwargs.get('finite')]
        capacity=[c for c in calls if not c.kwargs]
        profiles=[c for c in calls if c.kwargs.get('profile')]
        self.assertEqual((len(finite),len(capacity),len(profiles)),(12,18,8))
        self.assertEqual([c.args[3] for c in capacity],[3,8,32,3,8,32,32,8,3,32,8,3,3,8,32,3,8,32])
        self.assertTrue(all(c.args[4]==1 for c in capacity))
        self.assertEqual({(c.args[3],c.args[4]) for c in profiles},{(1,0),(3,1),(8,1),(32,1)})
        self.assertEqual({(c.args[3],c.args[4]) for c in finite},{(1,0),(32,0),(1,1),(32,1),(3,1),(8,1)})

    def test_correctness_only_has_no_capacity_or_profiles(self):
        calls=self.run_study(True)
        self.assertEqual(len(calls),12)
        self.assertTrue(all(c.kwargs.get('finite') for c in calls))

if __name__=='__main__': unittest.main()
