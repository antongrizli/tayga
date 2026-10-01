import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('envelope',Path(__file__).resolve().parents[1]/'tools/run-udp-envelope-study.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class EnvelopeTests(unittest.TestCase):
    def rows(self):
        return [dict(case=f'{d}-{r}',direction=d,finite=False,requested_rate_mbps=r,rate='paced' if r else 'unrestricted',sender=dict(rate_mbps=r,packets=100,bytes=120000),receiver=dict(packets=100,bytes=120000,invalid=0,duplicates=0),capture_valid=True,workload_valid=True,acceptance_pass=True,offered_mbps=r or 10000,received_mbps=r or 10000,loss_percent=0,pressure_deltas={}) for d in ('upload','download') for r in (1000,0)]
    def test_complete(self):self.assertTrue(all(r['operating_point_pass'] for r in m.summarize(self.rows(),[1000,0],1)))
    def test_under_offered(self):
        rows=self.rows();rows[0]['offered_mbps']=800
        self.assertFalse(m.summarize(rows,[1000,0],1)[0]['operating_point_pass'])
    def test_pressure(self):
        rows=self.rows();rows[0]['pressure_deltas']={'UdpRcvbufErrors':1}
        self.assertFalse(m.summarize(rows,[1000,0],1)[0]['operating_point_pass'])
    def test_full_counts(self):
        rows=self.rows();rows[0]['receiver']['packets']=99
        self.assertFalse(m.summarize(rows,[1000,0],1)[0]['operating_point_pass'])
    def test_profiles_excluded(self):
        rows=self.rows();profile=dict(rows[0],case='profile',profile=True)
        self.assertTrue(all(r['operating_point_pass'] for r in m.summarize(rows+[profile],[1000,0],1)))
    def test_invalid(self):
        for mode in ('missing','duplicate','rate'):
            rows=self.rows()
            if mode=='missing':rows.pop()
            elif mode=='duplicate':rows[1]['case']=rows[0]['case']
            else:rows[0]['sender']['rate_mbps']=0
            with self.assertRaises(ValueError):m.summarize(rows,[1000,0],1)
if __name__=='__main__':unittest.main()
