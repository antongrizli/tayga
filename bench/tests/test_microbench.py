#!/usr/bin/env python3
"""Check that the translator microbenchmark reports every case."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = ["baseline_write_1400", "udp4to6_64", "udp4to6_1400", "udp6to4_64",
         "udp6to4_1400", "tcp4to6_1400", "tcp6to4_1400", "icmp_echo4to6"]

@unittest.skipUnless(sys.platform.startswith("linux") or sys.platform.startswith("freebsd"),
                     "the translator builds on Linux and FreeBSD only")
class MicrobenchTest(unittest.TestCase):
    def test_reports_every_case(self):
        subprocess.run(["make", "-C", str(ROOT), "build/bench_xlate"], check=True)
        out = subprocess.run([str(ROOT / "build/bench_xlate"), "--iters", "1000", "--runs", "2"],
                             check=True, capture_output=True, text=True).stdout
        rows = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([r["case"] for r in rows], CASES)
        for r in rows:
            self.assertGreater(r["ns_per_pkt"], 0)
            self.assertEqual((r["iters"], r["runs"]), (1000, 2))

    def test_rejects_zero_iterations(self):
        subprocess.run(["make", "-C", str(ROOT), "build/bench_xlate"], check=True)
        res = subprocess.run([str(ROOT / "build/bench_xlate"), "--iters", "0"], capture_output=True)
        self.assertEqual(res.returncode, 2)

if __name__ == "__main__":
    unittest.main()
