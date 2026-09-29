#!/usr/bin/env python3
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "tools" / "compare-perf-sessions.py"


def result(direction, rate, offload, received):
    return {
        "capture_valid": True, "workload_valid": True,
        "direction": direction, "clients": 2, "expected_clients": 2,
        "workload_protocol": "tcp", "flows_per_client": 1,
        "rate_per_flow": rate, "duration_seconds": 10, "warmup_seconds": 1,
        "datagram_size": None, "block_size": 131072, "offlink_mtu": 1280,
        "git_revision": "abc", "source_tree_sha256": "tree",
        "clat_start_sha256": "starter", "kernel": "Linux test", "perf_mode": "stat",
        "tayga_sha256": "binary",
        "offload_requested": offload, "offload_effective": offload,
        "workers": 2, "tun_txqlen": 1000, "received_mbps": received,
    }


class ComparePerfSessionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = self.root / "base"
        self.candidate = self.root / "candidate"
        self.base.mkdir()
        self.candidate.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, root, name, value):
        path = root / name / "result.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def run_tool(self):
        return subprocess.run(["python3", str(TOOL), str(self.base), str(self.candidate)],
                              capture_output=True, text=True)

    def test_groups_directions_separately(self):
        for direction, b, c in (("upload", 100, 120), ("download", 200, 180)):
            self.write(self.base, direction + "-a", result(direction, "0", "off", b - 2))
            self.write(self.base, direction + "-b", result(direction, "0", "off", b + 2))
            self.write(self.candidate, direction + "-a", result(direction, "0", "tcp", c - 2))
            self.write(self.candidate, direction + "-b", result(direction, "0", "tcp", c + 2))
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(report["comparisons"]), 2)
        rates = {item["workload"]["direction"]: item["baseline_summary"]["received_mbps"]["median"]
                 for item in report["comparisons"]}
        self.assertEqual(rates, {"upload": 100, "download": 200})
        self.assertIsNone(report["baseline_summary"])

    def test_unmatched_group_is_warning_and_never_pooled(self):
        self.write(self.base, "upload", result("upload", "0", "off", 100))
        self.write(self.candidate, "download", result("download", "0", "tcp", 200))
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertIsNone(report["changes_percent"])
        self.assertTrue(any("no matching" in warning for warning in report["warnings"]))

    def test_mixed_treatments_skip_workload(self):
        self.write(self.base, "upload-a", result("upload", "0", "off", 100))
        self.write(self.base, "upload-b", result("upload", "0", "tcp", 120))
        self.write(self.candidate, "upload", result("upload", "0", "tcp", 130))
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertTrue(any("mixed treatment" in warning for warning in report["warnings"]))

    def test_unknown_build_identity_skips_workload(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        base["source_tree_sha256"] = "unknown"
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertTrue(any("source_tree_sha256 (unknown)" in warning
                            for warning in report["warnings"]))

    def test_unknown_identity_never_produces_a_comparison(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        base["source_tree_sha256"] = "unknown"
        candidate["source_tree_sha256"] = "unknown"
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertIsNone(report["changes_percent"])

    def test_different_binaries_are_not_pooled(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        candidate["tayga_sha256"] = "other-binary"
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertTrue(any("no matching" in warning for warning in report["warnings"]))

    def test_missing_metrics_are_ignored(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        base["system_busy_cores"] = None
        candidate["system_busy_cores"] = None
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("system_busy_cores", report["baseline_summary"])

    def test_missing_treatment_skips_workload(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        del base["workers"]
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertTrue(any("complete treatment" in warning
                            for warning in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
