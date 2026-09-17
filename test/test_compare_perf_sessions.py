import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def write_result(root, name, cpu, mbps, drops=0):
    path = root / name / "download"
    path.mkdir(parents=True)
    (path / "result.json").write_text(json.dumps({
        "direction": "download", "clients": 20, "expected_clients": 20,
        "workload_protocol": "tcp", "received_mbps": mbps,
        "tayga_cpu_cores": cpu, "tayga_core_per_gbps": cpu / (mbps / 1000),
        "tun_drops": drops, "retransmits": drops, "elapsed_s": 60,
    }))


class ComparePerfSessionsTest(unittest.TestCase):
    def test_compare_emits_change(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            baseline = tmp_path / "baseline"
            candidate = tmp_path / "candidate"
            write_result(baseline, "a", 0.4, 300)
            write_result(candidate, "a", 0.3, 300)
            script = Path(__file__).parents[1] / "tools" / "compare-perf-sessions.py"
            output = subprocess.run([sys.executable, str(script), str(baseline), str(candidate)],
                                    check=True, capture_output=True, text=True)
            report = json.loads(output.stdout)
            self.assertAlmostEqual(report["changes_percent"]["tayga_cpu_cores_percent"], -25.0)
            self.assertFalse(report["warnings"])


if __name__ == "__main__":
    unittest.main()
