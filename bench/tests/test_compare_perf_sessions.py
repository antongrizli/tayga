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
        "clat_start_sha256": "starter", "kernel": "Linux test", "guest_cpu_count": 4, "perf_mode": "stat",
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

    def run_tool(self, *args):
        return subprocess.run(["python3", str(TOOL), *args, str(self.base), str(self.candidate)],
                              capture_output=True, text=True)

    def test_accounting_v3_udp_loss_is_supported(self):
        doc = result("upload", "0", "off", 100)
        doc.update(workload_protocol="udp", datagram_size=1200,
                   udp_accounting_version=3, udp_loss_percent=.1)
        self.write(self.base, "run", doc)
        self.write(self.candidate, "run", doc)
        report = json.loads(self.run_tool().stdout)
        self.assertEqual(report["comparisons"][0]["baseline_summary"]["udp_loss_percent"]["median"], .1)
        self.assertFalse(any("Legacy UDP" in w for w in report["warnings"]))

    def test_guard_capture_without_guard_binary_identity_is_invalid(self):
        doc = result("upload", "0", "off", 100)
        doc.update(receiver_drain_seconds=.5, receiver_drain_method="udp-write-eagain-v1")
        self.write(self.base, "run", doc)
        self.write(self.candidate, "run", doc)
        report = json.loads(self.run_tool().stdout)
        self.assertIn("guard binary identity", report["baseline_invalid"][0]["invalid_reason"])
        self.assertEqual(report["comparisons"], [])

    def test_drain_methods_and_guard_binaries_are_not_pooled(self):
        for change in ({"receiver_drain_method": "legacy"},
                       {"receiver_drain_guard_sha256": "other-guard"}):
            with self.subTest(change=change):
                baseline = result("upload", "0", "off", 100)
                baseline.update(receiver_drain_seconds=.5, receiver_drain_method="udp-write-eagain-v1",
                                receiver_drain_guard_sha256="guard")
                candidate = dict(baseline, **change)
                self.write(self.base, "run", baseline)
                self.write(self.candidate, "run", candidate)
                report = json.loads(self.run_tool().stdout)
                self.assertEqual(report["comparisons"], [])

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

    def test_build_mode_matches_distinct_known_builds(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        candidate["git_revision"] = "def"
        candidate["source_tree_sha256"] = "tree-new"
        candidate["tayga_sha256"] = "binary-new"
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool("--mode", "build")
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(report["comparisons"]), 1)
        self.assertEqual(report["comparisons"][0]["baseline_build"]["git_revision"], "abc")
        self.assertEqual(report["comparisons"][0]["candidate_build"]["git_revision"], "def")

    def test_forwarding_gro_is_a_distinct_treatment(self):
        base = result("upload", "0", "udp", 100)
        candidate = dict(base, forwarding_gro="on", received_mbps=120)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["comparisons"][0]["baseline_treatment"]["forwarding_gro"], "off")
        self.assertEqual(report["comparisons"][0]["candidate_treatment"]["forwarding_gro"], "on")

    def test_pacing_buffer_and_fq_limits_are_distinct_treatments(self):
        base = result("upload", "750M", "udp", 100)
        candidate = dict(base, pacing_timer_us=250, socket_buffer_bytes=2097152,
                         sender_fq="on", fq_rate="800M", sender_fq_flow_limit=1000)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        comparison = report["comparisons"][0]
        self.assertEqual(comparison["baseline_treatment"]["sender_fq_flow_limit"], 100)
        self.assertEqual(comparison["candidate_treatment"]["sender_fq_flow_limit"], 1000)

    def test_system_profiles_are_not_pooled_with_process_profiles(self):
        base = result("upload", "750M", "udp", 100)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", dict(base, perf_scope="system"))
        run = self.run_tool()
        self.assertEqual(run.returncode, 2)
        self.assertFalse(json.loads(run.stdout)["comparisons"])

    def test_queue_count_and_total_limit_are_distinct_treatments(self):
        base = result("upload", "750M", "udp", 100)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", dict(base, sender_fq_limit=4096, veth_queues=4))
        run = self.run_tool()
        self.assertEqual(run.returncode, 0, run.stderr)
        comparison = json.loads(run.stdout)["comparisons"][0]
        self.assertEqual(comparison["baseline_treatment"]["sender_fq_limit"], 10000)
        self.assertEqual(comparison["candidate_treatment"]["veth_queues"], 4)

    def test_affinity_changes_are_not_pooled_with_other_treatments(self):
        base = result("upload", "750M", "udp", 100)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "unpinned", base)
        self.write(self.candidate, "pinned", dict(base, tayga_cpuset="2,3", client_cpuset="0", server_cpuset="1"))
        run = self.run_tool()
        self.assertEqual(run.returncode, 2)
        self.assertTrue(any("mixed treatment" in warning for warning in json.loads(run.stdout)["warnings"]))

    def test_cpu_resource_changes_are_not_pooled(self):
        base = result("upload", "750M", "udp", 100)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", dict(base, guest_cpu_count=8))
        run = self.run_tool()
        self.assertEqual(run.returncode, 2)
        self.assertFalse(json.loads(run.stdout)["comparisons"])

    def test_legacy_cpu_count_uses_saved_cpuinfo(self):
        base = result("upload", "750M", "udp", 100)
        del base["guest_cpu_count"]
        self.write(self.base, "upload", base)
        (self.base / "cpuinfo.txt").write_text("processor : 0\nprocessor : 1\nprocessor : 2\nprocessor : 3\n")
        self.write(self.candidate, "upload", dict(base, guest_cpu_count=4))
        run = self.run_tool()
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_socket_sampling_changes_workload_identity(self):
        base = result("upload", "750M", "udp", 100)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", dict(base, socket_sample_interval=1))
        run = self.run_tool()
        self.assertEqual(run.returncode, 2)
        self.assertFalse(json.loads(run.stdout)["comparisons"])

    def test_mixed_forwarding_gro_is_not_pooled(self):
        base = result("upload", "0", "udp", 100)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "off", base)
        self.write(self.candidate, "on", dict(base, forwarding_gro="on"))
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertTrue(any("mixed treatment" in warning for warning in report["warnings"]))

    def test_legacy_udp_loss_is_excluded(self):
        base = dict(result("upload", "0", "udp", 100), workload_protocol="udp",
                    datagram_size=1200, udp_loss_percent=10)
        candidate = dict(base, udp_accounting_version=2, udp_loss_percent=12)
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2, run.stderr)  # legacy accounting warning
        comparison = report["comparisons"][0]
        self.assertNotIn("udp_loss_percent", comparison["baseline_summary"])
        self.assertNotIn("udp_loss_percent_percent", comparison["changes_percent"])
        self.assertTrue(any("Legacy UDP loss" in warning for warning in report["warnings"]))

    def test_build_mode_rejects_mixed_builds_within_arm(self):
        base_a = result("upload", "0", "off", 100)
        base_b = result("upload", "0", "off", 110)
        base_b["tayga_sha256"] = "binary-other"
        candidate = result("upload", "0", "tcp", 120)
        self.write(self.base, "upload-a", base_a)
        self.write(self.base, "upload-b", base_b)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool("--mode", "build")
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertTrue(any("mixed build identities" in warning for warning in report["warnings"]))

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
        self.assertTrue(any("complete treatment" in warning for warning in report["warnings"]))

    def test_different_receiver_drain_not_pooled(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "tcp", 120)
        base["receiver_drain_seconds"] = 0.5
        candidate["receiver_drain_seconds"] = 1.0
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(report["comparisons"])
        self.assertTrue(any("no matching" in warning for warning in report["warnings"]))

    def test_legacy_capture_without_receiver_drain_defaults_to_zero(self):
        base = result("upload", "0", "off", 100)
        candidate = result("upload", "0", "off", 100)
        # candidate explicitly has receiver_drain_seconds = 0.0, base omits it (legacy)
        candidate["receiver_drain_seconds"] = 0.0
        self.write(self.base, "upload", base)
        self.write(self.candidate, "upload", candidate)
        run = self.run_tool()
        report = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(report["comparisons"]), 1)
        self.assertEqual(report["comparisons"][0]["workload"]["receiver_drain_seconds"], 0.0)


if __name__ == "__main__":
    unittest.main()
