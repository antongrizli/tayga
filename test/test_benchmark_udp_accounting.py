#!/usr/bin/env python3
"""Exercise the exact accounting function embedded in the deployed harness."""
import ast
import os
import json
import tempfile
import subprocess
from pathlib import Path
import unittest

script = (Path(__file__).resolve().parents[1] / "benchmark-clat.sh").read_text()
start = script.index("def udp_packet_accounting(")
end = script.index("\nfor path in sorted(", start)
namespace = {}
exec(compile(ast.parse(script[start:end]), "benchmark UDP accounting", "exec"), namespace)
account = namespace["udp_packet_accounting"]


class UdpAccountingTests(unittest.TestCase):
    def test_loss_is_already_in_expected_count(self):
        result = account({"packets": 1000}, {"packets": 990, "lost_packets": 90, "bytes": 900 * 1200}, 1200)
        self.assertEqual(result, dict(packets=900, receiver_expected_packets=990,
                                      lost_packets=90, sent_packets=1000))
        self.assertAlmostEqual(100 * result["lost_packets"] / result["receiver_expected_packets"], 9.090909, places=5)

    def test_actual_receipts_come_from_bytes_even_with_duplicates(self):
        result = account({}, {"packets": 100, "lost_packets": 0, "bytes": 101 * 64}, 64)
        self.assertEqual(result["packets"], 101)
        self.assertIsNone(result["sent_packets"])

    def test_missing_or_impossible_counters_are_rejected(self):
        for received in ({"packets": 10, "lost_packets": 11, "bytes": 0},
                         {"packets": -1, "lost_packets": 0, "bytes": 0},
                         {"packets": 10, "lost_packets": 0, "bytes": 63},
                         {"packets": float("nan"), "lost_packets": 0, "bytes": 0}):
            with self.assertRaises(ValueError):
                account({}, received, 64)


class UdpCounterTests(unittest.TestCase):
    def test_ipv4_fields_and_no_double_count(self):
        parse = namespace["parse_udp_snmp"]
        delta = namespace["udp_snmp_delta"]
        before = parse("Udp: InDatagrams InErrors RcvbufErrors\nUdp: 10 2 2\n")
        after = parse("Udp: InDatagrams InErrors RcvbufErrors\nUdp: 15 5 5\n")
        self.assertEqual(delta(before, after), {"UdpInDatagrams": 5, "UdpInErrors": 3, "UdpRcvbufErrors": 3})

    def test_ipv6_and_missing_fields(self):
        parse = namespace["parse_udp_snmp"]
        self.assertEqual(parse("Ip6InReceives 100\nUdp6InErrors 3\n", True), {"Udp6InErrors": 3})
        self.assertEqual(parse("Ip: InReceives\nIp: 1\n"), {})
        with self.assertRaises(ValueError):
            parse("Udp: InErrors RcvbufErrors\nUdp: 1\n")

    def test_reset_and_changed_fields_are_not_zero(self):
        delta = namespace["udp_snmp_delta"]
        for before, after in (({}, {}), ({"UdpInErrors": 2}, {"UdpInErrors": 1}),
                              ({"UdpInErrors": 0}, {"UdpSndbufErrors": 0})):
            with self.assertRaises(ValueError):
                delta(before, after)


class TreatmentValidationTests(unittest.TestCase):
    def test_invalid_treatments_exit_before_topology_setup(self):
        harness = Path(__file__).resolve().parents[1] / "benchmark-clat.sh"
        for config in ({"PERF_SCOPE": "invalid"}, {"FQ_RATE": "."}, {"FQ_RATE": "1MM"},
                       {"FQ_RATE": "750M", "SENDER_FQ": "off"},
                       {"SENDER_FQ_FLOW_LIMIT": "0"}, {"SENDER_FQ_FLOW_LIMIT": "10001"},
                       {"PACING_TIMER_US": "0"}, {"SOCKET_BUFFER_BYTES": "-1"},
                       {"PROTOCOL": "udp", "BLOCK_SIZE": "64", "DATAGRAM_SIZE": "1200"}):
            env = dict(os.environ, FQ_RATE="0", PACING_TIMER_US="1000", SENDER_FQ="off",
                       SOCKET_BUFFER_BYTES="0", PROTOCOL="tcp", BLOCK_SIZE="", DATAGRAM_SIZE="1200")
            env.update(config)
            result = subprocess.run(["sh", str(harness)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 64, result.stderr.decode())


class QdiscCounterTests(unittest.TestCase):
    def row(self, **updates):
        row = dict(dev="lan0", handle="1:", kind="fq", root=True, options={"flow_limit": 100},
                   bytes=1000, packets=10, drops=2, overlimits=0, requeues=0, backlog=0, qlen=0)
        row.update(updates)
        return row

    def test_each_qdisc_keeps_its_own_counters(self):
        delta = namespace["qdisc_counter_delta"]([self.row()], [self.row(bytes=2000, packets=20, drops=5)])
        self.assertEqual(delta[0]["counters"]["drops"], 3)
        self.assertEqual(delta[0]["options"], {"flow_limit": 100})

    def test_reset_missing_and_changed_qdiscs_are_rejected(self):
        for after in ([], [self.row(drops=0)], [self.row(handle="2:")],
                      [self.row(kind="fq_codel")], [self.row(options={"flow_limit": 1000})]):
            with self.assertRaises(ValueError):
                namespace["qdisc_counter_delta"]([self.row()], after)


class UdpReconciliationTests(unittest.TestCase):
    def test_trailing_loss_is_visible_even_with_no_sequence_gap(self):
        result = namespace["udp_delivery_reconciliation"]([dict(sent_packets=1000, packets=990, receiver_expected_packets=990)])
        self.assertFalse(result["udp_delivery_accounting_match"])
        self.assertEqual(result["udp_sender_unobserved_tail_packets"], 10)
        self.assertEqual(result["udp_sender_receiver_gap_percent"], 1)

    def test_opposite_flow_gaps_do_not_cancel(self):
        result = namespace["udp_delivery_reconciliation"]([
            dict(sent_packets=1000, packets=990, receiver_expected_packets=990),
            dict(sent_packets=1000, packets=1010, receiver_expected_packets=1000)])
        self.assertEqual(result["udp_sender_receiver_packet_gap"], 0)
        self.assertFalse(result["udp_delivery_accounting_match"])
        self.assertEqual(result["udp_sender_receiver_gap_percent"], 1)

    def test_missing_and_exact_counts(self):
        reconcile = namespace["udp_delivery_reconciliation"]
        self.assertIsNone(reconcile([dict(sent_packets=None)])["udp_sender_receiver_gap_percent"])
        self.assertTrue(reconcile([dict(sent_packets=100, packets=100, receiver_expected_packets=100)])["udp_delivery_accounting_match"])


class BufferCleanupTests(unittest.TestCase):
    def run_failure(self, fail_raise):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "limits.json"
            original = {"net.core.rmem_max": 212992, "net.core.wmem_max": 212992}
            state.write_text(json.dumps(original))
            (root / "ip").write_text("#!/bin/sh\ncase \"$1 $2\" in \"link add\") exit 1;; *) exit 0;; esac\n")
            (root / "sysctl").write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
path = Path(os.environ['FAKE_LIMITS'])
values = json.loads(path.read_text())
if sys.argv[1] == '-n':
    print('\\n'.join(str(values[key]) for key in sys.argv[2:]))
else:
    for argument in sys.argv[2:]:
        key, value = argument.split('=')
        if os.environ['FAIL_RAISE'] == 'yes' and key == 'net.core.wmem_max' and int(value) > 212992:
            sys.exit(1)
        values[key] = int(value)
        path.write_text(json.dumps(values))
""")
            for name in ("ip", "sysctl"):
                (root / name).chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       FAKE_LIMITS=str(state), FAIL_RAISE=fail_raise,
                       SOCKET_BUFFER_BYTES="2097152", ARTIFACT_DIR=str(root / "artifacts"),
                       BENCHMARK_LOCK_DIR=str(root / "lock"), PERF_SCOPE="process",
                       FQ_RATE="0", SENDER_FQ="off", SENDER_FQ_FLOW_LIMIT="100", PROTOCOL="tcp",
                       PACING_TIMER_US="1000", SOCKET_SAMPLE_INTERVAL="0", BLOCK_SIZE="")
            harness = Path(__file__).resolve().parents[1] / "benchmark-clat.sh"
            run = subprocess.run(["sh", str(harness)], env=env, capture_output=True)
            self.assertEqual(run.returncode, 1, run.stderr.decode())
            self.assertEqual(json.loads(state.read_text()), original)
            self.assertFalse((root / "lock").exists())

    def test_topology_failure_restores_limits(self):
        self.run_failure("no")

    def test_partial_limit_change_restores_limits(self):
        self.run_failure("yes")


class ThreadCounterTests(unittest.TestCase):
    def snapshot(self, time_ns, ticks):
        return dict(pid=10, monotonic_ns=time_ns, clock_ticks=100, threads=[
            dict(tid=11, start_ticks=1, comm="tayga", cpu_ticks=ticks,
                 voluntary_context_switches=ticks, involuntary_context_switches=0,
                 migrations=0, scheduler_running_ns=None, runqueue_wait_ns=None)])

    def test_cpu_time_and_unavailable_optional_counters(self):
        result = namespace["thread_counter_deltas"](self.snapshot(0, 100), self.snapshot(10**9, 150))
        self.assertEqual(result["threads"][0]["cpu_cores"], 0.5)
        self.assertIsNone(result["threads"][0]["runqueue_wait_ns"])
        self.assertFalse(result["threads"][0]["main_thread"])

    def test_reset_and_reused_threads_are_rejected(self):
        before = self.snapshot(0, 100)
        for after in (self.snapshot(0, 150), self.snapshot(10**9, 50),
                      dict(self.snapshot(10**9, 150), threads=[])):
            with self.assertRaises(ValueError):
                namespace["thread_counter_deltas"](before, after)
        after = self.snapshot(10**9, 150)
        after["threads"][0]["start_ticks"] = 2
        with self.assertRaises(ValueError):
            namespace["thread_counter_deltas"](before, after)


if __name__ == "__main__":
    unittest.main()
