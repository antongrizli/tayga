#!/usr/bin/env python3
"""Exercise the exact accounting function embedded in the deployed harness."""
import ast
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


if __name__ == "__main__":
    unittest.main()
