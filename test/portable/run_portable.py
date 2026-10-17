#!/usr/bin/env python3
"""Explicit portable suite; do not discover integration modules with side effects."""
import sys
from pathlib import Path
import unittest

TOPDIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(TOPDIR / 'bench/tests'))
sys.path.insert(0, str(TOPDIR / 'bench'))

MODULES = (
    "test_affinity_study", "test_benchmark_offload", "test_benchmark_udp_accounting",
    "test_compare_perf_sessions", "test_recovery_acceptance", "test_iperf_server_logs", "test_tcp_flow_study",
    "test_tcp_worker_study", "test_tun_steering_study", "test_udp_batch_study",
    "test_udp_batch_summary", "test_udp_common_stop", "test_udp_envelope_study",
    "test_lima_retention", "test_benchmark_cleanup", "test_udp_batch_endpoint",
    "test_udp_drain_guard", "test_iperf_start_gate", "test_iperf_read_diagnostic",
    "test_protocols_compatibility",
)
if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(MODULES))
    raise SystemExit(not result.wasSuccessful())
