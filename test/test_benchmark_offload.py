#!/usr/bin/env python3
"""Validate effective-mode identity used by real benchmark captures."""
import ast
import copy
from pathlib import Path
import unittest

script = (Path(__file__).resolve().parents[1] / 'benchmark-clat.sh').read_text()
start = script.index('def negotiated_offload_mode(')
end = script.index('\neffective_offload =', start)
namespace = {}
exec(compile(ast.parse(script[start:end]), 'benchmark offload negotiation', 'exec'), namespace)
verify = namespace['negotiated_offload_mode']


def state(mode='udp', requested='auto', header=10):
    return dict(offload_effective=mode, offload_mode=requested,
                offload_flags={'off': 0, 'tcp': 7, 'udp': 103}[mode],
                udp_offload_available=mode == 'udp', vnet_hdr_sz=header,
                offload_negotiation_complete=True)


class OffloadCaptureTests(unittest.TestCase):
    def test_auto_records_udp_and_supported_fallbacks(self):
        for mode in ('udp', 'tcp', 'off'):
            s = state(mode)
            self.assertEqual(verify([s, s], 'auto'), mode)

    def test_explicit_modes_and_disabled_vnet_framing(self):
        for mode in ('udp', 'tcp', 'off'):
            for header in ((10, 12) if mode != 'off' else (0, 10, 12)):
                s = state(mode, mode, header)
                self.assertEqual(verify([s, s], mode), mode)

    def test_missing_or_inconsistent_capabilities_invalidate_capture(self):
        base = state()
        for key in base:
            bad = copy.deepcopy(base)
            del bad[key]
            with self.assertRaises((ValueError, KeyError)):
                verify([base, bad], 'auto')
        for key, value in [('offload_flags', 7), ('udp_offload_available', False),
                           ('offload_negotiation_complete', 1), ('vnet_hdr_sz', 14),
                           ('offload_mode', 'udp'), ('offload_effective', 'tcp')]:
            bad = dict(base, **{key: value})
            with self.assertRaises(ValueError):
                verify([base, bad], 'auto')

    def test_explicit_mode_cannot_silently_fall_back(self):
        for requested in ('tcp', 'udp'):
            s = state('off', requested)
            with self.assertRaises(ValueError):
                verify([s, s], requested)

    def test_feature_support_does_not_require_observed_udp_aggregation(self):
        # Workloads with ordinary scalar UDP are valid on a capable device.
        s = dict(state(), gso={'udp_rx_aggregates': 0})
        self.assertEqual(verify([s, s], 'auto'), 'udp')


if __name__ == '__main__':
    unittest.main()
