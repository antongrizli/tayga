import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[2] / 'packaging/installer/tayga-managed.openrc'


class OpenRcTemplateTests(unittest.TestCase):
    def setUp(self):
        self.text = TEMPLATE.read_text()

    def test_translator_is_respawned_with_a_bounded_budget(self):
        for line in ('supervisor=supervise-daemon', 'respawn_delay=2',
                     'respawn_max=5', 'respawn_period=120'):
            self.assertIn(line, self.text)
        self.assertNotIn('command_background', self.text)

    def test_stale_network_state_is_cleared_before_start(self):
        pre = self.text.split('start_pre()', 1)[1].split('start_post()', 1)[0]
        self.assertLess(pre.index('tayga-net-ctl down'), pre.index('tayga-net-ctl up'))

    def test_failed_verification_stops_through_the_supervisor(self):
        self.assertIn('supervise-daemon "$RC_SVCNAME" --stop', self.text)
        self.assertNotIn('start-stop-daemon', self.text)


if __name__ == '__main__':
    unittest.main()
