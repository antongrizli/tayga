import subprocess
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[2] / 'packaging/installer/freebsd-rc.in'


class FreeBsdRcTemplateTests(unittest.TestCase):
    def setUp(self):
        self.text = TEMPLATE.read_text()

    def test_syntax(self):
        subprocess.run(['sh', '-n', str(TEMPLATE)], check=True)

    def test_supervisor_restarts_the_runner(self):
        self.assertIn('-r -R 3 -P ${pidfile}', self.text)
        self.assertIn('procname="/usr/sbin/daemon"', self.text)
        self.assertIn('onerunner', self.text)

    def test_runner_rebuilds_network_before_each_start_and_is_bounded(self):
        run = self.text.split('tayga_runner() {', 1)[1]
        self.assertLess(run.index('"$net" down'), run.index('"$net" up'))
        self.assertLess(run.index('"$net" up'), run.index('exec /usr/local/sbin/pref64-discover'))
        self.assertIn('-ge 5', run)
        self.assertIn('kill -TERM "$PPID"', run)

    def test_start_pre_does_not_bring_the_network_up(self):
        pre = self.text.split('tayga_start_pre() {', 1)[1].split('tayga_start_post()', 1)[0]
        self.assertNotIn('tayga-net-ctl up', pre)

    def test_explicit_start_resets_restart_budget(self):
        pre = self.text.split('tayga_start_pre() {', 1)[1].split('tayga_start_post()', 1)[0]
        self.assertIn('/starts"', pre)
        self.assertIn('rm -f', pre)

    def test_status_never_signals_the_daemon_supervisor(self):
        ctl = (TEMPLATE.parent / 'tayga-ctl.sh').read_text()
        self.assertIn('pgrep -P', ctl)
        self.assertNotIn('kill -USR2 "$(cat', ctl)


if __name__ == '__main__':
    unittest.main()
