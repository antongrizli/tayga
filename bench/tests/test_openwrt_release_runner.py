"""SDK runner refuses unsafe input before starting/provisioning any environment."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('openwrt_release_runner', ROOT / 'test/system/run-openwrt-release-build.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SdkRunnerPreflightTests(unittest.TestCase):
    def test_next_patch_fixture_has_a_distinct_stable_version(self):
        self.assertEqual(runner.next_patch_version('0.9.14'), '0.9.15')
        self.assertEqual(runner.next_patch_version('1.2.99'), '1.2.100')
        for value in ('v1.2.3', '1.2.3-rc.1', '1.2', '1.2.3+build'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.next_patch_version(value)

    def test_bad_sdk_digest_cannot_start_vm_or_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            sdk = Path(tmp) / 'sdk'; sdk.write_bytes(b'not the pinned SDK')
            output = Path(tmp) / 'output'
            args = ['runner', '--sdk', str(sdk), '--release', '24.10.8', '--output', str(output)]
            with patch.object(sys, 'argv', args), patch.object(runner.subprocess, 'run') as execute:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    runner.main()
                execute.assert_not_called()
            self.assertFalse(output.exists())

    def test_existing_user_vm_is_not_provisioned(self):
        args = ['runner', '--vm', 'tayga-perf', '--sdk', 'unused', '--release', '24.10.8', '--output', 'unused']
        with patch.object(sys, 'argv', args), patch.object(runner.subprocess, 'run') as execute:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.main()
            execute.assert_not_called()
