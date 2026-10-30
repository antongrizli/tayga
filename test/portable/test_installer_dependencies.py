"""Distribution package selection without modifying the host package database."""
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'packaging/installer/dependencies.sh'


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.release = self.root / 'os-release'
        self.log = self.root / 'log'
        for name in ('apk', 'opkg', 'apt-get', 'dnf', 'yum', 'rpm', 'dpkg-query'):
            path = self.bin / name
            path.write_text('#!/bin/sh\necho "$0 $*" >> "$TEST_LOG"\nexit "${TEST_MANAGER_RESULT:-0}"\n')
            path.chmod(0o755)
        (self.bin / 'ip').write_text('#!/bin/sh\nexit 1\n')
        (self.bin / 'ip').chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'TAYGA_TESTING': '1', 'TAYGA_TEST_OS_RELEASE': str(self.release), 'TEST_LOG': str(self.log)}

    def run_helper(self, distro, action='check', mode='nat64', build='no', **env):
        self.release.write_text('ID="' + distro + '"\n')
        return subprocess.run(['sh', str(HELPER), action, mode, 'nft', 'no', 'keep', build, 'validate'],
                              env={**self.env, **env}, capture_output=True, text=True)

    def test_check_selects_family_packages_without_installation(self):
        for distro, manager, package in (('debian', 'apt-get', 'iproute2'), ('alpine', 'apk', 'iproute2'),
                                         ('rocky', 'dnf', 'iproute')):
            result = self.run_helper(distro)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Dependency manager: ' + manager, result.stdout)
            self.assertIn(package, result.stdout)
            self.assertFalse(self.log.exists())

    def test_binary_only_does_not_require_network_packages(self):
        result = self.run_helper('debian', mode='binary-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('iproute', result.stdout)
        self.assertFalse(self.log.exists())

    def test_failed_cache_update_stops_before_install_and_never_upgrades(self):
        result = self.run_helper('debian', action='install', TEST_MANAGER_RESULT='1')
        # Skip on non-root hosts: installation must refuse before invoking apt.
        if os.geteuid() == 0:
            self.assertIn('apt-get update', self.log.read_text())
            self.assertNotIn('install', self.log.read_text())
        else:
            self.assertIn('requires root', result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_openwrt_and_unknown_distribution_fail_closed(self):
        for distro in ('openwrt', 'unknown'):
            result = self.run_helper(distro, action='install')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.log.exists())

    def test_openwrt_binary_only_selects_apk_or_opkg_without_alpine_dependencies(self):
        for manager in ('apk', 'opkg'):
            result = self.run_helper('openwrt', mode='binary-only')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Distribution: OpenWrt', result.stdout)
            self.assertIn('Dependency manager: ' + manager, result.stdout)
            self.assertFalse(self.log.exists())
            if manager == 'apk':
                (self.bin / 'apk').unlink()

    def test_source_fallback_selects_static_build_dependencies(self):
        result = self.run_helper('rocky', build='yes', TEST_MANAGER_RESULT='1')
        self.assertNotEqual(result.returncode, 0)
        for package in ('gcc', 'make', 'kernel-headers', 'glibc-static'):
            self.assertIn(package, result.stdout)
        self.assertNotIn(' install ', self.log.read_text())
        self.assertNotIn(' upgrade', self.log.read_text())

    def test_openwrt_installs_only_coreutils_install_and_rechecks(self):
        self.release.write_text('ID=openwrt\n')
        for manager in ('apk', 'opkg'):
            minimal = self.root / ('minimal-' + manager)
            minimal.mkdir()
            for name in ('sh', 'awk'):
                (minimal / name).symlink_to(shutil.which(name))
            (minimal / 'id').write_text('#!/bin/sh\necho 0\n')
            (minimal / 'id').chmod(0o755)
            tool = minimal / manager
            tool.write_text('#!/bin/sh\necho "$*" >> "$TEST_LOG"\ncase "$1" in add|install) /bin/ln -s /usr/bin/true "$TEST_BIN/install";; esac\n')
            tool.chmod(0o755)
            result = subprocess.run(['/bin/sh', str(HELPER), 'install', 'binary-only', 'nft', 'no', 'keep', 'no', 'validate'],
                                    env={**self.env, 'PATH': str(minimal), 'TEST_BIN': str(minimal)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Dependencies satisfied', result.stdout)
            commands = self.log.read_text().splitlines()
            self.assertEqual(commands, ['add coreutils-install'] if manager == 'apk' else ['update', 'install coreutils-install'])
            self.log.unlink()
