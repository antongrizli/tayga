"""Required release inventory must not silently shrink when an output is lost."""
import importlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/ci'))
platforms = importlib.import_module('release_platforms')


class ReleaseInventoryTests(unittest.TestCase):
    def setUp(self):
        self.native = {arch: {'artifacts': {
            f'tayga-managed-test-{arch}.{fmt}': 'digest'
            for fmt in platforms.NATIVE_FORMATS}}
            for arch in platforms.LINUX_ARCHES}

    def test_every_required_member_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = platforms.required_assets(self.native)
            for name in names:
                (root / name).touch()
            platforms.verify_assets(root, self.native)
            for name in sorted(names):
                with self.subTest(missing=name):
                    (root / name).unlink()
                    with self.assertRaisesRegex(ValueError, 'missing required assets'):
                        platforms.verify_assets(root, self.native)
                    (root / name).touch()

    def test_unplanned_file_cannot_enter_the_signed_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in platforms.required_assets(self.native):
                (root / name).touch()
            (root / 'unplanned-release-file.txt').touch()
            with self.assertRaisesRegex(ValueError, 'unexpected assets'):
                platforms.verify_assets(root, self.native)

    def test_missing_architecture_and_native_format_fail(self):
        for arch in platforms.LINUX_ARCHES:
            with self.subTest(arch=arch):
                subset = dict(self.native)
                del subset[arch]
                with self.assertRaisesRegex(ValueError, 'Missing native package manifest'):
                    platforms.required_assets(subset)
            for fmt in platforms.NATIVE_FORMATS:
                with self.subTest(arch=arch, fmt=fmt):
                    subset = {a: {'artifacts': dict(m['artifacts'])} for a, m in self.native.items()}
                    del subset[arch]['artifacts'][f'tayga-managed-test-{arch}.{fmt}']
                    with self.assertRaisesRegex(ValueError, 'Missing native format'):
                        platforms.required_assets(subset)

    def test_duplicate_native_format_is_not_an_extra_release_asset(self):
        arch = platforms.LINUX_ARCHES[0]
        self.native[arch]['artifacts']['second-package.deb'] = 'digest'
        with self.assertRaisesRegex(ValueError, 'exactly one native package per format'):
            platforms.required_assets(self.native)

    def test_pending_targets_are_not_enabled(self):
        self.assertFalse(set(platforms.LINUX_ARCHES) & set(platforms.CONTRACT['pending_linux']))
        self.assertEqual(set(platforms.NATIVE_FORMATS), {'deb', 'rpm', 'apk'})
