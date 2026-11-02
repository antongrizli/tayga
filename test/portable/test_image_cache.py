"""Shared image cache integrity and offline reuse; no network required."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('image_cache', ROOT / 'scripts/ci/cache-test-image.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class ImageCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'existing-image'
        self.source.write_bytes(b'pinned operating system image')
        self.sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.cache = self.root / 'cache'

    def test_import_then_reuse_offline_without_source_or_download(self):
        path = cache.cached_image(self.cache, self.sha, source=self.source, offline=True)
        self.source.unlink()
        with patch.object(cache.urllib.request, 'urlopen', side_effect=AssertionError('network used')):
            self.assertEqual(cache.cached_image(self.cache, self.sha, offline=True), path)

    def test_verified_https_download_is_published_once(self):
        import io
        response = io.BytesIO(self.source.read_bytes())
        response.geturl = lambda: 'https://example.invalid/image'
        with patch.object(cache.urllib.request, 'urlopen', return_value=response) as fetch:
            path = cache.cached_image(self.cache, self.sha, url='https://example.invalid/image')
            self.assertEqual(cache.cached_image(self.cache, self.sha, offline=True), path)
            self.assertEqual(fetch.call_count, 1)
        self.assertEqual(path.read_bytes(), self.source.read_bytes())

    def test_invalid_import_never_publishes_or_leaves_partial_file(self):
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            cache.cached_image(self.cache, 'a' * 64, source=self.source)
        self.assertEqual([p.name for p in (self.cache / 'sha256' / ('a' * 64)).iterdir()], ['lock'])

    def test_corrupt_cache_is_not_silently_reused(self):
        path = cache.cached_image(self.cache, self.sha, source=self.source)
        path.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'Corrupt cached image'):
            cache.cached_image(self.cache, self.sha, offline=True)

    def test_offline_miss_never_attempts_download(self):
        with patch.object(cache.urllib.request, 'urlopen', side_effect=AssertionError('network used')):
            with self.assertRaisesRegex(ValueError, 'not cached'):
                cache.cached_image(self.cache, self.sha, url='https://example.invalid/image', offline=True)

    def test_digest_cannot_escape_cache_directory(self):
        with self.assertRaises(ValueError):
            cache.cached_image(self.cache, '../image', source=self.source)
