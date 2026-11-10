#!/usr/bin/env python3
"""Offline checks of scripts/ci/openwrt_feed.py: Ed25519, usign framing, index parsing."""
import base64
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('openwrt_feed', ROOT / 'scripts/ci/openwrt_feed.py')
feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)

# RFC 8032 section 7.1, test vectors 1 and 2.
VECTORS = [
    ('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b'
     'd25bf5f0595bbe24655141438e7a100b'),
    ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c'
     '387b2eaeb4302aeeb00d291612bb0c00'),
]


def usign_text(kind, keynum, payload):
    return f'untrusted comment: test\n{base64.b64encode(b"Ed" + keynum + payload).decode()}\n'


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors_verify(self):
        for public, message, signature in VECTORS:
            self.assertTrue(feed.ed25519_verify(bytes.fromhex(public), bytes.fromhex(message),
                                                bytes.fromhex(signature)))

    def test_tampering_is_rejected(self):
        public, message, signature = (bytes.fromhex(v) for v in VECTORS[1])
        self.assertFalse(feed.ed25519_verify(public, message + b'x', signature))
        broken = bytearray(signature)
        broken[10] ^= 1
        self.assertFalse(feed.ed25519_verify(public, message, bytes(broken)))
        self.assertFalse(feed.ed25519_verify(public, message, signature[:63]))
        # s >= group order must be refused (signature malleability)
        malleable = signature[:32] + (int.from_bytes(signature[32:], 'little') + feed.L).to_bytes(32, 'little')
        self.assertFalse(feed.ed25519_verify(public, message, malleable))


class UsignTests(unittest.TestCase):
    def test_usign_framing_and_key_binding(self):
        public, message, signature = (bytes.fromhex(v) for v in VECTORS[1])
        key = b'\x01' * 8
        pub_text = usign_text('pub', key, public)
        self.assertTrue(feed.usign_verify(pub_text, message, usign_text('sig', key, signature)))
        # a signature made by a different key number is never accepted
        self.assertFalse(feed.usign_verify(pub_text, message, usign_text('sig', b'\x02' * 8, signature)))
        with self.assertRaises(ValueError):
            feed.usign_verify(pub_text, message, 'untrusted comment: x\nnot base64!!\n')

    def test_repository_key_is_a_valid_usign_key_with_matching_name(self):
        path = ROOT / 'scripts/ci/openwrt-keys/d310c6f2833e97f7'
        blob = feed._usign_blob(path.read_text())
        self.assertEqual(blob[:2], b'Ed')
        self.assertEqual(len(blob), 42)
        self.assertEqual(blob[2:10].hex(), path.name)


class IndexTests(unittest.TestCase):
    INDEX = ('Package: coreutils\nVersion: 9.6-r1\nFilename: coreutils_9.6-r1_x.ipk\nSHA256sum: aa\n\n'
             'Package: coreutils\nVersion: 9.7-r1\nFilename: coreutils_9.7-r1_x.ipk\nSHA256sum: bb\n'
             'Description: text\n second line\n\n'
             'Package: flock\nVersion: 2.40.2-r1\nFilename: flock.ipk\nSHA256sum: cc\n')

    def test_version_selects_the_entry(self):
        self.assertEqual(feed.select_package(self.INDEX, 'coreutils', '9.6-r1')['SHA256sum'], 'aa')
        self.assertEqual(feed.select_package(self.INDEX, 'coreutils', '9.7-r1')['SHA256sum'], 'bb')
        self.assertEqual(feed.select_package(self.INDEX, 'flock')['Filename'], 'flock.ipk')

    def test_missing_package_or_version_fails(self):
        with self.assertRaises(SystemExit):
            feed.select_package(self.INDEX, 'coreutils', '1.0')
        with self.assertRaises(SystemExit):
            feed.select_package(self.INDEX, 'nothing')


if __name__ == '__main__':
    unittest.main()
