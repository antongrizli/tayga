"""Release identity and fail-closed artifact/publication regressions (no network)."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
metadata = importlib.import_module('release_metadata')
artifacts = importlib.import_module('release_artifacts')
publisher = importlib.import_module('release_publish')


class ReleaseSourceTests(unittest.TestCase):
    def test_tag_formats_and_invalid_input(self):
        for tag in ('1.2.3', 'v1.2.3', 'version1.2.3', 'version-1.2.3'):
            self.assertEqual(metadata.normalize_tag(tag), '1.2.3')
        self.assertEqual(metadata.normalize_tag('v1.2.3-rc.1'), '1.2.3-rc.1')
        for tag in ('', 'main', 'v', '1.2', '01.2.3', 'v1.2.3-01', 'v1.2.3+meta',
                    'v1.2.3\nsha=bad', 'v1.2.3;echo bad', 'refs/tags/v1.2.3', '-1.2.3'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                metadata.normalize_tag(tag)

    def test_existing_tag_resolves_its_commit_not_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return metadata.git(root, *args)
            git('init', '-q')
            git('config', 'user.name', 'Release Test')
            git('config', 'user.email', 'test@example.invalid')
            (root / 'VERSION').write_text('1.2.3\n')
            (root / 'CHANGELOG.md').write_text('## [1.2.3] - 2026-10-19\n\nRelease fix.\n')
            git('add', '.')
            git('commit', '-qm', 'prepared')
            first = git('rev-parse', 'HEAD')
            git('tag', '-a', 'version-1.2.3', '-m', 'release')
            (root / 'VERSION').write_text('9.9.9\n')
            git('add', '.')
            git('commit', '-qm', 'later main')
            result = metadata.resolve(root, 'version-1.2.3', 'Owner/Repo')
            self.assertEqual(result['sha'], first)
            self.assertEqual(result['repository'], 'owner/repo')
            self.assertEqual((root / 'VERSION').read_text(), '9.9.9\n')
            with self.assertRaises(ValueError):
                metadata.resolve(root, 'version-1.2.3', 'Owner/Repo', git('rev-parse', 'HEAD'))
            with self.assertRaises(subprocess.CalledProcessError):
                metadata.resolve(root, 'v1.2.3', 'Owner/Repo')
            git('tag', 'v1.2.4', first)
            with self.assertRaises(ValueError):
                metadata.resolve(root, 'v1.2.4', 'Owner/Repo')
            git('tag', 'v9.9.9')
            with self.assertRaises(ValueError):
                metadata.resolve(root, 'v9.9.9', 'Owner/Repo')


class ReleaseArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = {'tag': 'version-1.2.3', 'version': '1.2.3', 'sha': 'a' * 40,
                       'repository': 'owner/repo', 'prerelease': False}
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.manifests = {}
        for arch in artifacts.ARCHES:
            directory = self.inputs / f'candidate-{arch}'
            directory.mkdir()
            names = [artifacts.archive_name(p, arch) for p in artifacts.PROFILES] + [
                f'tayga-linux-{arch}', f'pref64-discover-linux-{arch}', 'binary-help.txt', 'install-files.txt']
            for name in names:
                (directory / name).write_text(name)
            manifest = {'source': self.source, 'arch': arch,
                        'files': {n: artifacts.sha256(directory / n) for n in names},
                        'images': {p: {'archive': artifacts.archive_name(p, arch),
                                      'reference': f'tayga-release-{p}:{arch}',
                                      'id': 'sha256:' + 'b' * 64, 'smoke': 'pass'} for p in artifacts.PROFILES}}
            self.manifests[arch] = manifest
            (directory / 'manifest.json').write_text(json.dumps(manifest))

    def test_missing_corrupt_or_mixed_artifacts_rejected(self):
        directory = self.inputs / 'candidate-arm64'
        artifacts.verify(directory, 'arm64', self.source)
        binary = directory / 'tayga-linux-arm64'
        binary.write_text('corrupt')
        with self.assertRaises(ValueError):
            artifacts.verify(directory, 'arm64', self.source)
        binary.unlink()
        with self.assertRaises(FileNotFoundError):
            artifacts.verify(directory, 'arm64', self.source)
        with self.assertRaises(ValueError):
            artifacts.verify(directory, 'arm64', {**self.source, 'sha': 'c' * 40})

    def test_assemble_pins_scripts_and_hashes_all_assets(self):
        (self.root / 'deploy').mkdir()
        # Real scripts are exercised, including repository names other than the original fork.
        import shutil
        shutil.copytree(ROOT / 'deploy/mikrotik', self.root / 'deploy/mikrotik')
        shutil.copytree(ROOT / 'scripts', self.root / 'scripts')
        (self.root / 'CHANGELOG.md').write_text('## [1.2.3] - 2026-10-19\n\nA release fix.\n')
        output = self.root / 'assets'
        artifacts.assemble(self.root, self.inputs, output, self.source)
        self.assertIn('ghcr.io/owner/repo-clat:version-1.2.3',
                      (output / 'routeros-install-clat.rsc').read_text())
        self.assertIn('A release fix.', (output / 'release-notes.md').read_text())
        self.assertIn('release-manifest.json', (output / 'SHA256SUMS').read_text())
        with self.assertRaises(ValueError):
            artifacts.assemble(self.root, self.inputs, output, self.source)

    def publication_fixture(self):
        directory = self.root / 'publish'
        directory.mkdir()
        import shutil
        for arch in artifacts.ARCHES:
            for profile in artifacts.PROFILES:
                name = artifacts.archive_name(profile, arch)
                shutil.copy2(self.inputs / f'candidate-{arch}' / name, directory / name)
        (directory / 'release-manifest.json').write_text(json.dumps(
            {'source': self.source, 'architectures': self.manifests}))
        return directory

    def test_corrupt_last_archive_prevents_every_registry_write(self):
        directory = self.publication_fixture()
        (directory / 'tayga-nat64-armv7.tar').write_text('corrupt')
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha']}), \
                patch.object(publisher.subprocess, 'run') as calls, \
                patch.object(publisher, 'run', return_value='sha256:' + 'b' * 64):
            with self.assertRaises(ValueError):
                publisher.publish(directory)
        self.assertTrue(all(call.args[0][1] == 'load' for call in calls.call_args_list))

    def test_last_image_id_mismatch_prevents_every_registry_write(self):
        directory = self.publication_fixture()
        outputs = ['sha256:' + 'b' * 64] * 8 + ['sha256:' + 'd' * 64]
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha']}), \
                patch.object(publisher.subprocess, 'run') as calls, \
                patch.object(publisher, 'run', side_effect=outputs):
            with self.assertRaisesRegex(ValueError, 'saved image ID'):
                publisher.publish(directory)
        self.assertTrue(all(call.args[0][1] == 'load' for call in calls.call_args_list))

    def test_alias_digest_mismatch_stops_before_latest(self):
        directory = self.publication_fixture()
        def output(*args):
            if args[1:3] == ('image', 'inspect'):
                return 'sha256:' + 'b' * 64
            return 'sha256:' + ('c' if ':candidate-' in args[4] else 'd') * 64
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'GITHUB_RUN_ID': '123',
                                     'GITHUB_RUN_ATTEMPT': '2'}), \
                patch.object(publisher.subprocess, 'run') as calls, \
                patch.object(publisher, 'run', side_effect=output):
            with self.assertRaisesRegex(ValueError, 'promoted alias digest mismatch'):
                publisher.publish(directory)
        self.assertFalse(any(':latest' in arg for call in calls.call_args_list for arg in call.args[0]))

    def test_all_images_staged_before_aliases_and_prerelease_keeps_latest(self):
        for prerelease in (False, True):
            with self.subTest(prerelease=prerelease):
                directory = self.publication_fixture() if not prerelease else self.root / 'publish'
                if prerelease:
                    self.source.update(tag='v1.2.3-rc.1', version='1.2.3-rc.1', prerelease=True)
                    (directory / 'release-manifest.json').write_text(json.dumps(
                        {'source': self.source, 'architectures': self.manifests}))
                def output(*args):
                    if args[1:3] == ('image', 'inspect'):
                        return 'sha256:' + 'b' * 64
                    return 'sha256:' + 'c' * 64
                with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'GITHUB_RUN_ID': '123',
                                             'GITHUB_RUN_ATTEMPT': '2'}), \
                        patch.object(publisher.subprocess, 'run') as calls, \
                        patch.object(publisher, 'run', side_effect=output):
                    publisher.publish(directory)
                commands = [c.args[0] for c in calls.call_args_list]
                pushes = [i for i, c in enumerate(commands) if c[1] == 'push']
                aliases = [i for i, c in enumerate(commands) if 'imagetools' in c and
                           ':candidate-' not in c[c.index('-t') + 1]]
                self.assertEqual(len(pushes), 9)
                self.assertLess(max(pushes), min(aliases))
                self.assertEqual(any(':latest' in arg for c in commands for arg in c), not prerelease)
                self.assertFalse(any('build' in c for c in commands))


if __name__ == '__main__':
    unittest.main()
