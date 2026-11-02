"""Release identity and fail-closed artifact/publication regressions (no network)."""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'bench/tests'))
from test_package_metadata import package_bytes
sys.path.insert(0, str(ROOT / 'scripts/ci'))
metadata = importlib.import_module('release_metadata')
artifacts = importlib.import_module('release_artifacts')
publisher = importlib.import_module('release_publish')


def openwrt_candidates(inputs, source):
    from release_platforms import CONTRACT
    from openwrt_release import ROLES
    for spec in CONTRACT['openwrt']:
        directory = inputs / f'candidate-openwrt-{spec["release"]}'
        directory.mkdir()
        packages = {}
        for role in ROLES:
            name = f'openwrt-{spec["release"]}-armsr-armv8-{role}.{spec["format"]}'
            from test_openwrt_release import ipk_bytes
            (directory / name).write_bytes(ipk_bytes(role, source['version']) if spec['format'] == 'ipk' else b'ADBdpackage-fixture')
            package_name = 'tayga-managed-openwrt' + {'base': '', 'upgrader': '-upgrade'}.get(role, '-' + role)
            packages[role] = {'name': name, 'sha256': artifacts.sha256(directory / name),
                              'identity': [package_name, source['version'] + '-r1', 'aarch64_generic']}
        (directory / 'manifest.json').write_text(json.dumps(
            {'source': source, 'platform': spec, 'packages': packages,
             'sdk_source': {'version': source['version'], 'target': 'armsr',
                            'subtarget': 'armv8', 'architecture': 'aarch64_generic'}}))


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


class CandidateSourceTests(unittest.TestCase):
    def test_candidate_resolves_committed_version_without_creating_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return metadata.git(root, *args)
            git('init', '-q'); git('config', 'user.name', 'Candidate Test')
            git('config', 'user.email', 'test@example.invalid')
            (root / 'VERSION').write_text('0.9.14\n')
            git('add', '.'); git('commit', '-qm', 'candidate source')
            first = git('rev-parse', 'HEAD')
            (root / 'VERSION').write_text('0.9.15\n')
            git('add', '.'); git('commit', '-qm', 'later source')
            result = metadata.resolve_candidate(root, first, 'Owner/Repo')
            self.assertEqual(result['sha'], first)
            self.assertEqual(result['version'], '0.9.14')
            self.assertTrue(result['candidate_only'])
            self.assertEqual(result['repository'], 'owner/repo')
            self.assertEqual(git('tag', '--list'), '')
            self.assertEqual((root / 'VERSION').read_text(), '0.9.15\n')
            for invalid in ('main', 'HEAD', first[:12], first.upper(), '--help'):
                with self.subTest(ref=invalid), self.assertRaises(ValueError):
                    metadata.resolve_candidate(root, invalid, 'owner/repo')


    def test_candidate_mode_does_not_relax_production_release_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return metadata.git(root, *args)
            git('init', '-q'); git('config', 'user.name', 'Candidate Test')
            git('config', 'user.email', 'test@example.invalid')
            (root / 'VERSION').write_text('0.9.14\n')
            (root / 'CHANGELOG.md').write_text('# Unreleased draft\n')
            git('add', '.'); git('commit', '-qm', 'unprepared source')
            sha = git('rev-parse', 'HEAD'); git('tag', 'v0.9.14')
            self.assertTrue(metadata.resolve_candidate(root, sha, 'owner/repo')['candidate_only'])
            with self.assertRaisesRegex(ValueError, 'dated, nonempty notes'):
                metadata.resolve(root, 'v0.9.14', 'owner/repo')

    def test_candidate_override_is_rejected_for_tag_push(self):
        import contextlib
        import io
        with patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'push', 'CANDIDATE_ONLY': 'true'}), \
                patch.object(sys, 'argv', ['metadata']), patch.object(metadata, 'git') as execute:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                metadata.main()
            execute.assert_not_called()


class ReleaseArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = {'tag': 'version-1.2.3', 'version': '1.2.3', 'sha': 'a' * 40,
                       'repository': 'owner/repo', 'prerelease': False}
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        openwrt_candidates(self.inputs, self.source)
        self.manifests = {}
        for arch in artifacts.ARCHES:
            directory = self.inputs / f'candidate-{arch}'
            directory.mkdir()
            profiles = artifacts.PROFILES if arch in artifacts.CONTAINER_ARCHES else ()
            names = [artifacts.archive_name(p, arch) for p in profiles] + [
                f'tayga-linux-{arch}', f'pref64-discover-linux-{arch}', 'binary-help.txt', 'install-files.txt']
            for name in names:
                (directory / name).write_text(name)
            manifest = {'source': self.source, 'arch': arch,
                        'files': {n: artifacts.sha256(directory / n) for n in names},
                        'images': {p: {'archive': artifacts.archive_name(p, arch),
                                      'reference': f'tayga-release-{p}:{arch}',
                                      'id': 'sha256:' + 'b' * 64, 'smoke': 'pass'} for p in profiles}}
            self.manifests[arch] = manifest
            (directory / 'manifest.json').write_text(json.dumps(manifest))
        for arch in artifacts.FREEBSD_ARCHES:
            directory = self.inputs / f'candidate-freebsd-{arch}'
            directory.mkdir()
            names = [f'tayga-freebsd-{arch}', f'pref64-discover-freebsd-{arch}']
            for name in names:
                (directory / name).write_text(name)
            manifest = {'version': self.source['version'], 'sha': self.source['sha'],
                        'platform': f'freebsd-{arch}', 'smoke': 'pass',
                        'files': {n: artifacts.sha256(directory / n) for n in names}}
            (directory / 'manifest.json').write_text(json.dumps(manifest))

    def test_binary_only_candidate_has_no_container_payload(self):
        for arch in set(artifacts.ARCHES) - set(artifacts.CONTAINER_ARCHES):
            directory = self.inputs / f'candidate-{arch}'
            manifest = artifacts.verify(directory, arch, self.source)
            self.assertEqual(manifest['images'], {})
            binary = directory / f'tayga-linux-{arch}'
            binary.unlink()
            with self.assertRaises(FileNotFoundError):
                artifacts.verify(directory, arch, self.source)

    def test_binary_only_candidate_rejects_unexpected_image(self):
        directory = self.inputs / 'candidate-riscv64'
        manifest = json.loads((directory / 'manifest.json').read_text())
        manifest['images']['production'] = {}
        (directory / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'incomplete artifact set'):
            artifacts.verify(directory, 'riscv64', self.source)

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
        shutil.copytree(ROOT / 'packaging', self.root / 'packaging')
        shutil.copytree(ROOT / 'docs/man', self.root / 'docs/man')
        shutil.copytree(ROOT / 'src', self.root / 'src')
        shutil.copytree(ROOT / 'mk', self.root / 'mk')
        shutil.copy2(ROOT / 'Makefile', self.root / 'Makefile')
        shutil.copy2(ROOT / 'LICENSE', self.root / 'LICENSE')
        (self.root / 'VERSION').write_text('1.2.3\n')
        (self.root / 'CHANGELOG.md').write_text('## [1.2.3] - 2026-10-19\n\nA release fix.\n')
        native_dir = self.inputs / 'candidate-native'
        native_dir.mkdir()
        for arch in artifacts.ARCHES:
            deb_pkg = native_dir / f'tayga-managed_1.2.3-1_{arch}.deb'
            rpm_pkg = native_dir / f'tayga-managed-1.2.3-1.{arch}.rpm'
            apk_pkg = native_dir / f'tayga-managed-1.2.3-r1-{arch}.apk'
            deb_pkg.write_bytes(package_bytes('deb', arch))
            rpm_pkg.write_bytes(package_bytes('rpm', arch))
            apk_pkg.write_bytes(package_bytes('apk', arch))
            artifacts_map = {
                deb_pkg.name: artifacts.sha256(deb_pkg),
                rpm_pkg.name: artifacts.sha256(rpm_pkg),
                apk_pkg.name: artifacts.sha256(apk_pkg),
            }
            manifest = {
                'version': '1.2.3',
                'release': '1',
                'arch': arch,
                'inputs': {
                    'tayga': artifacts.sha256(self.inputs / f'candidate-{arch}' / f'tayga-linux-{arch}'),
                    'pref64-discover': artifacts.sha256(self.inputs / f'candidate-{arch}' / f'pref64-discover-linux-{arch}')
                },
                'artifacts': artifacts_map,
                'signed': False,
                'source_commit': self.source['sha']
            }
            (native_dir / f'tayga-managed-1.2.3-1-{arch}.json').write_text(json.dumps(manifest))
        output = self.root / 'assets'
        artifacts.assemble(self.root, self.inputs, output, self.source)
        self.assertIn('ghcr.io/owner/repo-clat:version-1.2.3',
                      (output / 'routeros-install-clat.rsc').read_text())
        self.assertIn('A release fix.', (output / 'release-notes.md').read_text())
        self.assertIn('release-manifest.json', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-installer-linux-universal.sh', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-installer-universal.sh', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-installer-freebsd-amd64.sh', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-installer-freebsd-arm64.sh', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-managed_1.2.3-1_amd64.deb', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-managed-1.2.3-1.amd64.rpm', (output / 'SHA256SUMS').read_text())
        self.assertIn('tayga-managed-1.2.3-r1-amd64.apk', (output / 'SHA256SUMS').read_text())
        with self.assertRaises(ValueError):
            artifacts.assemble(self.root, self.inputs, output, self.source)

        if not shutil.which('minisign'):
            self.skipTest('minisign required for signed assembly roundtrip')
        key = self.root / 'bundle.key'; public = self.root / 'bundle.pub'
        subprocess.run(['minisign', '-G', '-W', '-s', str(key), '-p', str(public)],
                       check=True, capture_output=True)
        environment = {**os.environ, 'MINISIGN_KEY_FILE': str(key),
                       'MINISIGN_PUBKEY_FILE': str(public), 'MINISIGN_PASSWORD': '',
                       'RELEASE_SHA': self.source['sha']}
        with patch.dict(os.environ, environment):
            artifacts.sign_manifest(output, require_signature=True)
        command = [sys.executable, str(ROOT / 'scripts/ci/release_publish.py'), str(output), '--verify-only']
        # A real subprocess exercises the public CLI; Docker must never be needed.
        subprocess.run(command, env=environment, check=True, capture_output=True)
        signed_manifest = json.loads((output / 'release-manifest.json').read_text())
        expected = publisher.required_signed_assets(signed_manifest) | {'SHA256SUMS', 'SHA256SUMS.minisig'}
        self.assertEqual({path.name for path in output.iterdir()}, expected)
        self.assertEqual(signed_manifest['platform_contract'], importlib.import_module('release_platforms').CONTRACT)
        targets = ['tayga-installer-linux-armv6.sh', 'pref64-discover-freebsd-arm64',
                   'tayga-managed-1.2.3-r1-s390x.apk']
        bundle = json.loads((output / 'release-manifest.json').read_text())
        targets.append(bundle['openwrt']['25.12.6']['packages']['network']['name'])
        for name in targets:
            with self.subTest(missing_signed_asset=name):
                path = output / name; original = path.read_bytes(); path.unlink()
                result = subprocess.run(command, env=environment, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                path.write_bytes(original)
        # The same real assembler supports unprepared candidate notes and
        # preserves an unpublishable marker through signing and verification.
        candidate_source = {**self.source, 'candidate_only': True}
        for arch in artifacts.ARCHES:
            path = self.inputs / f'candidate-{arch}' / 'manifest.json'
            data = json.loads(path.read_text()); data['source'] = candidate_source
            path.write_text(json.dumps(data))
        (self.root / 'CHANGELOG.md').write_text('# Draft notes only\n')
        candidate_output = self.root / 'candidate-assets'
        with patch.dict(os.environ, environment):
            artifacts.assemble(self.root, self.inputs, candidate_output, candidate_source, require_signature=True)
        candidate_command = [sys.executable, str(ROOT / 'scripts/ci/release_publish.py'), str(candidate_output), '--verify-only']
        subprocess.run(candidate_command, env=environment, check=True, capture_output=True)
        self.assertIn('Unpublished CI candidate', (candidate_output / 'release-notes.md').read_text())
        with patch.object(publisher.subprocess, 'run') as external:
            with self.assertRaisesRegex(ValueError, 'must never be published'):
                publisher.publish(candidate_output, allow_unsigned=True)
            external.assert_not_called()
        # Unsigned environment overrides cannot weaken verify-only mode.
        (output / 'SHA256SUMS.minisig').unlink()
        result = subprocess.run(command, env={**environment, 'ALLOW_UNSIGNED_RELEASE': '1'}, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_assemble_requires_candidate_native_and_complete_packages(self):
        root_dir = self.root / 'test_assembly_req'
        root_dir.mkdir()
        (root_dir / 'deploy').mkdir()
        import shutil
        shutil.copytree(ROOT / 'deploy/mikrotik', root_dir / 'deploy/mikrotik')
        shutil.copytree(ROOT / 'scripts', root_dir / 'scripts')
        shutil.copytree(ROOT / 'packaging', root_dir / 'packaging')
        shutil.copytree(ROOT / 'docs/man', root_dir / 'docs/man')
        shutil.copytree(ROOT / 'src', root_dir / 'src')
        shutil.copytree(ROOT / 'mk', root_dir / 'mk')
        shutil.copy2(ROOT / 'Makefile', root_dir / 'Makefile')
        shutil.copy2(ROOT / 'LICENSE', root_dir / 'LICENSE')
        (root_dir / 'VERSION').write_text('1.2.3\n')
        (root_dir / 'CHANGELOG.md').write_text('## [1.2.3] - 2026-10-19\n\nA release fix.\n')

        inputs_dir = self.root / 'inputs_test_req'
        inputs_dir.mkdir()
        openwrt_candidates(inputs_dir, self.source)
        for arch in artifacts.ARCHES:
            d = inputs_dir / f'candidate-{arch}'
            d.mkdir()
            names = [artifacts.archive_name(p, arch) for p in (artifacts.PROFILES if arch in artifacts.CONTAINER_ARCHES else ())] + [
                f'tayga-linux-{arch}', f'pref64-discover-linux-{arch}', 'binary-help.txt', 'install-files.txt']
            for name in names:
                (d / name).write_text(name)
            m = {'source': self.source, 'arch': arch,
                 'files': {n: artifacts.sha256(d / n) for n in names},
                 'images': {p: {'archive': artifacts.archive_name(p, arch),
                               'reference': f'tayga-release-{p}:{arch}',
                               'id': 'sha256:' + 'b' * 64, 'smoke': 'pass'} for p in (artifacts.PROFILES if arch in artifacts.CONTAINER_ARCHES else ())}}
            (d / 'manifest.json').write_text(json.dumps(m))
        for arch in artifacts.FREEBSD_ARCHES:
            d = inputs_dir / f'candidate-freebsd-{arch}'
            d.mkdir()
            names = [f'tayga-freebsd-{arch}', f'pref64-discover-freebsd-{arch}']
            for name in names:
                (d / name).write_text(name)
            m = {'version': self.source['version'], 'sha': self.source['sha'],
                 'platform': f'freebsd-{arch}', 'smoke': 'pass',
                 'files': {n: artifacts.sha256(d / n) for n in names}}
            (d / 'manifest.json').write_text(json.dumps(m))

        output_dir = self.root / 'assets_req'

        # 1. Missing candidate-native directory
        with self.assertRaisesRegex(ValueError, 'candidate-native directory is required'):
            artifacts.assemble(root_dir, inputs_dir, output_dir, self.source)
        shutil.rmtree(output_dir, ignore_errors=True)

        native_dir = inputs_dir / 'candidate-native'
        native_dir.mkdir()

        # 2. Missing manifest for arch
        with self.assertRaisesRegex(ValueError, 'expected exactly 1 manifest'):
            artifacts.assemble(root_dir, inputs_dir, output_dir, self.source)
        shutil.rmtree(output_dir, ignore_errors=True)

        # 3. Empty artifacts in manifest
        for arch in artifacts.ARCHES:
            manifest = {
                'version': '1.2.3', 'release': '1', 'arch': arch,
                'inputs': {
                    'tayga': artifacts.sha256(inputs_dir / f'candidate-{arch}' / f'tayga-linux-{arch}'),
                    'pref64-discover': artifacts.sha256(inputs_dir / f'candidate-{arch}' / f'pref64-discover-linux-{arch}')
                },
                'artifacts': {}, 'signed': False, 'source_commit': self.source['sha']
            }
            (native_dir / f'tayga-managed-1.2.3-1-{arch}.json').write_text(json.dumps(manifest))

        with self.assertRaisesRegex(ValueError, 'contains no artifacts'):
            artifacts.assemble(root_dir, inputs_dir, output_dir, self.source)
        shutil.rmtree(output_dir, ignore_errors=True)

        # 4. Incomplete formats in manifest (e.g. missing .apk and .rpm)
        for arch in artifacts.ARCHES:
            deb_pkg = native_dir / f'tayga-managed_1.2.3-1_{arch}.deb'
            deb_pkg.write_bytes(package_bytes('deb', arch))
            manifest = {
                'version': '1.2.3', 'release': '1', 'arch': arch,
                'inputs': {
                    'tayga': artifacts.sha256(inputs_dir / f'candidate-{arch}' / f'tayga-linux-{arch}'),
                    'pref64-discover': artifacts.sha256(inputs_dir / f'candidate-{arch}' / f'pref64-discover-linux-{arch}')
                },
                'artifacts': {deb_pkg.name: artifacts.sha256(deb_pkg)},
                'signed': False, 'source_commit': self.source['sha']
            }
            (native_dir / f'tayga-managed-1.2.3-1-{arch}.json').write_text(json.dumps(manifest))

        with self.assertRaisesRegex(ValueError, 'missing formats'):
            artifacts.assemble(root_dir, inputs_dir, output_dir, self.source)

    def test_freebsd_hash_and_source_mismatch_rejected(self):
        directory = self.inputs / 'candidate-freebsd-arm64'
        artifacts.verify_freebsd(directory, 'arm64', self.source)
        with self.assertRaises(ValueError):
            artifacts.verify_freebsd(directory, 'arm64', {**self.source, 'sha': 'f' * 40})
        (directory / 'tayga-freebsd-arm64').write_text('corrupt')
        with self.assertRaises(ValueError):
            artifacts.verify_freebsd(directory, 'arm64', self.source)

    def test_minisign_signing_and_verification(self):
        output = self.root / 'minisign_test'
        output.mkdir()
        (output / 'file1.txt').write_text('content1')
        key_file = self.root / 'test.key'
        key_file.write_text('dummy-key')
        pub_file = self.root / 'test.pub'
        pub_file.write_text('dummy-pub')

        commands = []
        def mock_run(cmd, **kwargs):
            commands.append(cmd)
            if '-S' in cmd:
                (output / 'SHA256SUMS.minisig').write_text('dummy-signature')
            return subprocess.CompletedProcess(cmd, 0)

        with patch('shutil.which', return_value='/usr/bin/minisign'), \
             patch('subprocess.run', side_effect=mock_run), \
             patch.dict(os.environ, {'MINISIGN_KEY_FILE': str(key_file), 'MINISIGN_PASSWORD': 'secret'}):
            artifacts.sign_manifest(output)
            self.assertTrue((output / 'SHA256SUMS').exists())
            self.assertTrue((output / 'SHA256SUMS.minisig').exists())
            self.assertEqual(len(commands), 2)
            self.assertIn('-S', commands[0])
            self.assertIn('-V', commands[1])
            self.assertIn(str(pub_file), commands[1])

    def publication_fixture(self):
        directory = self.root / 'publish'
        directory.mkdir()
        import shutil
        for arch in artifacts.CONTAINER_ARCHES:
            for profile in artifacts.PROFILES:
                name = artifacts.archive_name(profile, arch)
                shutil.copy2(self.inputs / f'candidate-{arch}' / name, directory / name)
        (directory / 'release-manifest.json').write_text(json.dumps(
            {'source': self.source, 'architectures': self.manifests}))
        return directory

    def test_corrupt_last_archive_prevents_every_registry_write(self):
        directory = self.publication_fixture()
        (directory / 'tayga-nat64-armv7.tar').write_text('corrupt')
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'ALLOW_UNSIGNED_RELEASE': 'true'}), \
                patch.object(publisher.subprocess, 'run') as calls, \
                patch.object(publisher, 'run', return_value='sha256:' + 'b' * 64):
            with self.assertRaises(ValueError):
                publisher.publish(directory)
        self.assertTrue(all(call.args[0][1] == 'load' for call in calls.call_args_list))

    def test_last_image_id_mismatch_prevents_every_registry_write(self):
        directory = self.publication_fixture()
        outputs = ['sha256:' + 'b' * 64] * 8 + ['sha256:' + 'd' * 64]
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'ALLOW_UNSIGNED_RELEASE': 'true'}), \
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
                                     'GITHUB_RUN_ATTEMPT': '2', 'ALLOW_UNSIGNED_RELEASE': 'true'}), \
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
                                             'GITHUB_RUN_ATTEMPT': '2', 'ALLOW_UNSIGNED_RELEASE': 'true'}), \
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

    def test_publication_preserves_signed_sha256sums_and_minisig(self):
        directory = self.publication_fixture()
        # Seed SHA256SUMS and SHA256SUMS.minisig before publication
        artifacts.checksums(directory)
        original_sha = (directory / 'SHA256SUMS').read_text()
        (directory / 'SHA256SUMS.minisig').write_text('untrusted comment: test signature\nminisig-blob\n')

        def output(*args):
            if args[1:3] == ('image', 'inspect'):
                return 'sha256:' + 'b' * 64
            return 'sha256:' + 'c' * 64

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'GITHUB_RUN_ID': '123',
                                     'GITHUB_RUN_ATTEMPT': '2', 'ALLOW_UNSIGNED_RELEASE': 'true'}), \
                patch.object(publisher.subprocess, 'run'), \
                patch.object(publisher, 'run', side_effect=output):
            publisher.publish(directory)

        # SHA256SUMS must remain identical and MUST NOT include published-images.json
        self.assertEqual((directory / 'SHA256SUMS').read_text(), original_sha)
        self.assertNotIn('published-images.json', (directory / 'SHA256SUMS').read_text())
        self.assertTrue((directory / 'published-images.json').is_file())
        self.assertTrue((directory / 'published-images.json.sha256').is_file())
        self.assertTrue((directory / 'SHA256SUMS.minisig').is_file())


def is_registry_write(call_args):
    cmd = call_args[0] if isinstance(call_args[0], (list, tuple)) else list(call_args)
    if 'docker' in cmd:
        if 'push' in cmd or ('imagetools' in cmd and 'create' in cmd):
            return True
    return False


class ReleasePublicationPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = {'tag': 'version-1.2.3', 'version': '1.2.3', 'sha': 'a' * 40,
                       'repository': 'owner/repo', 'prerelease': False}
        self.directory = self.root / 'publish'
        self.directory.mkdir()
        self.manifests = {}
        for arch in artifacts.ARCHES:
            names = [artifacts.archive_name(p, arch) for p in (artifacts.PROFILES if arch in artifacts.CONTAINER_ARCHES else ())]
            for name in names:
                (self.directory / name).write_text(name)
            manifest = {'source': self.source, 'arch': arch,
                        'files': {n: artifacts.sha256(self.directory / n) for n in names},
                        'images': {p: {'archive': artifacts.archive_name(p, arch),
                                      'reference': f'tayga-release-{p}:{arch}',
                                      'id': 'sha256:' + 'b' * 64, 'smoke': 'pass'} for p in (artifacts.PROFILES if arch in artifacts.CONTAINER_ARCHES else ())}}
            self.manifests[arch] = manifest
        from release_platforms import CONTRACT, required_assets
        from openwrt_release import ROLES
        native = {arch: {'artifacts': {f'native-{arch}.{fmt}': 'fixture' for fmt in CONTRACT['native_formats']}}
                  for arch in artifacts.ARCHES}
        for name in required_assets(native):
            if not (self.directory / name).exists():
                (self.directory / name).write_text('fixture')
        openwrt = {}
        for spec in CONTRACT['openwrt']:
            packages = {}
            for role in ROLES:
                name = f'openwrt-{spec["release"]}-{role}.{spec["format"]}'
                (self.directory / name).write_text('fixture')
                packages[role] = {'name': name, 'sha256': artifacts.sha256(self.directory / name)}
            openwrt[spec['release']] = {'platform': spec, 'packages': packages}
        (self.directory / 'release-manifest.json').write_text(json.dumps(
            {'source': self.source, 'architectures': self.manifests, 'native': native, 'openwrt': openwrt}))

    def create_keypair(self, name='test'):
        if not shutil.which('minisign'):
            self.skipTest('minisign is not installed')
        key_file = self.root / f'{name}.key'
        pub_file = self.root / f'{name}.pub'
        subprocess.run(['minisign', '-G', '-W', '-p', str(pub_file), '-s', str(key_file)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        pubkey = pub_file.read_text().splitlines()[1].strip()
        return key_file, pub_file, pubkey

    def sign_directory(self, key_file):
        artifacts.checksums(self.directory)
        sha_file = self.directory / 'SHA256SUMS'
        sig_file = self.directory / 'SHA256SUMS.minisig'
        subprocess.run(['minisign', '-S', '-s', str(key_file), '-m', str(sha_file),
                        '-x', str(sig_file), '-t', 'TAYGA Release Verification'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    def test_missing_sha256sums_fails_closed_before_registry_writes(self):
        docker_calls = []
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha']}), \
                patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kw: docker_calls.append(cmd)):
            with self.assertRaisesRegex(ValueError, 'Release SHA256SUMS is required for production publication'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_missing_signature_fails_closed_before_registry_writes(self):
        artifacts.checksums(self.directory)
        docker_calls = []
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha']}), \
                patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kw: docker_calls.append(cmd)):
            with self.assertRaisesRegex(ValueError, 'Release signature SHA256SUMS.minisig is required for production publication'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_missing_minisign_binary_fails_closed_before_registry_writes(self):
        artifacts.checksums(self.directory)
        (self.directory / 'SHA256SUMS.minisig').write_text('dummy-sig')
        docker_calls = []
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha']}), \
                patch('shutil.which', return_value=None), \
                patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kw: docker_calls.append(cmd)):
            with self.assertRaisesRegex(ValueError, 'Minisign binary is required for production publication'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_missing_public_key_fails_closed_before_registry_writes(self):
        artifacts.checksums(self.directory)
        (self.directory / 'SHA256SUMS.minisig').write_text('dummy-sig')
        docker_calls = []
        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha']}), \
                patch('shutil.which', return_value='/usr/bin/minisign'), \
                patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kw: docker_calls.append(cmd)):
            with self.assertRaisesRegex(ValueError, 'Trusted Minisign public key'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_invalid_signature_or_wrong_key_fails_closed_before_registry_writes(self):
        key_a, _, _ = self.create_keypair('key_a')
        _, _, pubkey_b = self.create_keypair('key_b')
        self.sign_directory(key_a)

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'MINISIGN_PUBKEY': pubkey_b}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run):
            with self.assertRaisesRegex(ValueError, 'Minisign cryptographic verification failed'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_tampered_artifact_checksum_fails_closed_before_registry_writes(self):
        key_file, _, pubkey = self.create_keypair('signer')
        self.sign_directory(key_file)

        # Tamper with an archive after signing
        target_archive = self.directory / artifacts.archive_name('production', 'amd64')
        target_archive.write_text('tampered-content')

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'MINISIGN_PUBKEY': pubkey}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run):
            with self.assertRaisesRegex(ValueError, 'Release artifact checksum mismatch'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_missing_artifact_fails_closed_before_registry_writes(self):
        key_file, _, pubkey = self.create_keypair('signer')
        self.sign_directory(key_file)

        # Delete an artifact listed in SHA256SUMS
        target_archive = self.directory / artifacts.archive_name('production', 'amd64')
        target_archive.unlink()

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'MINISIGN_PUBKEY': pubkey}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run):
            with self.assertRaisesRegex(ValueError, 'Release artifact missing'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_sha256sums_omitting_release_manifest_fails_closed_before_registry_writes(self):
        key_file, _, pubkey = self.create_keypair('signer')
        artifacts.checksums(self.directory)
        sha_file = self.directory / 'SHA256SUMS'
        # Omit release-manifest.json from SHA256SUMS
        filtered_lines = [l for l in sha_file.read_text().splitlines() if 'release-manifest.json' not in l]
        sha_file.write_text('\n'.join(filtered_lines) + '\n')
        sig_file = self.directory / 'SHA256SUMS.minisig'
        subprocess.run(['minisign', '-S', '-s', str(key_file), '-m', str(sha_file),
                        '-x', str(sig_file), '-t', 'TAYGA Release Verification'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'MINISIGN_PUBKEY': pubkey}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run):
            with self.assertRaisesRegex(ValueError, 'release-manifest.json must be included in signed SHA256SUMS'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_tampered_release_manifest_fails_closed_before_registry_writes(self):
        key_file, _, pubkey = self.create_keypair('signer')
        self.sign_directory(key_file)

        # Tamper with release-manifest.json after signing
        manifest_data = json.loads((self.directory / 'release-manifest.json').read_text())
        manifest_data['tampered_comment'] = 'attacker_added'
        (self.directory / 'release-manifest.json').write_text(json.dumps(manifest_data, indent=2))

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'MINISIGN_PUBKEY': pubkey}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run):
            with self.assertRaisesRegex(ValueError, 'Release artifact checksum mismatch: release-manifest.json'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_sha256sums_omitting_required_archive_fails_closed_before_registry_writes(self):
        key_file, _, pubkey = self.create_keypair('signer')
        artifacts.checksums(self.directory)
        sha_file = self.directory / 'SHA256SUMS'
        target_name = artifacts.archive_name('production', 'armv7')
        # Omit target_name from SHA256SUMS
        filtered_lines = [l for l in sha_file.read_text().splitlines() if target_name not in l]
        sha_file.write_text('\n'.join(filtered_lines) + '\n')
        sig_file = self.directory / 'SHA256SUMS.minisig'
        subprocess.run(['minisign', '-S', '-s', str(key_file), '-m', str(sha_file),
                        '-x', str(sig_file), '-t', 'TAYGA Release Verification'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'MINISIGN_PUBKEY': pubkey}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run):
            with self.assertRaisesRegex(ValueError, f'Required release archive {target_name} must be included in signed SHA256SUMS'):
                publisher.publish(self.directory)
        self.assertFalse(any(is_registry_write(c) for c in docker_calls))

    def test_signed_list_requires_shell_native_freebsd_and_openwrt_assets(self):
        key_file, _, pubkey = self.create_keypair('inventory')
        targets = ['tayga-installer-linux-riscv64.sh', 'native-s390x.rpm',
                   'pref64-discover-freebsd-arm64', 'openwrt-24.10.8-network.ipk']
        for target in targets:
            with self.subTest(target=target):
                artifacts.checksums(self.directory)
                sums = self.directory / 'SHA256SUMS'
                sums.write_text(''.join(line + '\n' for line in sums.read_text().splitlines()
                                        if line.split(None, 1)[1] != target))
                signature = self.directory / 'SHA256SUMS.minisig'
                signature.unlink(missing_ok=True)
                subprocess.run(['minisign', '-S', '-s', str(key_file), '-m', str(sums),
                                '-x', str(signature)], check=True, capture_output=True)
                with patch.dict(os.environ, {'MINISIGN_PUBKEY': pubkey}):
                    with self.assertRaisesRegex(ValueError, 'missing from signed SHA256SUMS'):
                        publisher.verify_production_preflight(self.directory,
                            json.loads((self.directory / 'release-manifest.json').read_text()))

    def test_real_minisign_roundtrip_production_publication_succeeds(self):
        key_file, _, pubkey = self.create_keypair('signer')
        self.sign_directory(key_file)
        original_sha = (self.directory / 'SHA256SUMS').read_text()
        original_sig = (self.directory / 'SHA256SUMS.minisig').read_text()

        def output(*args):
            if args[1:3] == ('image', 'inspect'):
                return 'sha256:' + 'b' * 64
            return 'sha256:' + 'c' * 64

        docker_calls = []
        orig_run = subprocess.run
        def mock_run(cmd, **kw):
            if cmd[0] == 'docker':
                docker_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)
            return orig_run(cmd, **kw)

        with patch.dict(os.environ, {'RELEASE_SHA': self.source['sha'], 'GITHUB_RUN_ID': '456',
                                     'GITHUB_RUN_ATTEMPT': '1', 'MINISIGN_PUBKEY': pubkey}), \
                patch.object(publisher.subprocess, 'run', side_effect=mock_run), \
                patch.object(publisher, 'run', side_effect=output):
            publisher.publish(self.directory, allow_unsigned=False)

        # Registry writes must have been executed
        self.assertTrue(any(is_registry_write(c) for c in docker_calls))
        # SHA256SUMS and signature must remain identical and valid
        self.assertEqual((self.directory / 'SHA256SUMS').read_text(), original_sha)
        self.assertEqual((self.directory / 'SHA256SUMS.minisig').read_text(), original_sig)
        self.assertNotIn('published-images.json', (self.directory / 'SHA256SUMS').read_text())
        self.assertTrue((self.directory / 'published-images.json').is_file())
        self.assertTrue((self.directory / 'published-images.json.sha256').is_file())


if __name__ == '__main__':
    unittest.main()
