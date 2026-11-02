#!/usr/bin/env python3
"""Promote saved, verified images to GHCR; never compile or rebuild images."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from release_artifacts import PROFILES, run, sha256
from release_platforms import CONTAINER_ARCHES as ARCHES, CONTRACT, required_signed_assets
from release_metadata import normalize_tag


def verify_production_preflight(directory, manifest, allow_unsigned=False):
    sha_file = directory / 'SHA256SUMS'
    sig_file = directory / 'SHA256SUMS.minisig'
    pubkey = os.environ.get('MINISIGN_PUBKEY')
    pubkey_file = os.environ.get('MINISIGN_PUBKEY_FILE')
    minisign_bin = shutil.which('minisign')

    if not sha_file.is_file():
        if not allow_unsigned:
            raise ValueError('Release SHA256SUMS is required for production publication')
        return

    if not allow_unsigned:
        if not sig_file.is_file():
            raise ValueError('Release signature SHA256SUMS.minisig is required for production publication')
        if not minisign_bin:
            raise ValueError('Minisign binary is required for production publication')
        if not pubkey and not (pubkey_file and Path(pubkey_file).is_file()):
            raise ValueError('Trusted Minisign public key (MINISIGN_PUBKEY or MINISIGN_PUBKEY_FILE) is required for production publication')

    if sig_file.is_file() and (pubkey or (pubkey_file and Path(pubkey_file).is_file())) and minisign_bin:
        cmd = [minisign_bin, '-V', '-m', str(sha_file), '-x', str(sig_file)]
        if pubkey_file and Path(pubkey_file).is_file():
            cmd.extend(['-p', str(pubkey_file)])
        else:
            cmd.extend(['-P', pubkey])
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode != 0:
            err = res.stderr.decode(errors='replace').strip()
            raise ValueError(f'Minisign cryptographic verification failed: {err}')
    elif not allow_unsigned:
        raise ValueError('Production publication requires a verified Minisign signature')

    # Verify integrity of all release artifacts listed in SHA256SUMS
    listed_files = {}
    for line in sha_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f'Malformed SHA256SUMS entry: {line}')
        expected_sha, name = parts[0].strip(), parts[1].strip()
        if (Path(name).name != name or name in listed_files
                or not re.fullmatch(r'[0-9a-f]{64}', expected_sha)):
            raise ValueError('Invalid or duplicate SHA256SUMS entry')
        target_path = directory / name
        if not target_path.is_file():
            raise ValueError(f'Release artifact missing: {name}')
        if sha256(target_path) != expected_sha:
            raise ValueError(f'Release artifact checksum mismatch: {name}')
        listed_files[name] = expected_sha

    # Mandatory signed manifest and complete archive bundle validation
    if 'release-manifest.json' not in listed_files:
        raise ValueError('release-manifest.json must be included in signed SHA256SUMS')

    if not isinstance(manifest, dict) or 'architectures' not in manifest:
        raise ValueError('release-manifest.json has invalid structure')

    for arch in ARCHES:
        if arch not in manifest['architectures']:
            raise ValueError(f'manifest missing required architecture: {arch}')
        evidence = manifest['architectures'][arch]
        if 'images' not in evidence:
            raise ValueError(f'manifest missing images for architecture: {arch}')
        for profile in PROFILES:
            if profile not in evidence['images']:
                raise ValueError(f'manifest missing image profile {profile} for {arch}')
            image = evidence['images'][profile]
            archive = image.get('archive')
            if not archive:
                raise ValueError(f'manifest image {profile} for {arch} has no archive')
            if archive not in listed_files:
                raise ValueError(f'Required release archive {archive} must be included in signed SHA256SUMS')

    if 'platform_contract' in manifest and manifest['platform_contract'] != CONTRACT:
        raise ValueError('Release platform contract mismatch')

    if not allow_unsigned:
        missing = required_signed_assets(manifest) - set(listed_files)
        if missing:
            raise ValueError(f'Required release assets missing from signed SHA256SUMS: {sorted(missing)}')


def publish(directory, allow_unsigned=False):
    allow_unsigned = allow_unsigned or (os.environ.get('ALLOW_UNSIGNED_RELEASE', '').lower() in ('1', 'true', 'yes'))
    manifest_file = directory / 'release-manifest.json'
    if not manifest_file.is_file():
        raise ValueError('release-manifest.json is missing')
    manifest = json.loads(manifest_file.read_text())
    source = manifest['source']
    if source.get('candidate_only'):
        raise ValueError('Candidate-only bundles must never be published')
    if normalize_tag(source['tag']) != source['version']:
        raise ValueError('tag/version mismatch')
    if source['prerelease'] != ('-' in source['version']):
        raise ValueError('prerelease metadata mismatch')
    if source['sha'] != os.environ.get('RELEASE_SHA'):
        raise ValueError('publication source mismatch')

    # Production preflight: verify SHA256SUMS, minisig signature and artifact checksums BEFORE touching docker or registry
    verify_production_preflight(directory, manifest, allow_unsigned=allow_unsigned)
    # All archive hashes and IDs must pass before the first registry write.
    for arch in ARCHES:
        evidence = manifest['architectures'][arch]
        if evidence['source'] != source or evidence['arch'] != arch:
            raise ValueError('mixed release sources')
        for profile in PROFILES:
            image = evidence['images'][profile]
            archive = directory / image['archive']
            if sha256(archive) != evidence['files'][image['archive']]:
                raise ValueError(f'archive hash mismatch: {archive}')
            subprocess.run(['docker', 'load', '-i', str(archive)], check=True)
            if run('docker', 'image', 'inspect', '--format', '{{.Id}}', image['reference']) != image['id']:
                raise ValueError('saved image ID differs from tested image')
    registry = f"ghcr.io/{source['repository']}"
    # Unique run tags stage the tested images; public version/latest aliases come later.
    run_id = os.environ['GITHUB_RUN_ID']
    attempt = os.environ['GITHUB_RUN_ATTEMPT']
    if not run_id.isdigit() or not attempt.isdigit():
        raise ValueError('invalid workflow run identity')
    evidence = {'source': source, 'profiles': {}}
    (directory / 'published-images.json').write_text(json.dumps(evidence, indent=2) + '\n')
    for profile in PROFILES:
        repo = registry + ('' if profile == 'production' else '-' + profile)
        images = []
        for arch in ARCHES:
            image = manifest['architectures'][arch]['images'][profile]
            ref = f"{repo}:candidate-{source['sha']}-{run_id}-{attempt}-{arch}"
            subprocess.run(['docker', 'tag', image['id'], ref], check=True)
            subprocess.run(['docker', 'push', ref], check=True)
            digest = run('docker', 'buildx', 'imagetools', 'inspect', ref, '--format', '{{.Manifest.Digest}}')
            if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
                raise ValueError('invalid registry digest')
            images.append(f'{repo}@{digest}')
        candidate = f"{repo}:candidate-{source['sha']}-{run_id}-{attempt}"
        subprocess.run(['docker', 'buildx', 'imagetools', 'create', '-t', candidate, *images], check=True)
        digest = run('docker', 'buildx', 'imagetools', 'inspect', candidate, '--format', '{{.Manifest.Digest}}')
        if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid manifest-list digest')
        evidence['profiles'][profile] = {'digest': digest, 'repository': repo, 'platform_images': images}
        (directory / 'published-images.json').write_text(json.dumps(evidence, indent=2) + '\n')
    def assign(image, tag):
        target = image['repository'] + ':' + tag
        subprocess.run(['docker', 'buildx', 'imagetools', 'create', '-t', target,
                        image['repository'] + '@' + image['digest']], check=True)
        actual = run('docker', 'buildx', 'imagetools', 'inspect', target, '--format', '{{.Manifest.Digest}}')
        if actual != image['digest']:
            raise ValueError(f'promoted alias digest mismatch: {target}')

    # Every profile/platform is staged before any version or latest alias is changed.
    for image in evidence['profiles'].values():
        tags = sorted({source['tag'], source['version']})
        for tag in tags:
            assign(image, tag)
    if not source['prerelease']:
        for image in evidence['profiles'].values():
            assign(image, 'latest')

    # Record publication evidence digest without invalidating immutable signed release checksums
    (directory / 'published-images.json.sha256').write_text(
        f"{sha256(directory / 'published-images.json')}  published-images.json\n")

    # Verify that publication did not alter or corrupt any signed release artifacts
    sha_file = directory / 'SHA256SUMS'
    if sha_file.is_file():
        for line in sha_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                expected_sha = parts[0].strip()
                name = parts[1].strip()
                target_path = directory / name
                if not target_path.is_file():
                    raise ValueError(f'Signed release artifact missing after publication: {name}')
                if sha256(target_path) != expected_sha:
                    raise ValueError(f'Signed release artifact checksum mismatch after publication: {name}')

    sig_file = directory / 'SHA256SUMS.minisig'
    pubkey = os.environ.get('MINISIGN_PUBKEY')
    pubkey_file = os.environ.get('MINISIGN_PUBKEY_FILE')
    if sig_file.is_file() and shutil.which('minisign'):
        if pubkey_file and Path(pubkey_file).is_file():
            subprocess.run(['minisign', '-V', '-p', pubkey_file, '-m', str(sha_file), '-x', str(sig_file)], check=True)
        elif pubkey:
            subprocess.run(['minisign', '-V', '-P', pubkey, '-m', str(sha_file), '-x', str(sig_file)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--allow-unsigned', action='store_true',
                        help='Allow publishing unsigned releases (test/staging only)')
    parser.add_argument('--verify-only', action='store_true',
                        help='Verify the production signature/inventory without Docker or registry writes')
    args = parser.parse_args()
    if args.verify_only:
        if args.allow_unsigned:
            parser.error('--verify-only requires a signed production bundle')
        manifest = json.loads((args.directory / 'release-manifest.json').read_text())
        source = manifest['source']
        if normalize_tag(source['tag']) != source['version']:
            raise ValueError('tag/version mismatch')
        if source['prerelease'] != ('-' in source['version']):
            raise ValueError('prerelease metadata mismatch')
        if source['sha'] != os.environ.get('RELEASE_SHA'):
            raise ValueError('verification source mismatch')
        # Intentionally ignore ALLOW_UNSIGNED_RELEASE for this read-only gate.
        verify_production_preflight(args.directory, manifest, allow_unsigned=False)
        label = 'unpublished candidate' if source.get('candidate_only') else 'production release bundle'
        print(f'PASS: signed {label}; no publication performed')
    else:
        publish(args.directory, allow_unsigned=args.allow_unsigned)


if __name__ == '__main__':
    main()
