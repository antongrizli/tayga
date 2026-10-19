#!/usr/bin/env python3
"""Promote saved, verified images to GHCR; never compile or rebuild images."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from release_artifacts import ARCHES, PROFILES, checksums, run, sha256
from release_metadata import normalize_tag


def publish(directory):
    manifest = json.loads((directory / 'release-manifest.json').read_text())
    source = manifest['source']
    if normalize_tag(source['tag']) != source['version']:
        raise ValueError('tag/version mismatch')
    if source['prerelease'] != ('-' in source['version']):
        raise ValueError('prerelease metadata mismatch')
    if source['sha'] != os.environ['RELEASE_SHA']:
        raise ValueError('publication source mismatch')
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
    checksums(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    publish(args.directory)


if __name__ == '__main__':
    main()
