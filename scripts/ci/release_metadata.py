#!/usr/bin/env python3
"""Resolve a prepared release tag to one immutable source commit without writes."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

NUMBER = r'(?:0|[1-9][0-9]*)'
VERSION = re.compile(rf'{NUMBER}\.{NUMBER}\.{NUMBER}(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?')


def normalize_tag(tag):
    version = tag
    for prefix in ('version-', 'version', 'v'):
        if tag.startswith(prefix):
            version = tag[len(prefix):]
            break
    match = VERSION.fullmatch(version)
    if not match or len(tag) > 128:
        raise ValueError('expected an existing release tag: v1.2.3, version-1.2.3, version1.2.3 or 1.2.3')
    prerelease = match.group(1)
    if prerelease and any(p.isdigit() and len(p) > 1 and p.startswith('0') for p in prerelease.split('.')):
        raise ValueError('numeric prerelease identifiers must not have leading zeros')
    return version


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def resolve(root, tag, repository, expected_sha=None):
    version = normalize_tag(tag)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid owner/repository')
    sha = git(root, 'rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}')
    if expected_sha and sha != expected_sha:
        raise ValueError('release tag does not point to the triggering commit')
    actual = git(root, 'show', f'{sha}:VERSION')
    if actual != version:
        raise ValueError(f'tag version {version} differs from committed VERSION {actual!r}; prepare it before tagging')
    changelog = git(root, 'show', f'{sha}:CHANGELOG.md')
    match = re.search(rf'^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})\s*\n(.*?)(?=^## |\Z)', changelog, re.M | re.S)
    if not match or not match.group(2).strip():
        raise ValueError('tagged CHANGELOG.md needs dated, nonempty notes for this version')
    from datetime import date
    date.fromisoformat(match.group(1))
    return {'tag': tag, 'version': version, 'sha': sha, 'repository': repository.lower(),
            'prerelease': '-' in version}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, default=Path('release-source.json'))
    args = parser.parse_args()
    event = os.environ.get('GITHUB_EVENT_NAME')
    if event == 'workflow_dispatch':
        tag = os.environ.get('RELEASE_TAG', '')
        expected = None
    elif event == 'push' and os.environ.get('GITHUB_REF_TYPE') == 'tag':
        tag = os.environ.get('GITHUB_REF_NAME', '')
        # Annotated tags are peeled explicitly, as is the triggering ref.
        expected = git(args.root, 'rev-parse', f"{os.environ['GITHUB_SHA']}^{{commit}}")
    else:
        parser.error('only a release tag push or an explicit manual tag is supported')
    try:
        data = resolve(args.root, tag, os.environ['GITHUB_REPOSITORY'], expected)
    except (ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(data, indent=2) + '\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            for key, value in data.items():
                output.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')
    print(json.dumps(data))


if __name__ == '__main__':
    main()
