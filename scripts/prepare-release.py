#!/usr/bin/env python3
"""Prepare VERSION and dated changelog notes for review before committing/tagging."""
import argparse
from datetime import date
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    args = parser.parse_args()
    version = args.version.removeprefix('v')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version):
        parser.error('expected a version such as 0.9.14 or 0.9.14-rc.1')
    root = Path(__file__).resolve().parents[1]
    changelog = root / 'CHANGELOG.md'
    text = changelog.read_text()
    if f'## [{version}]' in text:
        parser.error('version already has a changelog entry')
    marker = '## [Unreleased]\n'
    if marker not in text:
        parser.error('CHANGELOG.md needs an Unreleased section')
    notes = text.split(marker, 1)[1].split('\n## ', 1)[0].strip()
    if not notes:
        parser.error('add Unreleased notes before preparing a release')
    text = text.replace(marker, f'{marker}\n## [{version}] - {date.today().isoformat()}\n', 1)
    changelog.write_text(text)
    (root / 'VERSION').write_text(version + '\n')
    print(f'Prepared {version}: review VERSION and CHANGELOG.md before committing and tagging.')


if __name__ == '__main__':
    main()
