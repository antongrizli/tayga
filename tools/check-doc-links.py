#!/usr/bin/env python3
"""Offline Markdown target existence check; no dependency on external sites."""
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '*.md'], text=True).splitlines()
errors = []
for name in tracked:
    source = root / name
    if not source.is_file():
        continue
    text = re.sub(r'```.*?```', '', source.read_text(), flags=re.S)
    for match in re.finditer(r'!?\[[^\]\n]*\]\(([^\)\n]+)\)', text):
        target = match[1].split(' "', 1)[0].strip('<>')
        parsed = urlsplit(target)
        if parsed.scheme == 'file' or target.startswith('/Users/'):
            errors.append(f'{name}: nonportable local target {target}')
        elif parsed.scheme or not parsed.path:
            continue
        elif not (source.parent / unquote(parsed.path)).exists():
            errors.append(f'{name}: missing {target}')
for error in errors:
    print(error)
print(f'Checked {len(tracked)} Markdown files; {len(errors)} errors')
raise SystemExit(bool(errors))
