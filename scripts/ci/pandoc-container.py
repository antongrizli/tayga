#!/usr/bin/env python3
"""Render a man page with a pinned Pandoc and a minimal disposable input mount."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

IMAGE = 'pandoc/core:3.6.4@sha256:5b8a29d9b70d5d8ca766e5d1dcfc41916b23ab79276a80527be70516110f4c1e'
args = sys.argv[1:]
base = ['docker', 'run', '--rm', '--network', 'none']
if args == ['--version']:
    raise SystemExit(subprocess.call([*base, IMAGE, *args]))
index = args.index('-o')
source, destination = Path(args[index - 1]), Path(args[index + 1])
with tempfile.TemporaryDirectory(prefix='tayga-man-render-') as directory:
    work = Path(directory)
    shutil.copyfile(source, work / 'source.md')
    args[index - 1], args[index + 1] = '/data/source.md', '/data/result.man'
    subprocess.run([*base, '-v', f'{work}:/data', IMAGE, *args], check=True)
    shutil.copyfile(work / 'result.man', destination)
