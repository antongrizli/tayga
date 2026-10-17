#!/usr/bin/env python3
"""Exercise build outputs and dependencies in a private build directory."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='tayga-build-check-') as directory:
    build = Path(directory) / 'build'
    base = ['make', '-C', str(root), f'BUILDDIR={build}', 'VERSION=build-check']
    def make(*args):
        subprocess.run([*base, *args], check=True)
    make('pref64-discover')
    assert (build / 'pref64-discover').is_file()
    make()  # The default goal must really build the daemon.
    binary = build / 'tayga'
    assert binary.is_file() and (root / 'tayga').is_file()
    obj = build / 'obj/nat64.o'
    original = obj.stat().st_mtime_ns
    make()
    assert obj.stat().st_mtime_ns == original, 'unchanged build recompiled'
    # Touch only a private header copy via include search order; do not mutate source.
    header = root / 'src/tayga.h'
    deps = (build / 'obj/nat64.d').read_text()
    assert 'src/tayga.h' in deps, 'missing header dependency'
    # Force a header newer through make's -W, without changing source timestamps.
    make('-W', str(header.relative_to(root)))
    assert obj.stat().st_mtime_ns != original, 'header change did not recompile'
    make('static')
    result = subprocess.check_output(['file', str(binary)], text=True)
    assert 'statically linked' in result, result
    make('LDFLAGS=')
    result = subprocess.check_output(['file', str(binary)], text=True)
    assert 'dynamically linked' in result, result
    make('CC=clang', 'CFLAGS=-O1 -g -fsanitize=address,undefined', 'LDFLAGS=-fsanitize=address,undefined')
    subprocess.run([str(binary), '--help'], check=True, stdout=subprocess.DEVNULL)
print('PASS: default/helper builds, incremental dependencies, static/dynamic and compiler/sanitizer transitions')
