"""Shared source discovery, identity and result-file helpers (stdlib only)."""
import hashlib
import json
import os
from pathlib import Path


def repo_root(start=None):
    path = Path(start or __file__).resolve()
    for candidate in (path, *path.parents):
        if (candidate / 'Makefile').is_file() and (candidate / 'src').is_dir():
            return candidate
    raise FileNotFoundError(f'cannot locate TAYGA source root from {path}')


def results_root():
    state = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state')))
    return Path(os.environ.get('PERF_SESSION_ROOT', str(state / 'tayga/perf-sessions')))


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def benchmark_source(path):
    """Read the executable source including explicitly sourced CLAT libraries."""
    path = Path(path)
    text = path.read_text()
    for name in ('netns', 'offload', 'collect', 'iperf'):
        marker = f'. "$BENCH_LIB_DIR/{name}.sh"'
        if marker in text:
            text = text.replace(marker, (path.parent / 'lib' / f'{name}.sh').read_text())
    return text
