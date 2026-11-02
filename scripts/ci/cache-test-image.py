#!/usr/bin/env python3
"""Fetch or import pinned test images into a shared, verified host cache."""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import urllib.request


def default_cache():
    if os.environ.get('TAYGA_TEST_CACHE'):
        return Path(os.environ['TAYGA_TEST_CACHE'])
    base = os.environ.get('XDG_CACHE_HOME')
    if not base:
        base = Path.home() / ('Library/Caches' if sys.platform == 'darwin' else '.cache')
    return Path(base) / 'tayga-tests' / 'images'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def cached_image(cache, sha256, source=None, url=None, offline=False):
    if len(sha256) != 64 or any(c not in '0123456789abcdef' for c in sha256):
        raise ValueError('A lowercase SHA256 digest is required')
    directory = Path(cache) / 'sha256' / sha256
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / 'image'
    # Keep the lock inode: concurrent import/download must never publish a
    # partially written image or change the inode being locked.
    with (directory / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if destination.exists():
            if digest(destination) != sha256:
                raise ValueError(f'Corrupt cached image: {destination}')
            return destination
        if source is None and (offline or not url):
            raise ValueError('Image is not cached; provide --source or permit HTTPS download')
        if source is None and not url.startswith('https://'):
            raise ValueError('Only HTTPS downloads are permitted')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
                temporary = Path(output.name)
                if source is not None:
                    with Path(source).open('rb') as stream:
                        shutil.copyfileobj(stream, output)
                else:
                    with urllib.request.urlopen(url, timeout=60) as stream:
                        if not stream.geturl().startswith('https://'):
                            raise ValueError('Image download redirected outside HTTPS')
                        shutil.copyfileobj(stream, output)
                output.flush()
                os.fsync(output.fileno())
            if digest(temporary) != sha256:
                raise ValueError('Image SHA256 mismatch; nothing published')
            temporary.replace(destination)
            return destination
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache-dir', type=Path, default=default_cache())
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--source', type=Path, help='Import an existing download without network access')
    parser.add_argument('--url', help='Pinned upstream HTTPS image URL')
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    print(cached_image(args.cache_dir, args.sha256, args.source, args.url, args.offline))


if __name__ == '__main__':
    main()
