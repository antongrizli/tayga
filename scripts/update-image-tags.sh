#!/usr/bin/env bash
# Update container image tags and release URLs in MikroTik RouterOS scripts
set -euo pipefail

TAG="${1:-}"
REPO="${2:-antongrizli/tayga}"
TARGET_DIR="${3:-scripts/mikrotik}"

if [ -z "$TAG" ]; then
  echo "Usage: $0 <version-tag> [repo] [target-directory]" >&2
  echo "Example: $0 0.9.12 antongrizli/tayga scripts/mikrotik" >&2
  exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
  echo "ERROR: Target directory '$TARGET_DIR' does not exist." >&2
  exit 1
fi

echo "--> Updating image tags and release URLs in '$TARGET_DIR' to tag '${TAG}' (Repo: '${REPO}')..."

python3 -c "
import os, sys, re

tag = sys.argv[1]
repo = sys.argv[2]
target_dir = sys.argv[3]

for fname in os.listdir(target_dir):
    fpath = os.path.join(target_dir, fname)
    if not (fname.endswith('.rsc') or fname.endswith('.md')):
        continue
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Pin CLAT image to release version
    content = re.sub(r'ghcr\.io/[^/\s\"\']+/tayga-clat:[a-zA-Z0-9._-]+', f'ghcr.io/{repo}-clat:{tag}', content)

    # Pin NAT64 image to release version
    content = re.sub(r'ghcr\.io/[^/\s\"\']+/tayga-nat64:[a-zA-Z0-9._-]+', f'ghcr.io/{repo}-nat64:{tag}', content)

    # Pin unified base image to release version
    content = re.sub(r'ghcr\.io/[^/\s\"\']+/tayga:[a-zA-Z0-9._-]+', f'ghcr.io/{repo}:{tag}', content)

    # Pin helper script fetch URLs to release version
    content = re.sub(r'https://github\.com/[^/\s\"\']+/tayga/releases/download/[^/\s\"\']+', f'https://github.com/{repo}/releases/download/{tag}', content)

    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(content)
" "$TAG" "$REPO" "$TARGET_DIR"

echo "--> Updated scripts in '$TARGET_DIR' successfully."
