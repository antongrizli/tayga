#!/bin/sh
set -eu

# Script to build and package minimal ARM64 TAYGA unified image for MikroTik RouterOS
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_VERSION=$(cat "$ROOT_DIR/VERSION" 2>/dev/null | tr -d '\n\r' || echo "latest")
DIST_DIR="$ROOT_DIR/dist"
ARCH="linux/arm64"
IMAGE_TAG="tayga:arm64"
OUTPUT_TAR="$DIST_DIR/tayga-arm64.tar"

mkdir -p "$DIST_DIR"

echo "============================================================"
echo " Building TAYGA Unified Container Image for $ARCH"
echo "============================================================"

# Check for docker or podman
if command -v docker >/dev/null 2>&1; then
  BUILDER="docker"
elif command -v podman >/dev/null 2>&1; then
  BUILDER="podman"
else
  echo "ERROR: Neither docker nor podman found in PATH" >&2
  exit 1
fi

# Check git dirty status
GIT_DIRTY=false
if [ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null)" ]; then
  GIT_DIRTY=true
fi

GIT_COMMIT=$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
GIT_DESCRIBE=$(git -C "$ROOT_DIR" describe --tags --always 2>/dev/null || echo "$RELEASE_VERSION")
if [ "$GIT_DIRTY" = "true" ] && [ "${GIT_DESCRIBE%-dirty}" = "$GIT_DESCRIBE" ]; then
  GIT_DESCRIBE="${GIT_DESCRIBE}-dirty"
fi
BASE_IMAGE=$(awk '$1 == "FROM" {print $2; exit}' "$ROOT_DIR/container/Containerfile")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "--> Builder : $BUILDER"
echo "--> Version : $RELEASE_VERSION ($GIT_DESCRIBE)"
echo "--> Commit  : $GIT_COMMIT"
echo "--> Date    : $BUILD_DATE"

# Build single-platform arm64 image
cd "$ROOT_DIR"
$BUILDER build \
  --platform "$ARCH" \
  --target production \
  --build-arg TAYGA_VERSION="$GIT_DESCRIBE" \
  --build-arg TAYGA_COMMIT="$GIT_COMMIT" \
  --build-arg TAYGA_BRANCH="$GIT_BRANCH" \
  -t "$IMAGE_TAG" \
  -f container/Containerfile .

echo "--> Exporting image archive to $OUTPUT_TAR..."
rm -f "$OUTPUT_TAR"
$BUILDER save -o "$OUTPUT_TAR" "$IMAGE_TAG"

# Generate Checksums and Manifest
TAR_SIZE_BYTES=$(wc -c < "$OUTPUT_TAR" | tr -d ' ')
TAR_SIZE_MB=$(awk "BEGIN {printf \"%.2f\", $TAR_SIZE_BYTES / 1048576}")

cd "$DIST_DIR"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum tayga-arm64.tar > SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 tayga-arm64.tar > SHA256SUMS
fi

SHA256_VAL=$(cat "$DIST_DIR/SHA256SUMS" | awk '{print $1}')

# Check git status
GIT_DIRTY=false
if [ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null)" ]; then
  GIT_DIRTY=true
fi

cat > "$DIST_DIR/manifest.json" <<EOF
{
  "project": "tayga-clat-perf",
  "version": "$RELEASE_VERSION",
  "git_describe": "$GIT_DESCRIBE",
  "commit": "$GIT_COMMIT",
  "git_dirty": $GIT_DIRTY,
  "build_date": "$BUILD_DATE",
  "architecture": "$ARCH",
  "target_hardware": "MikroTik Chateau 5G ax / ARM64 RouterOS 7.x",
  "tar_file": "tayga-arm64.tar",
  "tar_size_bytes": $TAR_SIZE_BYTES,
  "tar_size_mb": "$TAR_SIZE_MB MB",
  "sha256": "$SHA256_VAL",
  "base_image": "$BASE_IMAGE",
  "modes_supported": ["clat", "nat64", "diagnose"],
  "features": [
    "Atomic-1 IPv4 ID Allocator",
    "GSO/GRO Segmentation Offload Engine",
    "RFC 7050 Native PREF64 Discovery",
    "Unbound DNS64 Supervisor",
    "Multi-Worker Processing"
  ]
}
EOF

echo "============================================================"
echo " Build & Packaging Complete!"
echo " Image Archive : $OUTPUT_TAR ($TAR_SIZE_MB MB)"
echo " SHA256        : $SHA256_VAL"
echo " Manifest      : $DIST_DIR/manifest.json"
echo "============================================================"
