#!/usr/bin/env bash
# Prepare one architecture locally; this script never pushes images.
set -euo pipefail
arch=$1
platform=$2
source_json=$3
out=$4
case "$arch:$platform" in
  amd64:linux/amd64|arm64:linux/arm64|armv7:linux/arm/v7) ;;
  *) echo "Unsupported architecture/platform pair" >&2; exit 1 ;;
esac
read -r version sha tag < <(python3 - "$source_json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(m['version'], m['sha'], m['tag'])
PY
)
mkdir -p "$out"
out=$(cd "$out" && pwd)
base=$(awk '$1 == "FROM" {print $2; exit}' container/Containerfile)
# Use the pinned platform manifest; classic Docker stores cannot load several
# platforms under one index digest on the same development machine.
platform_digest=$(docker buildx imagetools inspect "$base" --raw | python3 -c '
import json, sys
parts = sys.argv[1].split("/")
items = [m for m in json.load(sys.stdin)["manifests"]
         if m.get("platform", {}).get("os") == parts[0]
         and m["platform"].get("architecture") == parts[1]
         and (len(parts) < 3 or m["platform"].get("variant") == parts[2])]
if len(items) != 1:
    raise SystemExit("Expected one pinned platform manifest")
print(items[0]["digest"])
' "$platform")
base="${base%@*}@$platform_digest"
printf 'FROM %s
RUN apk add --no-cache gcc make musl-dev linux-headers binutils
' "$base" | \
  docker buildx build --platform "$platform" --provenance=false --load -t "tayga-release-tools:$arch" -
container=$(docker create --platform "$platform" -w /work \
  -e RELEASE_VERSION="$version" -e RELEASE_SHA="$sha" -e RELEASE_TAG="$tag" \
  -e RELEASE_ARCH="$arch" "tayga-release-tools:$arch" sh -ec '
    mkdir -p /out
    make static pref64-discover test VERSION="$RELEASE_VERSION" COMMIT="$RELEASE_SHA" BRANCH="$RELEASE_TAG"
    for binary in tayga pref64-discover; do
      if readelf -l "$binary" | grep -q INTERP; then
        echo "Unexpected dynamic interpreter in $binary" >&2; exit 1
      fi
    done
    make static install DESTDIR=/tmp/release-install VERSION="$RELEASE_VERSION" COMMIT="$RELEASE_SHA" BRANCH="$RELEASE_TAG"
    cmp tayga /tmp/release-install/usr/local/sbin/tayga
    cmp docs/man/tayga.8 /tmp/release-install/usr/local/share/man/man8/tayga.8
    cmp docs/man/tayga.conf.5 /tmp/release-install/usr/local/share/man/man5/tayga.conf.5
    find /tmp/release-install -type f | sort > /out/install-files.txt
    test "$(wc -l < /out/install-files.txt)" -eq 3
    for binary in tayga pref64-discover; do
      if readelf -l "$binary" | grep -q INTERP; then
        echo "Dynamic interpreter after staged install: $binary" >&2; exit 1
      fi
    done
    strip tayga pref64-discover
    ./tayga --help > /out/binary-help.txt
    test "$(head -n 1 /out/binary-help.txt)" = "TAYGA version $RELEASE_VERSION"
    test "$(./pref64-discover --check 64:ff9b::192.0.0.170)" = "64:ff9b::/96"
    cp tayga "/out/tayga-linux-$RELEASE_ARCH"
    cp pref64-discover "/out/pref64-discover-linux-$RELEASE_ARCH"
  ')
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    docker cp "$container:/work/build/test-bin" "$out/failed-test-bin" 2>/dev/null || true
    docker logs "$container" > "$out/failed-build.log" 2>&1 || true
  fi
  docker rm -f "$container" >/dev/null
  exit "$status"
}
trap cleanup EXIT
for input in src mk test packaging docs Makefile VERSION; do
  docker cp "$input" "$container:/work/$input"
done
docker start --attach "$container"
test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" -eq 0
docker cp "$container:/out/." "$out/"
docker rm "$container" >/dev/null
trap - EXIT
for profile in production clat nat64; do
  image="tayga-release-$profile:$arch"
  docker buildx build --platform "$platform" --target "$profile" \
    --build-arg "TAYGA_VERSION=$version" --build-arg "TAYGA_COMMIT=$sha" \
    --build-arg "TAYGA_BRANCH=$tag" --provenance=false --load \
    -t "$image" -f container/Containerfile .
done
python3 scripts/ci/release_artifacts.py record --source "$source_json" --arch "$arch" --directory "$out"
