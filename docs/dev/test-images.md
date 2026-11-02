# Reusing operating system images for tests

Keep immutable OS downloads outside the checkout, shared across worktrees. Keep
mutable VM disks and per-run reports separate from those downloads.

## Lima images

Use Lima's existing cache instead of downloading another copy in project scripts.
On this macOS installation it is `~/Library/Caches/lima/download/`. Lima keys
downloads by URL, verifies the template digest, and also caches image conversions.
Creating another instance from the same pinned template reuses those files.
Existing VM disks live under `~/.lima/<instance>/`; starting a stopped test VM
reuses that disk and requires no OS image download.

For example, a separate Fedora test VM can reuse the cached base image:

```sh
limactl create --name=tayga-installer-fedora-new \
  --cpus=2 --memory=2 --disk=12 --mount-none --containerd=none \
  --tty=false template:fedora
```

Inspect the installed template's image URL and digest before using it as a new
baseline; pin updates are explicit test-input changes. Do not use an unverified
mutable `latest` URL as a certified baseline. Do not run `limactl prune` or clear
the Lima cache between tests. Creating a fresh VM and resuming a used VM provide
different isolation guarantees; sharing immutable base downloads supports both.

## OpenWrt images, kernels and other pinned downloads

Use `scripts/ci/cache-test-image.py` for downloads not owned by Lima. Defaults:

- macOS: `~/Library/Caches/tayga-tests/images/`;
- Linux: `${XDG_CACHE_HOME:-~/.cache}/tayga-tests/images/`;
- override with `TAYGA_TEST_CACHE` or `--cache-dir`.

Objects are stored as `sha256/<digest>/image`. Every reuse verifies the hash.
Concurrent writers are serialized, and failed or incomplete downloads are never
published. The helper prints only the resulting path on stdout. Python 3.11+
and a Unix host are required.

Import a previously downloaded OpenWrt 24.10.8 test image once, without network:

```sh
python3 scripts/ci/cache-test-image.py \
  --sha256 9013deabf64ddd93bd2039b1b469a595c48201d611a9885afffd050053d063a5 \
  --source build/openwrt-vm/squashfs.img.gz --offline
```

Reuse it from any worktree, even if the original build directory is gone:

```sh
image=$(python3 scripts/ci/cache-test-image.py \
  --sha256 9013deabf64ddd93bd2039b1b469a595c48201d611a9885afffd050053d063a5 \
  --offline)
# Supply "$image" as --image to test/system/run-openwrt-vm.py.
```

For a cache miss, provide `--url` with the official HTTPS URL and a separately
verified SHA256 pin. The same helper can cache a kernel, rootfs or SDK archive.
Use `--source` to import existing local downloads rather than fetching them again.
A corrupt cached object causes an explicit error; investigate and remove only
that object before retrying. Importing preserves the source file. This helper
does not move or prune existing artifacts automatically.

## Working disks and evidence

Keep Lima working disks under `~/.lima`, and disposable QEMU working disks and
reports under ignored `build/`. Never boot an immutable cached base directly
writable; make a working copy or overlay as the VM runner requires. A test image
cache is not a backup of test results. Preserve package/image hashes, reports,
and relevant logs separately when certifying a run.

OS images, cached downloads and VM disks must not be committed to Git. Internal
plans in `improvenments/` also remain local and ignored.
