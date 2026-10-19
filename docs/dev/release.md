# Release preparation

Add human-readable notes under `CHANGELOG.md`'s Unreleased section, then run
`make release VERSION=x.y.z`. This prepares `VERSION` and dated notes for review;
it does not commit, tag, push or publish. Review the changes and perform the
acceptance matrix before creating a tag.

Man pages use the version file and a fixed `MAN_DATE` in the Makefile. Update the
metadata deliberately for a release. Generate and verify with the pinned renderer:

```sh
make man PANDOC=scripts/ci/pandoc-container.sh
make check-man PANDOC=scripts/ci/pandoc-container.sh
```

The renderer mounts only a temporary copy of each input, with networking disabled.
A compatible native Pandoc may be selected with `PANDOC=/path/to/pandoc`; CI uses
the pinned image/digest. Generator or comparison failure must return nonzero.

Run GCC/Clang, sanitizer, Linux integration/system and static Alpine architecture
checks, plus FreeBSD and target-device acceptance where applicable. Build `clat`
and `nat64` images and run diagnose smoke checks. Compare staged installation
contents and retain raw benchmark evidence if claiming performance changes.
The historical pre-migration image/install tree is not automatically available.

`scripts/build-arm64.sh` reads `VERSION`, passes version/commit/branch as build
arguments, and derives the manifest's base image from the production recipe.
The script builds/exports locally; publishing remains an explicit release action.

## Verified release pipeline

Prepare and commit `VERSION`, dated nonempty release notes and generated man pages
before creating a tag. Supported tags are `v1.2.3`, `version-1.2.3`,
`version1.2.3` and `1.2.3`, including SemVer prereleases such as `v1.2.3-rc.1`.
Build metadata (`+suffix`) is not supported in container tags. The workflow never
writes `VERSION`, commits changes or pushes to `main`.

A tag push starts the pipeline. A manual run requires an **existing tag** in
`ver`; selecting a workflow branch alone does not select the release source.
The resolver peels annotated tags, validates the committed metadata and records
one full commit SHA in `release-source.json`. Every downstream checkout and image
revision uses that SHA. Keep the release tag immutable throughout publication.

The pipeline calls the compiler/platform and correctness workflows for that SHA,
including FreeBSD, static architecture builds, sanitizers, portable/man checks and
Linux kernel tests. Linux integration is also required. In parallel, it prepares
standalone binaries and production/CLAT/NAT64 images for amd64, arm64 and armv7.
Each architecture runs native or QEMU-assisted units, static-link and staged-install
checks, exact binary version/helper checks, image label/default-mode checks,
diagnose and startup readiness smoke tests. Containers must create their TUN and
run TAYGA; NAT64 must also run Unbound. These smoke tests do not substitute for
physical-device acceptance or a throughput benchmark.

All artifacts are hashed and tied to their source and tested image IDs. After all
gates pass, the assembly job checks hashes, pins RouterOS scripts and prepares
changelog-based release notes. The publish job loads the saved archives and
checks their image IDs; **it does not rebuild**. It stages every platform/profile,
creates multi-platform manifests from recorded registry digests, and then assigns
version aliases. Stable releases also update `latest`; prereleases do not.
Only the publish job has repository/package write permissions.

Registry updates across profiles and a GitHub Release are not one transaction.
A registry/API failure can leave candidate tags or some aliases published. Runs
are serialized. Retain the `release-publication-evidence` artifact, inspect
`published-images.json`, fix the external failure and rerun the same immutable
candidate. Do not move a tag to repair a partial release.

The release assets include `release-manifest.json`, `published-images.json` and
`SHA256SUMS`, plus static binaries, archives for all three profiles and pinned
RouterOS scripts. CI preserves integration/kernel evidence separately. Local
`build/` and `improvenments/` files are ignored by Git; archive any required
performance or device acceptance evidence explicitly and associate it with the
release SHA. Performance claims require successful acceptance of the production
candidate; rejected research patches must remain experimental.

Before publishing a MikroTik-supported release, record physical-device acceptance
for the intended hardware and RouterOS version. This cannot be inferred from
QEMU/VM smoke tests. The release workflow does not manufacture such evidence.
