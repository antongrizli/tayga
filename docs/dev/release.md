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
