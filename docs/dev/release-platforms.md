# Release platform inventory

`packaging/release-platforms.json` defines the required Linux binary/SFX/native
package architectures, FreeBSD binary/SFX architectures, native formats and
container profiles. The release workflow resolves its matrix from this file at
the exact tagged source commit, rather than the workflow checkout's branch.

All seven Linux targets (amd64, arm64, armv7, armv6, riscv64, ppc64le, s390x)
produce static TAYGA and pref64-discover binaries, platform shell installers,
and DEB/RPM/Alpine APK archives. Assembly rejects missing candidates and missing
native formats. Universal installers include all enabled binary platforms.

Container images and saved image archives are a separate subset:
`container_arches` contains amd64, arm64 and armv7. Binary-only candidates must
have an empty images map; publication promotes only container architectures.
Enabling a binary target must not implicitly advertise an untested container.

Before signing, assembly checks mandatory binaries, helpers, shell installers,
container archives, native archive names and release metadata. Native filenames
come from the independently verified per-architecture package manifests.

The pinned Alpine 3.24 build index contains all seven Linux platforms. Full
cross-architecture builds, package metadata/installability and runtime acceptance
still require the release CI jobs; inventory unit tests alone do not certify
those properties. OpenWrt 24.10.8 IPK and 25.12.6 APK release delivery is required for
`armsr/armv8`. Alpine APK archives are not OpenWrt APK packages.

The SDK jobs export the four original-version packages (base, procd, network,
upgrader) before building next-patch upgrade fixtures. Candidates are uploaded
only after the job gates succeed. Each branch has its own namespace and manifest
with source SHA, version, SDK source/config metadata and archive hashes. Assembly
requires both candidates, checks every role and hash, copies their archives into
the final release, and includes their metadata in the signed release manifest.
It must never publish the next-patch test fixture as the tagged release.

Local export/inventory tests validate orchestration, not package installability.
The SDK/VM gates on the exact final source are required for acceptance.

To inspect the enabled matrix:

```sh
python3 scripts/ci/release_platforms.py matrix
python3 scripts/ci/release_platforms.py linux-arches
python3 -m unittest discover -s bench/tests -p 'test_release*.py'
```

## Native metadata and production preflight

Assembly reads package identity from the DEB control archive, Alpine APK
`.PKGINFO`, and RPM header tags, without installing packages or running scripts.
It requires the package name `tayga-managed`, expected version/revision, and the
format-specific architecture alias. Matching magic bytes or a plausible filename
are insufficient. The parser supports the unsigned Alpine APKs emitted by nFPM;
it does not claim support for arbitrary signed/repository APK layouts.

Production publication additionally requires all mandatory bundle members in
the verified signed checksum list: Linux/FreeBSD binaries and helpers, shell
installers, native archives, OpenWrt subpackages, image archives and release
metadata. Unsafe paths, duplicate entries and invalid digest syntax are rejected
before Docker operations. Tests use real minisign signatures for incomplete
inventories, including omitted shell, native, FreeBSD and OpenWrt files.

Archive-structure unit fixtures verify parsing and mismatch rejection for every
native architecture/format. They are not installable packages and do not replace
nFPM builds or package-manager runtime gates on the actual final artifacts.

## Real nFPM acceptance

The native release job runs `test_package_metadata_nfpm.py` against its verified
nFPM executable before building release packages. The test generates 21 real
metadata-only archives (seven architectures times three formats) and checks their
identity. ARMv6 uses nFPM `arm6`: Debian `armhf`, RPM `armv6hl`, Alpine `armhf`.
These aliases describe hard-float packages; they must not be changed to Debian
`armel` without changing the binary ABI and package contract.

```sh
NFPM_TEST_BINARY=/absolute/path/to/verified/nfpm \
  python3 -m unittest discover -s bench/tests -p test_package_metadata_nfpm.py
```

The RPM parser deliberately skips identity decoding in the signature header:
signature tag 1000 is an integer size, whereas main-header tag 1000 is the name.
A regression fixture includes this tag to prevent confusing the two namespaces.

Local acceptance also built current static arm64 TAYGA/helper in a disposable
Alpine VM and packaged them as actual DEB/RPM/APK with nFPM 2.48.0. Those three
archives passed metadata validation. They were not installed by that check;
package-manager upgrade/recovery and other-architecture execution remain separate
gates. Evidence is kept under ignored `build/native-real-validation/`.

Native release CI now calls `package_metadata.py MANIFEST` after building each
architecture's archives and before candidate upload. This checks the complete
DEB/RPM/APK format set, exact archive hashes and actual package identity.

Local arm64 package-manager acceptance used revisions 101 and 102 of current
TAYGA 0.9.14. Debian/systemd, Fedora/systemd and Alpine/OpenRC all passed native
installation, active upgrade, forwarded SIIT ICMP/HTTP, a hard power cut after
real package-manager installation, autonomous recovery of the accepted package
and data, repeated traffic verification, cleanup and VM stop. Exact package and
fixture hashes are in `build/native-real-validation/runtime-acceptance.json` and
its referenced reports. This certifies one interruption boundary on arm64, not
all crash boundaries or all release architectures.

## Standalone real OpenWrt release build

`test/system/run-openwrt-release-build.py` builds a pinned Linux/x86_64 SDK in a
disposable container, with no host mounts or published ports. It exports only
original-version packages, verifies the candidate on the host, records the SDK,
source archive and tools-image identity, and removes its container on exit.
Requires Docker amd64 emulation and enough free space *inside the Docker VM*
for the tools image and extracted SDK (allow roughly 8–10 GiB headroom).

```sh
docker build --platform linux/amd64 -t tayga-openwrt-sdk-tools:local \
  - < test/system/containers/openwrt-sdk-tools.Dockerfile
sdk=$(python3 scripts/ci/cache-test-image.py \
  --sha256 5f430f5b30c9ea6dc472710356c139abf916b7ebd5de14e108e9cc204f40a2a4 \
  --offline)
python3 test/system/run-openwrt-release-build.py --release 24.10.8 \
  --sdk "$sdk" --output build/openwrt-release-validation/ipk-run-01
sdk=$(python3 scripts/ci/cache-test-image.py \
  --sha256 cbf3343bc3d6dc6180fc84077b966c13596a79904adaadbfe68409d563b0b596 \
  --offline)
python3 test/system/run-openwrt-release-build.py --release 25.12.6 \
  --sdk "$sdk" --output build/openwrt-release-validation/apk-run-01
```

Output directories must be new. Success requires `report.json` with `passed:true`
and four verified candidate archives. This is a package build/export gate, not a
booted OpenWrt runtime certification. The tools Dockerfile is for local testing;
its resolved image ID is recorded and it is not a release artifact.

The first local attempt cached both verified SDKs but could not build the tools
image: Docker's 59 GiB filesystem was 100% used. No foreign images, volumes or
build cache were removed. See `build/openwrt-release-validation/report.json` and
`tools-build.log`. That attempt is **not** a successful OpenWrt package acceptance.

### Lima fallback when Docker storage is full

A dedicated x86_64 Lima guest can build the same packages using a disk outside
Docker. Never reuse a workload VM. The template pins the Debian cloud image and
disables host mounts and containerd. Apple Silicon requires QEMU plus Lima's
additional x86_64 guest agent (`lima-additional-guestagents` matching Lima).

```sh
limactl start --name=tayga-openwrt-sdk-amd64 --tty=false \
  test/system/openwrt-sdk-amd64.yaml
python3 test/system/run-openwrt-release-build.py \
  --vm tayga-openwrt-sdk-amd64 --release 24.10.8 \
  --sdk /absolute/path/to/cached/sdk/image \
  --output build/openwrt-release-validation/ipk-vm-new
```

The VM backend requires a `tayga-openwrt-sdk-*` name and x86_64 architecture.
It waits for cloud-init completion before apt provisioning. Recoverable cloud-init
warnings are recorded; critical errors or incomplete status stop the run. Every
run uses a unique guest directory, saves build logs and verifies candidate hashes.
Cleanup removes only that directory and stops its guest. SDK archives remain in
the host shared cache; the stopped guest disk retains installed build tools.

The subsequent Lima fallback succeeded for both real SDKs: OpenWrt 24.10.8
produced four IPKs and 25.12.6 produced four APK3 archives, all at 0.9.14-r7.
Both candidates passed current host manifest/hash verification. The IPK verifier
also checks internal control metadata (role/name, version and architecture) and
rejects role substitution or mixed revisions. The pinned APK branch requires
`ADBd` APK3 archives and rejects Alpine gzip APKs. Export invokes the pinned SDK's
`apk adbdump --format json` to read actual internal name/version/architecture and
records this identity beside each archive hash. Host verification requires that
identity and checks roles, version, architecture and consistent package revisions. The producer calls candidate verification before successful
export. See `build/openwrt-release-validation/report.json` for the latest verdict;
the earlier Docker storage failure is retained separately as historical evidence.

SDK build/export success is separate from booted OpenWrt installation/recovery
acceptance and from a complete signed Linux/FreeBSD/OpenWrt bundle rehearsal.
Neither is implied by these SDK reports.

APK3 identities were independently read from the four real SDK-produced packages
using the executable, loader and libraries extracted from the pinned SDK. A
repeat export of those unchanged archives with the current producer succeeded;
the metadata-bearing candidate is in
`build/openwrt-release-validation/apk-metadata-candidate/`. Tests reject missing
APK3 identity and wrong name, version or architecture. The host verifier relies
on the trusted SDK producer's recorded identity; it does not reimplement the
APK3 ADB decoder in Python.

Both original-version SDK package sets subsequently passed booted OpenWrt runtime
acceptance. IPK 24.10.8 and APK3 25.12.6 were installed in separate disposable
arm64 QEMU guests using cached pinned images and dependencies. Gates covered
explicit startup, procd lifecycle/respawn, WAN handover, reboot, configuration/data
recovery after hard power cut, managed NAT64/DNS64/SIIT/CLAT, forwarded LAN traffic,
readiness rollback and removal. Runtime input hashes were compared with every
candidate subpackage hash. See
`build/openwrt-release-validation/runtime-acceptance.json`.

These runs did not supply next-version packages or request the separate two-VM
DHCPv6 server gate. OpenWrt package upgrade recovery across versions and the
complete signed multi-platform bundle still require their own final acceptance.

## Explicit next-patch SDK fixtures

The standalone SDK runner supports `--test-next-patch` for upgrade acceptance.
It builds, for example, 0.9.15 from a 0.9.14 checkout by changing VERSION only in
the isolated source copy before staging the SDK package. The checkout remains
unchanged. Reports mark `test_fixture:true` and record the effective version and
input archive hash. The resulting candidates are test inputs, not release assets;
source/version verification rejects them against the original release version.
Use separate output directories and never overwrite the accepted baseline.

```sh
python3 test/system/run-openwrt-release-build.py \
  --vm tayga-openwrt-sdk-amd64 --release 24.10.8 --test-next-patch \
  --sdk /absolute/path/to/cached/sdk/image \
  --output build/openwrt-release-validation/ipk-next-patch-new
```

Supply baseline base/procd/network/upgrader archives and target
`--upgrade-base`, `--upgrade-procd`, `--upgrade-network` to the existing
`run-openwrt-vm.py`; add `--dhcpv6-server` for the isolated two-VM lease/renumbering
gate. The independent upgrade coordinator remains the baseline package.

Both OpenWrt branches subsequently passed the two-version upgrade and two-VM
DHCPv6 gate using baseline 0.9.14-r7 and explicit test target 0.9.15-r7. The actual
archive hashes were checked against baseline and target candidate manifests.
Scenarios included malformed targets, package-manager failure, target readiness
failure, QEMU SIGKILL after target installation and before confirmation, boot
recovery of old packages/configuration/data/traffic, successful upgrade and
stopped reinstall policy. The independent baseline coordinator drove the upgrade.

Real odhcpd peers supplied IA_NA and IA_PD /62 with SLAAC disabled; renew preserved
stable facts/PID, renumber changed addresses/prefixes/PID while retaining accepted
configuration, and old-prefix retirement preserved the replacement lease. Both
peer reports passed. See
`build/openwrt-release-validation/upgrade-dhcpv6-acceptance.json`.

This closes those specific local scenarios on armsr/armv8. It does not certify
all crash boundaries, other boards, or publication of the test target version.
The final signed multi-platform bundle rehearsal remains a separate gate.

## Signed bundle rehearsal without publication

The release job now invokes production preflight after assembly/signing, before
uploading `verified-release-assets`. The same read-only gate can be run locally:

```sh
RELEASE_SHA="$verified_source_sha" MINISIGN_PUBKEY_FILE=/absolute/path/trusted.pub \
  python3 scripts/ci/release_publish.py release-assets --verify-only
```

Use the trusted public key and the expected source SHA obtained independently of
the bundle. Verify-only never invokes Docker/registry publication and always
requires production signing; `ALLOW_UNSIGNED_RELEASE` cannot weaken it.

The current contract requires 82 immutable signed members: 18 binaries/helpers,
11 shell installers, 21 native packages, 8 OpenWrt packages, 9 container archives,
12 RouterOS scripts plus their ZIP, and manifest/notes. Checksums and the minisign
signature make 84 prepublication files. Assembly rejects both missing and
unexpected files before signing; the platform contract snapshot is embedded in
the release manifest. Publication adds its images evidence JSON and checksum
separately without modifying the signed checksum list.

A full-matrix fixture test executes the actual assembler and installer builder,
generates a real temporary minisign keypair, signs/verifies the resulting bundle,
invokes verify-only in a subprocess, and checks exact inventory. Missing Linux
shell, FreeBSD helper, native APK and OpenWrt archive cases fail, as does an
unsigned-environment override. Reports are under
`build/release-bundle-validation/`.

This is an orchestration/crypto rehearsal using test inputs. Complete real
Linux binaries for all seven architectures and FreeBSD amd64/arm64 candidates
from the final source are still required for production acceptance. Fixture
signing success is not a substitute for those builds or runtime gates.

## Candidate-only GitHub Actions run

Manual dispatch defaults to `candidate_only=true`. No existing release tag or
dated release notes are required. The resolver reads VERSION from the selected
immutable commit (full lowercase 40-character SHA); an empty `candidate_sha`
uses the commit selected by the workflow dispatch. The source manifest records
`candidate_only:true`. Its logical version tag is metadata only: no Git tag is
created. All normal compiler, integration, SDK, FreeBSD and package gates remain
required.

After committing/pushing the implementation, dispatch the branch containing it:

```sh
source_sha=$(git rev-parse HEAD)
gh workflow run release.yml --ref codex/self-extracting-installer \
  -f candidate_only=true -f candidate_sha="$source_sha"
```

The complete artifact is named `verified-candidate-assets`; the temporary public
key is uploaded separately as `candidate-verification-public-key`. The private
key stays in runner temporary storage and is not uploaded. Candidate assembly
never references production Minisign secrets. Verification uses the temporary
public key and expected source SHA, and release notes identify the unpublished
candidate. RouterOS references are packaging checks, not published candidate
registry aliases.

The publish job is skipped for this mode and does not receive write permissions
through execution. As a second independent guard, `release_publish.py` rejects
candidate-only source manifests even with `--allow-unsigned`. Candidate signatures
are test signatures, not production trust anchors. A candidate run can prove the
full pipeline without Docker push, registry tag promotion or a GitHub release.

Tag-push production releases retain their strict prepared-tag/VERSION/dated-notes
checks. For an intentional manual production release, explicitly set
`candidate_only=false` and provide `ver`; candidate_sha does not replace the
prepared release tag. Production signing credentials remain mandatory.
