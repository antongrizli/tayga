# Release signature verification

The project's production public key is [release-signing.pub](../release-signing.pub).
Obtain this key from a trusted checkout or independently confirmed project channel
before verifying downloaded assets. A key supplied alongside untrusted downloads
does not establish their origin. Keep the trusted key for subsequent releases.

The SHA-256 fingerprint of the public key's base64 line, excluding whitespace, is:

```text
bc8c08b594471c0c807ac1785e8d68a7f663f45c2ffedfedd203ce9de52a8a67
```

## Verify downloaded files

Install Minisign using your operating system's package manager (on macOS,
`brew install minisign`). Download `SHA256SUMS`, `SHA256SUMS.minisig` and the desired
assets from the intended release. In that directory, using your trusted key:

```sh
minisign -V -p /absolute/path/to/release-signing.pub -m SHA256SUMS
```

Only after signature verification succeeds, check file contents. If you downloaded
the complete signed bundle, use `sha256sum -c SHA256SUMS` on Linux or
`shasum -a 256 -c SHA256SUMS` on macOS. For a subset of downloads, verify each
selected basename without ignoring a checksum mismatch:

```sh
python3 - tayga-installer-universal.sh <<'PY'
import hashlib
import sys
from pathlib import Path
entries = {}
for line in Path('SHA256SUMS').read_text().splitlines():
    digest, name = line.split('  ', 1)
    if name in entries:
        raise SystemExit('Duplicate checksum entry')
    entries[name] = digest
for name in sys.argv[1:]:
    if Path(name).name != name or name not in entries:
        raise SystemExit('Missing or invalid checksum entry: ' + name)
    with Path(name).open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != entries[name]:
        raise SystemExit('Checksum mismatch: ' + name)
    print('Verified: ' + name)
PY
```

The subset example requires Python 3.11 or later. Never run an installer after
a failed signature or checksum check. Older releases may predate this signing
key; do not assume every historical release has a signature.

The signature covers the immutable `SHA256SUMS` inventory. Registry publication
evidence (`published-images.json` and its separate checksum) is added afterward
and is outside that signature. Standalone package archives are authenticated by
the signed inventory; this does not configure APK/RPM repository signing.

## Maintainer setup and isolated credential check

Store these repository Actions secrets in `antongrizli/tayga`:

| Secret | Value |
| --- | --- |
| `MINISIGN_KEY_DATA` | Entire password-protected private key file, including comment |
| `MINISIGN_PASSWORD` | Password protecting that private key |
| `MINISIGN_PUBKEY` | Only the public key's base64 line, without comment |

Keep an encrypted backup of the private key and its password outside GitHub.
Never commit the private key. Leave `MINISIGN_KEY_FILE` unset when using key data;
it is an alternative runner-local file path and takes precedence over key data.

To check the configured production credentials without building or publishing:

```sh
gh workflow run release.yml --repo antongrizli/tayga \
  --ref codex/self-extracting-installer \
  -f signing_check_only=true -f candidate_only=true
```

Select a reviewed ref containing this workflow mode. The job signs an isolated
test checksum list through the release signer, verifies it using the configured
public key, and prints the public key fingerprint. Compare that fingerprint with
the trusted key above. It uploads no keys or signing files. Source resolution,
builds and publication jobs are skipped. Ordinary candidate-only runs use
temporary keys and do not test production credentials.

Production credential roundtrip and local public key fingerprint matching passed
in [the isolated signing check](https://github.com/antongrizli/tayga/actions/runs/41394934162),
attempt 3, on 2026-11-02. This was not a release publication.
