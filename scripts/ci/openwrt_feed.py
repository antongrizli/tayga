#!/usr/bin/env python3
"""Fetch one package from an OpenWrt opkg feed and verify it end to end.

The feed's `Packages` index must carry a valid usign (Ed25519) signature from a
key stored in this repository; the package file must match the SHA256sum the
signed index lists.  Nothing but the standard library is needed, so CI does not
depend on usign/signify being packaged for the runner.

  openwrt_feed.py fetch --feed URL --key FILE --package NAME [--version V] --output FILE
  openwrt_feed.py verify --key FILE --message FILE --signature FILE
"""
import argparse
import base64
import hashlib
from pathlib import Path
import sys
import time
import urllib.request

# --- Ed25519 verification (RFC 8032, section 6 reference algorithm) ---------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    E = 2 * a[2] * b[2] % P
    F, G, H, I = B - A, E - C, E + C, B + A
    return (F * G % P, H * I % P, G * H % P, F * I % P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _decompress(data):
    y = int.from_bytes(data, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % L
    return _equal(_mul(s, BASE), _add(r, _mul(h, a)))


# --- usign container ----------------------------------------------------------
def _usign_blob(text):
    lines = [line for line in text.splitlines() if line and not line.startswith('untrusted comment:')]
    if len(lines) != 1:
        raise ValueError('malformed usign file')
    return base64.b64decode(lines[0], validate=True)


def usign_verify(public_text, message, signature_text):
    """True when signature_text is a valid usign signature of message by public_text's key."""
    public, signature = _usign_blob(public_text), _usign_blob(signature_text)
    if public[:2] != b'Ed' or signature[:2] != b'Ed' or len(public) != 42 or len(signature) != 74:
        raise ValueError('unsupported usign algorithm')
    if public[2:10] != signature[2:10]:
        return False	# signed by a different key than the trusted one
    return ed25519_verify(public[10:], message, signature[10:])


# --- feed handling --------------------------------------------------------------
def fetch(url, attempts=3):
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                return response.read()
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(2 * (attempt + 1))


def parse_packages(text):
    for stanza in text.split('\n\n'):
        fields = {}
        for line in stanza.splitlines():
            if ': ' in line and not line.startswith((' ', '\t')):
                key, value = line.split(': ', 1)
                fields[key] = value
        if 'Package' in fields:
            yield fields


def select_package(index_text, name, version=None):
    matches = [f for f in parse_packages(index_text)
               if f['Package'] == name and (version is None or f.get('Version') == version)]
    if not matches:
        raise SystemExit(f'{name} {version or ""} not listed in the signed feed index'.replace('  ', ' '))
    entry = matches[-1]
    for field in ('Filename', 'SHA256sum'):
        if field not in entry:
            raise SystemExit(f'index entry for {name} has no {field}')
    return entry


def command_fetch(args):
    feed = args.feed.rstrip('/')
    key = Path(args.key).read_text()
    index = fetch(feed + '/Packages')
    if not usign_verify(key, index, fetch(feed + '/Packages.sig').decode()):
        raise SystemExit(f'{feed}: Packages signature does not verify against {args.key}')
    entry = select_package(index.decode(), args.package, args.version)
    data = fetch(f"{feed}/{entry['Filename']}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != entry['SHA256sum']:
        raise SystemExit(f"{entry['Filename']}: sha256 {actual} differs from signed index {entry['SHA256sum']}")
    Path(args.output).write_bytes(data)
    print(f"{entry['Filename']} {entry.get('Version', '')} sha256={actual} (index signature verified)")


def command_verify(args):
    ok = usign_verify(Path(args.key).read_text(), Path(args.message).read_bytes(),
                      Path(args.signature).read_text())
    print('signature OK' if ok else 'signature INVALID')
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    f = sub.add_parser('fetch')
    f.add_argument('--feed', required=True)
    f.add_argument('--key', required=True)
    f.add_argument('--package', required=True)
    f.add_argument('--version')
    f.add_argument('--output', required=True)
    f.set_defaults(func=lambda a: command_fetch(a) or 0)
    v = sub.add_parser('verify')
    v.add_argument('--key', required=True)
    v.add_argument('--message', required=True)
    v.add_argument('--signature', required=True)
    v.set_defaults(func=command_verify)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
