#!/usr/bin/env python3
"""Stage base/optional-service sources in a matched OpenWrt SDK; never download tools."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]


def prepare(sdk, target, subtarget, architecture, version):
    for value in (target, subtarget, architecture):
        if not re.fullmatch(r'[a-zA-Z0-9_+-]+', value):
            raise ValueError('invalid SDK identity token')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('use an x.y.z package version')
    if not (sdk / '.config').is_file():
        raise ValueError('SDK .config missing: run make -C SDK defconfig first')
    config = (sdk / '.config').read_text()
    required = (f'CONFIG_TARGET_BOARD="{target}"', f'CONFIG_TARGET_SUBTARGET="{subtarget}"',
                f'CONFIG_TARGET_ARCH_PACKAGES="{architecture}"', 'CONFIG_USE_MUSL=y')
    if not all(line in config.splitlines() for line in required):
        raise ValueError('SDK target/subtarget/package architecture/libc mismatch')
    if not (sdk / 'include/package.mk').is_file() or not (sdk / 'staging_dir').is_dir():
        raise ValueError('not an extracted OpenWrt SDK')
    destination = sdk / 'package/tayga-managed-openwrt'
    if destination.exists() or destination.is_symlink():
        raise ValueError(f'refusing to replace {destination}')
    # Copy a deliberate allowlist, excluding .git, build products and local secrets.
    inputs = [ROOT / name for name in ('Makefile', 'VERSION', 'LICENSE', 'packaging/tayga.conf.example')]
    inputs += sorted((ROOT / 'mk').glob('*.mk'))
    inputs += sorted(path for path in (ROOT / 'src').rglob('*') if path.suffix in ('.c', '.h'))
    inputs += [ROOT / 'packaging/openwrt' / name for name in
               ('tayga-managed.init', 'tayga_managed.config', 'openwrt-state.sh',
                'openwrt-uplink.sh', 'tayga-managed.hotplug', 'openwrt-network.sh',
                'tayga-managed.proto', 'fw4-forward.nft', 'fw4-output.nft', 'fw4-srcnat.nft')]
    inputs += [ROOT / 'packaging/installer/configure.sh']
    hashes = {}
    try:
        destination.mkdir(parents=True)
        for path in inputs:
            if path.is_symlink():
                raise ValueError(f'symlink source refused: {path}')
            relative = path.relative_to(ROOT)
            output = destination / 'source' / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
            hashes[str(relative)] = hashlib.sha256(output.read_bytes()).hexdigest()
        recipe = (ROOT / 'packaging/openwrt/Makefile').read_text().replace('@VERSION@', version)
        (destination / 'Makefile').write_text(recipe)
        (destination / 'package-owner').write_text('openwrt-sdk\n')
        (destination / 'source-manifest.json').write_text(json.dumps({
            'target': target, 'subtarget': subtarget, 'architecture': architecture,
            'libc': 'musl', 'version': version, 'binary_only': True,
            'optional_service': {'enabled_by_default': False, 'network_mode': 'external'},
            'sdk_config_sha256': hashlib.sha256(config.encode()).hexdigest(),
            'recipe_sha256': hashlib.sha256(recipe.encode()).hexdigest(), 'sources': hashes,
        }, indent=2) + '\n')
    except BaseException:
        shutil.rmtree(destination)
        raise
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--subtarget', required=True)
    parser.add_argument('--architecture', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        print(prepare(args.sdk.resolve(), args.target, args.subtarget, args.architecture, args.version))
    except (ValueError, OSError) as error:
        parser.error(str(error))
