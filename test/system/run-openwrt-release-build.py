#!/usr/bin/env python3
"""Build pinned-SDK release packages or explicit next-patch upgrade fixtures.

Uses a prebuilt Docker tools image or a dedicated Lima VM with provisioned tools.
No shared host mounts, application port publishing or registry writes are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from release_platforms import CONTRACT
from openwrt_release import verify

PINS = {'24.10.8': '5f430f5b30c9ea6dc472710356c139abf916b7ebd5de14e108e9cc204f40a2a4',
        '25.12.6': 'cbf3343bc3d6dc6180fc84077b966c13596a79904adaadbfe68409d563b0b596'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def next_patch_version(version):
    parts = version.split('.')
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise ValueError('Next-patch fixtures require an x.y.z source version')
    return '.'.join(parts[:2] + [str(int(parts[2]) + 1)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=tuple(PINS), required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', default='tayga-openwrt-sdk-tools:local')
    parser.add_argument('--test-next-patch', action='store_true', help='Build a clearly marked next-patch upgrade fixture; never a release candidate')
    parser.add_argument('--vm', help='Use a dedicated tayga-openwrt-sdk-* Lima Linux/amd64 VM instead of Docker')
    args = parser.parse_args()
    if args.vm and not args.vm.startswith('tayga-openwrt-sdk-'):
        parser.error('Only dedicated SDK VMs may be provisioned/stopped')
    if digest(args.sdk) != PINS[args.release]:
        parser.error('SDK archive checksum mismatch')
    args.output.mkdir(parents=True, exist_ok=False)
    source = {'sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'version': (ROOT / 'VERSION').read_text().strip()}
    if args.test_next_patch:
        try:
            source['version'] = next_patch_version(source['version'])
        except ValueError as error:
            parser.error(str(error))
    report = {'passed': False, 'source': source, 'release': args.release,
              'sdk_sha256': PINS[args.release], 'phases': [], 'test_fixture': args.test_next_patch}
    container = None
    vm_started = False
    workspace = None

    def run(phase, command, timeout=1800, acceptable=(0,)):
        log = args.output / f'{phase}.log'
        with log.open('wb') as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        report['phases'].append({'name': phase, 'exit_code': result.returncode})
        if result.returncode not in acceptable:
            result.check_returncode()
        return log.read_text(errors='replace').strip()

    try:
        if args.vm:
            vm_started = True
            run('start-vm', ['limactl', 'start', '--tty=false', args.vm])
            report['vm_arch'] = run('guest-arch', ['limactl', 'shell', args.vm, 'uname', '-m'])
            if report['vm_arch'] != 'x86_64':
                raise ValueError('SDK requires a Linux/x86_64 guest')
            cloud = json.loads(run('cloud-init', ['limactl', 'shell', args.vm, 'sudo', 'cloud-init',
                'status', '--wait', '--format', 'json'], timeout=600, acceptable=(0, 2)))
            report['cloud_init'] = cloud
            if cloud.get('status') != 'done' or cloud.get('errors'):
                raise ValueError('Cloud-init did not complete successfully')
            run('provision', ['limactl', 'shell', args.vm, 'sudo', 'sh', '-ec',
                'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '
                'build-essential gawk rsync unzip zstd file libncurses-dev libssl-dev zlib1g-dev '
                'python3 ca-certificates wget git patch time && (id builder >/dev/null 2>&1 || useradd -m builder)'])
        else:
            report['tools_image_id'] = run('image', ['docker', 'image', 'inspect', '--format', '{{.Id}}', args.image])
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'source.tar'
            run('source', ['env', 'COPYFILE_DISABLE=1', 'tar', '--no-xattrs', '-cf', str(archive), 'Makefile', 'VERSION', 'LICENSE', 'src', 'mk',
                           'packaging', 'scripts', 'docs/man'])
            report['source_archive_sha256'] = digest(archive)
            command = '''set -eu
mkdir -p /work/source /work/sdk
tar -xf /source.tar -C /work/source
printf "%s\\n" "$PACKAGE_VERSION" > /work/source/VERSION
tar --zstd -xf /sdk.tar.zst -C /work/sdk --strip-components=1
chown -R builder:builder /work
runuser -u builder -- sh -ec '
cd /work/sdk
printf "%s\\n" "# CONFIG_ALL is not set" "# CONFIG_ALL_KMODS is not set" "# CONFIG_ALL_NONSHARED is not set" > .config
make defconfig
cd /work/source
python3 scripts/prepare-openwrt-package.py --sdk /work/sdk --target armsr --subtarget armv8 --architecture aarch64_generic --version "$PACKAGE_VERSION"
for package in tayga-managed-openwrt tayga-managed-openwrt-procd tayga-managed-openwrt-network tayga-managed-openwrt-upgrade; do
 echo "CONFIG_PACKAGE_$package=m" >> /work/sdk/.config
done
make -C /work/sdk defconfig
make -C /work/sdk package/tayga-managed-openwrt/compile V=s -j2
python3 scripts/ci/openwrt_release.py --sdk /work/sdk --output /work/candidate --release "$OPENWRT_RELEASE" --source-sha "$SOURCE_SHA"
'
'''
            if args.vm:
                workspace = '/var/tmp/tayga-sdk-' + uuid.uuid4().hex
                run('guest-work', ['limactl', 'shell', args.vm, 'mkdir', workspace])
                run('copy-source', ['limactl', 'copy', '--backend=scp', str(archive), f'{args.vm}:{workspace}/source.tar'])
                run('copy-sdk', ['limactl', 'copy', '--backend=scp', str(args.sdk.resolve()), f'{args.vm}:{workspace}/sdk.tar.zst'])
                command = command.replace('/source.tar', workspace + '/source.tar').replace('/sdk.tar.zst', workspace + '/sdk.tar.zst').replace('/work', workspace + '/work')
                run('build', ['limactl', 'shell', args.vm, 'sudo', 'env',
                    f'PACKAGE_VERSION={source["version"]}', f'SOURCE_SHA={source["sha"]}',
                    f'OPENWRT_RELEASE={args.release}', 'sh', '-ec', command], timeout=3600)
                run('collect', ['limactl', 'copy', '--backend=scp', '-r',
                    f'{args.vm}:{workspace}/work/candidate', str(args.output / 'candidate')])
            else:
                container = run('create', ['docker', 'create', '--platform', 'linux/amd64',
                    '-e', f'PACKAGE_VERSION={source["version"]}', '-e', f'SOURCE_SHA={source["sha"]}',
                    '-e', f'OPENWRT_RELEASE={args.release}', args.image, 'sh', '-ec', command])
                run('copy-source', ['docker', 'cp', str(archive), f'{container}:/source.tar'])
                run('copy-sdk', ['docker', 'cp', str(args.sdk.resolve()), f'{container}:/sdk.tar.zst'])
                run('build', ['docker', 'start', '--attach', container], timeout=3600)
                exit_code = run('exit-code', ['docker', 'inspect', '--format', '{{.State.ExitCode}}', container])
                if exit_code != '0':
                    raise ValueError(f'SDK build exited {exit_code}')
                run('collect', ['docker', 'cp', f'{container}:/work/candidate', str(args.output / 'candidate')])
            spec = next(s for s in CONTRACT['openwrt'] if s['release'] == args.release)
            verify(args.output / 'candidate', spec, source)
            report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if container:
            try:
                run('remove-container', ['docker', 'rm', '-f', container])
            except Exception as error:
                report['cleanup_error'] = str(error)
                report['passed'] = False
        if vm_started:
            try:
                if workspace:
                    run('remove-work', ['limactl', 'shell', args.vm, 'sudo', 'rm', '-rf', workspace])
            except Exception as error:
                report['cleanup_error'] = str(error)
                report['passed'] = False
            finally:
                try:
                    run('stop-vm', ['limactl', 'stop', args.vm])
                except Exception as error:
                    report['stop_error'] = str(error)
                    report['passed'] = False
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
