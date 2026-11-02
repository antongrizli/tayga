#!/usr/bin/env python3
"""Run real Debian/Alpine/Fedora package/service upgrade and hard-cut recovery in a test Lima VM."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', required=True, help='Dedicated VM named tayga-installer-*')
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--profile-state', choices=('active', 'stopped', 'unconfigured'), default='active')
    parser.add_argument('--traffic', action='store_true', help='Verify forwarded ICMP and HTTP through SIIT')
    args = parser.parse_args()
    if not args.vm.startswith('tayga-installer-') or args.vm.endswith('freebsd'):
        parser.error('Only dedicated Linux installer test VMs may be hard-stopped')
    kind = args.baseline.suffix
    if kind not in ('.deb', '.apk', '.rpm') or args.target.suffix != kind:
        parser.error('Matching DEB, APK or RPM packages required')
    if kind == '.apk' and args.profile_state != 'active':
        parser.error('Non-active boot recovery currently requires a systemd package')
    fixture = Path(__file__).with_name('installer-native-upgrade-vm.sh')
    inputs = {'baseline': args.baseline.resolve(), 'target': args.target.resolve(),
              'fixture': fixture.resolve()}
    if args.traffic:
        if args.profile_state != 'active':
            parser.error('--traffic requires an active profile')
        inputs['wire_fixture'] = fixture.with_name('installer-native-wire-smoke.sh').resolve()
    report = {'vm': args.vm, 'profile_state': args.profile_state, 'passed': False, 'phases': [],
              'inputs': {key: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                         for key, path in inputs.items()}}
    args.output.mkdir(parents=True, exist_ok=True)

    def run(phase, *command, timeout=240):
        start = time.monotonic()
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        (args.output / f'{phase}.log').write_text(result.stdout)
        report['phases'].append({'name': phase, 'exit_code': result.returncode,
                                 'seconds': time.monotonic() - start})
        result.check_returncode()

    remote = f'/var/tmp/tayga-native-upgrade-{int(time.time())}'
    started = False
    try:
        run('start', 'limactl', 'start', args.vm)
        started = True
        run('directory', 'limactl', 'shell', args.vm, 'mkdir', '-p', remote)
        for key, path in inputs.items():
            suffix = '.sh' if key.endswith('fixture') else kind
            run(f'copy-{key}', 'limactl', 'copy', str(path), f'{args.vm}:{remote}/{key}{suffix}')

        def guest(phase):
            run(phase, 'limactl', 'shell', args.vm, 'sudo', 'env',
                'TAYGA_ISOLATED_TEST=yes', f'TAYGA_TEST_PROFILE_STATE={args.profile_state}', 'sh', f'{remote}/fixture.sh', phase,
                f'{remote}/baseline{kind}', f'{remote}/target{kind}')

        def traffic(phase):
            if args.traffic:
                run(phase, 'limactl', 'shell', args.vm, 'sudo', 'env',
                    'TAYGA_ISOLATED_TEST=yes', 'sh', f'{remote}/wire_fixture.sh')

        guest('setup')
        traffic('traffic-baseline')
        guest('upgrade')
        traffic('traffic-upgraded')
        guest('arm-powercut')
        run('hard-cut', 'limactl', 'stop', '--force', args.vm)
        run('reboot', 'limactl', 'start', args.vm)
        guest('check-recovery')
        traffic('traffic-recovered')
        guest('cleanup')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if started:
            try:
                run('stop', 'limactl', 'stop', args.vm)
            except Exception as error:
                report['stop_error'] = str(error)
                report['passed'] = False
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
