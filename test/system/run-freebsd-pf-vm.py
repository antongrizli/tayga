#!/usr/bin/env python3
"""PF ownership gate in a dedicated FreeBSD Lima VM, using its cached base image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='tayga-installer-freebsd-pf')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gate', choices=('ownership', 'ipv6'), default='ownership')
    args = parser.parse_args()
    if not args.vm.startswith('tayga-installer-freebsd-'):
        parser.error('A separate FreeBSD test VM is required')
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True)
    fixture = ('test/system/installer-freebsd-ipv6-smoke.sh' if args.gate == 'ipv6' else
               'test/system/installer-freebsd-pf-ownership.sh')
    evidence = 'tayga-ipv6-gate-evidence' if args.gate == 'ipv6' else 'tayga-pf-evidence'
    report = {'vm': args.vm, 'gate': args.gate, 'passed': False, 'phases': [], 'sources': {}}
    for name in ('src/nat64.c', 'src/tayga.h', 'packaging/installer/tayga-net-ctl.sh', fixture):
        report['sources'][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()

    def run(phase, command, data=None, timeout=600):
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        (args.output / f'{phase}.log').write_bytes(result.stdout)
        report['phases'].append({'name': phase, 'exit_code': result.returncode})
        result.check_returncode()
        return result.stdout

    try:
        run('start', ['limactl', 'start', args.vm])
        run('mkdir', ['limactl', 'shell', args.vm, 'mkdir', '-p', '/var/tmp/tayga-pf-source'])
        source = subprocess.check_output(['tar', '-cf', '-', 'Makefile', 'VERSION', 'mk', 'src',
                                          'packaging', fixture], cwd=root)
        run('copy', ['limactl', 'shell', args.vm, 'tar', '-xf', '-', '-C', '/var/tmp/tayga-pf-source'], source)
        report['source_archive_sha256'] = hashlib.sha256(source).hexdigest()
        run('version', ['limactl', 'shell', args.vm, 'freebsd-version', '-ku'])
        command = '''cd /var/tmp/tayga-pf-source &&
            (command -v gmake >/dev/null || sudo pkg install -y gmake) &&
            gmake -j2 tayga &&
            sh packaging/installer/configure.sh --mode=siit --pref64=fd64:100::/96 \
                --map-ipv4=198.18.10.1 --map-ipv6=fd64:200::1 --firewall=pf \
                --output=/var/tmp/tayga-pf-source/siit.conf &&
            sudo env TAYGA_ISOLATED_TEST=yes PATH="/var/tmp/tayga-pf-source:$PATH" \
                sh test/system/installer-freebsd-pf-ownership.sh \
                packaging/installer/tayga-net-ctl.sh siit.conf /var/tmp/tayga-pf-evidence'''
        if args.gate == 'ipv6':
            command = '''cd /var/tmp/tayga-pf-source &&
                (command -v gmake >/dev/null || sudo pkg install -y gmake) &&
                (command -v curl >/dev/null || sudo pkg install -y curl) &&
                (command -v python3 >/dev/null || sudo pkg install -y python3) &&
                gmake -j2 tayga &&
                sudo env TAYGA_ISOLATED_TEST=yes PATH="/var/tmp/tayga-pf-source:$PATH" \
                    sh test/system/installer-freebsd-ipv6-smoke.sh \
                    /var/tmp/tayga-pf-source /var/tmp/tayga-ipv6-gate-evidence'''
        run(args.gate, ['limactl', 'shell', args.vm, 'sh', '-ec', command])
        report['passed'] = True
    finally:
        try:
            run('pack-evidence', ['limactl', 'shell', args.vm, 'sudo', 'tar', '-cf',
                                  f'/var/tmp/{evidence}.tar', '-C', '/var/tmp', evidence])
            run('evidence-permissions', ['limactl', 'shell', args.vm, 'sudo', 'chmod', '644',
                                        f'/var/tmp/{evidence}.tar'])
            run('collect', ['limactl', 'copy', '--backend=scp',
                            f'{args.vm}:/var/tmp/{evidence}.tar', str(args.output / 'evidence.tar')])
        except Exception as error:
            report['collection_error'] = str(error)
            report['passed'] = False
        try:
            run('stop', ['limactl', 'stop', args.vm])
        except Exception as error:
            report['stop_error'] = str(error)
            report['passed'] = False
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
