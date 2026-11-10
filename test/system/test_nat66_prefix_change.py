#!/usr/bin/env python3
"""NAT66 prefix replacement with the real controller and nftables (Linux, root).

A CLAT profile in NAT66 mode is brought up by tayga-net-ctl, then the RA
supervisor swaps the advertised PREF64 from A to B: the nftables rules must name
only B afterwards, the translator must run on B, and a later outage must leave
the rules alone.  Everything lives in two private network namespaces.
"""
import argparse
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
NET_CTL = ROOT / 'packaging/installer/tayga-net-ctl.sh'
CONFIGURE = ROOT / 'packaging/installer/configure.sh'
A, B = '2001:db8:a64::', '2001:db8:b64::'


DIAGNOSTICS = lambda: ''


def wait_for(predicate, what, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError('timed out waiting for ' + what + '\n' + DIAGNOSTICS())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux root is required')
    if subprocess.run(['sh', '-c', 'command -v nft'], capture_output=True).returncode:
        print('SKIP nft is not installed')
        return
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    client, router = f'n66c{os.getpid()}', f'n66r{os.getpid()}'
    script = ROOT / 'test/system/test_ra_supervisor.py'
    results, supervisor = [], None
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        (work / 'bin').mkdir()
        (work / 'runtime').mkdir()
        os.symlink(args.binary.resolve(), work / 'bin/tayga')
        os.symlink(args.helper.resolve(), work / 'bin/pref64-discover')
        env = dict(os.environ, PATH=f'{work}/bin:{os.environ["PATH"]}', TAYGA_NET_STATE=str(work / 'state'))
        env.pop('SSH_CONNECTION', None)
        env.pop('SSH_CLIENT', None)

        def ns(name, *cmd, check=True, **kw):
            return subprocess.run(['ip', 'netns', 'exec', name, *cmd], check=check, env=env,
                                  capture_output=True, text=True, **kw)

        def rules():
            return ns(client, 'nft', 'list', 'ruleset').stdout

        try:
            for name in (client, router):
                subprocess.run(['ip', 'netns', 'add', name], check=True)
            subprocess.run(['ip', 'link', 'add', 'cwan0', 'netns', client, 'type', 'veth',
                            'peer', 'name', 'crt0', 'netns', router], check=True)
            for name, dev, addr in ((client, 'cwan0', '2001:db8:2::2/64'), (router, 'crt0', '2001:db8:2::1/64')):
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
                ns(name, 'sysctl', '-qw', f'net.ipv6.conf.{dev}.accept_ra=0')
                ns(name, 'ip', '-6', 'addr', 'add', addr, 'dev', dev, 'nodad')
                ns(name, 'ip', 'link', 'set', dev, 'up')
            ns(router, 'ip', '-6', 'addr', 'add', 'fe80::1/64', 'dev', 'crt0', 'nodad')
            ns(client, 'ip', '-6', 'addr', 'add', 'fe80::2/64', 'dev', 'cwan0', 'nodad')
            ns(client, 'ip', '-4', 'addr', 'add', '10.77.0.2/24', 'dev', 'cwan0')
            ns(client, 'ip', '-4', 'route', 'add', 'default', 'via', '10.77.0.1', 'dev', 'cwan0', 'onlink')
            ns(client, 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:2::1', 'dev', 'cwan0', 'onlink')

            # The installer ships the controller executable; the source tree keeps it as a script.
            controller = work / 'bin/tayga-net-ctl'
            controller.write_text('#!/bin/sh\nexec sh ' + shlex.quote(str(NET_CTL)) + ' "$@"\n')
            controller.chmod(0o755)
            config = work / 'clat.conf'
            (work / 'state').mkdir()
            subprocess.run(['sh', str(CONFIGURE), '--mode=clat', f'--pref64={A}/96',
                            '--clat-ipv6=fd64:2::464', '--tayga-ipv6=fd64:2::465',
                            '--clat-address-mode=nat66', '--workers=1', '--offload=off',
                            '--firewall=nft', f'--output={config}'],
                           check=True, env=dict(env, NAT66_ADDRESS='2001:db8:2::2'))
            (work / 'data').mkdir()
            text = ''.join(f'data-dir {work / "data"}\n' if line.startswith('data-dir ') else line
                           for line in config.read_text().splitlines(keepends=True))
            config.write_text(text + '# installer-pref64-interface cwan0\n')
            profile = config.read_text()

            ns(client, 'sh', str(NET_CTL), 'up', str(config))
            assert f'{A}/96' in rules(), 'initial NAT66 rule missing'
            results.append('controller installs the rule for A')

            log = (out / 'supervisor.log').open('w')
            supervisor = subprocess.Popen(
                ['ip', 'netns', 'exec', client, str(args.helper.resolve()), '--supervise-ra', str(config),
                 '--network-controller', str(controller), '--runtime-dir', str(work / 'runtime'), '--',
                 'tayga', '--config', str(config), '--runtime-dir', str(work / 'runtime'), '-d'],
                env=env, stdout=log, stderr=log, start_new_session=True)

            def emit(prefix, units):
                ns(router, sys.executable, str(script), '--emit', prefix, str(units), 'crt0', 'fe80::1')

            def translator_prefix():
                snap = subprocess.run(['pgrep', '-ax', 'tayga'], capture_output=True, text=True).stdout
                for line in snap.splitlines():
                    parts = shlex.split(line)
                    if '--config' in parts:
                        path = Path(parts[parts.index('--config') + 1])
                        if path.exists():
                            for row in path.read_text().splitlines():
                                if row.startswith('prefix '):
                                    return row.split()[1]
                return None

            time.sleep(0.5)
            emit(A, 20)
            def diagnostics():
                return ('supervisor returncode: %s\nsupervisor log:\n%s\nrules:\n%s' %
                        (supervisor.poll(), (out / 'supervisor.log').read_text(), rules()))
            global DIAGNOSTICS
            DIAGNOSTICS = diagnostics
            wait_for(lambda: translator_prefix() == f'{A}/96', 'translator on A')
            assert f'{A}/96' in rules() and f'{B}/96' not in rules()
            results.append('supervisor starts on A without touching the rules')

            emit(B, 20)
            wait_for(lambda: translator_prefix() == f'{B}/96', 'translator on B')
            wait_for(lambda: f'{B}/96' in rules(), 'rule for B')
            assert f'{A}/96' not in rules(), 'rule for the old prefix survived:\n' + rules()
            assert (work / 'runtime/active-prefix').read_text().split()[0] == f'{B}/96'
            results.append('replacement: rules name only B, translator runs on B')

            emit(B, 0)
            wait_for(lambda: translator_prefix() is None, 'translator stopped after withdrawal')
            assert supervisor.poll() is None, 'supervisor must survive the outage'
            assert f'{B}/96' in rules() and f'{A}/96' not in rules(), 'outage must leave the rules alone'
            emit(B, 20)
            wait_for(lambda: translator_prefix() == f'{B}/96', 'translator back on B')
            assert rules().count(f'{B}/96') >= 1 and f'{A}/96' not in rules()
            results.append('outage keeps rules; same prefix returns without a network rebuild')

            os.killpg(supervisor.pid, signal.SIGTERM)
            supervisor.wait(timeout=15)
            supervisor = None
            assert profile == config.read_text(), 'installed profile must be unchanged'
            ns(client, 'sh', str(NET_CTL), 'down', str(config))
            assert 'tayga_sfx' not in rules(), 'rules left after down:\n' + rules()
            results.append('down removes everything')
        finally:
            if supervisor is not None:
                try:
                    os.killpg(supervisor.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                supervisor.wait()
            if (work / 'state').exists():
                ns(client, 'sh', str(NET_CTL), 'down', str(work / 'clat.conf'), check=False)
            for name in (client, router):
                subprocess.run(['ip', 'netns', 'del', name], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('PASS NAT66 prefix change:', ', '.join(results))


if __name__ == '__main__':
    main()
