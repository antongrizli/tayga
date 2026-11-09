#!/usr/bin/env python3
"""Linux RA-supervisor process lifecycle. Requires root, iproute2 and Scapy.
No network or process is created on import. Use --helper and a new --output.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import shlex
import socket
import subprocess
import sys
import time


def child(config, events):
    events = Path(events)
    pid = os.getpid()
    prefix = next(line.split()[1] for line in Path(config).read_text().splitlines()
                  if line.startswith('prefix '))
    def received(sig, _frame):
        (events / f'{pid}.{sig}').write_text('received')
        if sig in (signal.SIGTERM, signal.SIGINT):
            raise SystemExit(0)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGUSR2):
        signal.signal(sig, received)
    network_state = events.parent / 'network-state'
    if network_state.exists():
        assert network_state.read_text() == prefix, 'translator/network prefix mismatch'
    (events / f'{pid}.start').write_text(prefix)
    while True:
        signal.pause()


def network_fixture(output, action, config):
    output = Path(output)
    prefix = next(line.split()[1] for line in Path(config).read_text().splitlines()
                  if line.startswith('prefix '))
    with (output / 'controller.jsonl').open('a') as log:
        log.write(json.dumps({'action': action, 'prefix': prefix}) + '\n')
    if action == 'down':
        (output / 'network-state').write_text('none')
    elif action == 'up':
        failure = output / 'fail-prefix'
        if failure.exists() and failure.read_text() == prefix:
            raise SystemExit(1)
        (output / 'network-state').write_text(prefix)
    else:
        raise SystemExit(2)


def emit(prefix, units):
    from scapy.all import Ether, IPv6, ICMPv6ND_RA, Raw, sendp
    import struct
    # Explicit link-local address assigned during setup; all-nodes multicast.
    option = bytes([38, 2]) + struct.pack('!H', units << 3)
    option += socket.inet_pton(socket.AF_INET6, prefix)[:12]
    packet = (Ether(dst='33:33:00:00:00:01') /
              IPv6(src='fe80::1', dst='ff02::1', hlim=255) /
              ICMPv6ND_RA(routerlifetime=0) / Raw(option))
    sendp(packet, iface='vr', count=2, inter=0.1, verbose=False)


def wait_for(predicate, timeout=7):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError('timed out waiting for expected lifecycle event')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux root is required')
    helper, script = str(args.helper.resolve()), str(Path(__file__).resolve())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    events = out / 'events'
    events.mkdir()
    client, router = f'ras-c{os.getpid()}', f'ras-r{os.getpid()}'
    proc = None
    processes, owned_namespaces = [], []
    log = (out / 'supervisor.log').open('w')
    results = []
    def run(*command):
        return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def advertise(prefix, units):
        run('ip', 'netns', 'exec', router, sys.executable, script, '--emit', prefix, str(units))
    def started(prefix, exclude=None):
        for path in events.glob('*.start'):
            pid = int(path.stem)
            if pid != exclude and path.read_text() == prefix:
                return pid
        return None
    def launch(controller=None):
        control = ['--network-controller', str(controller)] if controller else []
        process = subprocess.Popen(['ip', 'netns', 'exec', client, helper,
                                 '--supervise-ra', str(config), *control, '--', sys.executable,
                                 script, '--child', str(config), str(events)],
                                stdout=log, stderr=log, start_new_session=True)
        processes.append(process)
        return process
    a, b = '2001:db8:1::', '2001:db8:2::'
    config = out / 'profile.conf'
    original = '# installer-pref64-interface vc\nprefix ' + a + '/96\n'
    config.write_text(original)
    try:
        for ns in (client, router):
            run('ip', 'netns', 'add', ns)
            owned_namespaces.append(ns)
        run('ip', 'link', 'add', 'vc', 'netns', client, 'type', 'veth',
            'peer', 'name', 'vr', 'netns', router)
        for ns, dev, address in ((client, 'vc', 'fe80::2'), (router, 'vr', 'fe80::1')):
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
            run('ip', 'netns', 'exec', ns, 'sysctl', '-qw', f'net.ipv6.conf.{dev}.accept_ra=0')
            run('ip', '-n', ns, '-6', 'addr', 'add', address + '/64', 'dev', dev, 'nodad')
            run('ip', '-n', ns, 'link', 'set', dev, 'up')
        proc = launch()
        time.sleep(0.3)
        advertise(a, 1)
        first = wait_for(lambda: started(a + '/96'))
        time.sleep(4)
        advertise(a, 1)
        time.sleep(5)
        assert proc.poll() is None, 'renewal failed to extend lifetime'
        assert not (events / f'{first}.{signal.SIGTERM}').exists(), 'renewal restarted child'
        results.append('renewal without restart')
        advertise(b, 2)
        second = wait_for(lambda: started(b + '/96', first))
        assert (events / f'{first}.{signal.SIGTERM}').exists(), 'old child not stopped'
        os.kill(proc.pid, signal.SIGUSR2)
        wait_for(lambda: (events / f'{second}.{signal.SIGUSR2}').exists())
        advertise(a, 0)
        time.sleep(0.3)
        assert proc.poll() is None, 'unrelated withdrawal stopped supervisor'
        advertise(b, 0)
        assert proc.wait(timeout=9) != 0, 'withdrawal must report failure'
        assert (events / f'{second}.{signal.SIGTERM}').exists()
        assert config.read_text() == original
        assert not list(out.glob('profile.conf.ra.*')), 'snapshot leaked after withdrawal'
        results.extend(['prefix replacement', 'signal forwarding', 'withdrawal', 'snapshot cleanup'])
        proc = launch()
        time.sleep(0.3)
        advertise(a, 1)
        third = wait_for(lambda: started(a + '/96', first))
        assert proc.wait(timeout=15) != 0, 'expiry must report failure'
        assert (events / f'{third}.{signal.SIGTERM}').exists()
        assert not list(out.glob('profile.conf.ra.*'))
        results.append('expiry')
        controller = out / 'network-controller'
        controller.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' +
                              shlex.quote(script) + ' --network-fixture ' +
                              shlex.quote(str(out)) + ' "$@"\n')
        controller.chmod(0o700)
        nat66_config = original + '# installer-clat-address-mode nat66\n'
        config.write_text(nat66_config)
        for failing in (False, True):
            for path in events.iterdir():
                path.unlink()
            (out / 'network-state').write_text(a + '/96')
            (out / 'controller.jsonl').write_text('')
            if failing:
                (out / 'fail-prefix').write_text(b + '/96')
            proc = launch(controller)
            time.sleep(0.3)
            advertise(a, 5)
            first = wait_for(lambda: started(a + '/96'))
            advertise(b, 5)
            if failing:
                assert proc.wait(timeout=10) != 0
                assert not started(b + '/96'), 'translator started after failed network update'
                assert (out / 'network-state').read_text() == a + '/96'
            else:
                wait_for(lambda: started(b + '/96'))
                assert (out / 'network-state').read_text() == b + '/96'
                os.kill(proc.pid, signal.SIGTERM)
                assert proc.wait(timeout=9) == 0
            assert (events / f'{first}.{signal.SIGTERM}').exists()
            actions = [json.loads(line) for line in (out / 'controller.jsonl').read_text().splitlines()]
            expected = [{'action': 'down', 'prefix': a + '/96'},
                        {'action': 'up', 'prefix': b + '/96'}]
            if failing:
                expected.append({'action': 'up', 'prefix': a + '/96'})
            assert actions == expected, actions
            assert config.read_text() == nat66_config
            assert not list(out.glob('profile.conf.ra.*'))
        results.extend(['NAT66 controller ordering', 'NAT66 network failure restore'])

    finally:
        for proc in processes:
            # Always clean the private process group, even if supervisor crashed.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                time.sleep(0.2)
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        for ns in reversed(owned_namespaces):
            subprocess.run(['ip', 'netns', 'del', ns], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.close()
        (out / 'results.json').write_text(json.dumps({'completed': results}, indent=2) + '\n')
    print('PASS RA supervisor:', ', '.join(results))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child(sys.argv[2], sys.argv[3])
    elif len(sys.argv) > 1 and sys.argv[1] == '--network-fixture':
        network_fixture(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) > 1 and sys.argv[1] == '--emit':
        emit(sys.argv[2], int(sys.argv[3]))
    else:
        main()
