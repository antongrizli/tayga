#!/usr/bin/env python3
"""Linux/FreeBSD RA-supervisor process lifecycle. Requires root.
Linux uses iproute2/Scapy; FreeBSD uses epair and native raw ICMPv6.
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


def emit(prefix, units, device='vr', source='fe80::1'):
    if sys.platform.startswith('freebsd'):
        import struct
        idx = socket.if_nametoindex(device)
        option = bytes([38, 2]) + struct.pack('!H', units << 3)
        option += socket.inet_pton(socket.AF_INET6, prefix)[:12]
        # The IPv6 stack computes the checksum for raw ICMPv6 sockets.
        ra = struct.pack('!BBHBBHII', 134, 0, 0, 64, 0, 0, 0, 0) + option
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sender:
            sender.bind((source, 0, 0, idx))
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            for _ in range(2):
                sender.sendto(ra, ('ff02::1', 0, 0, idx))
                time.sleep(0.1)
        return
    from scapy.all import Ether, IPv6, ICMPv6ND_RA, Raw, sendp
    import struct
    # Explicit link-local address assigned during setup; all-nodes multicast.
    option = bytes([38, 2]) + struct.pack('!H', units << 3)
    option += socket.inet_pton(socket.AF_INET6, prefix)[:12]
    packet = (Ether(dst='33:33:00:00:00:01') /
              IPv6(src=source, dst='ff02::1', hlim=255) /
              ICMPv6ND_RA(routerlifetime=0) / Raw(option))
    sendp(packet, iface=device, count=2, inter=0.1, verbose=False)


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
    freebsd = sys.platform.startswith('freebsd')
    if (sys.platform != 'linux' and not freebsd) or os.geteuid() != 0:
        parser.error('Linux or FreeBSD root is required')
    helper, script = str(args.helper.resolve()), str(Path(__file__).resolve())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    events = out / 'events'
    events.mkdir()
    client, router = f'ras-c{os.getpid()}', f'ras-r{os.getpid()}'
    client_device = f'rc{os.getpid()}' if freebsd else 'vc'
    router_device = f'rr{os.getpid()}' if freebsd else 'vr'
    epair = None
    proc = None
    processes, owned_namespaces = [], []
    log = (out / 'supervisor.log').open('w')
    results = []
    def run(*command):
        return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def advertise(prefix, units, source='fe80::1'):
        command = [sys.executable, script, '--emit', prefix, str(units), router_device, source]
        run(*(command if freebsd else ['ip', 'netns', 'exec', router, *command]))
    def started(prefix, exclude=None):
        for path in events.glob('*.start'):
            pid = int(path.stem)
            if pid != exclude and path.read_text() == prefix:
                return pid
        return None
    runtime = out / 'runtime'
    runtime.mkdir()
    def launch(controller=None, extra=()):
        control = ['--network-controller', str(controller)] if controller else []
        process = subprocess.Popen(([] if freebsd else ['ip', 'netns', 'exec', client]) + [helper,
                                 '--supervise-ra', str(config), *control, '--runtime-dir', str(runtime),
                                 *extra, '--', sys.executable,
                                 script, '--child', str(config), str(events)],
                                stdout=log, stderr=log, start_new_session=True)
        processes.append(process)
        return process
    a, b = '2001:db8:1::', '2001:db8:2::'
    config = out / 'profile.conf'
    original = '# installer-pref64-interface ' + client_device + '\nprefix ' + a + '/96\n'
    config.write_text(original)
    try:
        if freebsd:
            epair = run('ifconfig', 'epair', 'create').stdout.decode().strip()
            peer = epair[:-1] + 'b'
            run('ifconfig', epair, 'name', client_device)
            epair = client_device
            run('ifconfig', peer, 'name', router_device)
            for dev, address in ((client_device, 'fe80::2'), (router_device, 'fe80::1'),
                                 (router_device, 'fe80::3')):
                run('ifconfig', dev, 'up')
                run('ifconfig', dev, 'inet6', address, 'prefixlen', '64', 'alias')
            time.sleep(2)  # DAD on the private epair, not a global sysctl change.
        else:
            for ns in (client, router):
                run('ip', 'netns', 'add', ns)
                owned_namespaces.append(ns)
            run('ip', 'link', 'add', 'vc', 'netns', client, 'type', 'veth',
                'peer', 'name', 'vr', 'netns', router)
            for ns, dev, address in ((client, 'vc', 'fe80::2'), (router, 'vr', 'fe80::1'),
                                     (router, 'vr', 'fe80::3')):
                run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
                run('ip', 'netns', 'exec', ns, 'sysctl', '-qw', f'net.ipv6.conf.{dev}.accept_ra=0')
                run('ip', '-n', ns, '-6', 'addr', 'add', address + '/64', 'dev', dev, 'nodad')
                run('ip', '-n', ns, 'link', 'set', dev, 'up')
        active_file = runtime / 'active-prefix'
        proc = launch()
        time.sleep(0.3)
        advertise(a, 1)
        first = wait_for(lambda: started(a + '/96'))
        wait_for(active_file.exists)
        assert active_file.read_text().split()[0] == a + '/96', 'active-prefix not published'
        time.sleep(4)
        advertise(a, 1)
        time.sleep(5)
        assert proc.poll() is None, 'renewal failed to extend lifetime'
        assert not (events / f'{first}.{signal.SIGTERM}').exists(), 'renewal restarted child'
        results.append('renewal without restart')
        advertise(b, 2)
        second = wait_for(lambda: started(b + '/96', first))
        assert (events / f'{first}.{signal.SIGTERM}').exists(), 'old child not stopped'
        wait_for(lambda: active_file.read_text().split()[0] == b + '/96')
        os.kill(proc.pid, signal.SIGUSR2)
        wait_for(lambda: (events / f'{second}.{signal.SIGUSR2}').exists())
        advertise(a, 0)
        time.sleep(0.3)
        assert proc.poll() is None, 'unrelated withdrawal stopped supervisor'
        advertise(b, 0)
        # Withdrawn everywhere: the translator stops, the supervisor stays and solicits.
        wait_for(lambda: (events / f'{second}.{signal.SIGTERM}').exists())
        assert not active_file.exists(), 'active-prefix kept after withdrawal'
        time.sleep(0.5)
        assert proc.poll() is None, 'supervisor must outlive a prefix outage'
        advertise(b, 20)
        recovered = wait_for(lambda: started(b + '/96', second))
        os.kill(proc.pid, signal.SIGTERM)
        assert proc.wait(timeout=9) == 0, 'SIGTERM must end the supervisor cleanly'
        assert (events / f'{recovered}.{signal.SIGTERM}').exists()
        assert config.read_text() == original
        assert not list(out.glob('profile.conf.ra.*')), 'snapshot leaked after stop'
        assert not active_file.exists()
        results.extend(['prefix replacement', 'signal forwarding', 'withdrawal outage and recovery',
                        'active-prefix file', 'snapshot cleanup'])

        # Expiry: the translator stops, the supervisor waits, a later RA restarts it.
        for path in events.iterdir():
            path.unlink()
        proc = launch()
        time.sleep(0.3)
        advertise(a, 1)
        third = wait_for(lambda: started(a + '/96'))
        wait_for(lambda: (events / f'{third}.{signal.SIGTERM}').exists(), timeout=15)
        assert proc.poll() is None, 'expiry must not end the supervisor'
        advertise(a, 20)
        wait_for(lambda: started(a + '/96', third))
        os.kill(proc.pid, signal.SIGTERM)
        assert proc.wait(timeout=9) == 0
        assert not list(out.glob('profile.conf.ra.*'))
        results.append('expiry and re-advertisement')

        # Two routers with different prefixes must not make the translator flap.
        for path in events.iterdir():
            path.unlink()
        proc = launch()
        time.sleep(0.3)
        advertise(a, 25, 'fe80::1')
        first = wait_for(lambda: started(a + '/96'))
        for _ in range(4):
            advertise(b, 25, 'fe80::3')
            advertise(a, 25, 'fe80::1')
        time.sleep(1)
        assert proc.poll() is None
        assert len(list(events.glob('*.start'))) == 1, 'translator restarted by a second router'
        assert not (events / f'{first}.{signal.SIGTERM}').exists()
        os.kill(proc.pid, signal.SIGTERM)
        assert proc.wait(timeout=9) == 0
        results.append('two routers without flapping')

        # A prefix learned elsewhere starts the translator without a first RA,
        # and the first real RA supersedes it.
        for path in events.iterdir():
            path.unlink()
        proc = launch(extra=['--initial-prefix', a + '/96', '--initial-lifetime', '60'])
        initial = wait_for(lambda: started(a + '/96'), timeout=3)
        advertise(b, 20)
        wait_for(lambda: started(b + '/96', initial))
        assert (events / f'{initial}.{signal.SIGTERM}').exists()
        os.kill(proc.pid, signal.SIGTERM)
        assert proc.wait(timeout=9) == 0
        results.append('initial prefix')

        # First start without any RA: three solicitations, then a failed start.
        for path in events.iterdir():
            path.unlink()
        began = time.monotonic()
        proc = launch()
        assert proc.wait(timeout=25) != 0, 'start without any RA must fail'
        waited = time.monotonic() - began
        assert 9 <= waited <= 20, f'unexpected start-up window {waited:.1f}s'
        assert not started(a + '/96')
        results.append('start-up solicitation window')

        # A late first RA (after the old 3 s window) still starts the translator.
        for path in events.iterdir():
            path.unlink()
        proc = launch()
        time.sleep(6)
        advertise(a, 20)
        wait_for(lambda: started(a + '/96'))
        os.kill(proc.pid, signal.SIGTERM)
        assert proc.wait(timeout=9) == 0
        results.append('late first RA')
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
        if epair is not None:
            subprocess.run(['ifconfig', epair, 'destroy'], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        emit(sys.argv[2], int(sys.argv[3]), sys.argv[4] if len(sys.argv) > 4 else 'vr',
             sys.argv[5] if len(sys.argv) > 5 else 'fe80::1')
    else:
        main()
