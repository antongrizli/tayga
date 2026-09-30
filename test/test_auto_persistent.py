#!/usr/bin/env python3
"""Verify persistent TUN configuration, restart, ownership and removal."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='/usr/sbin/tayga')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    lock = open('/tmp/tayga-perf-workflow.lock', 'r')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    ns = f'tayga-persist-{os.getpid()}'
    proc = None
    def run(*command, **kw):
        return subprocess.run(['ip', 'netns', 'exec', ns, *map(str, command)],
                              check=True, capture_output=True, text=True, timeout=10, **kw)
    def config_state():
        addresses = json.loads(run('ip', '-j', 'addr', 'show', 'dev', 'autotun').stdout)
        routes = json.loads(run('ip', '-j', 'route', 'show', 'table', 'all', 'dev', 'autotun').stdout)
        routes += json.loads(run('ip', '-j', '-6', 'route', 'show', 'table', 'all', 'dev', 'autotun').stdout)
        # Dynamic link-local DAD timing and lifetime fields are kernel-managed.
        a = sorted((x['family'], x['local'], x['prefixlen']) for x in addresses[0]['addr_info']
                   if x['scope'] != 'link')
        keys = ('dst', 'gateway', 'prefsrc', 'table', 'protocol', 'scope')
        r = sorted(tuple(str(x.get(k, '')) for k in keys) for x in routes
                   if x.get('protocol') != 'kernel')
        return a, r
    subprocess.run(['ip', 'netns', 'add', ns], check=True)
    try:
        with tempfile.TemporaryDirectory(prefix='tayga-persistent-') as tmp:
            cfg = Path(tmp) / 'tayga.conf'
            for iteration in range(4):
                for mode in ('auto', 'tcp', 'off'):
                    for workers in (0, 3):
                        cfg.write_text(f'tun-device autotun\nipv4-addr 192.0.2.1\n'
                                       f'ipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\n'
                                       f'workers {workers}\ntun-offload {mode}\n')
                        if iteration == 0 and mode == 'auto' and workers == 0:
                            run(args.binary, '-c', cfg, '--mktun')
                            run('ip', 'link', 'set', 'autotun', 'up')
                            run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'autotun')
                            run('ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'autotun', 'nodad')
                            run('ip', 'route', 'add', '198.51.100.0/24', 'dev', 'autotun')
                            run('ip', '-6', 'route', 'add', '2001:db8:2::/64', 'dev', 'autotun')
                            run('ip', 'route', 'add', '203.0.113.0/24', 'dev', 'autotun', 'table', '100')
                        before = config_state()
                        case = f'{iteration}-{mode}-w{workers}'
                        log_path = out / (case + '.log')
                        with log_path.open('w') as log:
                            proc = subprocess.Popen(['ip', 'netns', 'exec', ns, args.binary, '-d', '-c', str(cfg)],
                                                    stdout=log, stderr=subprocess.STDOUT)
                            deadline = time.monotonic() + 5
                            while time.monotonic() < deadline:
                                if proc.poll() is not None or 'TUN offload negotiated:' in log_path.read_text():
                                    break
                                time.sleep(.02)
                            assert proc.poll() is None, log_path.read_text()
                            assert 'TUN offload negotiated:' in log_path.read_text(), log_path.read_text()
                            assert config_state() == before, (before, config_state(), log_path.read_text())
                            contender = subprocess.run(['ip', 'netns', 'exec', ns, args.binary, '-d', '-c', str(cfg)],
                                                       capture_output=True, text=True, timeout=5)
                            assert contender.returncode != 0 and 'exclusive TUN ownership' in contender.stdout + contender.stderr, contender
                            assert config_state() == before
                            proc.terminate()
                            assert proc.wait(timeout=5) == 0
                            proc = None
                        print('PASS', case, flush=True)
            # Removal succeeds even when header capability queries are broken.
            shim = Path(tmp) / 'fault.so'
            subprocess.run(['cc', '-Wall', '-Werror', '-shared', '-fPIC', str(Path(__file__).with_name('offload_ioctl_fault.c')),
                            '-o', str(shim), '-ldl'], check=True)
            env = os.environ.copy()
            env.update(LD_PRELOAD=str(shim), TAYGA_TEST_OFFLOAD_FAIL='header')
            run(args.binary, '-c', cfg, '--rmtun', env=env)
            assert all(link['ifname'] != 'autotun' for link in json.loads(run('ip', '-j', 'link', 'show').stdout))
            (out / 'summary.json').write_text(json.dumps({'restart_cases': 24, 'ownership_cases': 24, 'removal_passed': True}) + '\n')
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
        subprocess.run(['ip', 'netns', 'del', ns], check=True)


if __name__ == '__main__':
    main()
