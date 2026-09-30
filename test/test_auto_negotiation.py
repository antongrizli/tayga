#!/usr/bin/env python3
"""Root-only startup negotiation/failure matrix on disposable Linux namespaces."""
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
    workflow = open('/tmp/tayga-perf-workflow.lock', 'r')
    fcntl.flock(workflow, fcntl.LOCK_EX | fcntl.LOCK_NB)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix='tayga-auto-negotiation-') as tmp:
        shim = Path(tmp) / 'fault.so'
        subprocess.run(['cc', '-Wall', '-Werror', '-fPIC', '-shared',
                        str(Path(__file__).with_name('offload_ioctl_fault.c')),
                        '-o', str(shim), '-ldl'], check=True)
        cases = [(None, 'auto', 'udp'), ('uso', 'auto', 'tcp'),
                 ('eintr-once', 'auto', 'udp'), ('eintr-always', 'auto', None),
                 ('attach-worker', 'auto', None),
                 ('uso-worker', 'auto', 'tcp'), ('all', 'auto', 'off'),
                 ('worker', 'auto', 'tcp'), ('all-worker', 'auto', 'off'),
                 ('disabled', 'auto', None), ('header-worker', 'auto', None), ('vnet', 'auto', 'off'),
                 ('header', 'auto', None), ('header-size', 'auto', None),
                 ('broken', 'auto', None), ('zero', 'off', None),
                 ('all', 'tcp', None), ('uso', 'udp', None),
                 (None, 'tcp', 'tcp'), (None, 'udp', 'udp'), (None, 'off', 'off')]
        for workers in (0, 1, 3):
            for fault, mode, expected in cases:
                if workers == 0 and fault in ('uso-worker', 'worker', 'all-worker', 'header-worker', 'attach-worker'):
                    continue
                name = f'w{workers}-{mode}-{fault or "supported"}'
                cfg = Path(tmp) / 'tayga.conf'
                cfg.write_text(f'tun-device autotest\nipv4-addr 192.0.2.1\n'
                               f'ipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\nworkers {workers}\ntun-offload {mode}\n')
                env = os.environ.copy()
                env['LD_PRELOAD'] = str(shim)
                if fault:
                    env['TAYGA_TEST_OFFLOAD_FAIL'] = fault
                log_path = output / (name + '.log')
                with log_path.open('w') as log:
                    proc = subprocess.Popen(['unshare', '-n', args.binary, '-d', '-c', str(cfg)],
                                            env=env, stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        text = log_path.read_text()
                        if 'TUN offload negotiated:' in text or proc.poll() is not None:
                            break
                        time.sleep(.05)
                    text = log_path.read_text()
                    if expected is None:
                        try:
                            assert proc.wait(timeout=2) != 0, text
                            assert 'TUN offload negotiated:' not in text, text
                        finally:
                            if proc.poll() is None:
                                proc.kill()
                                proc.wait(timeout=3)
                    else:
                        try:
                            assert proc.poll() is None, text
                            assert f'requested={mode} effective={expected}' in text, text
                            assert ('USO4|USO6' in text) == (expected == 'udp'), text
                            deadline = time.monotonic() + 3
                            status = {}
                            while time.monotonic() < deadline:
                                try:
                                    status = json.loads(Path('/run/tayga-status.json').read_text())
                                except (OSError, ValueError):
                                    pass
                                if status.get('pid') == proc.pid:
                                    break
                                time.sleep(.05)
                            assert status.get('pid') == proc.pid, status
                            assert status['offload_mode'] == mode, status
                            assert status['offload_effective'] == expected, status
                            assert status['offload_negotiation_complete'], status
                            assert status['offload_flags'] == {'off': 0, 'tcp': 7, 'udp': 103}[expected], status
                            assert status['udp_offload_available'] == (expected == 'udp'), status
                        finally:
                            if proc.poll() is None:
                                proc.terminate()
                                proc.wait(timeout=3)
                results.append(dict(case=name, expected=expected, passed=True))
                print('PASS', name, flush=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'Passed {len(results)} startup cases')


if __name__ == '__main__':
    main()
