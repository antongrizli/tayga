#!/usr/bin/env python3
"""Verify real worker-loop continuation, drained input and fatal poll handling."""
import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', default='/usr/sbin/tayga')
p.add_argument('--output', required=True)
a = p.parse_args()
with open('/tmp/tayga-perf-workflow.lock') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        shim = tmp/'fault.so'
        subprocess.run(['cc', '-Wall', '-Werror', '-shared', '-fPIC', str(Path(__file__).with_name('offload_ioctl_fault.c')), '-o', str(shim), '-ldl'], check=True)
        cfg = tmp/'tayga.conf'
        cfg.write_text('tun-device bursttest\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\nworkers 1\ntun-offload auto\n')
        for case, expected in [('full', 256), ('drain', 33)]:
            env = dict(os.environ, LD_PRELOAD=str(shim), TAYGA_TEST_BURST=case)
            result = subprocess.run(['unshare', '-n', a.binary, '-d', '-c', str(cfg)], env=env, text=True, capture_output=True, timeout=10)
            text = result.stdout + result.stderr
            (out/(case+'.log')).write_text(text)
            assert result.returncode == 1, text
            assert f'TEST_BURST_READS={expected}\n' in text, text
            assert 'worker TUN poll reported a failed descriptor' in text, text
            print('PASS', case, 'reads=', expected)

    # Empty input must sleep rather than spin, and shutdown must remain prompt.
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp)/'tayga.conf'
        cfg.write_text('tun-device idletest\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\nworkers 1\ntun-offload auto\n')
        with (out/'idle.log').open('w') as log:
            proc = subprocess.Popen(['unshare', '-n', a.binary, '-d', '-c', str(cfg)], stdout=log, stderr=subprocess.STDOUT)
            try:
                time.sleep(.5)
                def ticks():
                    fields = Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')', 1)[1].split()
                    return int(fields[11]) + int(fields[12])
                before = ticks()
                time.sleep(2)
                consumed = ticks() - before
                assert consumed <= os.sysconf('SC_CLK_TCK') / 10, consumed
                start = time.monotonic()
                proc.terminate()
                assert proc.wait(timeout=2) == 0
                (out/'idle-result.txt').write_text(f'cpu_ticks={consumed} shutdown_seconds={time.monotonic()-start:.3f}\n')
                print('PASS idle/shutdown ticks=', consumed)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
