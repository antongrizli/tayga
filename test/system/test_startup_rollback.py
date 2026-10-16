#!/usr/bin/env python3
"""Fail each setup mutation and partial worker creation on an owned persistent TUN."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    binary = str(Path(a.binary).resolve())
    out = Path(a.output); out.mkdir(parents=True, exist_ok=False)
    with open('/tmp/tayga-perf-workflow.lock', 'a') as lock, tempfile.TemporaryDirectory() as temp:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tmp = Path(temp); shim = tmp/'fault.so'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', str(Path(__file__).resolve().parents[1] / "fault/startup_fault.c"), '-o', str(shim), '-ldl'], check=True)
        ns = 'tayga-rollback-'+str(os.getpid())
        subprocess.run(['ip', 'netns', 'add', ns], check=True)
        def run(*cmd, **kw):
            return subprocess.run(['ip', 'netns', 'exec', ns, *cmd], check=True, capture_output=True, text=True, **kw)
        def snapshot():
            addr = json.loads(run('ip','-j','addr','show','dev','rollback').stdout)
            addresses = sorted((x['family'], x['local'], x['prefixlen']) for x in addr[0]['addr_info'] if x['scope'] != 'link')
            routes = [json.loads(run('ip',family,'-j','route','show','table','all').stdout) for family in ('-4','-6')]
            # JSON order can change after replay; route cache observations are not configuration.
            for group in routes:
                group[:] = [row for row in group if row.get('protocol') != 'kernel']
                for row in group: row.pop('flags', None)
                group.sort(key=lambda row: json.dumps(row, sort_keys=True))
            return {'up': 'UP' in addr[0]['flags'], 'addresses': addresses, 'routes': routes}
        try:
            run('ip','link','set','lo','up')
            run('ip','tuntap','add','dev','rollback','mode','tun','multi_queue')
            run('ip','addr','add','192.0.2.7/32','dev','rollback')
            run('ip','-6','addr','add','2001:db8::7/128','dev','rollback','nodad')
            run('ip','link','set','rollback','up')
            run('ip','route','add','203.0.113.0/24','dev','lo')
            cfg = tmp/'config'; cfg.write_text('tun-device rollback\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\nprefix 64:ff9b::/96\nworkers 3\ntun-offload off\ntun-up yes\ntun-ip 192.0.2.9/32\ntun-ip 2001:db8::9/128\ntun-route 203.0.113.0/24\ntun-route 2001:db8:9::/64\n')
            (tmp/'maps').write_text('')
            cfg.write_text(cfg.read_text()+f'map-file {tmp / "maps"}\n')
            before = snapshot(); results = []
            # Two address replays precede four configured mutations.
            for var, steps in [('TAYGA_TEST_SETUP_FAIL', range(1,7)), ('TAYGA_TEST_THREAD_FAIL', (1,2,3)), ('TAYGA_TEST_BUFFER_OOM', range(1,6)), ('TAYGA_TEST_CACHE_OOM', (1,)), ('TAYGA_TEST_ACK_FAIL', range(1,7))]:
                for step in steps:
                    env = dict(os.environ, LD_PRELOAD=str(shim), **{var: str(step)})
                    result = subprocess.run(['ip','netns','exec',ns,binary,'-d','-c',str(cfg),'--runtime-dir',str(tmp)], env=env, capture_output=True, text=True, timeout=8)
                    (out/f'{var}-{step}.log').write_text(result.stdout+result.stderr)
                    assert result.returncode != 0, result.stdout
                    after = snapshot()
                    assert after == before, (var, step, before, after)
                    assert not (tmp/'tayga-status.json').exists(), 'premature readiness/telemetry'
                    results.append({'fault': var, 'step': step, 'passed': True})
                    print('PASS', var, step, flush=True)
            (out/'summary.json').write_text(json.dumps(results, indent=2)+'\n')
        finally:
            subprocess.run(['ip','netns','del',ns], check=True)
if __name__ == '__main__': main()
