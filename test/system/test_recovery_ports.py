#!/usr/bin/env python3
"""Scheduled data ports must survive ephemeral iperf control connections."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)  # Common system runner interface.
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux root required')
    lock = open('/tmp/tayga-perf-workflow.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    args.output.mkdir(parents=True, exist_ok=True)
    library = Path(__file__).resolve().parents[2] / 'bench/clat/lib/iperf.sh'
    namespace = f'tgports-{os.getpid()}'

    def run(*cmd, **kwargs):
        return subprocess.run(list(map(str, cmd)), check=True, **kwargs)

    run('ip', 'netns', 'add', namespace)
    try:
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', 'netns', 'exec', namespace, 'sysctl', '-qw',
            'net.ipv4.ip_local_port_range=40000 40011',
            'net.ipv4.ip_local_reserved_ports=12345')
        env = dict(os.environ, CLIENT_PORT_BASE='40000', CLIENTS='4', FLOWS='2',
                   ARTIFACT_DIR=str(args.output.resolve()))
        run('sh', '-c', '. "$1"; reserve_client_ports "$2"', 'sh', library,
            namespace, env=env)
        probe = r'''
import json, socket
from contextlib import ExitStack
from pathlib import Path
ranges=Path('/proc/sys/net/ipv4/ip_local_reserved_ports').read_text().strip()
reserved=set()
for interval in ranges.split(','):
    pair=list(map(int,interval.split('-')))
    reserved.update(range(pair[0],pair[-1]+1))
expected={12345}
for offset in (0,1000,2000,3000):expected.update(range(40002+offset,40010+offset))
assert reserved==expected,(reserved,expected)
with ExitStack() as stack:
    server=stack.enter_context(socket.socket());server.bind(('127.0.0.1',7000));server.listen(16)
    # Use distinct loopback source addresses, as the real four-client harness
    # does. Each control stays open while its explicitly bound data connects.
    pairs=[]
    for client in range(1,5):
        address=f'127.0.0.{client+1}'
        control=stack.enter_context(socket.socket());control.bind((address,0));control.connect(server.getsockname())
        stack.enter_context(server.accept()[0])
        assert control.getsockname()[1] not in reserved
        ports=[]
        for stream in range(2):
            port=40000+client*2+stream
            data=stack.enter_context(socket.socket());data.bind((address,port));data.connect(server.getsockname())
            stack.enter_context(server.accept()[0]);ports.append(data.getsockname()[1])
        pairs.append(dict(control=control.getsockname()[1],data=ports))
    print(json.dumps(dict(reserved=ranges,connections=pairs)))
'''
        result = run('ip', 'netns', 'exec', namespace, 'python3', '-c', probe,
                     capture_output=True, text=True)
        (args.output / 'connections.json').write_text(result.stdout)
        json.loads(result.stdout)
        print('PASS: ephemeral control sockets avoid all scheduled data ports; explicit binds succeed')
    finally:
        run('ip', 'netns', 'del', namespace)


if __name__ == '__main__':
    main()
