#!/usr/bin/env python3
"""Readiness notification is optional: an unusable NOTIFY_SOCKET must not stop the daemon.

Also checks that a usable one still receives READY=1.  Linux, root; own netns and TUN.
"""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    binary = str(Path(a.binary).resolve())
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=False)
    ns = f'tayga-notify-{os.getpid()}'
    subprocess.run(['ip', 'netns', 'add', ns], check=True)
    results = []

    def run(*cmd):
        return subprocess.run(['ip', 'netns', 'exec', ns, *cmd], check=True, capture_output=True, text=True)

    with tempfile.TemporaryDirectory() as temp:
        tmp = Path(temp)
        try:
            run('ip', 'link', 'set', 'lo', 'up')
            run('ip', 'tuntap', 'add', 'dev', 'notify0', 'mode', 'tun', 'multi_queue')
            cfg = tmp / 'tayga.conf'
            cfg.write_text('tun-device notify0\nipv4-addr 192.0.2.1\nipv6-addr 2001:db8::1\n'
                           'prefix 64:ff9b::/96\nworkers 0\ntun-offload off\ntun-up yes\n')

            def start(notify_path):
                env = dict(os.environ, NOTIFY_SOCKET=notify_path)
                return subprocess.Popen(['ip', 'netns', 'exec', ns, binary, '-d', '-c', str(cfg),
                                         '--runtime-dir', str(tmp)], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            # Unreachable socket: warn, keep running.
            proc = start(str(tmp / 'missing-dir' / 'notify'))
            time.sleep(2)
            assert proc.poll() is None, 'daemon exited because NOTIFY_SOCKET was unusable'
            proc.send_signal(signal.SIGTERM)
            output = proc.communicate(timeout=10)[0]
            (out / 'unreachable.log').write_text(output)
            assert 'Readiness socket unavailable' in output, output
            results.append('unusable NOTIFY_SOCKET is a warning')

            # Working socket: READY=1 arrives.
            path = str(tmp / 'notify.sock')
            server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            server.bind(path)
            server.settimeout(8)
            proc = start(path)
            try:
                message = server.recv(256)
                assert b'READY=1' in message, message
            finally:
                proc.send_signal(signal.SIGTERM)
                (out / 'working.log').write_text(proc.communicate(timeout=10)[0])
                server.close()
            results.append('READY=1 still delivered')
        finally:
            subprocess.run(['ip', 'netns', 'del', ns], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('PASS notify optional:', ', '.join(results))


if __name__ == '__main__':
    main()
