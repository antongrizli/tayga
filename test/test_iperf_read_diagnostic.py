#!/usr/bin/env python3
"""Check that receive instrumentation preserves results and errno."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

@unittest.skipUnless(sys.platform.startswith('linux'),'Linux preload diagnostic')
class DiagnosticTest(unittest.TestCase):
    def test_errors_and_payload_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lib=root/'diagnostic.so';binary=root/'fixture'
            subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(Path(__file__).resolve().parents[1]/'tools/iperf-read-diagnostic.c'),'-ldl','-o',str(lib)],check=True)
            source=root/'fixture.c'
            source.write_text('''#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
 char b[4]; int f[2];
 assert(read(-1,b,4)==-1 && errno==EBADF);
 assert(socketpair(AF_UNIX,SOCK_DGRAM,0,f)==0);
 assert(recv(f[0],b,4,MSG_DONTWAIT)==-1 && errno==EAGAIN);
 errno=EDOM;
 assert(write(f[1],"9876",4)==4 && errno==EDOM);
 assert(recv(f[0],b,4,0)==4 && memcmp(b,"9876",4)==0);
 close(f[0]);close(f[1]);return 0;
}
''')
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True)
            result=subprocess.run([str(binary)],env=dict(os.environ,LD_PRELOAD=str(lib)),capture_output=True,text=True,check=True)
            self.assertIn('errno=9',result.stderr)
            self.assertIn('result=-1 errno=11',result.stderr)
            self.assertIn('first4=39383736',result.stderr)
            self.assertIn('UDP_SETUP_WRITE',result.stderr)

    def test_udp_connect_return_and_errno_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lib=root/'diagnostic.so';mock=root/'mock.so';binary=root/'fixture'
            subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(Path(__file__).resolve().parents[1]/'tools/iperf-read-diagnostic.c'),'-ldl','-o',str(lib)],check=True)
            (root/'mock.c').write_text('#include <errno.h>\nint i_errno=123;\nint iperf_udp_connect(void *test) { (void)test; errno=EPROTO; return -1; }\n')
            subprocess.run(['cc','-shared','-fPIC',str(root/'mock.c'),'-o',str(mock)],check=True)
            (root/'fixture.c').write_text('#include <assert.h>\n#include <errno.h>\nint iperf_udp_connect(void *);\nint main(void) { assert(iperf_udp_connect(0)==-1 && errno==EPROTO); return 0; }\n')
            subprocess.run(['cc',str(root/'fixture.c'),str(mock),'-Wl,-rpath,'+str(root),'-o',str(binary)],check=True)
            result=subprocess.run([str(binary)],env=dict(os.environ,LD_PRELOAD=str(lib)),capture_output=True,text=True,check=True)
            self.assertIn('UDP_CONNECT_RESULT',result.stderr)
            self.assertIn('result=-1 errno=71 i_errno=123',result.stderr)

if __name__=='__main__': unittest.main()
