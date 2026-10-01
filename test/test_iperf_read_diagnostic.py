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
 close(f[0]);close(f[1]);
 assert(socketpair(AF_UNIX,SOCK_STREAM,0,f)==0);
 assert(write(f[1],"AB",2)==2);
 errno=EDOM;
 assert(read(f[0],b,4)==2 && errno==EDOM && memcmp(b,"AB",2)==0);
 close(f[1]);
 assert(read(f[0],b,4)==0);
 close(f[0]);return 0;
}
''')
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True)
            result=subprocess.run([str(binary)],env=dict(os.environ,LD_PRELOAD=str(lib)),capture_output=True,text=True,check=True)
            self.assertIn('errno=9',result.stderr)
            self.assertIn('result=-1 errno=11',result.stderr)
            self.assertIn('first4=39383736',result.stderr)
            self.assertIn('UDP_SETUP_WRITE',result.stderr)
            self.assertIn('CONTROL_READ',result.stderr)
            self.assertIn('count=4 result=2',result.stderr)
            self.assertIn('count=4 result=0',result.stderr)

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

    def test_control_framing_and_exchange_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lib=root/'diagnostic.so';mock=root/'mock.so';binary=root/'fixture'
            subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(Path(__file__).resolve().parents[1]/'tools/iperf-read-diagnostic.c'),'-ldl','-o',str(lib)],check=True)
            (root/'mock.c').write_text('#include <errno.h>\n#include <unistd.h>\n#include <sys/select.h>\nint i_errno=0;\nint Nread(int fd,char *b,unsigned long count,int protocol) { (void)protocol; fd_set f; FD_ZERO(&f); FD_SET(fd,&f); struct timeval t={0,1000}; int r=select(fd+1,&f,0,0,&t); return r>0?read(fd,b,count):r; }\nint iperf_set_send_state(void *test,signed char state) { (void)test; (void)state; errno=ERANGE; return 7; }\nint iperf_exchange_results(void *test) { (void)test; i_errno=123; errno=EPROTO; return -1; }\n')
            subprocess.run(['cc','-shared','-fPIC',str(root/'mock.c'),'-o',str(mock)],check=True)
            (root/'fixture.c').write_text('#include <assert.h>\n#include <errno.h>\n#include <sys/socket.h>\n#include <unistd.h>\nint Nread(int,char *,unsigned long,int);\nint iperf_exchange_results(void *);\nint iperf_set_send_state(void *,signed char);\nint main(void) { int f[2]; char b[4]; assert(socketpair(AF_UNIX,SOCK_STREAM,0,f)==0); errno=EDOM; assert(Nread(f[0],b,4,1)==0 && errno==EDOM); assert(write(f[1],"AB",2)==2); errno=EDOM; assert(Nread(f[0],b,4,1)==2 && errno==EDOM); close(f[1]); assert(Nread(f[0],b,4,1)==0); assert(iperf_exchange_results(0)==-1 && errno==EPROTO); assert(iperf_set_send_state(0,4)==7 && errno==ERANGE); close(f[0]); return 0; }\n')
            subprocess.run(['cc',str(root/'fixture.c'),str(mock),'-Wl,-rpath,'+str(root),'-o',str(binary)],check=True)
            result=subprocess.run([str(binary)],env=dict(os.environ,LD_PRELOAD=str(lib),IPERF_DIAGNOSTIC_CONTROL_ONLY="1"),capture_output=True,text=True,check=True)
            self.assertIn('CONTROL_NREAD',result.stderr)
            self.assertIn('count=4 result=2 errno=33 first4=41420000',result.stderr)
            self.assertIn('count=4 result=0',result.stderr)
            self.assertIn('CONTROL_SELECT',result.stderr)
            self.assertIn('timeout=0.001000 result=0 errno=33',result.stderr)
            self.assertIn('state=4 result=7 errno=34',result.stderr)
            self.assertEqual(result.stderr.count('CONTROL_READ'),2)
            self.assertIn('EXCHANGE_BEGIN',result.stderr)
            self.assertIn('EXCHANGE_END',result.stderr)
            self.assertIn('result=-1 errno=71 i_errno=123',result.stderr)

    def test_control_only_skips_udp_socket_queries(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lib=root/'diagnostic.so';mock=root/'mock.so';binary=root/'fixture'
            subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(Path(__file__).resolve().parents[1]/'tools/iperf-read-diagnostic.c'),'-ldl','-o',str(lib)],check=True)
            (root/'mock.c').write_text('#define _GNU_SOURCE\n#include <sys/socket.h>\n#include <sys/syscall.h>\n#include <unistd.h>\nstatic int queries;\nint query_count(void) { return queries; }\nint getsockopt(int fd,int level,int option,void *value,socklen_t *length) { ++queries; return syscall(SYS_getsockopt,fd,level,option,value,length); }\n')
            subprocess.run(['cc','-shared','-fPIC',str(root/'mock.c'),'-o',str(mock)],check=True)
            (root/'fixture.c').write_text('#include <assert.h>\n#include <errno.h>\n#include <fcntl.h>\n#include <sys/socket.h>\n#include <unistd.h>\nint query_count(void);\nint main(void) { int f[2]; char b[4]; assert(socketpair(AF_UNIX,SOCK_DGRAM,0,f)==0); assert(send(f[1],"AB",2,0)==2); errno=EDOM; assert(read(f[0],b,4)==2 && errno==EDOM); assert(fcntl(f[0],F_SETFL,O_NONBLOCK)==0); assert(read(f[0],b,4)==-1 && errno==EAGAIN); assert(query_count()==0); close(f[0]);close(f[1]);return 0; }\n')
            subprocess.run(['cc',str(root/'fixture.c'),str(mock),'-Wl,-rpath,'+str(root),'-o',str(binary)],check=True)
            result=subprocess.run([str(binary)],env=dict(os.environ,LD_PRELOAD=str(lib),IPERF_DIAGNOSTIC_CONTROL_ONLY='1'),capture_output=True,text=True,check=True)
            self.assertNotIn('CONTROL_READ',result.stderr)

if __name__=='__main__': unittest.main()
