/* Diagnostic-only LD_PRELOAD interposer; never use for capacity comparisons. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static int control_only;
static _Thread_local unsigned control_read_depth;
__attribute__((constructor)) static void configure(void)
{
    int saved=errno;
    const char *value=getenv("IPERF_DIAGNOSTIC_CONTROL_ONLY");
    control_only=value && !strcmp(value,"1");
    errno=saved;
}

ssize_t read(int fd, void *buffer, size_t count)
{
    /* Resolve per thread, avoiding a shared initialization race. */
    static _Thread_local ssize_t (*original)(int, void *, size_t);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"read");
        if (!original) { errno=ENOSYS; return -1; }
    }
    errno=entry_error;
    ssize_t result=original(fd,buffer,count);
    int error=errno;
    if (control_only && !control_read_depth &&
        !(result<0 && error!=EAGAIN && error!=EWOULDBLOCK && error!=EINTR)) {
        errno=error;return result;
    }
    int type=-1; socklen_t length=sizeof(type);
    int socket_status=getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length);
    if (type==SOCK_STREAM || (result<0 && error!=EAGAIN && error!=EWOULDBLOCK && error!=EINTR)) {
        struct sockaddr_storage local={0},peer={0};
        socklen_t local_size=sizeof(local),peer_size=sizeof(peer);
        int local_status=getsockname(fd,(void *)&local,&local_size);
        int peer_status=getpeername(fd,(void *)&peer,&peer_size);
        struct timespec timestamp; clock_gettime(CLOCK_MONOTONIC,&timestamp);
        dprintf(STDERR_FILENO,"%s mono=%lld.%09ld pid=%ld tid=%ld fd=%d count=%zu result=%zd errno=%d socket_status=%d type=%d local_status=%d local_family=%d peer_status=%d peer_family=%d\n",
                type==SOCK_STREAM?"CONTROL_READ":"READ_FAILURE",
                (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),fd,count,result,error,socket_status,type,local_status,local.ss_family,peer_status,peer.ss_family);
    }
    errno=error;
    return result;
}
/* iperf 3.18 uses recv(), rather than read(), for its UDP connect reply. */
ssize_t recv(int fd, void *buffer, size_t count, int flags)
{
    static _Thread_local ssize_t (*original)(int, void *, size_t, int);
    static _Thread_local unsigned records;
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"recv");
        if (!original) { errno=ENOSYS; return -1; }
    }
    errno=entry_error;
    ssize_t result=original(fd,buffer,count,flags);
    int error=errno;
    if (records++<1024) {
        unsigned char *bytes=buffer;
        struct timespec timestamp;clock_gettime(CLOCK_MONOTONIC,&timestamp);
        int type=-1; socklen_t length=sizeof(type);
        int status=getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length);
        dprintf(STDERR_FILENO,"RECV_RESULT mono=%lld.%09ld pid=%ld tid=%ld fd=%d count=%zu result=%zd errno=%d socket_status=%d type=%d first4=%02x%02x%02x%02x\n",
                (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),fd,count,result,result<0?error:0,status,type,
                result>0?bytes[0]:0,result>1?bytes[1]:0,result>2?bytes[2]:0,result>3?bytes[3]:0);
    }
    errno=error;return result;
}

/* Only the four-byte UDP setup write is logged; data writes stay untouched. */
ssize_t write(int fd, const void *buffer, size_t count)
{
    static _Thread_local ssize_t (*original)(int, const void *, size_t);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"write");
        if (!original) { errno=ENOSYS; return -1; }
    }
    errno=entry_error;
    ssize_t result=original(fd,buffer,count);
    int error=errno;
    if (count==4) {
        int type=-1; socklen_t length=sizeof(type);
        if (!getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length) && type==SOCK_DGRAM) {
            const unsigned char *bytes=buffer;
            struct timespec timestamp;clock_gettime(CLOCK_MONOTONIC,&timestamp);
            dprintf(STDERR_FILENO,"UDP_SETUP_WRITE mono=%lld.%09ld pid=%ld tid=%ld fd=%d result=%zd errno=%d first4=%02x%02x%02x%02x\n",
                    (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),fd,result,result<0?error:0,bytes[0],bytes[1],bytes[2],bytes[3]);
        }
    }
    errno=error;return result;
}

int iperf_udp_connect(void *test)
{
    static _Thread_local int (*original)(void *);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"iperf_udp_connect");
        if (!original) { errno=ENOSYS; return -1; }
    }
    errno=entry_error;
    int result=original(test),error=errno;
    int *iperf_error=dlsym(RTLD_NEXT,"i_errno");
    struct timespec timestamp;clock_gettime(CLOCK_MONOTONIC,&timestamp);
    dprintf(STDERR_FILENO,"UDP_CONNECT_RESULT mono=%lld.%09ld pid=%ld tid=%ld result=%d errno=%d i_errno=%d\n",
            (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),result,error,iperf_error?*iperf_error:-1);
    errno=error;return result;
}

/* TCP control framing: lengths only, never dump result JSON. */
int Nread(int fd, char *buffer, size_t count, int protocol)
{
    static _Thread_local int (*original)(int, char *, size_t, int);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"Nread");
        if (!original) { errno=ENOSYS; return -1; }
    }
    int type=-1; socklen_t length=sizeof(type);
    int trace=!getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length) && type==SOCK_STREAM;
    if (trace) ++control_read_depth;
    errno=entry_error;
    int result=original(fd,buffer,count,protocol),error=errno;
    if (trace) --control_read_depth;
    if (trace) {
        struct timespec timestamp;clock_gettime(CLOCK_MONOTONIC,&timestamp);
        unsigned char *bytes=(unsigned char *)buffer;
        dprintf(STDERR_FILENO,"CONTROL_NREAD mono=%lld.%09ld pid=%ld tid=%ld fd=%d count=%zu result=%d errno=%d first4=%02x%02x%02x%02x\n",
            (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),fd,count,result,error,
            result>0?bytes[0]:0,result>1?bytes[1]:0,result>2?bytes[2]:0,result>3?bytes[3]:0);
    }
    errno=error;return result;
}

int iperf_exchange_results(void *test)
{
    static _Thread_local int (*original)(void *);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"iperf_exchange_results");
        if (!original) { errno=ENOSYS; return -1; }
    }
    struct timespec timestamp;clock_gettime(CLOCK_MONOTONIC,&timestamp);
    dprintf(STDERR_FILENO,"EXCHANGE_BEGIN mono=%lld.%09ld pid=%ld tid=%ld\n",
            (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid));
    errno=entry_error;
    int result=original(test),error=errno;
    int *iperf_error=dlsym(RTLD_NEXT,"i_errno");
    clock_gettime(CLOCK_MONOTONIC,&timestamp);
    dprintf(STDERR_FILENO,"EXCHANGE_END mono=%lld.%09ld pid=%ld tid=%ld result=%d errno=%d i_errno=%d\n",
            (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),result,error,iperf_error?*iperf_error:-1);
    errno=error;return result;
}

/* Only control-framing waits are logged; UDP readiness/data loops are untouched. */
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout)
{
    static _Thread_local int (*original)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"select");
        if (!original) { errno=ENOSYS; return -1; }
    }
    long seconds=timeout?timeout->tv_sec:-1, microseconds=timeout?timeout->tv_usec:-1;
    struct timespec before={0},after;
    if (control_read_depth) clock_gettime(CLOCK_MONOTONIC,&before);
    errno=entry_error;
    int result=original(nfds,readfds,writefds,exceptfds,timeout),error=errno;
    if (control_read_depth) {
        clock_gettime(CLOCK_MONOTONIC,&after);
        dprintf(STDERR_FILENO,"CONTROL_SELECT mono=%lld.%09ld pid=%ld tid=%ld nfds=%d timeout=%ld.%06ld result=%d errno=%d elapsed_ns=%lld\n",
            (long long)after.tv_sec,after.tv_nsec,(long)getpid(),syscall(SYS_gettid),nfds,seconds,microseconds,result,error,
            (long long)(after.tv_sec-before.tv_sec)*1000000000LL+after.tv_nsec-before.tv_nsec);
    }
    errno=error;return result;
}

int iperf_set_send_state(void *test, signed char state)
{
    static _Thread_local int (*original)(void *, signed char);
    int entry_error=errno;
    if (!original) {
        *(void **)(&original)=dlsym(RTLD_NEXT,"iperf_set_send_state");
        if (!original) { errno=ENOSYS; return -1; }
    }
    struct timespec before,after;clock_gettime(CLOCK_MONOTONIC,&before);
    errno=entry_error;
    int result=original(test,state),error=errno;
    clock_gettime(CLOCK_MONOTONIC,&after);
    dprintf(STDERR_FILENO,"SEND_STATE mono=%lld.%09ld begin=%lld.%09ld pid=%ld tid=%ld state=%d result=%d errno=%d\n",
        (long long)after.tv_sec,after.tv_nsec,(long long)before.tv_sec,before.tv_nsec,(long)getpid(),syscall(SYS_gettid),(int)state,result,error);
    errno=error;return result;
}
