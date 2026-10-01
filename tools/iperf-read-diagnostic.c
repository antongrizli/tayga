/* Diagnostic-only LD_PRELOAD interposer; never use for capacity comparisons. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
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
    if (result<0 && error!=EAGAIN && error!=EWOULDBLOCK && error!=EINTR) {
        int type=-1; socklen_t length=sizeof(type);
        int socket_status=getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length);
        struct sockaddr_storage local={0},peer={0};
        socklen_t local_size=sizeof(local),peer_size=sizeof(peer);
        int local_status=getsockname(fd,(void *)&local,&local_size);
        int peer_status=getpeername(fd,(void *)&peer,&peer_size);
        struct timespec timestamp; clock_gettime(CLOCK_MONOTONIC,&timestamp);
        dprintf(STDERR_FILENO,"READ_FAILURE mono=%lld.%09ld pid=%ld tid=%ld fd=%d count=%zu errno=%d socket_status=%d type=%d local_status=%d local_family=%d peer_status=%d peer_family=%d\n",
                (long long)timestamp.tv_sec,timestamp.tv_nsec,(long)getpid(),syscall(SYS_gettid),fd,count,error,socket_status,type,local_status,local.ss_family,peer_status,peer.ss_family);
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
