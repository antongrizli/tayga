/* Test-only failure injection, never linked into the daemon. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
static int lose_reply;
ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen)
{
    static ssize_t (*real_sendto)(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
    static unsigned writes;
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    const struct nlmsghdr *n = buf;
    if (addr && addr->sa_family == AF_NETLINK && len >= sizeof(*n) &&
        (n->nlmsg_type == RTM_NEWADDR || n->nlmsg_type == RTM_NEWROUTE)) {
        const char *at = getenv("TAYGA_TEST_SETUP_FAIL");
        writes++;
        if (at && writes == strtoul(at, NULL, 10)) { errno = EIO; return -1; }
        const char *ack = getenv("TAYGA_TEST_ACK_FAIL");
        if (ack && writes == strtoul(ack, NULL, 10)) lose_reply = 1;
    }
    return real_sendto(fd, buf, len, flags, addr, alen);
}
ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    static ssize_t (*real_recvmsg)(int,struct msghdr*,int);
    if (!real_recvmsg) real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    ssize_t result = real_recvmsg(fd, msg, flags);
    if (lose_reply && result >= 0) { lose_reply = 0; errno = EPROTO; return -1; }
    return result;
}
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start)(void*), void *arg)
{
    static int (*real_create)(pthread_t*,const pthread_attr_t*,void*(*)(void*),void*);
    static unsigned count;
    if (!real_create) real_create = dlsym(RTLD_NEXT, "pthread_create");
    const char *at = getenv("TAYGA_TEST_THREAD_FAIL");
    if (at && ++count == strtoul(at, NULL, 10)) return EAGAIN;
    return real_create(thread, attr, start, arg);
}

void *malloc(size_t size)
{
    static void *(*real_malloc)(size_t);
    static unsigned buffers;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    const char *at = getenv("TAYGA_TEST_BUFFER_OOM");
    if (at && size == (64 + 40 + 65535 + 12 + 1) && ++buffers == strtoul(at, NULL, 10)) {
        errno = ENOMEM; return NULL;
    }
    return real_malloc(size);
}
void *calloc(size_t count, size_t size)
{
    static void *(*real_calloc)(size_t,size_t);
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    if (getenv("TAYGA_TEST_CACHE_OOM") && count == 8192) { errno = ENOMEM; return NULL; }
    return real_calloc(count, size);
}
