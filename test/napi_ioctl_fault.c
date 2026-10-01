/* Research-only NAPI initialization fault injection. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
static int primary=-1;
int ioctl(int fd, unsigned long request, ...)
{
    static int (*real_ioctl)(int,unsigned long,...);
    if(!real_ioctl) real_ioctl=dlsym(RTLD_NEXT,"ioctl");
    va_list ap;va_start(ap,request);unsigned long arg=va_arg(ap,unsigned long);va_end(ap);
    const char *fault=getenv("TAYGA_TEST_NAPI_FAIL");
    if(fault && request==TUNSETIFF && (((struct ifreq *)arg)->ifr_flags&IFF_NAPI) &&
       (!strcmp(fault,"unsupported-main") || (!strcmp(fault,"unsupported-worker") && primary>=0))) {
        errno=EOPNOTSUPP;return -1;
    }
    int ret=real_ioctl(fd,request,arg);
    if(ret==0 && request==TUNSETIFF && primary<0) primary=fd;
    if(ret==0 && request==TUNGETIFF && fault &&
       (!strcmp(fault,"unverified-main") || (!strcmp(fault,"unverified-worker") && fd!=primary)))
        ((struct ifreq *)arg)->ifr_flags &= ~IFF_NAPI;
    return ret;
}
