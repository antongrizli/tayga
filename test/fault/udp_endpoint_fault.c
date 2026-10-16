#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <sys/socket.h>
int setsockopt(int fd,int level,int option,const void *value,socklen_t length) {
    int (*original)(int,int,int,const void *,socklen_t)=dlsym(RTLD_NEXT,"setsockopt");
    if(level==IPPROTO_UDP && (option==UDP_GRO || option==UDP_SEGMENT) && getenv("UDP_ENDPOINT_FAULT")) {
        errno=atoi(getenv("UDP_ENDPOINT_FAULT")); return -1;
    }
    return original(fd,level,option,value,length);
}

ssize_t sendto(int fd,const void *buffer,size_t size,int flags,const struct sockaddr *address,socklen_t length) {
    ssize_t (*original)(int,const void *,size_t,int,const struct sockaddr *,socklen_t)=dlsym(RTLD_NEXT,"sendto");
    static int injected;
    if(getenv("UDP_ENDPOINT_SEND_FAULT") && !injected++) { errno=EOPNOTSUPP; return -1; }
    return original(fd,buffer,size,flags,address,length);
}
