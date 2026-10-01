/* Linux-only diagnostic endpoint. Not linked into TAYGA. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define SIZE 1200
#define MAXSEQ (1U << 30)
static volatile sig_atomic_t stop;
static void stopped(int sig) { (void)sig; stop = 1; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static void fail(const char *s) { perror(s); exit(1); }
static unsigned long long number(const char *s) { char *end; errno=0; unsigned long long n=strtoull(s,&end,10); if(errno || *end || !*s || *s=='-') { fprintf(stderr,"invalid number\n"); exit(2); } return n; }
static int unsupported(int error) { return error==ENOPROTOOPT || error==EOPNOTSUPP || error==EINVAL; }
int main(int argc, char **argv) {
    if(argc < 7) { fprintf(stderr,"send AF source destination seconds batch cookie output [count [tail]] OR receive AF address gro cookie output\n"); return 2; }
    unsigned af=number(argv[2]); if(af!=4 && af!=6) return 2;
    int sending=!strcmp(argv[1],"send"), family=af==4?AF_INET:AF_INET6;
    const char *policy=getenv("UDP_ENDPOINT_OFFLOAD");
    int automatic=policy && !strcmp(policy,"auto");
    if(policy && strcmp(policy,"auto") && strcmp(policy,"strict")) return 2;
    if(strcmp(argv[1],"send") && strcmp(argv[1],"receive")) return 2;
    if(sending && argc<9) return 2;
    unsigned batch=sending?number(argv[6]):1;
    unsigned gro=sending?0:number(argv[4]);
    unsigned seconds=sending?number(argv[5]):0;
    uint64_t cookie=number(argv[sending?7:5]);
    const char *output=argv[sending?8:6];
    uint64_t limit=sending && argc>9?number(argv[9]):0;
    unsigned tail=sending && argc>10?number(argv[10]):SIZE;
    if(batch<1 || batch>32 || gro>1 || (sending && (!seconds || seconds>300)) || tail<16 || tail>SIZE || limit>=MAXSEQ) return 2;
    int fd=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0); if(fd<0) fail("socket");
    struct sockaddr_storage src={0}, dst={0}; socklen_t addrlen;
    if(family==AF_INET) {
        struct sockaddr_in *s=(void*)&src,*d=(void*)&dst; addrlen=sizeof(*s); s->sin_family=d->sin_family=AF_INET;
        if(inet_pton(family,argv[3],&s->sin_addr)!=1 || (sending && inet_pton(family,argv[4],&d->sin_addr)!=1)) return 2;
        d->sin_port=htons(49153); if(!sending) s->sin_port=d->sin_port;
    } else {
        struct sockaddr_in6 *s=(void*)&src,*d=(void*)&dst; addrlen=sizeof(*s); s->sin6_family=d->sin6_family=AF_INET6;
        if(inet_pton(family,argv[3],&s->sin6_addr)!=1 || (sending && inet_pton(family,argv[4],&d->sin6_addr)!=1)) return 2;
        d->sin6_port=htons(49153); if(!sending) s->sin6_port=d->sin6_port;
    }
    if(bind(fd,(void*)&src,addrlen)) fail("bind");
    unsigned requested_batch=batch, requested_gro=gro;
    int fallback_errno=0;
    if(gro && setsockopt(fd,IPPROTO_UDP,UDP_GRO,&gro,sizeof(gro))) {
        if(!automatic || !unsupported(errno)) fail("UDP_GRO");
        fallback_errno=errno; gro=0;
    }
    uint16_t segment=SIZE;
    if(sending && batch>1) { int seg=SIZE; if(setsockopt(fd,IPPROTO_UDP,UDP_SEGMENT,&seg,sizeof(seg))) {
        if(!automatic || !unsupported(errno)) fail("UDP_SEGMENT");
        fallback_errno=errno; batch=1;
    } }
    struct sigaction action={.sa_handler=stopped}; sigemptyset(&action.sa_mask); sigaction(SIGTERM,&action,NULL); sigaction(SIGINT,&action,NULL);
    unsigned char data[65536], expected[SIZE]; memset(expected,0xa5,sizeof(expected));
    unsigned char *seen=sending?NULL:calloc(MAXSEQ/8,1); if(!sending && !seen) fail("calloc");
    uint64_t packets=0,bytes=0,calls=0,aggregates=0,duplicates=0,invalid=0,reordered=0,highest=0,shorts=0;
    double started=now(),ended=started;
    if(!sending) { puts("READY"); fflush(stdout); }
    while(!stop) {
        if(sending) {
            if((limit && packets>=limit) || now()-started>=seconds) break;
            unsigned n=batch; if(limit && n>limit-packets) n=limit-packets;
            size_t length=0;
            for(unsigned i=0;i<n;i++) {
                unsigned len=limit && packets+i+1==limit?tail:SIZE;
                memcpy(data+length,expected,len); uint64_t seq=htobe64(packets+i), tag=htobe64(cookie);
                memcpy(data+length,&seq,8); memcpy(data+length+8,&tag,8); length+=len;
            }
            ssize_t sent=sendto(fd,data,length,0,(void*)&dst,addrlen); calls++;
            if(sent<0) { if(errno==EINTR) continue;
                if(automatic && batch>1 && unsupported(errno)) {
                    int zero=0; fallback_errno=errno;
                    if(setsockopt(fd,IPPROTO_UDP,UDP_SEGMENT,&zero,sizeof(zero))) fail("disable UDP_SEGMENT");
                    batch=1; continue;
                }
                fail("sendto"); }
            if((size_t)sent!=length || packets+n>=MAXSEQ) { fprintf(stderr,"short send or sequence limit\n"); return 1; }
            packets+=n; bytes+=sent; ended=now();
        } else {
            struct pollfd p={fd,POLLIN,0}; int ready=poll(&p,1,100);
            if(ready<0) { if(errno==EINTR) continue; fail("poll"); } if(!ready) continue;
            union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
            struct iovec iov={data,sizeof(data)};
            struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
            ssize_t length=recvmsg(fd,&msg,0); calls++;
            if(length<0) { if(errno==EINTR) continue; fail("recvmsg"); }
            if(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) { invalid++; continue; }
            size_t seg=length;
            for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
                if(c->cmsg_level==IPPROTO_UDP && c->cmsg_type==UDP_GRO) {
                    int value=0; if(c->cmsg_len!=CMSG_LEN(sizeof(value))) { invalid++; seg=0; break; }
                    memcpy(&value,CMSG_DATA(c),sizeof(value)); if(value<=0 || value>SIZE) {invalid++;seg=0;break;} seg=value;
                }
            }
            if(!seg) { invalid++;continue; } if((size_t)length>seg) aggregates++;
            for(size_t offset=0;offset<(size_t)length;offset+=seg) {
                size_t len=(size_t)length-offset; if(len>seg) len=seg;
                if(len<16 || len>SIZE) { invalid++;continue; }
                uint64_t seq,tag; memcpy(&seq,data+offset,8); memcpy(&tag,data+offset+8,8); seq=be64toh(seq);tag=be64toh(tag);
                if(seq>=MAXSEQ || tag!=cookie || memcmp(data+offset+16,expected+16,len-16)) { invalid++;continue; }
                if(seen[seq/8]&(1U<<(seq%8))) { duplicates++;continue; }
                seen[seq/8]|=1U<<(seq%8); if(packets && seq<highest) reordered++; if(seq>highest) highest=seq;
                packets++;bytes+=len; if(len<SIZE) shorts++;
            }
            ended=now();
        }
    }
    FILE *f=fopen(output,"wx"); if(!f) fail("output");
    fprintf(f,"{\"offload_policy\":\"%s\",\"requested_batch\":%u,\"requested_gro\":%u,\"fallback_errno\":%d,",automatic?"auto":"strict",requested_batch,requested_gro,fallback_errno);
    fprintf(f,"\"packets\":%"PRIu64",\"bytes\":%"PRIu64",\"calls\":%"PRIu64",\"aggregates\":%"PRIu64",\"duplicates\":%"PRIu64",\"invalid\":%"PRIu64",\"reordered\":%"PRIu64",\"short_tails\":%"PRIu64",\"highest_sequence\":%"PRIu64",\"elapsed_seconds\":%.9f,\"batch\":%u,\"gro\":%u,\"segment_size\":%u}\n",packets,bytes,calls,aggregates,duplicates,invalid,reordered,shorts,highest,ended-started,batch,gro,segment);
    if(fclose(f)) fail("fclose");
    free(seen);close(fd);return invalid?1:0;
}
