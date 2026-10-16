/* Benchmark-only barrier before iperf timers/data threads, after stream setup. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define MAGIC 0x54494731u
struct control { uint32_t magic,expected; _Atomic uint32_t arrived,released; };
static struct control *ctl;
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static void invalid(void) { fputs("invalid iperf start gate\n",stderr); exit(127); }
static void map_control(const char *path) {
    int fd=open(path,O_RDWR);struct stat st;
    if(fd<0 || fstat(fd,&st) || st.st_size!=sizeof(*ctl)) invalid();
    ctl=mmap(NULL,sizeof(*ctl),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);close(fd);
    if(ctl==MAP_FAILED || ctl->magic!=MAGIC || !ctl->expected || ctl->expected>512 || !atomic_is_lock_free(&ctl->arrived) || !atomic_is_lock_free(&ctl->released)) invalid();
}
#ifdef IPERF_GATE_CONTROLLER
int main(int argc,char **argv) {
    if(argc<3) return 2;
    if(!strcmp(argv[1],"init")) {
        if(argc!=4) return 2;
        char *end;errno=0;unsigned long expected=strtoul(argv[3],&end,10);
        if(errno || *end || !*argv[3] || expected<1 || expected>512) return 2;
        struct control initial={.magic=MAGIC,.expected=expected};
        int fd=open(argv[2],O_CREAT|O_EXCL|O_WRONLY,0600);
        if(fd<0 || write(fd,&initial,sizeof(initial))!=sizeof(initial)) return 1;
        return close(fd)!=0;
    }
    map_control(argv[2]);
    if(!strcmp(argv[1],"wait-ready")) {
        if(argc!=3) return 2;
        double deadline=now()+10;
        while(atomic_load_explicit(&ctl->arrived,memory_order_acquire)!=ctl->expected) {
            if(now()>deadline) { fputs("iperf start gate readiness timeout\n",stderr); return 1; }
            struct timespec delay={.tv_nsec=1000000};nanosleep(&delay,NULL);
        }
    } else if(!strcmp(argv[1],"release")) {
        if(argc!=3 || atomic_load_explicit(&ctl->arrived,memory_order_acquire)!=ctl->expected) return 1;
        atomic_store_explicit(&ctl->released,1,memory_order_release);
    } else if(strcmp(argv[1],"status") || argc!=3) return 2;
    printf("{\"method\":\"iperf-init-barrier-v1\",\"expected\":%u,\"arrived\":%u,\"released\":%u}\n",ctl->expected,atomic_load(&ctl->arrived),atomic_load(&ctl->released));
    return 0;
}
#else
#include <dlfcn.h>
static int (*original_init)(void *);
static int participated;
__attribute__((constructor)) static void setup(void) {
    const char *path=getenv("TAYGA_IPERF_START_CONTROL");
    if(!path || !*path) return;
    /* PATH may resolve to a script wrapper before exec of the real iperf.
     * Resolve the iperf symbol at its call site; readiness proves interposition. */
    map_control(path);
}
int iperf_init_test(void *test) {
    int saved_errno=errno;
    if(!original_init) {
        *(void **)(&original_init)=dlsym(RTLD_NEXT,"iperf_init_test");
        if(!original_init) { errno=ENOSYS; return -1; }
    }
    if(ctl) {
        if(participated++) invalid();
        uint32_t arrived=atomic_fetch_add_explicit(&ctl->arrived,1,memory_order_acq_rel)+1;
        if(arrived>ctl->expected) invalid();
        double deadline=now()+15;
        while(!atomic_load_explicit(&ctl->released,memory_order_acquire)) {
            if(now()>deadline) { fputs("iperf start gate release timeout\n",stderr); exit(124); }
            struct timespec delay={.tv_nsec=1000000};nanosleep(&delay,NULL);
        }
    }
    errno=saved_errno;
    return original_init(test);
}
#endif
