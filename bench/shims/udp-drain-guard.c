/* Benchmark-only iperf3 UDP drain control. Unsent datagrams return EAGAIN;
 * TCP control and receiving threads continue until iperf's normal end timer. */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#define MAGIC 0x54444731u
struct control { uint32_t magic; _Atomic uint32_t stopped; _Atomic uint64_t attached, blocked; };
static struct control *ctl;
static void map_control(const char *path) {
    int fd = open(path, O_RDWR);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size != sizeof(*ctl)) goto fail;
    ctl = mmap(NULL, sizeof(*ctl), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ctl == MAP_FAILED || ctl->magic != MAGIC) goto fail;
    if (!atomic_is_lock_free(&ctl->blocked)) goto fail;
    return;
fail:
    fprintf(stderr, "invalid UDP drain control: %s\n", path); exit(127);
}
#ifdef UDP_DRAIN_CONTROLLER
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[1], "init")) {
        struct control initial = {.magic = MAGIC};
        int fd = open(argv[2], O_CREAT|O_TRUNC|O_WRONLY, 0600);
        if (fd < 0 || write(fd, &initial, sizeof(initial)) != sizeof(initial)) return 1;
        return close(fd) != 0;
    }
    map_control(argv[2]);
    if (!strcmp(argv[1], "stop")) atomic_store_explicit(&ctl->stopped, 1, memory_order_release);
    else if (strcmp(argv[1], "status")) return 2;
    printf("{\"method\":\"udp-write-eagain-v1\",\"stopped\":%u,\"attached\":%llu,\"blocked_writes\":%llu}\n",
           atomic_load(&ctl->stopped), (unsigned long long)atomic_load(&ctl->attached),
           (unsigned long long)atomic_load(&ctl->blocked));
    return 0;
}
#else
#include <dlfcn.h>
static ssize_t (*real_write)(int, const void *, size_t);
__attribute__((constructor)) static void setup(void) {
    real_write = dlsym(RTLD_NEXT, "write");
    if (!real_write) exit(127);
    const char *path = getenv("TAYGA_UDP_DRAIN_CONTROL");
    if (path) { map_control(path); atomic_fetch_add(&ctl->attached, 1); }
}
ssize_t write(int fd, const void *buf, size_t size) {
    if (ctl && atomic_load_explicit(&ctl->stopped, memory_order_acquire)) {
        int saved_errno = errno, type = 0; socklen_t len = sizeof(type);
        if (!getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) && type == SOCK_DGRAM) {
            atomic_fetch_add_explicit(&ctl->blocked, 1, memory_order_relaxed);
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
            errno = EAGAIN; return -1;
        }
        errno = saved_errno;
    }
    return real_write(fd, buf, size);
}
#endif
