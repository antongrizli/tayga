#ifndef TAYGA_EXPERIMENTAL_IO_H
#define TAYGA_EXPERIMENTAL_IO_H
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>
#include <stdatomic.h>
extern _Atomic uint64_t dispatch_drops, dispatch_held, dispatch_expired;
extern _Atomic uint64_t async_accepted, async_completed, async_errors, async_pressure;
int dispatch_init(unsigned workers);
int dispatch_submit(const uint8_t *buffer, int length);
int dispatch_take(unsigned worker, uint8_t **buffer, int *length);
void dispatch_wait(unsigned worker,int timeout);
void dispatch_release(unsigned slot);
void dispatch_expire(void);
void dispatch_stop(void);
void dispatch_destroy(void);
int async_tun_init(void);
void async_tun_select(unsigned worker);
ssize_t async_tun_submit(int fd,const struct iovec *iov,int count);
int async_tun_service(void);
int async_tun_finish(void);
void async_tun_destroy(void);
#endif
