/* Experimental bounded software dispatch and asynchronous TUN TX.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "tayga.h"
#include "stats.h"
#include "experimental_io.h"
#include "flow_dispatch.h"
#include "packet_io_lifetime.h"
#include <stdatomic.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#define DISPATCH_FRAMES 512
#define DISPATCH_FRAGMENTS 1024
#define EXP_WORKERS 8
#define ASYNC_FRAMES 64
static uint64_t mono_seconds(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec;}
_Atomic uint64_t dispatch_drops, dispatch_held, dispatch_expired;
_Atomic uint64_t async_accepted, async_completed, async_errors, async_pressure;
struct fragment_entry {
	uint8_t key[40]; unsigned used, resolved, queue, count;
	int first, last; uint64_t deadline;
};
static struct {
	pthread_mutex_t lock;
	unsigned workers, free_count, next_queue, stop;
	int wake[EXP_WORKERS];
	uint16_t free_slots[DISPATCH_FRAMES], flow_queues[65536];
	unsigned head[EXP_WORKERS], tail[EXP_WORKERS], count[EXP_WORKERS];
	uint16_t queues[EXP_WORKERS][DISPATCH_FRAMES];
	int length[DISPATCH_FRAMES], next[DISPATCH_FRAMES];
	struct packet_frame frames[DISPATCH_FRAMES];
	struct packet_frame_token tokens[DISPATCH_FRAMES];
	struct packet_frame_pool pool;
	struct fragment_entry fragments[DISPATCH_FRAGMENTS];
	uint8_t *storage;
	uint64_t last_expire;
} dispatch;
int dispatch_init(unsigned workers)
{
	if(!workers || workers>EXP_WORKERS) {errno=EINVAL;return -1;}
	memset(&dispatch,0,sizeof(dispatch));
	dispatch.storage=malloc((size_t)DISPATCH_FRAMES*RECV_BUF_SIZE);
	if(!dispatch.storage) return -1;
	int ret=pthread_mutex_init(&dispatch.lock,NULL);
	if(ret) {free(dispatch.storage);dispatch.storage=NULL;errno=ret;return -1;}
	dispatch.workers=workers;dispatch.free_count=DISPATCH_FRAMES;
#ifdef __linux__
	for(unsigned i=0;i<workers;i++) {
		dispatch.wake[i]=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
		if(dispatch.wake[i]<0){for(unsigned j=0;j<i;j++)close(dispatch.wake[j]);pthread_mutex_destroy(&dispatch.lock);free(dispatch.storage);dispatch.storage=NULL;return -1;}
	}
#endif
	for(unsigned i=0;i<DISPATCH_FRAMES;i++) {
		dispatch.free_slots[i]=i;
		dispatch.frames[i]=(struct packet_frame){.storage=dispatch.storage+(size_t)i*RECV_BUF_SIZE,.capacity=RECV_BUF_SIZE};
	}
	return packet_frame_pool_init(&dispatch.pool,dispatch.frames,DISPATCH_FRAMES,1);
}
static void dispatch_drop(unsigned bytes) {atomic_fetch_add(&dispatch_drops,1);stats_drop(bytes);stats_packet_done();}
static void dispatch_free_locked(unsigned slot)
{
	packet_frame_transition(&dispatch.pool,dispatch.tokens[slot],PACKET_FRAME_FREE);
	dispatch.free_slots[dispatch.free_count++]=slot;
}
static void dispatch_queue_locked(unsigned slot,unsigned queue)
{
	dispatch.queues[queue][dispatch.tail[queue]++%DISPATCH_FRAMES]=slot;
	if(!dispatch.count[queue]++) {
#ifdef __linux__
		uint64_t wake=1;(void)!write(dispatch.wake[queue],&wake,sizeof(wake));
#endif
	}
}
int dispatch_submit(const uint8_t *buffer,int length)
{
	struct flow_packet parsed;
	int plen=length-gcfg.vnet_hdr_sz;
	if(plen<=0 || flow_parse(buffer+HEADROOM,(size_t)plen,&parsed)) {dispatch_drop(length>0?length:0);return 0;}
	pthread_mutex_lock(&dispatch.lock);
	unsigned bucket=parsed.flow_hash&65535,queue=0;
	if(parsed.transport) {
		if(!dispatch.flow_queues[bucket]) dispatch.flow_queues[bucket]=1+dispatch.next_queue++%dispatch.workers;
		queue=dispatch.flow_queues[bucket]-1;
	}
	struct fragment_entry *fragment=NULL;
	if(parsed.fragmented) {
		fragment=&dispatch.fragments[parsed.fragment_hash%DISPATCH_FRAGMENTS];
		if(!fragment->used) {
			fragment->used=1;memcpy(fragment->key,parsed.fragment_key,40);
			fragment->first=fragment->last=-1;fragment->deadline=mono_seconds()+30;
		}
		if(memcmp(fragment->key,parsed.fragment_key,40) || fragment->resolved==2 ||
			mono_seconds()>=fragment->deadline || (!fragment->resolved && !parsed.first && fragment->count==8)) goto drop;
		if(parsed.first) {
			if(fragment->resolved && fragment->queue!=queue) {fragment->resolved=2;goto drop;}
			fragment->resolved=1;fragment->queue=queue;
		} else if(fragment->resolved) queue=fragment->queue;
	}
	if(dispatch.stop || !dispatch.free_count || (fragment && !fragment->resolved && dispatch.free_count<=32)) goto drop;
	unsigned slot=dispatch.free_slots[--dispatch.free_count];
	if(packet_frame_acquire(&dispatch.pool,slot,&dispatch.tokens[slot])) {dispatch.free_count++;goto drop;}
	/* Retain framing and translation headroom; no borrowed stack pointers. */
	memcpy(dispatch.frames[slot].storage+HEADROOM-gcfg.vnet_hdr_sz,buffer+HEADROOM-gcfg.vnet_hdr_sz,length);
	dispatch.frames[slot].length=(size_t)length+HEADROOM-gcfg.vnet_hdr_sz;
	dispatch.length[slot]=length;dispatch.next[slot]=-1;
	if(fragment && !fragment->resolved) {
		if(fragment->last>=0) dispatch.next[fragment->last]=slot;else fragment->first=slot;
		fragment->last=slot;fragment->count++;atomic_fetch_add(&dispatch_held,1);
	} else {
		dispatch_queue_locked(slot,queue);
		if(fragment) {
			for(int held=fragment->first;held>=0;held=dispatch.next[held]) dispatch_queue_locked(held,queue);
			fragment->first=fragment->last=-1;fragment->count=0;
		}
	}
	pthread_mutex_unlock(&dispatch.lock);return 0;
 drop:
	pthread_mutex_unlock(&dispatch.lock);dispatch_drop(length);return 0;
}
int dispatch_take(unsigned worker,uint8_t **buffer,int *length)
{
	int slot=-1;
	pthread_mutex_lock(&dispatch.lock);
	if(dispatch.count[worker]) {
		slot=dispatch.queues[worker][dispatch.head[worker]++%DISPATCH_FRAMES];dispatch.count[worker]--;
		packet_frame_transition(&dispatch.pool,dispatch.tokens[slot],PACKET_FRAME_TRANSLATING);
		*buffer=dispatch.frames[slot].storage;*length=dispatch.length[slot];
	}
	pthread_mutex_unlock(&dispatch.lock);return slot;
}
void dispatch_wait(unsigned worker,int timeout)
{
#ifdef __linux__
	struct pollfd pfd={.fd=dispatch.wake[worker],.events=POLLIN};
	if(poll(&pfd,1,timeout)>0){uint64_t value;(void)!read(pfd.fd,&value,sizeof(value));}
#else
	(void)worker;(void)timeout;
#endif
}
void dispatch_release(unsigned slot) {pthread_mutex_lock(&dispatch.lock);dispatch_free_locked(slot);pthread_mutex_unlock(&dispatch.lock);}
void dispatch_expire(void)
{
	uint64_t now=mono_seconds();if(now==dispatch.last_expire)return;dispatch.last_expire=now;
	pthread_mutex_lock(&dispatch.lock);
	for(unsigned i=0;i<DISPATCH_FRAGMENTS;i++) {
		struct fragment_entry *f=&dispatch.fragments[i];
		if(!f->used || f->resolved==2 || now<f->deadline)continue;
		for(int slot=f->first;slot>=0;) {
			int next=dispatch.next[slot];dispatch_drop(dispatch.length[slot]);dispatch_free_locked(slot);slot=next;
		}
		f->first=f->last=-1;f->count=0;f->resolved=2;atomic_fetch_add(&dispatch_expired,1);
	}
	pthread_mutex_unlock(&dispatch.lock);
}
void dispatch_stop(void) {pthread_mutex_lock(&dispatch.lock);dispatch.stop=1;packet_frame_stop(&dispatch.pool);pthread_mutex_unlock(&dispatch.lock);}
void dispatch_destroy(void)
{
	if(!dispatch.storage)return;
	/* Called after every worker joins. Count and retire all remaining frames. */
	for(unsigned i=0;i<DISPATCH_FRAMES;i++) if(dispatch.frames[i].state!=PACKET_FRAME_FREE) {
		dispatch_drop(dispatch.length[i]);dispatch_free_locked(i);
	}
	packet_frame_backend_closed(&dispatch.pool);
	for(unsigned i=0;i<dispatch.workers;i++) {
#ifdef __linux__
		close(dispatch.wake[i]);
#endif
	}
	free(dispatch.storage);dispatch.storage=NULL;pthread_mutex_destroy(&dispatch.lock);
}

#ifdef TAYGA_WITH_URING
#include <liburing.h>
struct async_context {
	struct io_uring ring; struct packet_frame frames[ASYNC_FRAMES];
	struct packet_frame_token tokens[ASYNC_FRAMES]; struct packet_frame_pool pool;
	unsigned queue[ASYNC_FRAMES], head, tail, count, cursor, outstanding;
	int fd[ASYNC_FRAMES], initialized, failed;
	uint8_t *storage;
};
static struct async_context contexts[EXP_WORKERS];
static unsigned context_count;
static __thread struct async_context *current;
int async_tun_init(void)
{
	context_count=gcfg.workers?gcfg.workers:1;
	if(context_count>EXP_WORKERS) {errno=EINVAL;return -1;}
	for(unsigned i=0;i<context_count;i++) {
		struct async_context *c=&contexts[i];
		int ret=io_uring_queue_init(8,&c->ring,0);
		if(ret<0) {errno=-ret;goto fail;} c->initialized=1;
		c->storage=malloc((size_t)ASYNC_FRAMES*RECV_BUF_SIZE);if(!c->storage)goto fail;
		for(unsigned n=0;n<ASYNC_FRAMES;n++)c->frames[n]=(struct packet_frame){.storage=c->storage+(size_t)n*RECV_BUF_SIZE,.capacity=RECV_BUF_SIZE};
		packet_frame_pool_init(&c->pool,c->frames,ASYNC_FRAMES,i+1);
	}
	return 0;
 fail: {int saved=errno;async_tun_destroy();errno=saved;return -1;}
}
void async_tun_select(unsigned worker) {current=&contexts[worker];}
int async_tun_service(void)
{
	struct async_context *c=current;if(!c)return 0;
	struct io_uring_cqe *cqe;
	while(!io_uring_peek_cqe(&c->ring,&cqe)) {
		unsigned slot=(unsigned)cqe->user_data;
		if(slot>=ASYNC_FRAMES || !c->outstanding || c->frames[slot].state!=PACKET_FRAME_TX_SUBMITTED) {c->failed=1;io_uring_cqe_seen(&c->ring,cqe);return -1;}
		struct packet_frame *f=&c->frames[slot];
		if(cqe->res!=(int)f->length) {
			atomic_fetch_add(&async_errors,1);stats_error();stats_drop(f->length);
			if(cqe->res!=-EAGAIN && cqe->res!=-ENOBUFS && cqe->res!=-EINTR)c->failed=1;
		} else {
			unsigned header=gcfg.vnet_hdr_sz;
			if(f->length>header) {
				unsigned ver=f->storage[header]>>4;
				if(ver==4)stats_tx4(f->length-header);else if(ver==6)stats_tx6(f->length-header);
			}
			atomic_fetch_add(&async_completed,1);
		}
		packet_frame_transition(&c->pool,c->tokens[slot],PACKET_FRAME_COMPLETED);
		packet_frame_transition(&c->pool,c->tokens[slot],PACKET_FRAME_FREE);
		c->outstanding=0;io_uring_cqe_seen(&c->ring,cqe);
	}
	/* One published write per worker preserves packet order even when the
	 * kernel dispatches an operation to io-wq. Remaining frames stay owned. */
	if(!c->failed && !c->outstanding && c->count) {
		unsigned slot=c->queue[c->head%ASYNC_FRAMES];
		struct io_uring_sqe *sqe=io_uring_get_sqe(&c->ring);
		if(!sqe) {c->failed=1;return -1;}
		io_uring_prep_write(sqe,c->fd[slot],c->frames[slot].storage,c->frames[slot].length,0);
		sqe->user_data=slot;
		packet_frame_transition(&c->pool,c->tokens[slot],PACKET_FRAME_TX_SUBMITTED);
		c->outstanding=1;c->head++;c->count--;
		int ret;do {ret=io_uring_submit(&c->ring);} while(ret==-EINTR);
		if(ret!=1)c->failed=1;
	}
	return c->failed?-1:0;
}
ssize_t async_tun_submit(int fd,const struct iovec *iov,int count)
{
	struct async_context *c=current;size_t total=0;
	if(!c || count<1) {errno=EINVAL;return -1;}
	if(c->pool.stopping) {errno=ESHUTDOWN;return -1;}
	for(int i=0;i<count;i++) {if(iov[i].iov_len>RECV_BUF_SIZE-total){errno=EMSGSIZE;return -1;}total+=iov[i].iov_len;}
	if(!total) {errno=EINVAL;return -1;}
	if(async_tun_service()<0) {errno=EIO;return -1;}
	unsigned slot=ASYNC_FRAMES;
	for(unsigned n=0;n<ASYNC_FRAMES;n++) {unsigned j=(c->cursor+n)%ASYNC_FRAMES;if(c->frames[j].state==PACKET_FRAME_FREE){slot=j;break;}}
	if(slot==ASYNC_FRAMES) {atomic_fetch_add(&async_pressure,1);stats_drop(total);stats_error();errno=EAGAIN;return -1;}
	if(packet_frame_acquire(&c->pool,slot,&c->tokens[slot]))return -1;
	c->cursor=(slot+1)%ASYNC_FRAMES;
	size_t pos=0;for(int i=0;i<count;i++){memcpy(c->frames[slot].storage+pos,iov[i].iov_base,iov[i].iov_len);pos+=iov[i].iov_len;}
	c->frames[slot].length=total;c->fd[slot]=fd;
	packet_frame_transition(&c->pool,c->tokens[slot],PACKET_FRAME_TRANSLATING);
	packet_frame_transition(&c->pool,c->tokens[slot],PACKET_FRAME_PENDING_TX);
	c->queue[c->tail++%ASYNC_FRAMES]=slot;c->count++;atomic_fetch_add(&async_accepted,1);
	return total;
}
int async_tun_finish(void)
{
	if(!current)return 0;
	packet_frame_stop(&current->pool);
	uint64_t deadline=mono_seconds()+3;
	while((current->count || current->outstanding) && mono_seconds()<deadline) {
		if(async_tun_service()<0)break;
		if(current->outstanding) {struct io_uring_cqe *cqe;struct __kernel_timespec timeout={0,10000000};io_uring_wait_cqe_timeout(&current->ring,&cqe,&timeout);}
	}
	if(current->count || current->outstanding) {current->failed=1;return -1;}return current->failed?-1:0;
}
void async_tun_destroy(void)
{
	for(unsigned i=0;i<context_count && i<EXP_WORKERS;i++) {
		struct async_context *c=&contexts[i];
		if(c->initialized)io_uring_queue_exit(&c->ring);
		/* A timed-out kernel request may retain userspace storage: keep it
		 * mapped until process exit, never recycle it after a timeout. */
		if(!c->outstanding)free(c->storage);
		else slog(LOG_ERR,"Retaining async buffer storage until process exit after failed drain\n");
		c->initialized=0;
	}
}
#else
int async_tun_init(void) {errno=ENOTSUP;return -1;}
void async_tun_select(unsigned worker) {(void)worker;}
ssize_t async_tun_submit(int fd,const struct iovec *iov,int count) {(void)fd;(void)iov;(void)count;errno=ENOTSUP;return -1;}
int async_tun_service(void) {return 0;}
int async_tun_finish(void) {return 0;}
void async_tun_destroy(void) {}
#endif
