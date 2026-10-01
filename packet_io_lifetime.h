/* Experimental single-owner frame lifetime contract. No kernel backend is
 * implemented here. Ring publication happens only after successful transition;
 * a failed publication must use rollback before ownership crosses to kernel. */
#ifndef TAYGA_PACKET_IO_LIFETIME_H
#define TAYGA_PACKET_IO_LIFETIME_H
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
enum packet_frame_state {
	PACKET_FRAME_FREE, PACKET_FRAME_RX_POSTED, PACKET_FRAME_RECEIVED,
	PACKET_FRAME_TRANSLATING, PACKET_FRAME_PENDING_TX,
	PACKET_FRAME_TX_SUBMITTED, PACKET_FRAME_COMPLETED
};
struct packet_frame {
	unsigned char *storage;
	size_t capacity, offset, length;
	uint64_t generation;
	enum packet_frame_state state;
};
struct packet_frame_token { uint32_t slot; uint64_t generation, pool_identity; };
struct packet_frame_pool {
	struct packet_frame *frames;
	uint32_t count;
	uint64_t identity;
	int stopping, backend_closed;
};
static inline int packet_lifetime_error(int code) { errno=code; return -1; }
static inline int packet_frame_geometry(const struct packet_frame *f)
{
	return f->storage && f->offset<=f->capacity && f->length<=f->capacity-f->offset;
}
/* Caller initializes storage/capacity; identity must never be reused while
 * any token may survive. Initialize only after previous backend/storage retire.
 * No allocation is hidden. */
static inline int packet_frame_pool_init(struct packet_frame_pool *p,
	struct packet_frame *frames, uint32_t count, uint64_t identity)
{
	if (!p || !frames || !count || !identity) return packet_lifetime_error(EINVAL);
	for (uint32_t i=0;i<count;i++)
		if (!frames[i].storage || !frames[i].capacity) return packet_lifetime_error(EINVAL);
	for (uint32_t i=0;i<count;i++) {
		frames[i].offset=frames[i].length=0;
		frames[i].generation=0; frames[i].state=PACKET_FRAME_FREE;
	}
	*p=(struct packet_frame_pool){.frames=frames,.count=count,.identity=identity}; return 0;
}
static inline struct packet_frame *packet_frame_lookup(struct packet_frame_pool *p,
	struct packet_frame_token token)
{
	if (!p || token.pool_identity!=p->identity || token.slot>=p->count || !token.generation ||
		p->frames[token.slot].generation!=token.generation) {
		errno=ESTALE; return NULL;
	}
	return &p->frames[token.slot];
}
static inline int packet_frame_acquire(struct packet_frame_pool *p, uint32_t slot,
	struct packet_frame_token *token)
{
	if (!p || !token || slot>=p->count) return packet_lifetime_error(EINVAL);
	if (p->stopping) return packet_lifetime_error(ESHUTDOWN);
	struct packet_frame *f=&p->frames[slot];
	if (f->state!=PACKET_FRAME_FREE) return packet_lifetime_error(EBUSY);
	if (f->generation==UINT64_MAX) return packet_lifetime_error(EOVERFLOW);
	f->generation++; f->offset=f->length=0; f->state=PACKET_FRAME_RECEIVED;
	*token=(struct packet_frame_token){slot,f->generation,p->identity}; return 0;
}
static inline int packet_frame_transition(struct packet_frame_pool *p,
	struct packet_frame_token token, enum packet_frame_state to)
{
	struct packet_frame *f=packet_frame_lookup(p,token);
	if (!f) return -1;
	int allowed=0;
	switch (to) {
	case PACKET_FRAME_RX_POSTED:
		allowed=f->state==PACKET_FRAME_RECEIVED && !p->stopping && !f->length; break;
	case PACKET_FRAME_RECEIVED: allowed=f->state==PACKET_FRAME_RX_POSTED; break;
	case PACKET_FRAME_TRANSLATING: allowed=f->state==PACKET_FRAME_RECEIVED; break;
	case PACKET_FRAME_PENDING_TX: allowed=f->state==PACKET_FRAME_TRANSLATING; break;
	case PACKET_FRAME_TX_SUBMITTED:
		allowed=(f->state==PACKET_FRAME_TRANSLATING || f->state==PACKET_FRAME_PENDING_TX) && !p->backend_closed && f->length; break;
	case PACKET_FRAME_COMPLETED: allowed=f->state==PACKET_FRAME_TX_SUBMITTED; break;
	case PACKET_FRAME_FREE:
		allowed=f->state==PACKET_FRAME_RECEIVED || f->state==PACKET_FRAME_TRANSLATING || f->state==PACKET_FRAME_PENDING_TX || f->state==PACKET_FRAME_COMPLETED; break;
	}
	if (!allowed) return packet_lifetime_error(EBUSY);
	if (to!=PACKET_FRAME_FREE && !packet_frame_geometry(f)) return packet_lifetime_error(EINVAL);
	f->state=to;
	if (to==PACKET_FRAME_FREE) f->length=f->offset=0;
	return 0;
}
/* Reserve header expansion while translating. Failure leaves geometry intact;
 * caller must acquire a separate bounded output frame or drop explicitly. */
static inline int packet_frame_prepend(struct packet_frame_pool *p,
	struct packet_frame_token token, size_t bytes)
{
	struct packet_frame *f=packet_frame_lookup(p,token); if (!f) return -1;
	if (f->state!=PACKET_FRAME_TRANSLATING) return packet_lifetime_error(EBUSY);
	if (!packet_frame_geometry(f)) return packet_lifetime_error(EINVAL);
	if (bytes>f->offset) return packet_lifetime_error(ENOBUFS);
	f->offset-=bytes; f->length+=bytes; return 0;
}
/* Use only BEFORE RX/TX producer publication, while still the exclusive owner. */
static inline int packet_frame_unpublished_rollback(struct packet_frame_pool *p,
	struct packet_frame_token token)
{
	struct packet_frame *f=packet_frame_lookup(p,token); if (!f) return -1;
	if (f->state==PACKET_FRAME_RX_POSTED) f->state=PACKET_FRAME_RECEIVED;
	else if (f->state==PACKET_FRAME_TX_SUBMITTED) f->state=PACKET_FRAME_PENDING_TX;
	else return packet_lifetime_error(EBUSY);
	return 0;
}
static inline void packet_frame_stop(struct packet_frame_pool *p) { p->stopping=1; }
/* PRECONDITION: redirection is removed and the actual backend is closed;
 * no kernel/device references to this storage remain. This is not a timeout. */
static inline int packet_frame_backend_closed(struct packet_frame_pool *p)
{
	if (!p || !p->stopping) return packet_lifetime_error(EINVAL);
	p->backend_closed=1;
	for (uint32_t i=0;i<p->count;i++)
		if (p->frames[i].state==PACKET_FRAME_RX_POSTED || p->frames[i].state==PACKET_FRAME_TX_SUBMITTED)
			p->frames[i].state=PACKET_FRAME_COMPLETED;
	return 0;
}
static inline int packet_frame_can_unmap(const struct packet_frame_pool *p)
{
	if (!p || !p->backend_closed) return 0;
	for (uint32_t i=0;i<p->count;i++) if (p->frames[i].state!=PACKET_FRAME_FREE) return 0;
	return 1;
}
#endif
