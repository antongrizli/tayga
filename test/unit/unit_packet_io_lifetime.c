#include <assert.h>
#include "packet_io_lifetime.h"
int main(void)
{
	unsigned char data[2][128];
	struct packet_frame frames[2]={{.storage=data[0],.capacity=128},{.storage=data[1],.capacity=128}};
	struct packet_frame_pool pool;
	struct packet_frame_token a,b,old;
	assert(packet_frame_pool_init(&pool,frames,2,1)==0);
	assert(packet_frame_acquire(&pool,0,&a)==0); old=a;
	assert(packet_frame_acquire(&pool,0,&b)==-1 && errno==EBUSY);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_RX_POSTED)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_FREE)==-1);
	frames[0].offset=120;frames[0].length=9;
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_RECEIVED)==-1 && errno==EINVAL);
	frames[0].length=8;
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_RECEIVED)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_TRANSLATING)==0);
	assert(packet_frame_prepend(&pool,a,121)==-1 && errno==ENOBUFS);
	assert(frames[0].offset==120 && frames[0].length==8);
	assert(packet_frame_prepend(&pool,a,20)==0);
	assert(frames[0].offset==100 && frames[0].length==28);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_PENDING_TX)==0);
	assert(packet_frame_prepend(&pool,a,1)==-1 && errno==EBUSY);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_TX_SUBMITTED)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_FREE)==-1);
	assert(packet_frame_unpublished_rollback(&pool,a)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_TX_SUBMITTED)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_COMPLETED)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_COMPLETED)==-1);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_FREE)==0);
	assert(packet_frame_acquire(&pool,0,&a)==0);
	assert(packet_frame_transition(&pool,old,PACKET_FRAME_COMPLETED)==-1 && errno==ESTALE);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_RX_POSTED)==0);
	assert(packet_frame_acquire(&pool,1,&b)==0);
	frames[1].length=64;
	assert(packet_frame_transition(&pool,b,PACKET_FRAME_TRANSLATING)==0);
	assert(packet_frame_transition(&pool,b,PACKET_FRAME_TX_SUBMITTED)==0);
	assert(packet_frame_backend_closed(&pool)==-1);
	packet_frame_stop(&pool);
	assert(!packet_frame_can_unmap(&pool));
	assert(packet_frame_acquire(&pool,1,&old)==-1 && errno==ESHUTDOWN);
	assert(packet_frame_backend_closed(&pool)==0);
	assert(packet_frame_transition(&pool,a,PACKET_FRAME_FREE)==0);
	assert(!packet_frame_can_unmap(&pool));
	assert(packet_frame_transition(&pool,b,PACKET_FRAME_FREE)==0);
	assert(packet_frame_can_unmap(&pool));
	/* Integer wrap cannot make a frame geometry valid, or recycle a token. */
	frames[0].offset=SIZE_MAX;frames[0].length=1;
	assert(!packet_frame_geometry(&frames[0]));
	assert(packet_frame_pool_init(&pool,frames,2,2)==0);
	assert(packet_frame_lookup(&pool,a)==NULL && errno==ESTALE);
	frames[0].generation=UINT64_MAX;
	assert(packet_frame_acquire(&pool,0,&a)==-1 && errno==EOVERFLOW);
	assert(packet_frame_lookup(&pool,(struct packet_frame_token){2,1,2})==NULL);
	return 0;
}
