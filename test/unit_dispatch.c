#include "tayga.h"
#include "experimental_io.h"
#include "flow_dispatch.h"
#include <assert.h>
struct config gcfg;
static time_t clock_seconds=100;
int __wrap_clock_gettime(clockid_t clock,struct timespec *out) {(void)clock;out->tv_sec=clock_seconds;out->tv_nsec=0;return 0;}
static void packet(uint8_t *b,unsigned port,unsigned id,unsigned fragment)
{
	memset(b,0,HEADROOM+64);uint8_t *p=b+HEADROOM;
	p[0]=0x45;p[3]=36;p[4]=id>>8;p[5]=id;p[6]=fragment>>8;p[7]=fragment;
	p[9]=17;p[12]=192;p[15]=1;p[16]=192;p[19]=2;p[20]=port>>8;p[21]=port;p[23]=53;
}
static int take(int worker,unsigned *count)
{
	uint8_t *b;int length,slot,last=-1;
	while((slot=dispatch_take(worker,&b,&length))>=0){assert(length==36);(*count)++;last=b[HEADROOM+21];dispatch_release(slot);}
	return last;
}
int main(void)
{
	uint8_t b[HEADROOM+64],reverse[HEADROOM+64];struct flow_packet f,r;
	packet(b,1234,1,0);assert(!flow_parse(b+HEADROOM,36,&f) && f.transport);
	memcpy(reverse,b,sizeof(b));memcpy(reverse+HEADROOM+12,b+HEADROOM+16,4);memcpy(reverse+HEADROOM+16,b+HEADROOM+12,4);
	memcpy(reverse+HEADROOM+20,b+HEADROOM+22,2);memcpy(reverse+HEADROOM+22,b+HEADROOM+20,2);
	assert(!flow_parse(reverse+HEADROOM,36,&r) && r.flow_hash==f.flow_hash);
	assert(flow_parse(b+HEADROOM,19,&r)<0);
	assert(dispatch_init(2)==0);
	gcfg.vnet_hdr_sz=0;
	/* Distinct flows round-robin only on first bucket assignment. */
	dispatch_submit(b,36);unsigned n0=0,n1=0;take(0,&n0);take(1,&n1);assert(n0==1 && !n1);
	packet(b,4321,2,0);dispatch_submit(b,36);take(0,&n0);take(1,&n1);assert(n1==1);
	/* Noninitial fragment waits until first identifies the existing flow. */
	packet(b,0,44,2);dispatch_submit(b,36);take(0,&n0);take(1,&n1);assert(n0==1 && n1==1);
	packet(b,4321,44,0x2000);dispatch_submit(b,36);take(0,&n0);take(1,&n1);assert(n0==1 && n1==3);
	packet(b,0,44,2);dispatch_submit(b,36);take(1,&n1);assert(n1==4);
	/* Expiry becomes a tombstone, never a reassignment. */
	clock_seconds=131;dispatch_expire();dispatch_submit(b,36);take(1,&n1);assert(n1==4);
	/* Pending-fragment capacity has explicit drops. */
	packet(b,0,50,2);for(int i=0;i<10;i++)dispatch_submit(b,36);
	assert(atomic_load(&dispatch_drops)>=3);
	packet(b,4321,50,0x2000);dispatch_submit(b,36);unsigned released=0;take(0,&released);take(1,&released);assert(released==9);
	dispatch_stop();dispatch_destroy();
	/* IPv6 extension parsing and fragment-key agreement. */
	uint8_t v6[72]={0};v6[0]=0x60;v6[5]=32;v6[6]=60;v6[8]=0x20;v6[24]=0x30;
	v6[40]=44;v6[48]=17;v6[51]=1;v6[55]=9;v6[56]=1;v6[58]=2;
	assert(!flow_parse(v6,sizeof(v6),&f) && f.first && f.transport);
	v6[50]=0;v6[51]=16;assert(!flow_parse(v6,sizeof(v6),&r) && !r.first && r.fragment_hash==f.fragment_hash);
	v6[41]=255;assert(flow_parse(v6,sizeof(v6),&r)<0);
	return 0;
}
