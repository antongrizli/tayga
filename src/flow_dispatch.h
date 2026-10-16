/* Bounded ingress classifier. Offload aggregates retain their ordinary IP
 * header key. Parsing never reads beyond the supplied packet/quoted header. */
#ifndef TAYGA_FLOW_DISPATCH_H
#define TAYGA_FLOW_DISPATCH_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
struct flow_packet {
	uint8_t fragment_key[40];
	uint32_t flow_hash, fragment_hash;
	int fragmented, first, transport;
};
static inline uint16_t flow_be16(const uint8_t *p) { return ((uint16_t)p[0]<<8)|p[1]; }
static inline uint32_t flow_hash_bytes(const void *ptr, size_t size)
{
	const uint8_t *p=ptr; uint32_t h=2166136261u;
	for(size_t i=0;i<size;i++) h=(h^p[i])*16777619u;
	h^=h>>16; h*=0x7feb352d; h^=h>>15; return h;
}
static inline int flow_parse_depth(const uint8_t *p, size_t n, struct flow_packet *out, int depth)
{
	uint8_t src[18]={0}, dst[18]={0}, key[38]={0};
	size_t off, address_size; unsigned proto, family; int seen_fragment=0;
	memset(out,0,sizeof(*out));
	if(!p || !n) return -1;
	family=p[0]>>4;
	if(family==4) {
		if(n<20 || (off=(p[0]&15)*4)<20 || off>n) return -1;
		size_t total=flow_be16(p+2);
		if(total<off || (!depth && total!=n)) return -1;
		if(total<n) n=total;
		proto=p[9];address_size=4;memcpy(src,p+12,4);memcpy(dst,p+16,4);
		unsigned frag=flow_be16(p+6);
		if(frag&0x8000) return -1;
		out->fragmented=!!(frag&0x3fff);out->first=!(frag&0x1fff);
		if(out->fragmented) {
			if((frag&0x4000) || ((frag&0x2000) && ((n-off)%8))) return -1;
			memcpy(out->fragment_key+34,p+4,2);
		}
	} else if(family==6) {
		if(n<40) return -1;
		size_t total=40+(size_t)flow_be16(p+4);
		if(!flow_be16(p+4) || (!depth && total!=n)) return -1;
		if(total<n) n=total;
		proto=p[6];off=40;address_size=16;memcpy(src,p+8,16);memcpy(dst,p+24,16);
		out->first=1;
		for(unsigned count=0;proto==0 || proto==43 || proto==60 || proto==51 || proto==44;count++) {
			if(count==8 || off>296 || off+2>n) return -1;
			unsigned next=p[off];size_t len;
			if(proto==44) {
				if(seen_fragment || off+8>n) return -1;
				seen_fragment=1;
				unsigned frag=flow_be16(p+off+2);
				if(p[off+1] || (frag&6)) return -1;
				out->fragmented=!!(frag&0xfff9);out->first=!(frag&0xfff8);
				if(out->fragmented) {
					memcpy(out->fragment_key+34,p+off+4,4);
					out->fragment_key[1]=next;
					if((frag&1) && (n-off-8)%8) return -1;
				}
				len=8;
			} else len=proto==51?((size_t)p[off+1]+2)*4:((size_t)p[off+1]+1)*8;
			if(len>n-off || off+len>296) return -1;
			off+=len;proto=next;
			if(!out->first) break;
		}
	} else return -1;
	if(out->fragmented) {
		out->fragment_key[0]=family;
		if(family==4) out->fragment_key[1]=proto;
		memcpy(out->fragment_key+2,src,address_size);memcpy(out->fragment_key+18,dst,address_size);
		out->fragment_hash=flow_hash_bytes(out->fragment_key,sizeof(out->fragment_key));
		if(!out->first) return 0;
	}
	if(proto==6 || proto==17) {
		if(off+4>n) return -1;
		memcpy(src+16,p+off,2);memcpy(dst+16,p+off+2,2);out->transport=1;
	} else if((proto==1 || proto==58) && off+8<=n) {
		unsigned type=p[off];
		if(!depth && ((proto==1 && (type==3 || type==11 || type==12)) || (proto==58 && type<128))) {
			struct flow_packet quoted;
			if(!flow_parse_depth(p+off+8,n-off-8,&quoted,1) && quoted.transport && (!quoted.fragmented || quoted.first)) {
				out->flow_hash=quoted.flow_hash;out->transport=1;return 0;
			}
		}
		if((proto==1 && (type==0 || type==8)) || (proto==58 && (type==128 || type==129))) {
			memcpy(src+16,p+off+4,2);memcpy(dst+16,p+off+4,2);out->transport=1;
		}
	}
	key[0]=family;key[1]=proto;
	if(memcmp(src,dst,18)<=0) {memcpy(key+2,src,18);memcpy(key+20,dst,18);}
	else {memcpy(key+2,dst,18);memcpy(key+20,src,18);}
	out->flow_hash=flow_hash_bytes(key,sizeof(key));return 0;
}
static inline int flow_parse(const uint8_t *p,size_t n,struct flow_packet *out)
{ return flow_parse_depth(p,n,out,0); }
#endif
