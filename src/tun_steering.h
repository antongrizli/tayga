/* Opt-in address-group and 4-tuple flow steering. Each hash bucket is assigned
 * once for the device lifetime. Collisions co-locate groups/flows; no eviction.
 */
#ifndef TAYGA_TUN_STEERING_H
#define TAYGA_TUN_STEERING_H
#ifdef __linux__
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int steering_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}
static int steering_map(unsigned entries)
{
	union bpf_attr attr = {0};
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = attr.value_size = 4;
	attr.max_entries = entries;
	return steering_bpf(BPF_MAP_CREATE, &attr);
}
struct steering_builder { struct bpf_insn code[512]; unsigned n; int overflow; };
static unsigned steering_emit(struct steering_builder *b, unsigned code,
	unsigned dst, unsigned src, int off, int imm)
{
	if (b->n == sizeof(b->code) / sizeof(b->code[0])) {
		b->overflow = 1;
		return 0;
	}
	unsigned n = b->n++;
	b->code[n] = (struct bpf_insn){ .code=code, .dst_reg=dst,
		.src_reg=src, .off=off, .imm=imm };
	return n;
}
#define SE(c,d,s,o,i) steering_emit(&b,c,d,s,o,i)
#define MOVI(d,i) SE(BPF_ALU64|BPF_MOV|BPF_K,d,0,0,i)
#define MOVR(d,s) SE(BPF_ALU64|BPF_MOV|BPF_X,d,s,0,0)
#define ALUI(op,d,i) SE(BPF_ALU64|op|BPF_K,d,0,0,i)
#define LOADMAP(d,fd) do { SE(BPF_LD|BPF_DW|BPF_IMM,d,BPF_PSEUDO_MAP_FD,0,fd); SE(0,0,0,0,0); } while(0)
#define CALL(i) SE(BPF_JMP|BPF_CALL,0,0,0,i)
#define PATCH(n,to) (b.code[n].off=(to)-(n)-1)
static int steering_program_ext(unsigned queues, int flow_aware, char *log, size_t log_size)
{
	int buckets=-1, counter=-1, program=-1, saved;
	struct steering_builder b = {0};
	unsigned fail[16], nf=0, ipv6, hash_done;
	union bpf_attr attr = {0};
	if (!queues || queues > 128) { errno=EINVAL; return -1; }
	buckets=steering_map(65536);
	if (buckets<0) goto done;
	/* Independent admission counters for IPv4 and IPv6. Ownership is permanent
	 * from the first packet: changing queues cannot drain an old worker. */
	counter=steering_map(2);
	if (counter<0) goto done;
	MOVR(6,1);
	/* Load first 20 bytes (covers entire basic IPv4 header + IPv6 version & next_header). */
	MOVI(2,0); MOVR(3,10); ALUI(BPF_ADD,3,-64); MOVI(4,20);
	CALL(BPF_FUNC_skb_load_bytes);
	fail[nf++]=SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
	SE(BPF_LDX|BPF_MEM|BPF_B,7,10,-64,0); ALUI(BPF_RSH,7,4);
	ipv6=SE(BPF_JMP|BPF_JEQ|BPF_K,7,0,0,6);
	fail[nf++]=SE(BPF_JMP|BPF_JNE|BPF_K,7,0,0,4);
	/* IPv4: r9 = 0 (family index 0). src4 is at r10-52 (off 12), dst4 is at r10-48 (off 16). */
	MOVI(9,0);
	SE(BPF_LDX|BPF_MEM|BPF_W,7,10,-52,0);
	SE(BPF_LDX|BPF_MEM|BPF_W,1,10,-48,0);
	SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0); ALUI(BPF_XOR,7,4);
	if (flow_aware) {
		/* frag_offset is at r10-58 (off 6); mask IP4_F_MASK (0x1fff) | IP4_F_MF (0x2000) = 0x3fff */
		SE(BPF_LDX|BPF_MEM|BPF_H,1,10,-58,0);
		ALUI(BPF_AND,1,(uint16_t)htons(0x3fff));
		unsigned is_frag = SE(BPF_JMP|BPF_JNE|BPF_K,1,0,0,0);
		/* proto is at r10-55 (off 9) */
		SE(BPF_LDX|BPF_MEM|BPF_B,1,10,-55,0);
		unsigned is_tcp = SE(BPF_JMP|BPF_JEQ|BPF_K,1,0,0,6);
		unsigned not_udp = SE(BPF_JMP|BPF_JNE|BPF_K,1,0,0,17);
		PATCH(is_tcp, b.n);
		/* IHL is in byte 0 at r10-64 */
		SE(BPF_LDX|BPF_MEM|BPF_B,2,10,-64,0);
		ALUI(BPF_AND,2,0x0f);
		ALUI(BPF_LSH,2,2);
		/* Load 4 bytes of transport ports (src_port:2, dst_port:2) at offset r2 */
		MOVR(1,6); MOVR(3,10); ALUI(BPF_ADD,3,-64); MOVI(4,4);
		CALL(BPF_FUNC_skb_load_bytes);
		unsigned skip_l4_ports = SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
		SE(BPF_LDX|BPF_MEM|BPF_W,1,10,-64,0);
		SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0);
		ALUI(BPF_MUL,7,16777619);
		PATCH(is_frag, b.n);
		PATCH(not_udp, b.n);
		PATCH(skip_l4_ports, b.n);
	}
	hash_done=SE(BPF_JMP|BPF_JA,0,0,0,0);
	PATCH(ipv6,b.n);
	/* IPv6: save next_header from r10-58 (offset 6) into r9 before overwriting stack */
	SE(BPF_LDX|BPF_MEM|BPF_B,9,10,-58,0);
	MOVR(1,6); MOVI(2,8); MOVR(3,10); ALUI(BPF_ADD,3,-64); MOVI(4,32);
	CALL(BPF_FUNC_skb_load_bytes);
	fail[nf++]=SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
	MOVI(7,6);
	for (int i=0;i<4;i++) {
		SE(BPF_LDX|BPF_MEM|BPF_W,1,10,-64+4*i,0);
		SE(BPF_LDX|BPF_MEM|BPF_W,2,10,-48+4*i,0);
		SE(BPF_ALU|BPF_XOR|BPF_X,1,2,0,0);
		SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0); ALUI(BPF_MUL,7,16777619);
	}
	if (flow_aware) {
		unsigned is_tcp6 = SE(BPF_JMP|BPF_JEQ|BPF_K,9,0,0,6);
		unsigned not_udp6 = SE(BPF_JMP|BPF_JNE|BPF_K,9,0,0,17);
		PATCH(is_tcp6, b.n);
		/* Unfragmented TCP or UDP: ports are at fixed offset 40 */
		MOVR(1,6); MOVI(2,40); MOVR(3,10); ALUI(BPF_ADD,3,-64); MOVI(4,4);
		CALL(BPF_FUNC_skb_load_bytes);
		unsigned skip_l4_ports6 = SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
		SE(BPF_LDX|BPF_MEM|BPF_W,1,10,-64,0);
		SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0);
		ALUI(BPF_MUL,7,16777619);
		PATCH(not_udp6, b.n);
		PATCH(skip_l4_ports6, b.n);
	}
	/* Set r9 = 1 (IPv6 family index) */
	MOVI(9,1);
	PATCH(hash_done,b.n);
	MOVR(1,7); ALUI(BPF_RSH,1,16); SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0);
	ALUI(BPF_MUL,7,0x45d9f3b); MOVR(1,7); ALUI(BPF_RSH,1,16);
	SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0); ALUI(BPF_AND,7,65535);
	SE(BPF_STX|BPF_MEM|BPF_W,10,7,-4,0);
	LOADMAP(1,buckets); MOVR(2,10); ALUI(BPF_ADD,2,-4); CALL(BPF_FUNC_map_lookup_elem);
	fail[nf++]=SE(BPF_JMP|BPF_JEQ|BPF_K,0,0,0,0);
	MOVR(8,0); SE(BPF_LDX|BPF_MEM|BPF_W,7,8,0,0);
	unsigned existing = SE(BPF_JMP|BPF_JNE|BPF_K,7,0,0,0);
	SE(BPF_STX|BPF_MEM|BPF_W,10,9,-8,0);
	LOADMAP(1,counter); MOVR(2,10); ALUI(BPF_ADD,2,-8); CALL(BPF_FUNC_map_lookup_elem);
	fail[nf++]=SE(BPF_JMP|BPF_JEQ|BPF_K,0,0,0,0);
	MOVI(1,1); SE(BPF_STX|BPF_ATOMIC|BPF_W,0,1,0,BPF_ADD|BPF_FETCH);
	ALUI(BPF_MOD,1,queues); ALUI(BPF_ADD,1,1); MOVI(0,0);
	SE(BPF_STX|BPF_ATOMIC|BPF_W,8,1,0,BPF_CMPXCHG);
	/* A losing contender must use the published winner, never its candidate. */
	unsigned won = SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
	MOVR(0,1);
	PATCH(won,b.n);
	MOVR(7,0);
	PATCH(existing,b.n);
	MOVR(0,7); ALUI(BPF_SUB,0,1);
	SE(BPF_JMP|BPF_EXIT,0,0,0,0);
	for (unsigned i=0;i<nf;i++) PATCH(fail[i],b.n);
	MOVI(0,0); SE(BPF_JMP|BPF_EXIT,0,0,0,0);
	if (b.overflow) { errno=E2BIG; goto done; }
	attr.prog_type=BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt=b.n; attr.insns=(uintptr_t)b.code;
	attr.license=(uintptr_t)"GPL";
	attr.log_buf=(uintptr_t)log; attr.log_size=log_size; attr.log_level=1;
	memcpy(attr.prog_name, flow_aware ? "tayga_flows" : "tayga_groups", flow_aware ? 12 : 13);
	program=steering_bpf(BPF_PROG_LOAD,&attr);
 done:
	saved=errno;
	if (buckets>=0) close(buckets);
	if (counter>=0) close(counter);
	errno=saved;
	return program;
}
static inline int steering_program(unsigned queues, char *log, size_t log_size)
{
	return steering_program_ext(queues, 0, log, log_size);
}
#undef SE
#undef MOVI
#undef MOVR
#undef ALUI
#undef LOADMAP
#undef CALL
#undef PATCH
#endif
#endif
