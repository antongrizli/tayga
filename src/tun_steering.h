/* Opt-in address-group steering. Each hash bucket is assigned once for the
 * device lifetime. Collisions co-locate groups; no eviction or migration.
 * This deliberately excludes ports so fragmentation cannot change a queue. */
#ifndef TAYGA_TUN_STEERING_H
#define TAYGA_TUN_STEERING_H
#ifdef __linux__
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
struct steering_builder { struct bpf_insn code[160]; unsigned n; };
static unsigned steering_emit(struct steering_builder *b, unsigned code,
	unsigned dst, unsigned src, int off, int imm)
{
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
static int steering_program(unsigned queues, char *log, size_t log_size)
{
	int buckets=-1, counter=-1, program=-1, saved;
	struct steering_builder b = {0};
	unsigned fail[8], nf=0, ipv6, hash_done, existing, won;
	union bpf_attr attr = {0};
	if (!queues || queues > 128) { errno=EINVAL; return -1; }
	buckets=steering_map(65536);
	if (buckets<0) goto done;
	counter=steering_map(1);
	if (counter<0) goto done;
	MOVR(6,1);
	/* Read only the version, then bounded addresses; never assume Ethernet. */
	MOVI(2,0); MOVR(3,10); ALUI(BPF_ADD,3,-64); MOVI(4,1);
	CALL(BPF_FUNC_skb_load_bytes);
	fail[nf++]=SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
	SE(BPF_LDX|BPF_MEM|BPF_B,7,10,-64,0); ALUI(BPF_RSH,7,4);
	ipv6=SE(BPF_JMP|BPF_JEQ|BPF_K,7,0,0,6);
	fail[nf++]=SE(BPF_JMP|BPF_JNE|BPF_K,7,0,0,4);
	MOVR(1,6); MOVI(2,12); MOVR(3,10); ALUI(BPF_ADD,3,-64); MOVI(4,8);
	CALL(BPF_FUNC_skb_load_bytes);
	fail[nf++]=SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
	SE(BPF_LDX|BPF_MEM|BPF_W,7,10,-64,0);
	SE(BPF_LDX|BPF_MEM|BPF_W,1,10,-60,0);
	SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0); ALUI(BPF_XOR,7,4);
	hash_done=SE(BPF_JMP|BPF_JA,0,0,0,0);
	PATCH(ipv6,b.n);
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
	PATCH(hash_done,b.n);
	MOVR(1,7); ALUI(BPF_RSH,1,16); SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0);
	ALUI(BPF_MUL,7,0x45d9f3b); MOVR(1,7); ALUI(BPF_RSH,1,16);
	SE(BPF_ALU|BPF_XOR|BPF_X,7,1,0,0); ALUI(BPF_AND,7,65535);
	SE(BPF_STX|BPF_MEM|BPF_W,10,7,-4,0);
	LOADMAP(1,buckets); MOVR(2,10); ALUI(BPF_ADD,2,-4); CALL(BPF_FUNC_map_lookup_elem);
	fail[nf++]=SE(BPF_JMP|BPF_JEQ|BPF_K,0,0,0,0);
	MOVR(8,0); SE(BPF_LDX|BPF_MEM|BPF_W,0,8,0,0);
	existing=SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0);
	SE(BPF_ST|BPF_MEM|BPF_W,10,0,-8,0);
	LOADMAP(1,counter); MOVR(2,10); ALUI(BPF_ADD,2,-8); CALL(BPF_FUNC_map_lookup_elem);
	fail[nf++]=SE(BPF_JMP|BPF_JEQ|BPF_K,0,0,0,0);
	MOVI(1,1); SE(BPF_STX|BPF_ATOMIC|BPF_W,0,1,0,BPF_ADD|BPF_FETCH);
	ALUI(BPF_MOD,1,queues); ALUI(BPF_ADD,1,1); MOVI(0,0);
	/* cmpxchg returns the previous value in r0. Losing first-packet races
	 * always use the winner's queue, never a transient local assignment. */
	SE(BPF_STX|BPF_ATOMIC|BPF_W,8,1,0,BPF_CMPXCHG);
	won=SE(BPF_JMP|BPF_JNE|BPF_K,0,0,0,0); MOVR(0,1);
	PATCH(won,b.n); PATCH(existing,b.n); ALUI(BPF_SUB,0,1);
	SE(BPF_JMP|BPF_EXIT,0,0,0,0);
	for (unsigned i=0;i<nf;i++) PATCH(fail[i],b.n);
	MOVI(0,0); SE(BPF_JMP|BPF_EXIT,0,0,0,0);
	attr.prog_type=BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt=b.n; attr.insns=(uintptr_t)b.code;
	attr.license=(uintptr_t)"GPL";
	attr.log_buf=(uintptr_t)log; attr.log_size=log_size; attr.log_level=1;
	memcpy(attr.prog_name,"tayga_groups",13);
	program=steering_bpf(BPF_PROG_LOAD,&attr);
 done:
	saved=errno;
	if (buckets>=0) close(buckets);
	if (counter>=0) close(counter);
	errno=saved;
	return program;
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
