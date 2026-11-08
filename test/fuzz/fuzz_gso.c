/* libFuzzer harness: GSO translation and software segmentation entry points.
 * Unlike fuzz_pkt4/6 this calls every gso_* function directly, with an MTU and
 * virtio header chosen by the input, so segmentation arithmetic is reached even
 * when the packet would be rejected earlier by handle_ip{4,6}. */
#include "fuzz_common.h"
#include "gso.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_setup_maps();
	return 0;
}

typedef int (*gso_fn)(struct pkt *);
static const gso_fn fns[] = {
	gso_translate_tcp_4to6, gso_translate_tcp_6to4,
	gso_translate_udp_4to6, gso_translate_udp_6to4,
	gso_software_segment_and_send_4to6, gso_software_segment_and_send_6to4,
	gso_software_segment_and_send_udp_4to6, gso_software_segment_and_send_udp_6to4,
};
static const unsigned mtus[] = {1280, 1500, 9000, 65535};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct pkt p;
	if (size < 2 + sizeof(p.vhdr) || size > 65536)
		return 0;
	gcfg.mtu = mtus[data[0] & 3];
	gcfg.tun_offload_effective = (enum tun_offload_mode)(1 + ((data[0] >> 2) & 1));
	gcfg.vnet_hdr_sz = (int)sizeof(p.vhdr);
	gcfg.log_opts = 0;
	gso_fn fn = fns[data[1] % (sizeof(fns) / sizeof(fns[0]))];
	data += 2; size -= 2;

	memset(&p, 0, sizeof(p));
	p.tun_fd = fuzz_null_fd;
	memcpy(&p.vhdr, data, sizeof(p.vhdr));
	data += sizeof(p.vhdr); size -= sizeof(p.vhdr);
	p.has_vhdr = 1;

	uint8_t *buf = malloc(HEADROOM + size);
	if (!buf)
		abort();
	memset(buf, 0, HEADROOM);
	memcpy(buf + HEADROOM, data, size);
	p.data = buf + HEADROOM;
	p.data_len = (uint32_t)size;
	(void)fn(&p);
	free(buf);
	return 0;
}
