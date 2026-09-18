/*
 * tools/probe-tun-offload.c - Probe Linux TUN device offload capabilities
 * Part of TAYGA CLAT performance optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>

int main(int argc, char **argv)
{
	int as_json = 0;
	if (argc > 1 && strcmp(argv[1], "--json") == 0)
		as_json = 1;

	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		int err = errno;
		if (as_json) {
			printf("{\"success\":false,\"error\":\"open(/dev/net/tun): %s\",\"errno\":%d}\n",
				strerror(err), err);
		} else {
			fprintf(stderr, "Error: open(/dev/net/tun) failed: %s (errno=%d)\n",
				strerror(err), err);
		}
		return 1;
	}

	unsigned int features = 0;
	if (ioctl(fd, TUNGETFEATURES, &features) < 0) {
		features = 0;
	}

	int feat_vnet_hdr = (features & IFF_VNET_HDR) ? 1 : 0;
	int feat_multi_queue = (features & IFF_MULTI_QUEUE) ? 1 : 0;
	int feat_no_pi = (features & IFF_NO_PI) ? 1 : 0;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
	snprintf(ifr.ifr_name, IFNAMSIZ, "taygaprobe%%d");

	int attach_ok = 1;
	int attach_errno = 0;
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		attach_ok = 0;
		attach_errno = errno;
	}

	int vnet_hdr_sz = -1;
	int get_vnet_hdr_sz_ok = 0;
	int get_vnet_hdr_sz_errno = 0;
	if (attach_ok) {
		if (ioctl(fd, TUNGETVNETHDRSZ, &vnet_hdr_sz) == 0) {
			get_vnet_hdr_sz_ok = 1;
		} else {
			get_vnet_hdr_sz_errno = errno;
		}
	}

	int offload_csum_tso4_tso6_ok = 0;
	int offload_errno = 0;
	if (attach_ok) {
		unsigned int offload_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
		if (ioctl(fd, TUNSETOFFLOAD, offload_flags) == 0) {
			offload_csum_tso4_tso6_ok = 1;
		} else {
			offload_errno = errno;
		}
	}

	close(fd);

	if (as_json) {
		printf("{\n");
		printf("  \"tun_features\": {\n");
		printf("    \"raw\": %u,\n", features);
		printf("    \"IFF_VNET_HDR\": %s,\n", feat_vnet_hdr ? "true" : "false");
		printf("    \"IFF_MULTI_QUEUE\": %s,\n", feat_multi_queue ? "true" : "false");
		printf("    \"IFF_NO_PI\": %s\n", feat_no_pi ? "true" : "false");
		printf("  },\n");
		printf("  \"attach_vnet_hdr\": {\n");
		printf("    \"success\": %s,\n", attach_ok ? "true" : "false");
		printf("    \"dev_name\": \"%s\",\n", attach_ok ? ifr.ifr_name : "");
		printf("    \"errno\": %d,\n", attach_errno);
		printf("    \"error\": \"%s\"\n", attach_errno ? strerror(attach_errno) : "");
		printf("  },\n");
		printf("  \"vnet_hdr_size\": {\n");
		printf("    \"success\": %s,\n", get_vnet_hdr_sz_ok ? "true" : "false");
		printf("    \"size\": %d,\n", vnet_hdr_sz);
		printf("    \"errno\": %d\n", get_vnet_hdr_sz_errno);
		printf("  },\n");
		printf("  \"offload_tso\": {\n");
		printf("    \"success\": %s,\n", offload_csum_tso4_tso6_ok ? "true" : "false");
		printf("    \"flags\": \"TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6\",\n");
		printf("    \"errno\": %d,\n", offload_errno);
		printf("    \"error\": \"%s\"\n", offload_errno ? strerror(offload_errno) : "");
		printf("  }\n");
		printf("}\n");
	} else {
		printf("=== Linux TUN Offload Probe ===\n");
		printf("TUNGETFEATURES: 0x%x (IFF_VNET_HDR=%d, IFF_MULTI_QUEUE=%d, IFF_NO_PI=%d)\n",
			features, feat_vnet_hdr, feat_multi_queue, feat_no_pi);
		printf("Attach with IFF_VNET_HDR: %s (dev=%s, errno=%d %s)\n",
			attach_ok ? "OK" : "FAILED",
			ifr.ifr_name, attach_errno, attach_errno ? strerror(attach_errno) : "");
		if (attach_ok) {
			printf("TUNGETVNETHDRSZ: %d bytes (OK=%d, errno=%d)\n",
				vnet_hdr_sz, get_vnet_hdr_sz_ok, get_vnet_hdr_sz_errno);
			printf("TUNSETOFFLOAD (CSUM|TSO4|TSO6): %s (errno=%d %s)\n",
				offload_csum_tso4_tso6_ok ? "OK" : "FAILED",
				offload_errno, offload_errno ? strerror(offload_errno) : "");
		}
	}

	return (attach_ok && offload_csum_tso4_tso6_ok) ? 0 : 2;
}
