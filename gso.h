/*
 *  gso.h -- TCP Generic Segmentation Offload routines for TAYGA
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 */

#ifndef TAYGA_GSO_H
#define TAYGA_GSO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

struct pkt;

/* VirtIO Net Header raw structure */
#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1
#define VIRTIO_NET_HDR_F_DATA_VALID	2
#define VIRTIO_NET_HDR_F_RSC_INFO	4

#define VIRTIO_NET_HDR_GSO_NONE		0
#define VIRTIO_NET_HDR_GSO_TCPV4	1
#define VIRTIO_NET_HDR_GSO_UDP		3
#define VIRTIO_NET_HDR_GSO_TCPV6	4
#define VIRTIO_NET_HDR_GSO_UDP_L4	5
#define VIRTIO_NET_HDR_GSO_ECN		0x80

struct virtio_net_hdr_raw {
	uint8_t flags;
	uint8_t gso_type;
	uint16_t hdr_len;
	uint16_t gso_size;
	uint16_t csum_start;
	uint16_t csum_offset;
	uint16_t num_buffers; /* only present if vnet_hdr_sz == 12 */
} __attribute__((packed));

enum tun_offload_mode {
	TUN_OFFLOAD_OFF = 0,
	TUN_OFFLOAD_TCP = 1,
	TUN_OFFLOAD_AUTO = 2,
};

struct gso_worker_stats {
	_Atomic uint64_t gso_pkts_rx;
	_Atomic uint64_t gso_pkts_tx;
	_Atomic uint64_t gso_bytes_rx;
	_Atomic uint64_t gso_bytes_tx;
	_Atomic uint64_t gso_fallback_pkts;
	_Atomic uint64_t gso_invalid_pkts;
};

extern struct gso_worker_stats g_gso_stats;

/* TCP Header definition for GSO inspection and translation */
struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack_seq;
	uint8_t  doff_res; /* 7-4: data offset (32-bit words), 3-0: reserved */
	uint8_t  flags;
	uint16_t window;
	uint16_t cksum;
	uint16_t urg_ptr;
} __attribute__((packed));

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

/* Validation: verifies that vhdr fields are within bounds of packet payload */
int gso_validate_header(const struct pkt *p);

/* Fast-path translation: converts GSO TCPv6 to GSO TCPv4 in-place or returns < 0 for fallback */
int gso_translate_tcp_6to4(struct pkt *p);

/* Fast-path translation: converts GSO TCPv4 to GSO TCPv6 in-place or returns < 0 for fallback */
int gso_translate_tcp_4to6(struct pkt *p);

/* Fallback software segmentation: segments aggregate into MSS-sized chunks and sends individually */
int gso_software_segment_and_send_6to4(struct pkt *p);
int gso_software_segment_and_send_4to6(struct pkt *p);

uint16_t gso_calc_tcp_pseudo4(const struct in_addr *src4, const struct in_addr *dst4, uint32_t tcp_len);
uint16_t gso_calc_tcp_pseudo6(const struct in6_addr *src6, const struct in6_addr *dst6, uint32_t tcp_len);

void gso_update_csum_seed_6to4(struct tcp_hdr *tcp, const struct in6_addr *src6,
                              const struct in6_addr *dst6, const struct in_addr *src4,
                              const struct in_addr *dst4, uint32_t tcp_len);

void gso_update_csum_seed_4to6(struct tcp_hdr *tcp, const struct in_addr *src4,
                              const struct in_addr *dst4, const struct in6_addr *src6,
                              const struct in6_addr *dst6, uint32_t tcp_len);

/* Update TCP pseudo-header checksum difference without recalculating payload */
void gso_update_csum_6to4(struct tcp_hdr *tcp, const struct in6_addr *src6,
                          const struct in6_addr *dst6, const struct in_addr *src4,
                          const struct in_addr *dst4, uint32_t tcp_len);

void gso_update_csum_4to6(struct tcp_hdr *tcp, const struct in_addr *src4,
                          const struct in_addr *dst4, const struct in6_addr *src6,
                          const struct in6_addr *dst6, uint32_t tcp_len);

#endif /* TAYGA_GSO_H */
