/*
 *  gso.c -- TCP Generic Segmentation Offload engine for TAYGA
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 */

#include "tayga.h"
#include "gso.h"

struct gso_worker_stats g_gso_stats = {0};

/*
 * Pseudo-header checksum calculation helpers
 */
static inline uint32_t csum_partial_fold(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static inline uint32_t csum_add_u16(uint32_t sum, uint16_t val)
{
	sum += val;
	return sum;
}

static inline uint32_t csum_sub_u16(uint32_t sum, uint16_t val)
{
	sum += (uint16_t)(~val);
	return sum;
}

uint16_t gso_calc_tcp_pseudo4(const struct in_addr *src4, const struct in_addr *dst4, uint32_t tcp_len)
{
	uint32_t sum = 0;
	const uint16_t *p4 = (const uint16_t *)src4;
	sum += ntohs(p4[0]);
	sum += ntohs(p4[1]);
	p4 = (const uint16_t *)dst4;
	sum += ntohs(p4[0]);
	sum += ntohs(p4[1]);
	sum += IPPROTO_TCP;
	sum += (tcp_len & 0xffff);

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (uint16_t)sum;
}

uint16_t gso_calc_tcp_pseudo6(const struct in6_addr *src6, const struct in6_addr *dst6, uint32_t tcp_len)
{
	uint32_t sum = 0;
	const uint16_t *p6 = (const uint16_t *)src6;
	for (int i = 0; i < 8; i++) sum += ntohs(p6[i]);
	p6 = (const uint16_t *)dst6;
	for (int i = 0; i < 8; i++) sum += ntohs(p6[i]);
	sum += (tcp_len >> 16);
	sum += (tcp_len & 0xffff);
	sum += IPPROTO_TCP;

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (uint16_t)sum;
}

/* Update TCP checksum for partially checksummed packet (CHECKSUM_PARTIAL / NEEDS_CSUM seed) */
void gso_update_csum_seed_6to4(struct tcp_hdr *tcp, const struct in6_addr *src6,
                              const struct in6_addr *dst6, const struct in_addr *src4,
                              const struct in_addr *dst4, uint32_t tcp_len)
{
	(void)src6;
	(void)dst6;
	tcp->cksum = htons(gso_calc_tcp_pseudo4(src4, dst4, tcp_len));
}

void gso_update_csum_seed_4to6(struct tcp_hdr *tcp, const struct in_addr *src4,
                              const struct in_addr *dst4, const struct in6_addr *src6,
                              const struct in6_addr *dst6, uint32_t tcp_len)
{
	(void)src4;
	(void)dst4;
	tcp->cksum = htons(gso_calc_tcp_pseudo6(src6, dst6, tcp_len));
}

/* RFC 1624 incremental update for fully checksummed packet (DATA_VALID / NONE) */
void gso_update_csum_6to4(struct tcp_hdr *tcp, const struct in6_addr *src6,
                          const struct in6_addr *dst6, const struct in_addr *src4,
                          const struct in_addr *dst4, uint32_t tcp_len)
{
	uint32_t sum = ntohs(tcp->cksum);

	/* Add old IPv6 pseudo-header (RFC 1624: HC' = HC + m + ~m') */
	const uint16_t *p6 = (const uint16_t *)src6;
	for (int i = 0; i < 8; i++) sum += ntohs(p6[i]);
	p6 = (const uint16_t *)dst6;
	for (int i = 0; i < 8; i++) sum += ntohs(p6[i]);
	sum += (tcp_len >> 16);
	sum += (tcp_len & 0xffff);
	sum += IPPROTO_TCP;

	/* Add inverted new IPv4 pseudo-header */
	const uint16_t *p4 = (const uint16_t *)src4;
	sum += (~ntohs(p4[0])) & 0xffff;
	sum += (~ntohs(p4[1])) & 0xffff;
	p4 = (const uint16_t *)dst4;
	sum += (~ntohs(p4[0])) & 0xffff;
	sum += (~ntohs(p4[1])) & 0xffff;
	sum += (~(uint16_t)IPPROTO_TCP) & 0xffff;
	sum += (~(uint16_t)(tcp_len & 0xffff)) & 0xffff;

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	if (sum == 0)
		sum = 0xffff;

	tcp->cksum = htons((uint16_t)sum);
}

void gso_update_csum_4to6(struct tcp_hdr *tcp, const struct in_addr *src4,
                          const struct in_addr *dst4, const struct in6_addr *src6,
                          const struct in6_addr *dst6, uint32_t tcp_len)
{
	uint32_t sum = ntohs(tcp->cksum);

	/* Add old IPv4 pseudo-header (RFC 1624: HC' = HC + m + ~m') */
	const uint16_t *p4 = (const uint16_t *)src4;
	sum += ntohs(p4[0]);
	sum += ntohs(p4[1]);
	p4 = (const uint16_t *)dst4;
	sum += ntohs(p4[0]);
	sum += ntohs(p4[1]);
	sum += IPPROTO_TCP;
	sum += (tcp_len & 0xffff);

	/* Add inverted new IPv6 pseudo-header */
	const uint16_t *p6 = (const uint16_t *)src6;
	for (int i = 0; i < 8; i++) sum += (~ntohs(p6[i])) & 0xffff;
	p6 = (const uint16_t *)dst6;
	for (int i = 0; i < 8; i++) sum += (~ntohs(p6[i])) & 0xffff;
	sum += (~(uint16_t)(tcp_len >> 16)) & 0xffff;
	sum += (~(uint16_t)(tcp_len & 0xffff)) & 0xffff;
	sum += (~(uint16_t)IPPROTO_TCP) & 0xffff;

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	if (sum == 0)
		sum = 0xffff;

	tcp->cksum = htons((uint16_t)sum);
}

int gso_validate_header(const struct pkt *p)
{
	if (!p->has_vhdr)
		return 0;

	uint8_t gso_type = p->vhdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN;
	if (gso_type == VIRTIO_NET_HDR_GSO_NONE)
		return 0;

	if (gso_type != VIRTIO_NET_HDR_GSO_TCPV4 && gso_type != VIRTIO_NET_HDR_GSO_TCPV6) {
		atomic_fetch_add_explicit(&g_gso_stats.gso_invalid_pkts, 1, memory_order_relaxed);
		return -1;
	}

	if (p->vhdr.gso_size == 0 || p->vhdr.hdr_len > p->data_len) {
		atomic_fetch_add_explicit(&g_gso_stats.gso_invalid_pkts, 1, memory_order_relaxed);
		return -1;
	}

	if (p->vhdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		if (p->vhdr.csum_start >= p->data_len ||
		    (uint32_t)p->vhdr.csum_start + p->vhdr.csum_offset + 2 > p->data_len) {
			atomic_fetch_add_explicit(&g_gso_stats.gso_invalid_pkts, 1, memory_order_relaxed);
			return -1;
		}
	}

	return 1;
}

int gso_translate_tcp_6to4(struct pkt *p)
{
	if (!p->has_vhdr || (p->vhdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) != VIRTIO_NET_HDR_GSO_TCPV6)
		return -1;

	atomic_fetch_add_explicit(&g_gso_stats.gso_pkts_rx, 1, memory_order_relaxed);
	atomic_fetch_add_explicit(&g_gso_stats.gso_bytes_rx, p->data_len, memory_order_relaxed);

	if (gso_validate_header(p) <= 0)
		return -1;

	if (p->data_len < sizeof(struct ip6) + sizeof(struct tcp_hdr))
		return -1;

	struct ip6 *ip6 = (struct ip6 *)p->data;
	if (ip6->next_header != IPPROTO_TCP)
		return -1;

	struct tcp_hdr *tcp = (struct tcp_hdr *)(p->data + sizeof(struct ip6));
	uint32_t tcp_hdr_len = (tcp->doff_res >> 4) * 4;
	if (tcp_hdr_len < sizeof(struct tcp_hdr) || sizeof(struct ip6) + tcp_hdr_len > p->data_len)
		return -1;

	uint32_t payload_len = p->data_len - sizeof(struct ip6) - tcp_hdr_len;
	uint32_t gso_size = p->vhdr.gso_size;
	if (gso_size == 0)
		return -1;

	/* RFC 7915 §5.1 & RFC 6864 §4.3: check whether all segments get DF=1 */
	uint32_t full_seg_ip4_len = sizeof(struct ip4) + tcp_hdr_len + gso_size;
	uint32_t tail_len = payload_len % gso_size;
	uint32_t tail_ip4_len = tail_len > 0 ? (sizeof(struct ip4) + tcp_hdr_len + tail_len) : full_seg_ip4_len;

	/* If segments <= 1260, they require DF=0 and unique IDs; must use software segmentation */
	if (full_seg_ip4_len <= 1260 || (tail_len > 0 && tail_ip4_len <= 1260)) {
		return gso_software_segment_and_send_6to4(p);
	}

	/* Fast-path: map addresses */
	struct in_addr src4, dst4;
	if (map_ip6_to_ip4(&src4, &ip6->src, 1) < 0 || map_ip6_to_ip4(&dst4, &ip6->dest, 0) < 0) {
		return -1;
	}

	/* Extract fields from IPv6 header BEFORE shifting overwrites p->data */
	uint8_t tos = (uint8_t)((ntohl(ip6->ver_tc_fl) >> 20) & 0xff);
	uint8_t ttl = ip6->hop_limit > 1 ? (ip6->hop_limit - 1) : 1;

	/* Update TCP checksum seed for IPv4 pseudo-header */
	uint32_t tcp_len = tcp_hdr_len + payload_len;
	gso_update_csum_seed_6to4(tcp, &ip6->src, &ip6->dest, &src4, &dst4, tcp_len);

	/* Shift complete TCP segment (header + payload) 20 bytes forward to overwrite part of IPv6 header */
	memmove(p->data + sizeof(struct ip4), tcp, tcp_len);

	/* Form IPv4 header directly before the moved TCP header */
	struct ip4 *ip4 = (struct ip4 *)p->data;
	ip4->ver_ihl = 0x45;
	ip4->tos = tos;
	ip4->length = htons((uint16_t)(sizeof(struct ip4) + tcp_len));
	ip4->ident = 0; /* DF=1, atomic datagram per RFC 6864 */
	ip4->flags_offset = htons(IP4_F_DF);
	ip4->ttl = ttl;
	ip4->proto = IPPROTO_TCP;
	ip4->cksum = 0;
	ip4->src = src4;
	ip4->dest = dst4;
	ip4->cksum = ip4_header_checksum(ip4);

	/* Update VirtIO Net Header for IPv4 TCP GSO */
	struct virtio_net_hdr_raw out_vhdr = p->vhdr;
	out_vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4 | (p->vhdr.gso_type & VIRTIO_NET_HDR_GSO_ECN);
	out_vhdr.hdr_len -= (sizeof(struct ip6) - sizeof(struct ip4));
	out_vhdr.csum_start -= (sizeof(struct ip6) - sizeof(struct ip4));
	out_vhdr.flags |= VIRTIO_NET_HDR_F_NEEDS_CSUM;

	size_t out_len = sizeof(struct ip4) + tcp_len;
	ssize_t ret = tun_write_vnet(p->tun_fd, &out_vhdr, p->data, out_len);
	if (ret > 0) {
		atomic_fetch_add_explicit(&g_gso_stats.gso_pkts_tx, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&g_gso_stats.gso_bytes_tx, out_len, memory_order_relaxed);
		return 0;
	}

	return -1;
}

int gso_translate_tcp_4to6(struct pkt *p)
{
	if (!p->has_vhdr || (p->vhdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) != VIRTIO_NET_HDR_GSO_TCPV4)
		return -1;

	atomic_fetch_add_explicit(&g_gso_stats.gso_pkts_rx, 1, memory_order_relaxed);
	atomic_fetch_add_explicit(&g_gso_stats.gso_bytes_rx, p->data_len, memory_order_relaxed);

	if (gso_validate_header(p) <= 0)
		return -1;

	if (p->data_len < sizeof(struct ip4) + sizeof(struct tcp_hdr))
		return -1;

	struct ip4 *ip4 = (struct ip4 *)p->data;
	if (ip4->proto != IPPROTO_TCP)
		return -1;

	uint32_t ip4_hdr_len = (ip4->ver_ihl & 0x0f) * 4;
	if (ip4_hdr_len < sizeof(struct ip4) || ip4_hdr_len > p->data_len)
		return -1;

	struct tcp_hdr *tcp = (struct tcp_hdr *)(p->data + ip4_hdr_len);
	uint32_t tcp_hdr_len = (tcp->doff_res >> 4) * 4;
	if (tcp_hdr_len < sizeof(struct tcp_hdr) || ip4_hdr_len + tcp_hdr_len > p->data_len)
		return -1;

	uint32_t payload_len = p->data_len - ip4_hdr_len - tcp_hdr_len;

	/* Map addresses */
	struct in6_addr src6, dst6;
	if (map_ip4_to_ip6(&src6, &ip4->src) < 0 || map_ip4_to_ip6(&dst6, &ip4->dest) < 0)
		return -1;

	/* Update TCP checksum seed for IPv6 pseudo-header */
	uint32_t tcp_len = tcp_hdr_len + payload_len;
	gso_update_csum_seed_4to6(tcp, &ip4->src, &ip4->dest, &src6, &dst6, tcp_len);

	/* Use headroom before p->data to prepend 20 bytes for IPv6 header */
	uint8_t *out = p->data - (sizeof(struct ip6) - sizeof(struct ip4));
	struct ip6 *ip6 = (struct ip6 *)out;
	ip6->ver_tc_fl = htonl(0x60000000 | ((uint32_t)ip4->tos << 20));
	ip6->payload_length = htons((uint16_t)tcp_len);
	ip6->next_header = IPPROTO_TCP;
	ip6->hop_limit = ip4->ttl > 1 ? (ip4->ttl - 1) : 1;
	ip6->src = src6;
	ip6->dest = dst6;

	/* Update VirtIO Net Header for IPv6 TCP GSO */
	struct virtio_net_hdr_raw out_vhdr = p->vhdr;
	out_vhdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6 | (p->vhdr.gso_type & VIRTIO_NET_HDR_GSO_ECN);
	out_vhdr.hdr_len += (sizeof(struct ip6) - sizeof(struct ip4));
	out_vhdr.csum_start += (sizeof(struct ip6) - sizeof(struct ip4));
	out_vhdr.flags |= VIRTIO_NET_HDR_F_NEEDS_CSUM;

	size_t out_len = sizeof(struct ip6) + tcp_len;
	ssize_t ret = tun_write_vnet(p->tun_fd, &out_vhdr, out, out_len);
	if (ret > 0) {
		atomic_fetch_add_explicit(&g_gso_stats.gso_pkts_tx, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&g_gso_stats.gso_bytes_tx, out_len, memory_order_relaxed);
		return 0;
	}

	return -1;
}

int gso_software_segment_and_send_6to4(struct pkt *p)
{
	atomic_fetch_add_explicit(&g_gso_stats.gso_fallback_pkts, 1, memory_order_relaxed);

	struct ip6 *ip6 = (struct ip6 *)p->data;
	struct tcp_hdr *orig_tcp = (struct tcp_hdr *)(p->data + sizeof(struct ip6));
	uint32_t tcp_hdr_len = (orig_tcp->doff_res >> 4) * 4;
	uint8_t *payload = p->data + sizeof(struct ip6) + tcp_hdr_len;
	uint32_t payload_len = p->data_len - sizeof(struct ip6) - tcp_hdr_len;
	uint32_t gso_size = p->vhdr.gso_size;

	struct in_addr src4, dst4;
	if (map_ip6_to_ip4(&src4, &ip6->src, 1) < 0 || map_ip6_to_ip4(&dst4, &ip6->dest, 0) < 0)
		return -1;

	uint32_t offset = 0;
	uint32_t orig_seq = ntohl(orig_tcp->seq);

	/* Buffer for individual segment */
	uint8_t seg_buf[HEADROOM + 2048];
	uint8_t *seg_ip = seg_buf + HEADROOM;

	while (offset < payload_len || (offset == 0 && payload_len == 0)) {
		uint32_t seg_data_len = payload_len - offset;
		if (seg_data_len > gso_size)
			seg_data_len = gso_size;

		int is_last = (offset + seg_data_len == payload_len);

		/* Form segment TCP header */
		struct tcp_hdr *seg_tcp = (struct tcp_hdr *)(seg_ip + sizeof(struct ip4));
		memcpy(seg_tcp, orig_tcp, tcp_hdr_len);
		seg_tcp->seq = htonl(orig_seq + offset);

		/* Flags: FIN and PSH only on last segment */
		if (!is_last) {
			seg_tcp->flags &= ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
		}

		/* Copy payload */
		if (seg_data_len > 0) {
			memcpy((uint8_t *)seg_tcp + tcp_hdr_len, payload + offset, seg_data_len);
		}

		uint32_t seg_tcp_total_len = tcp_hdr_len + seg_data_len;

		/* Form IPv4 header first so ip4_checksum can read src/dest/proto */
		struct ip4 *ip4 = (struct ip4 *)seg_ip;
		ip4->ver_ihl = 0x45;
		ip4->tos = (uint8_t)((ntohl(ip6->ver_tc_fl) >> 20) & 0xff);
		uint32_t ip4_total = sizeof(struct ip4) + seg_tcp_total_len;
		ip4->length = htons((uint16_t)ip4_total);

		/* DF & IPv4 ID policy (RFC 7915 §5.1, RFC 6864 §4.3) */
		if (ip4_total <= 1260) {
			ip4->flags_offset = 0; /* DF=0 */
			ip4->ident = next_ip4_ident();
		} else {
			ip4->flags_offset = htons(IP4_F_DF);
			ip4->ident = 0;
		}

		ip4->ttl = ip6->hop_limit > 1 ? (ip6->hop_limit - 1) : 1;
		ip4->proto = IPPROTO_TCP;
		ip4->src = src4;
		ip4->dest = dst4;
		ip4->cksum = 0;
		ip4->cksum = ip4_header_checksum(ip4);

		/* Compute complete TCP checksum for this segment using standard TAYGA checksum logic */
		seg_tcp->cksum = 0;
		seg_tcp->cksum = ones_add(ip_checksum(seg_tcp, seg_tcp_total_len),
		                          ip4_checksum(ip4, seg_tcp_total_len, IPPROTO_TCP));

		/* Send segment using tun_write */
		tun_write(p->tun_fd, seg_ip, ip4_total);

		offset += seg_data_len;
		if (offset >= payload_len)
			break;
	}

	return 0;
}

int gso_software_segment_and_send_4to6(struct pkt *p)
{
	atomic_fetch_add_explicit(&g_gso_stats.gso_fallback_pkts, 1, memory_order_relaxed);

	struct ip4 *ip4 = (struct ip4 *)p->data;
	uint32_t ip4_hdr_len = (ip4->ver_ihl & 0x0f) * 4;
	struct tcp_hdr *orig_tcp = (struct tcp_hdr *)(p->data + ip4_hdr_len);
	uint32_t tcp_hdr_len = (orig_tcp->doff_res >> 4) * 4;
	uint8_t *payload = p->data + ip4_hdr_len + tcp_hdr_len;
	uint32_t payload_len = p->data_len - ip4_hdr_len - tcp_hdr_len;
	uint32_t gso_size = p->vhdr.gso_size;

	struct in6_addr src6, dst6;
	if (map_ip4_to_ip6(&src6, &ip4->src) < 0 || map_ip4_to_ip6(&dst6, &ip4->dest) < 0)
		return -1;

	uint32_t offset = 0;
	uint32_t orig_seq = ntohl(orig_tcp->seq);

	uint8_t seg_buf[HEADROOM + 2048];
	uint8_t *seg_ip = seg_buf + HEADROOM;

	while (offset < payload_len || (offset == 0 && payload_len == 0)) {
		uint32_t seg_data_len = payload_len - offset;
		if (seg_data_len > gso_size)
			seg_data_len = gso_size;

		int is_last = (offset + seg_data_len == payload_len);

		struct tcp_hdr *seg_tcp = (struct tcp_hdr *)(seg_ip + sizeof(struct ip6));
		memcpy(seg_tcp, orig_tcp, tcp_hdr_len);
		seg_tcp->seq = htonl(orig_seq + offset);

		if (!is_last) {
			seg_tcp->flags &= ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
		}

		if (seg_data_len > 0) {
			memcpy((uint8_t *)seg_tcp + tcp_hdr_len, payload + offset, seg_data_len);
		}

		uint32_t seg_tcp_total_len = tcp_hdr_len + seg_data_len;

		/* IPv6 Header */
		struct ip6 *ip6 = (struct ip6 *)seg_ip;
		ip6->ver_tc_fl = htonl(0x60000000 | ((uint32_t)ip4->tos << 20));
		ip6->payload_length = htons((uint16_t)seg_tcp_total_len);
		ip6->next_header = IPPROTO_TCP;
		ip6->hop_limit = ip4->ttl > 1 ? (ip4->ttl - 1) : 1;
		ip6->src = src6;
		ip6->dest = dst6;

		/* Compute complete TCP checksum for this segment using standard TAYGA checksum logic */
		seg_tcp->cksum = 0;
		seg_tcp->cksum = ones_add(ip_checksum(seg_tcp, seg_tcp_total_len),
		                          ip6_checksum(ip6, seg_tcp_total_len, IPPROTO_TCP));

		tun_write(p->tun_fd, seg_ip, sizeof(struct ip6) + seg_tcp_total_len);

		offset += seg_data_len;
		if (offset >= payload_len)
			break;
	}

	return 0;
}
