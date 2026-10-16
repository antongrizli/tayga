/*
 *  addrmap.c -- address mapping routines
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 *  Copyright (C) 2010  Nathan Lutchansky <lutchann@litech.org>
 *  Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include "tayga.h"

/**
 * @brief Check if an IPv4 address is valid
 *
 * Checks if an address is within the ranges which are reserved
 * by protocol, such as multicast, link-local, etc.
 *
 * @param a struct in_addr address to validate
 * @returns ERROR_DROP if invalid, else 0
 */
int validate_ip4_addr(const struct in_addr *a)
{
	/* First Octet == 0 */
	if ((a->s_addr & htonl(0xff000000)) == htonl(0x00000000))
		return ERROR_DROP;
	/* First octet == 127 */
	if ((a->s_addr & htonl(0xff000000)) == htonl(0x7f000000))
		return ERROR_DROP;

	/* Link-local block 169.254.0.0/16 */
	if ((a->s_addr & htonl(0xffff0000)) == htonl(0xa9fe0000))
		return ERROR_LOCAL;

	/* Class D */
	if ((a->s_addr & htonl(0xf0000000)) == htonl(0xe0000000))
		return ERROR_DROP;

	/* Class E considered valid now */

	/* Local Broadcast not considered valid */
	if (a->s_addr== 0xffffffff)
		return ERROR_DROP;

	return ERROR_NONE;
}

/**
 * @brief Check if an IPv6 address is valid
 *
 * Checks if an address is within the ranges which are reserved
 * by protocol, such as multicast, link-local, etc.
 *
 * @param a struct in6_addr address to validate
 * @returns ERROR_DROP if invalid, else 0
 */
int validate_ip6_addr(const struct in6_addr *a)
{
	/* Well-known prefix for NAT64, plus Local-Use Space */
	if (a->s6_addr32[0] == WKPF)
		return ERROR_NONE;


	/* Reserved per RFC 2373 */
	if (!a->s6_addr[0])
		return ERROR_DROP;

	/* Multicast addresses */
	if (a->s6_addr[0] == 0xff)
		return ERROR_DROP;

	/* Link-local unicast addresses */
	if ((a->s6_addr16[0] & htons(0xffc0)) == htons(0xfe80))
		return ERROR_DROP;

	return ERROR_NONE;
}

/**
 * @brief Check if an IPv4 address is private
 *
 * Checks if an address is within the ranges which are reserved
 * by IANA, and therefore, must not be translated using the
 * well-known prefix (64:ff9b::/96)
 *
 * @param a struct in_addr address to validate
 * @returns ERROR_REJECT if invalid, else 0
 */
int is_private_ip4_addr(const struct in_addr *a)
{
	/* 10.0.0.0/8 RFC1918 */
	if ((a->s_addr & htonl(0xff000000)) == htonl(0x0a000000))
		return ERROR_REJECT;

	/* 100.64.0.0/10 RFC6598 */
	if ((a->s_addr & htonl(0xffc00000)) == htonl(0x64400000))
		return ERROR_REJECT;

	/* 172.16.0.0/12 RFC1918 */
	if ((a->s_addr & htonl(0xfff00000)) == htonl(0xac100000))
		return ERROR_REJECT;

	/* 192.0.2.0/24 RFC5737 */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xc0000200))
		return ERROR_REJECT;

	/* 192.168.0.0/16 RFC1918 */
	if ((a->s_addr & htonl(0xffff0000)) == htonl(0xc0a80000))
		return ERROR_REJECT;

	/* 198.18.0.0/15 RFC2544 */
	if ((a->s_addr & htonl(0xfffe0000)) == htonl(0xc6120000))
		return ERROR_REJECT;

	/* 198.51.100.0/24 RFC5737 */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xc6336400))
		return ERROR_REJECT;

	/* 203.0.113.0/24 RFC5737 */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xcb007100))
		return ERROR_REJECT;

	/* 192.0.0.0/24 RFC6890 IETF Protocol Assignments */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xc0000000))
		return ERROR_REJECT;

	/* 240.0.0.0/4 RFC1112 Reserved (Class E) */
	if ((a->s_addr & htonl(0xf0000000)) == htonl(0xf0000000))
		return ERROR_REJECT;

	return ERROR_NONE;
}

/**
 * @brief Calculate the mask of an IPv4 address
 *
 * @param mask Pointer to return mask
 * @param addr Pointer to address
 * @param len length in bits of IPv4 mask
 * @returns -1 if address has host bits of mask set
 */
int calc_ip4_mask(struct in_addr *mask, const struct in_addr *addr, int len)
{
	if (len < 0 || len > 32)
		return -1;
	mask->s_addr = htonl(len == 0 ? 0 : UINT32_MAX << (32 - len));
	return addr && (addr->s_addr & ~mask->s_addr) ? -1 : 0;
}

/**
 * @brief Calculate the mask of an IPv6 address
 *
 * @param mask Pointer to return mask
 * @param addr Pointer to address
 * @param len length in bits of IPv6 mask
 * @returns -1 if address has host bits of mask set
 */
int calc_ip6_mask(struct in6_addr *mask, const struct in6_addr *addr, int len)
{
	if (len < 0 || len > 128)
		return -1;
	memset(mask, 0, sizeof(*mask));
	for (int i = 0; i < 16; i++) {
		int bits = len - i * 8;
		if (bits >= 8)
			mask->s6_addr[i] = 0xff;
		else if (bits > 0)
			mask->s6_addr[i] = (uint8_t)(0xffu << (8 - bits));
	}
	if (addr)
		for (int i = 0; i < 16; i++)
			if (addr->s6_addr[i] & (uint8_t)~mask->s6_addr[i])
				return -1;
	return 0;
}

static uint32_t hash_ip4(const struct in_addr *addr4)
{
	return ((uint32_t)(addr4->s_addr *
				gcfg.rand[0])) >> (32 - gcfg.hash_bits);
}

static uint32_t hash_ip6(const struct in6_addr *addr6)
{
	uint32_t h;
	h = addr6->s6_addr32[0] + gcfg.rand[0];
	h ^= addr6->s6_addr32[1] + gcfg.rand[1];
	h ^= addr6->s6_addr32[2] + gcfg.rand[2];
	h ^= addr6->s6_addr32[3] + gcfg.rand[3];
	return h >> (32 - gcfg.hash_bits);
}

static void add_to_hash_table(struct cache_entry *c, uint32_t hash4,
		uint32_t hash6)
{
	list_add(&c->hash4, &gcfg.hash_table4[hash4]);
	list_add(&c->hash6, &gcfg.hash_table6[hash6]);
}

/**
 * @brief Initialize address translation cache
 *
 * This function initializes the two hash sets used
 * for caching address translations.
 * If it has not been done already, this function allocates
 * `gcfg.cache_size` cache entries for the memory pool.
 *
 * The address translation state is a set of IPv4-IPv6 address pairs.
 * There is additional metada as well: see `struct cache_entry`.
 * These pairs are stored in the linked list `gcfg.list`.
 * The cache is two hash sets (`gcfg.hash_table4` and `gcfg.hash_table6`)
 * that let Tayga query elements of this set using the IPv4
 * or the IPv6 address.
 * These hash sets use separate-chaining with a fixed bucket size
 * (configurable as `gcfg.cache_size`),
 * so the code here must initialize each of the buckets.
 *
 */
int create_cache(void)
{
	int i, hash_size = 1 << gcfg.hash_bits;
	struct list_head *entry;
	struct cache_entry *c;

	struct list_head *new4 = malloc(hash_size * sizeof(*new4));
	struct list_head *new6 = malloc(hash_size * sizeof(*new6));
	int new_pool = list_empty(&gcfg.cache_pool) && list_empty(&gcfg.cache_active);
	struct cache_entry *storage = new_pool ? calloc(gcfg.cache_size, sizeof(*storage)) : NULL;
	if (!new4 || !new6 || (new_pool && !storage)) {
		free(new4); free(new6); free(storage);
		errno = ENOMEM;
		slog(LOG_CRIT, "Unable to allocate mapping cache\n");
		return ERROR_REJECT;
	}
	free(gcfg.hash_table4); free(gcfg.hash_table6);
	gcfg.hash_table4 = new4; gcfg.hash_table6 = new6;
	for (i = 0; i < hash_size; ++i) {
		INIT_LIST_HEAD(&gcfg.hash_table4[i]);
		INIT_LIST_HEAD(&gcfg.hash_table6[i]);
	}

	if (new_pool) {
		c = storage;
		for (i = 0; i < gcfg.cache_size; ++i) {
			INIT_LIST_HEAD(&c->list);
			INIT_LIST_HEAD(&c->hash4);
			INIT_LIST_HEAD(&c->hash6);
			list_add_tail(&c->list, &gcfg.cache_pool);
			++c;
		}
	} else {
		list_for_each(entry, &gcfg.cache_active) {
			c = list_entry(entry, struct cache_entry, list);
			INIT_LIST_HEAD(&c->hash4);
			INIT_LIST_HEAD(&c->hash6);
			add_to_hash_table(c, hash_ip4(&c->addr4),
						hash_ip6(&c->addr6));
		}
	}
	return 0;
}

/* This must be called within cache mutex lock */
static struct cache_entry *cache_insert(const struct in_addr *addr4,
		const struct in6_addr *addr6,
		uint32_t hash4, uint32_t hash6)
{
	struct cache_entry *c;

	/* Both mapping and cache locks are held. Concurrent misses may already
	 * have inserted this pair while this caller waited for map_mutex. */
	struct list_head *entry;
	list_for_each(entry, &gcfg.hash_table4[hash4]) {
		c = list_entry(entry, struct cache_entry, hash4);
		if (c->addr4.s_addr == addr4->s_addr && IN6_ARE_ADDR_EQUAL(&c->addr6, addr6)) {
			c->last_use = now;
			return c;
		}
	}
	if (list_empty(&gcfg.cache_pool))
		return NULL;
	c = list_entry(gcfg.cache_pool.next, struct cache_entry, list);
	c->addr4 = *addr4;
	c->addr6 = *addr6;
	c->last_use = now;
	c->flags = 0;
	c->ip4_ident = 1;
	list_add(&c->list, &gcfg.cache_active);
	add_to_hash_table(c, hash4, hash6);
	return c;
}
/**
 * @brief Check if an IPv4 address is in the cache
 *
 * @param addr4 IPv4 address to check
 * @returns Cache entry, or NULL if none found
 */
struct map4 *find_map4(const struct in_addr *addr4)
{
	struct list_head *entry;
	struct map4 *m;

	list_for_each(entry, &gcfg.map4_list) {
		m = list_entry(entry, struct map4, list);
		if (m->addr.s_addr == (m->mask.s_addr & addr4->s_addr))
			return m;
	}
	return NULL;
}
/**
 * @brief Check if an IPv6 address is in the cache
 *
 * @param addr6 IPv6 address to check
 * @returns Cache entry, or NULL if none found
 */
struct map6 *find_map6(const struct in6_addr *addr6)
{
	struct list_head *entry;
	struct map6 *m;

	list_for_each(entry, &gcfg.map6_list) {
		m = list_entry(entry, struct map6, list);
		if (IN6_IS_IN_NET(addr6, &m->addr, &m->mask))
			return m;
	}
	return NULL;
}
/**
 * @brief Insert an IPv4 entry into the map
 *
 * @param map4 Entry to add
 * @param[out] conflict Pointer to return conflicting object
 * @returns -1 on conflict
 * Caller must possess map mutex
 */
int insert_map4(struct map4 *m, struct map4 **conflict)
{
	struct list_head *entry;
	struct map4 *s;

	list_for_each(entry, &gcfg.map4_list) {
		s = list_entry(entry, struct map4, list);
		if (s->prefix_len < m->prefix_len)
			break;
		if (s->prefix_len == m->prefix_len &&
				s->addr.s_addr == m->addr.s_addr) {
			if (conflict)
				*conflict = s;
			return -1;
		}
	}
	list_add_tail(&m->list, entry);
	return 0;
}
/**
 * @brief Insert an IPv6 entry into the map
 *
 * @param map6 Entry to add
 * @param[out] conflict Pointer to return conflicting object
 * @returns -1 on conflict
 * Caller must possess map mutex
 */
int insert_map6(struct map6 *m, struct map6 **conflict)
{
	struct list_head *entry, *insert_pos = NULL;
	struct map6 *s;

	list_for_each(entry, &gcfg.map6_list) {
		s = list_entry(entry, struct map6, list);
		if (s->prefix_len < m->prefix_len) {
			if (IN6_IS_IN_NET(&m->addr, &s->addr, &s->mask))
				goto conflict;
			if (!insert_pos)
				insert_pos = entry;
		} else {
			if (IN6_IS_IN_NET(&s->addr, &m->addr, &m->mask))
				goto conflict;
		}
	}
	list_add_tail(&m->list, insert_pos ? insert_pos : &gcfg.map6_list);
	return 0;

conflict:
	if (conflict)
		*conflict = s;
	return -1;
}
/**
 * @brief Append an IPv4 address to an IPv6 translation prefix
 *
 * @param[out] addr6 Return IPv6 address
 * @param[in] addr4 IPv4 address
 * @param[in] prefix IPv6 Prefix
 * @param[in] prefix_len IPv6 prefix length (must be defined by RFC6052)
 * @returns ERROR_DROP on invalid prefix
 */
int append_to_prefix(struct in6_addr *addr6, const struct in_addr *addr4,
		const struct in6_addr *prefix, int prefix_len)
{
	/* Do not allow invalid addresses to be appended to prefix */
	if(validate_ip4_addr(addr4)) return ERROR_DROP;
	switch (prefix_len) {
	case 32:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = addr4->s_addr;
		addr6->s6_addr32[2] = 0;
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 40:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
        addr6->s6_addr32[1] = BIG_LITTLE(
                prefix->s6_addr32[1] | (addr4->s_addr >> 8),
                prefix->s6_addr32[1] | (addr4->s_addr << 8));
        addr6->s6_addr32[2] = BIG_LITTLE(
                (addr4->s_addr << 16) & 0x00ff0000,
                (addr4->s_addr >> 16) & 0x0000ff00);
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 48:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = BIG_LITTLE(
                prefix->s6_addr32[1] | (addr4->s_addr >> 16),
                prefix->s6_addr32[1] | (addr4->s_addr << 16));
		addr6->s6_addr32[2] = BIG_LITTLE(
                (addr4->s_addr << 8) & 0x00ffff00,
                (addr4->s_addr >> 8) & 0x00ffff00);
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 56:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = BIG_LITTLE(
                prefix->s6_addr32[1] | (addr4->s_addr >> 24),
                prefix->s6_addr32[1] | (addr4->s_addr << 24));
		addr6->s6_addr32[2] = BIG_LITTLE(
                addr4->s_addr & 0x00ffffff,
                addr4->s_addr & 0xffffff00);
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 64:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = prefix->s6_addr32[1];
		addr6->s6_addr32[2] = BIG_LITTLE(
                addr4->s_addr >> 8,
                addr4->s_addr << 8);
		addr6->s6_addr32[3] = BIG_LITTLE(
                addr4->s_addr << 24,
                addr4->s_addr >> 24);
		return ERROR_NONE;
	case 96:
		//Do not allow translation of well-known prefix
		//But still allow local-use prefix
		if (prefix->s6_addr32[0] == WKPF &&
			!prefix->s6_addr32[1] &&
			!prefix->s6_addr32[2] &&
			gcfg.wkpf_strict &&
			is_private_ip4_addr(addr4))
			return ERROR_REJECT;
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = prefix->s6_addr32[1];
		addr6->s6_addr32[2] = prefix->s6_addr32[2];
		addr6->s6_addr32[3] = addr4->s_addr;
		return ERROR_NONE;
	default:
		return ERROR_DROP;
	}
}

/**
 * @brief Map IPv4 to IPv6
 *
 * @param[out] addr6 Return IPv6 address
 * @param[in] addr4 IPv4 address
 * @param[out] c_ptr Cache entry
 * @returns ERROR_REJECT or ERROR_DROP on error
 */
int map_ip4_to_ip6(struct in6_addr *addr6, const struct in_addr *addr4)
{
	uint32_t hash = 0;
	int ret;
	struct list_head *entry;
	struct cache_entry *c;
	struct map4 *map4;
	struct map_static *s;
	struct map_dynamic *d = NULL;

	if (gcfg.cache_size) {
		hash = hash_ip4(addr4);

		pthread_mutex_lock(&gcfg.cache_mutex);
		list_for_each(entry, &gcfg.hash_table4[hash]) {
			c = list_entry(entry, struct cache_entry, hash4);
			if (addr4->s_addr == c->addr4.s_addr) {
				*addr6 = c->addr6;
				c->last_use = now;
				pthread_mutex_unlock(&gcfg.cache_mutex);
				return 0;
			}
		}
		pthread_mutex_unlock(&gcfg.cache_mutex);
	}


	if (!gcfg.maps_immutable)
		pthread_mutex_lock(&gcfg.map_mutex);
	map4 = find_map4(addr4);

	if (!map4) {
		if (!gcfg.maps_immutable)
			pthread_mutex_unlock(&gcfg.map_mutex);
		return ERROR_REJECT;
	}

	switch (map4->type) {
	case MAP_TYPE_STATIC:
		s = container_of(map4, struct map_static, map4);
		*addr6 = s->map6.addr;
		if (map4->prefix_len < 32) {
			addr6->s6_addr32[3] = s->map6.addr.s6_addr32[3] | (addr4->s_addr & ~map4->mask.s_addr);
		}
		break;
	case MAP_TYPE_RFC6052:
		s = container_of(map4, struct map_static, map4);
		ret = append_to_prefix(addr6, addr4, &s->map6.addr,s->map6.prefix_len);
		if (ret < 0) {
			if (!gcfg.maps_immutable)
				pthread_mutex_unlock(&gcfg.map_mutex);
			return ret;
		}
		break;
	case MAP_TYPE_DYNAMIC_POOL:
		slog(LOG_DEBUG,"%s:%d Address map is dynamic pool\n",__FUNCTION__,__LINE__);
		if (!gcfg.maps_immutable)
			pthread_mutex_unlock(&gcfg.map_mutex);
		return ERROR_REJECT;
	case MAP_TYPE_DYNAMIC_HOST:
		d = container_of(map4, struct map_dynamic, map4);
		*addr6 = d->map6.addr;
		d->last_use = now;
		break;
	default:
		slog(LOG_DEBUG,"%s:%d Hit default case\n",__FUNCTION__,__LINE__);
		if (!gcfg.maps_immutable)
			pthread_mutex_unlock(&gcfg.map_mutex);
		return ERROR_DROP;
	}
	if (gcfg.cache_size) {		
		pthread_mutex_lock(&gcfg.cache_mutex);
#ifdef ADDRMAP_TEST_HOOK
		extern void addrmap_test_before_publish(void);
		addrmap_test_before_publish();
#endif
		c = cache_insert(addr4, addr6, hash, hash_ip6(addr6));

		/* Alloc Dynamic */
		if (d) {
			d->cache_entry = c;
			if (c)
				c->flags |= CACHE_F_REP_AGEOUT;
		}
		pthread_mutex_unlock(&gcfg.cache_mutex);
	}

	if (!gcfg.maps_immutable)
		pthread_mutex_unlock(&gcfg.map_mutex);
	return ERROR_NONE;
}

static int extract_from_prefix(struct in_addr *addr4,
		const struct in6_addr *addr6, int prefix_len)
{
	switch (prefix_len) {
	case 32:
		if (addr6->s6_addr32[2] || addr6->s6_addr32[3])
			return ERROR_DROP;
		addr4->s_addr = addr6->s6_addr32[1];
		break;
	case 40:
		if (addr6->s6_addr32[2] & htonl(0xff00ffff) ||
				addr6->s6_addr32[3])
			return ERROR_DROP;
		addr4->s_addr = BIG_LITTLE(
                (addr6->s6_addr32[1] << 8) | addr6->s6_addr[9],
                (addr6->s6_addr32[1] >> 8) | (addr6->s6_addr32[2] << 16));
		break;
	case 48:
		if (addr6->s6_addr32[2] & htonl(0xff0000ff) ||
				addr6->s6_addr32[3])
			return ERROR_DROP;
		addr4->s_addr = BIG_LITTLE(
            (addr6->s6_addr16[3] << 16) | (addr6->s6_addr32[2] >> 8),
            (addr6->s6_addr16[3]      ) | (addr6->s6_addr32[2] << 8));
		break;
	case 56:
		if (addr6->s6_addr[8] || addr6->s6_addr32[3])
			return ERROR_DROP;
		addr4->s_addr = BIG_LITTLE(
                (addr6->s6_addr[7] << 24) | addr6->s6_addr32[2],
		        addr6->s6_addr[7] | addr6->s6_addr32[2]);
		break;
	case 64:
		if (addr6->s6_addr[8] ||
				addr6->s6_addr32[3] & htonl(0x00ffffff))
			return ERROR_DROP;
		addr4->s_addr = BIG_LITTLE(
                (addr6->s6_addr32[2] << 8) | addr6->s6_addr[12],
		        (addr6->s6_addr32[2] >> 8) | (addr6->s6_addr32[3] << 24));
		break;
	case 96:
		addr4->s_addr = addr6->s6_addr32[3];
		break;
	default:
		return ERROR_DROP;
	}
	/* This function may return ERROR_LOCAL or ERROR_DROP */
	return validate_ip4_addr(addr4);
}
/**
 * @brief Map IPv6 to IPv4
 *
 * @param[out] addr4 Return IPv6 address
 * @param[in] addr6 IPv4 address
 * @param[in] dyn_allow Allow dynamic allocation for this mapping
 * @returns ERROR_REJECT or ERROR_DROP on error
 */
int map_ip6_to_ip4(struct in_addr *addr4, const struct in6_addr *addr6, int dyn_alloc)
{
	uint32_t hash = 0;
	int ret = 0;
	struct list_head *entry;
	struct cache_entry *c;
	struct map6 *map6;
	struct map_static *s;
	struct map_dynamic *d = NULL;

	if (gcfg.cache_size) {
		hash = hash_ip6(addr6);

		pthread_mutex_lock(&gcfg.cache_mutex);
		list_for_each(entry, &gcfg.hash_table6[hash]) {
			c = list_entry(entry, struct cache_entry, hash6);
			if (IN6_ARE_ADDR_EQUAL(addr6, &c->addr6)) {
				*addr4 = c->addr4;
				c->last_use = now;
				pthread_mutex_unlock(&gcfg.cache_mutex);
				return 0;
			}
		}
		pthread_mutex_unlock(&gcfg.cache_mutex);
	}
	if (!gcfg.maps_immutable)
		pthread_mutex_lock(&gcfg.map_mutex);
	map6 = find_map6(addr6);

	if (!map6) {
		if (dyn_alloc)
			map6 = assign_dynamic(addr6);
		if (!map6) {
			if (!gcfg.maps_immutable)
				pthread_mutex_unlock(&gcfg.map_mutex);
			return ERROR_REJECT; //TODO what's the right behavior here
		}
	}

	switch (map6->type) {
	case MAP_TYPE_STATIC:
		s = container_of(map6, struct map_static, map6);

		if (map6->prefix_len < 128) {
			addr4->s_addr = s->map4.addr.s_addr | (addr6->s6_addr32[3] & ~map6->mask.s6_addr32[3]);
		} else {
			*addr4 = s->map4.addr;
		}

		break;
	case MAP_TYPE_RFC6052:
		ret = extract_from_prefix(addr4, addr6, map6->prefix_len);
		if (ret < 0) {
			if (!gcfg.maps_immutable)
				pthread_mutex_unlock(&gcfg.map_mutex);
			return ERROR_DROP;
		}
		if (map6->addr.s6_addr32[0] == WKPF &&
			map6->addr.s6_addr32[1] == 0 &&
			map6->addr.s6_addr32[2] == 0 &&
			gcfg.wkpf_strict &&
				is_private_ip4_addr(addr4)) {
			if (!gcfg.maps_immutable)
				pthread_mutex_unlock(&gcfg.map_mutex);
			return ERROR_REJECT;
		}
		s = container_of(map6, struct map_static, map6);
		if (find_map4(addr4) != &s->map4){
			slog(LOG_DEBUG,"%s:%d Dropping packet due to hairpin condition",__FUNCTION__,__LINE__);
			if (!gcfg.maps_immutable)
				pthread_mutex_unlock(&gcfg.map_mutex);
			return ERROR_DROP;
		}
		break;
	case MAP_TYPE_DYNAMIC_HOST:
		d = container_of(map6, struct map_dynamic, map6);
		*addr4 = d->map4.addr;
		d->last_use = now;
		break;
	default:
		slog(LOG_DEBUG,"%s:%d Dropping packet due to default case",__FUNCTION__,__LINE__);
		if (!gcfg.maps_immutable)
			pthread_mutex_unlock(&gcfg.map_mutex);
		return ERROR_DROP;
	}
	if (gcfg.cache_size) {
		pthread_mutex_lock(&gcfg.cache_mutex);
#ifdef ADDRMAP_TEST_HOOK
		extern void addrmap_test_before_publish(void);
		addrmap_test_before_publish();
#endif
		c = cache_insert(addr4, addr6, hash_ip4(addr4), hash);

		/* Is Dynamic */
		if (d) {
			d->cache_entry = c;
			if (c)
				c->flags |= CACHE_F_REP_AGEOUT;
		}
		pthread_mutex_unlock(&gcfg.cache_mutex);
	}

	if (!gcfg.maps_immutable)
		pthread_mutex_unlock(&gcfg.map_mutex);
	return ERROR_NONE;
}

static void report_ageout(struct cache_entry *c)
{
	struct map4 *m4;
	struct map_dynamic *d;

	m4 = find_map4(&c->addr4);
	if (!m4 || m4->type != MAP_TYPE_DYNAMIC_HOST)
		return;
	d = container_of(m4, struct map_dynamic, map4);
	if (d->cache_entry == c) {
		d->last_use = c->last_use;
		d->cache_entry = NULL;
	}
}

/**
 * @brief Perform periodic address cache maintenance
 *
 */
void addrmap_maint(void)
{
	struct list_head *entry, *next;
	struct cache_entry *c;

	/* report_ageout will need map mutex
	 * and we must acquire map before cache if both are required 
	 * to avoid any deadlock */
    pthread_mutex_lock(&gcfg.map_mutex);
	pthread_mutex_lock(&gcfg.cache_mutex);

	list_for_each_safe(entry, next, &gcfg.cache_active) {
		c = list_entry(entry, struct cache_entry, list);
		if (c->last_use + CACHE_MAX_AGE < now) {
			if (c->flags & CACHE_F_REP_AGEOUT)
				report_ageout(c);
			list_add(&c->list, &gcfg.cache_pool);
			list_del(&c->hash4);
			list_del(&c->hash6);
		}
	}
	pthread_mutex_unlock(&gcfg.cache_mutex);
	pthread_mutex_unlock(&gcfg.map_mutex);
}

/* Parse an entire replacement before publishing any map-file changes. */
static struct map_static *parse_map_entry(int line, char *v4, char *v6)
{
	struct map_static *m = calloc(1, sizeof(*m));
	if (!m) return NULL;
	char *addresses[2] = {v4, v6};
	int lengths[2] = {32, 128};
	for (int i = 0; i < 2; i++) {
		char *slash = strchr(addresses[i], '/');
		if (slash) {
			char *end;
			*slash++ = 0;
			errno = 0;
			long bits = strtol(slash, &end, 10);
			if (errno || !*slash || *end || bits < 0 || bits > lengths[i]) goto bad;
			lengths[i] = (int)bits;
		}
	}
	if (32 - lengths[0] != 128 - lengths[1] ||
		inet_pton(AF_INET, v4, &m->map4.addr) != 1 ||
		inet_pton(AF_INET6, v6, &m->map6.addr) != 1 ||
		calc_ip4_mask(&m->map4.mask, &m->map4.addr, lengths[0]) ||
		calc_ip6_mask(&m->map6.mask, &m->map6.addr, lengths[1]) ||
		validate_ip4_addr(&m->map4.addr) == ERROR_DROP ||
		validate_ip6_addr(&m->map6.addr) < 0) goto bad;
	m->map4.type = m->map6.type = MAP_TYPE_STATIC;
	m->map4.prefix_len = lengths[0];
	m->map6.prefix_len = lengths[1];
	m->origin = MAP_ORIGIN_MAPFILE;
	m->line_no = line;
	INIT_LIST_HEAD(&m->map4.list);
	INIT_LIST_HEAD(&m->map6.list);
	return m;
 bad:
	slog(LOG_ERR, "MAP-FILE: invalid mapping on line %d; keeping previous mappings\n", line);
	free(m);
	return NULL;
}

static int map6_overlaps(const struct map6 *a, const struct map6 *b)
{
	return IN6_IS_IN_NET(&a->addr, &b->addr, &b->mask) ||
		IN6_IS_IN_NET(&b->addr, &a->addr, &a->mask);
}

static int is_file_map4(const struct map4 *m)
{
	return m->type == MAP_TYPE_STATIC &&
		container_of(m, struct map_static, map4)->origin == MAP_ORIGIN_MAPFILE;
}

int addrmap_reload(void)
{
	if (!gcfg.map_file[0]) return ERROR_NONE;
	#ifdef ADDRMAP_TEST_HOOK
	extern FILE *addrmap_test_open_file(const char *path);
	FILE *in = addrmap_test_open_file(gcfg.map_file);
#else
	FILE *in = fopen(gcfg.map_file, "r");
#endif
	if (!in) {
		slog(LOG_ERR, "MAP-FILE: cannot open %s: %s\n", gcfg.map_file, strerror(errno));
		return ERROR_REJECT;
	}
	LIST_HEAD(staged);
	char line[512];
	int lineno = 0, failed = 0;
	struct list_head *entry, *next;
	while (fgets(line, sizeof(line), in)) {
		lineno++;
		if (strlen(line) == sizeof(line) - 1) { failed = 1; break; }
		char *save, *args[4];
		int count = 0;
		for (char *tok = strtok_r(line, DELIM, &save); tok && *tok != '#';
			 tok = strtok_r(NULL, DELIM, &save)) {
			if (count == 4) { failed = 1; break; }
			args[count++] = tok;
		}
		if (failed) break;
		if (!count) continue;
		if (count != 3 || strcasecmp(args[0], "map")) { failed = 1; break; }
		struct map_static *m = parse_map_entry(lineno, args[1], args[2]);
		if (!m) { failed = 1; break; }
		/* Preserve the documented last-entry-wins behavior within the file.
		 * Conflicts with fixed/dynamic mappings reject the whole transaction. */
		list_for_each_safe(entry, next, &staged) {
			struct map_static *old = list_entry(entry, struct map_static, map4.list);
			if ((old->map4.prefix_len == m->map4.prefix_len &&
				 old->map4.addr.s_addr == m->map4.addr.s_addr) || map6_overlaps(&old->map6, &m->map6)) {
				list_del(entry);
				free(old);
			}
		}
		list_add_tail(&m->map4.list, &staged);
	}
	if (ferror(in)) failed = 1;
	if (fclose(in)) failed = 1;
	if (!failed) {
		pthread_mutex_lock(&gcfg.map_mutex);
		list_for_each_safe(entry, next, &staged) {
			struct map_static *m = list_entry(entry, struct map_static, map4.list);
			int conflict = 0;
			struct list_head *fixed;
			list_for_each(fixed, &gcfg.map4_list) {
				struct map4 *f = list_entry(fixed, struct map4, list);
				if (!is_file_map4(f) && f->prefix_len == m->map4.prefix_len &&
					f->addr.s_addr == m->map4.addr.s_addr) {
					conflict = 1;
					break;
				}
			}
			if (!conflict) {
				list_for_each(fixed, &gcfg.map6_list) {
					struct map6 *f = list_entry(fixed, struct map6, list);
					int file = f->type == MAP_TYPE_STATIC &&
						container_of(f, struct map_static, map6)->origin == MAP_ORIGIN_MAPFILE;
					if (!file && map6_overlaps(f, &m->map6)) {
						conflict = 1;
						break;
					}
				}
			}
			if (conflict) {
				slog(LOG_ERR, "MAP-FILE: Entry on line %d conflicts with static conf-file mapping; skipping\n", m->line_no);
				list_del(entry);
				free(m);
			}
		}
		pthread_mutex_lock(&gcfg.cache_mutex);
		list_for_each_safe(entry, next, &gcfg.map4_list) {
			struct map4 *m = list_entry(entry, struct map4, list);
			if (is_file_map4(m)) {
				struct map_static *s = container_of(m, struct map_static, map4);
				list_del(&s->map4.list);
				list_del(&s->map6.list);
				free(s);
			}
		}
		list_for_each_safe(entry, next, &staged) {
			struct map_static *m = list_entry(entry, struct map_static, map4.list);
			list_del(entry);
			insert_map4(&m->map4, NULL);
			insert_map6(&m->map6, NULL);
		}
		/* Flush active cache atomically under both map_mutex and cache_mutex */
		list_for_each_safe(entry, next, &gcfg.cache_active) {
			struct cache_entry *c = list_entry(entry, struct cache_entry, list);
			if (c->flags & CACHE_F_REP_AGEOUT) report_ageout(c);
			list_del(&c->hash4);
			list_del(&c->hash6);
			list_add(&c->list, &gcfg.cache_pool);
		}
		pthread_mutex_unlock(&gcfg.cache_mutex);
		pthread_mutex_unlock(&gcfg.map_mutex);
	}
	list_for_each_safe(entry, next, &staged) {
		struct map_static *m = list_entry(entry, struct map_static, map4.list);
		list_del(entry);
		free(m);
	}
	if (failed) slog(LOG_ERR, "MAP-FILE: reload rejected near line %d; previous mappings retained\n", lineno);
	return failed ? ERROR_REJECT : ERROR_NONE;
}
