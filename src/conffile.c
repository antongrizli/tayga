/*
 *  conffile.c -- config file parser
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

/* Global config */
struct config gcfg;
static struct config *cfg_target = &gcfg;

static int parse_prefix(int af, char *src, void *prefix, int *prefix_len)
{
	char *p, *end;
	long int a;
	int r;

	p = strchr(src, '/');
	if (!p)
		return ERROR_REJECT;
	*p = 0;
	a = strtol(p + 1, &end, 10);
	r = *end || !inet_pton(af, src, prefix);
	*p = '/';
	if (r)
		return ERROR_REJECT;
	if (a < 0 || a > (af == AF_INET6 ? 128 : 32))
		return ERROR_REJECT;

	*prefix_len = a;
	return ERROR_NONE;
}

static struct map_static *alloc_map_static(int ln)
{
	struct map_static *m;

	m = (struct map_static *)malloc(sizeof(struct map_static));
	if (!m) {
		slog(LOG_CRIT, "Unable to allocate config static map memory\n");
		return NULL;
	}
	memset(m, 0, sizeof(struct map_static));
	m->map4.type = MAP_TYPE_STATIC;
	m->map4.prefix_len = 32;
	calc_ip4_mask(&m->map4.mask, NULL, 32);
	INIT_LIST_HEAD(&m->map4.list);
	m->map6.type = MAP_TYPE_STATIC;
	m->map6.prefix_len = 128;
	calc_ip6_mask(&m->map6.mask, NULL, 128);
	INIT_LIST_HEAD(&m->map6.list);
	m->line_no = ln;
	m->origin = MAP_ORIGIN_CONFFILE;
	return m;
}

static void abort_on_conflict4(char *msg, int ln, struct map4 *old)
{
	char oldaddr[INET_ADDRSTRLEN];
	char oldline[128] = "";
	struct map_static *s;

	if (old->type == MAP_TYPE_STATIC || old->type == MAP_TYPE_RFC6052) {
		s = container_of(old, struct map_static, map4);
		if (s->line_no)
			sprintf(oldline, " from line %d", s->line_no);
	}

	inet_ntop(AF_INET, &old->addr, oldaddr, sizeof(oldaddr));
	if (ln)
		slog(LOG_CRIT, "%s on line %d conflicts with earlier "
				"definition of %s/%d%s\n", msg, ln,
				oldaddr, old->prefix_len, oldline);
	else
		slog(LOG_CRIT, "%s conflicts with earlier "
				"definition of %s/%d%s\n", msg,
				oldaddr, old->prefix_len, oldline);
}

static void abort_on_conflict6(char *msg, int ln, struct map6 *old)
{
	char oldaddr[INET6_ADDRSTRLEN];
	char oldline[128] = "";
	struct map_static *s;

	if (old->type == MAP_TYPE_STATIC || old->type == MAP_TYPE_RFC6052) {
		s = container_of(old, struct map_static, map6);
		if (s->line_no)
			sprintf(oldline, " from line %d", s->line_no);
	}

	inet_ntop(AF_INET6, &old->addr, oldaddr, sizeof(oldaddr));
	if (ln)
		slog(LOG_CRIT, "%s on line %d overlaps with earlier "
				"definition of %s/%d%s\n", msg, ln,
				oldaddr, old->prefix_len, oldline);
	else
		slog(LOG_CRIT, "%s overlaps with earlier "
				"definition of %s/%d%s\n", msg,
				oldaddr, old->prefix_len, oldline);
}

static int config_ipv4_addr(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (cfg_target->local_addr4.s_addr) {
		slog(LOG_CRIT, "Error: duplicate ipv4-addr directive on "
				"line %d\n", ln);
		return ERROR_REJECT;
	}
	if (!inet_pton(AF_INET, args[0], &cfg_target->local_addr4)) {
		slog(LOG_CRIT, "Expected an IPv4 address but found \"%s\" on "
				"line %d\n", args[0], ln);
		return ERROR_REJECT;
	}
	int ret = validate_ip4_addr(&cfg_target->local_addr4);
	if (ret == ERROR_LOCAL) {
		slog(LOG_WARNING, "Using link local address %s in ipv4-addr "
			"directive, use with caution\n", args[0]);
	} else if(ret < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in ipv4-addr "
				"directive, aborting...\n", args[0]);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

static int config_ipv6_addr(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (cfg_target->local_addr6.s6_addr[0]) {
		slog(LOG_CRIT, "Error: duplicate ipv6-addr directive on line "
				"%d\n", ln);
		return ERROR_REJECT;
	}
	if (!inet_pton(AF_INET6, args[0], &cfg_target->local_addr6)) {
		slog(LOG_CRIT, "Expected an IPv6 address but found \"%s\" on "
				"line %d\n", args[0], ln);
		return ERROR_REJECT;
	}
	if (validate_ip6_addr(&cfg_target->local_addr6) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in ipv6-addr "
				"directive, aborting...\n", args[0]);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

static int config_prefix(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	struct map_static *m;
	struct map6 *m6;

	m = alloc_map_static(ln);
	if(!m) return ERROR_REJECT;
	m->map4.prefix_len = 0;
	m->map4.mask.s_addr = 0;
	m->map4.type = MAP_TYPE_RFC6052;
	m->map6.type = MAP_TYPE_RFC6052;
	m6 = &m->map6;

	if (parse_prefix(AF_INET6, args[0], &m6->addr, &m6->prefix_len) ||
			calc_ip6_mask(&m6->mask, &m6->addr, m6->prefix_len)) {
		slog(LOG_CRIT, "Expected an IPv6 prefix but found \"%s\" on "
				"line %d\n", args[0], ln);
		free(m);
		return ERROR_REJECT;
	}
	if (validate_ip6_addr(&m6->addr) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in prefix "
				"directive, aborting...\n", args[0]);
		free(m);
		return ERROR_REJECT;
	}
	if (m6->prefix_len != 32 && m6->prefix_len != 40 &&
			m6->prefix_len != 48 && m6->prefix_len != 56 &&
			m6->prefix_len != 64 && m6->prefix_len != 96) {
		slog(LOG_CRIT, "NAT prefix length must be 32, 40, 48, 56, 64 "
				"or 96 only, aborting...\n");
		free(m);
		return ERROR_REJECT;
	}
	if (m6->addr.s6_addr32[0] == WKPF &&
	    m6->addr.s6_addr32[1] == 0 &&
	    m6->addr.s6_addr32[2] == 0 &&
	    m6->prefix_len != 96) {
		slog(LOG_CRIT, "Well-Known Prefix 64:ff9b::/96 can only be used with a /96 prefix length (use 64:ff9b:1::/48 per RFC 8215 for shorter local-use prefixes), aborting...\n");
		free(m);
		return ERROR_REJECT;
	}
	if (insert_map4_to(&cfg_target->map4_list, &m->map4, NULL) < 0) {
		slog(LOG_CRIT, "Error: duplicate prefix directive on line %d\n",
				ln);
		free(m);
		return ERROR_REJECT;
	}
	if (insert_map6_to(&cfg_target->map6_list, &m->map6, &m6) < 0) {
		abort_on_conflict6("Error: NAT64 prefix", ln, m6);
		list_del(&m->map4.list);
		free(m);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

static int parse_bounded_long(const char *text, long lo, long hi, long *out)
{
	char *end = NULL;
	errno = 0;
	if (*text < '0' || *text > '9')
		return -1;
	long v = strtol(text, &end, 10);
	if (errno || *end || v < lo || v > hi)
		return -1;
	*out = v;
	return 0;
}

static int hash_bits_explicit;

static int config_hash_bits(int ln, int arg_count, char **args)
{
	(void)arg_count;
	long v;
	if (parse_bounded_long(args[0], 4, 24, &v)) {
		slog(LOG_CRIT, "Error: hash-bits must be 4..24 on line %d\n", ln);
		return ERROR_REJECT;
	}
	cfg_target->hash_bits = (int)v;
	hash_bits_explicit = 1;
	return ERROR_NONE;
}

static int config_cache_size(int ln, int arg_count, char **args)
{
	(void)arg_count;
	long v;
	if (parse_bounded_long(args[0], 0, 1 << 22, &v)) {
		slog(LOG_CRIT, "Error: cache-size must be 0..4194304 on line %d\n", ln);
		return ERROR_REJECT;
	}
	cfg_target->cache_size = (int)v;
	return ERROR_NONE;
}

static int config_icmp_rate_limit(int ln, int arg_count, char **args)
{
	(void)arg_count;
	if (!strcasecmp(args[0], "unlimited") || !strcmp(args[0], "0")) {
		cfg_target->icmp_rate_limit = UINT32_MAX;
		return ERROR_NONE;
	}
	char *end = NULL;
	errno = 0;
	unsigned long v = strtoul(args[0], &end, 10);
	if (errno || !end || *end || args[0][0] < '0' || args[0][0] > '9' ||
			v == 0 || v >= UINT32_MAX) {
		slog(LOG_CRIT, "Error: invalid value for icmp-rate-limit on line %d\n", ln);
		return ERROR_REJECT;
	}
	cfg_target->icmp_rate_limit = (uint32_t)v;
	return ERROR_NONE;
}

static int config_wkpf_strict(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (!strcasecmp(args[0], "true") ||
	    !strcasecmp(args[0], "on") ||
	    !strcasecmp(args[0], "yes") ||
		!strcasecmp(args[0], "1")) {
		cfg_target->wkpf_strict = 1;
	} else if (!strcasecmp(args[0], "false") ||
			   !strcasecmp(args[0], "off") ||
			   !strcasecmp(args[0], "no") ||
			   !strcasecmp(args[0], "0")) {
		cfg_target->wkpf_strict = 0;
	} else {
		slog(LOG_CRIT, "Error: invalid value for wkpf-strict on line %d\n",ln);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

static int config_flow_label(int ln, int arg_count, char **args)
{
	(void)arg_count;
	if (!strcasecmp(args[0], "zero"))
		cfg_target->flow_label_mode = FLOW_LABEL_ZERO;
	else if (!strcasecmp(args[0], "compute"))
		cfg_target->flow_label_mode = FLOW_LABEL_COMPUTE;
	else {
		slog(LOG_CRIT, "Error: invalid value for flow-label on line %d\n", ln);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

#ifdef __linux__
/* "4-6,8" -> worker_cpu[] = {4,5,6,8}.  Strict: digits, commas and ranges only. */
static int parse_cpu_list(const char *text)
{
	int count = 0;
	const char *p = text;
	while (*p) {
		char *end = NULL;
		errno = 0;
		if (*p < '0' || *p > '9')
			return -1;
		long lo = strtol(p, &end, 10);
		long hi = lo;
		if (errno || lo > 1023)
			return -1;
		if (*end == '-') {
			p = end + 1;
			if (*p < '0' || *p > '9')
				return -1;
			hi = strtol(p, &end, 10);
			if (errno || hi < lo || hi > 1023)
				return -1;
		}
		for (long c = lo; c <= hi; c++) {
			if (count >= WORKER_CPU_MAX)
				return -1;
			cfg_target->worker_cpu[count++] = (int)c;
		}
		if (*end == ',')
			end++;
		else if (*end)
			return -1;
		p = end;
	}
	return count;
}

#endif

static int config_worker_affinity(int ln, int arg_count, char **args)
{
	(void)arg_count;
#ifdef __linux__
	if (!strcasecmp(args[0], "on") || !strcasecmp(args[0], "yes")) {
		cfg_target->worker_affinity = 1;
		cfg_target->worker_cpu_count = 0;
	} else if (!strcasecmp(args[0], "off") || !strcasecmp(args[0], "no")) {
		cfg_target->worker_affinity = 0;
		cfg_target->worker_cpu_count = 0;
	} else {
		int n = parse_cpu_list(args[0]);
		if (n <= 0) {
			slog(LOG_CRIT, "Error: invalid value for worker-affinity on line %d "
					"(expected on, off or a CPU list such as 4-6,8)\n", ln);
			return ERROR_REJECT;
		}
		cfg_target->worker_affinity = 2;
		cfg_target->worker_cpu_count = n;
	}
	return ERROR_NONE;
#else
	(void)args;
	slog(LOG_CRIT, "Error: `worker-affinity` (line %d) not supported on this platform\n", ln);
	return ERROR_REJECT;
#endif
}

static int config_udp_cksum_mode(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	/* Drop, or some variant of that */
	if (!strncasecmp(args[0], "dr",2)){
		cfg_target->udp_cksum_mode = UDP_CKSUM_DROP;
	/* Calculate, or some variant of that */
	} else if (!strncasecmp(args[0], "calc",4)) {
		cfg_target->udp_cksum_mode = UDP_CKSUM_CALC;
	} else if(!strncasecmp(args[0],"forw",4) ||
		      !strncasecmp(args[0],"fwd",3)) {
		cfg_target->udp_cksum_mode = UDP_CKSUM_FWD;
	} else {
		slog(LOG_CRIT, "Error: invalid value for udp-cksum-mode on line %d\n",ln);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

static int config_tun_up(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (!strcasecmp(args[0], "true") ||
	    !strcasecmp(args[0], "on") ||
	    !strcasecmp(args[0], "yes") ||
		!strcasecmp(args[0], "1")) {
		cfg_target->tun_up = 1;
	} else if (!strcasecmp(args[0], "false") ||
			   !strcasecmp(args[0], "off") ||
			   !strcasecmp(args[0], "no") ||
			   !strcasecmp(args[0], "0")) {
		cfg_target->tun_up = 0;
	} else {
		slog(LOG_CRIT, "Error: invalid value for tun-up on line %d\n",ln);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}


static int config_tun_device(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (cfg_target->tundev[0]) {
		slog(LOG_CRIT, "Error: duplicate tun-device directive on line "
				"%d\n", ln);
		return ERROR_REJECT;
	}
	if (strlen(args[0]) + 1 > sizeof(cfg_target->tundev)) {
		slog(LOG_CRIT, "Device name \"%s\" is invalid on line %d\n",
				args[0], ln);
		return ERROR_REJECT;
	}
	strcpy(cfg_target->tundev, args[0]);
	return ERROR_NONE;
}


/* Parse "addr[/len]" into a tun_ip4/tun_ip6 entry on the matching list.
 * Strict: the length must be all digits and within range; the argument is
 * not modified; each family gets its own correctly typed allocation. */
static int parse_tun_addr(int ln, const char *what, const char *arg,
		struct list_head *list4, struct list_head *list6)
{
	char buf[INET6_ADDRSTRLEN + 8];
	const char *slash = strchr(arg, '/');
	size_t alen = slash ? (size_t)(slash - arg) : strlen(arg);
	long prefix = -1;

	if (alen == 0 || alen >= INET6_ADDRSTRLEN) {
		slog(LOG_CRIT, "Expected an IPv4 or IPv6 address but found "
		     "\"%s\" on line %d\n", arg, ln);
		return ERROR_REJECT;
	}
	memcpy(buf, arg, alen);
	buf[alen] = '\0';
	if (slash) {
		char *end = NULL;
		const char *num = slash + 1;
		errno = 0;
		prefix = strtol(num, &end, 10);
		if (*num < '0' || *num > '9' || *end || errno || prefix > 128) {
			slog(LOG_CRIT, "Invalid prefix length in %s for "
			     "%s on line %d\n", arg, what, ln);
			return ERROR_REJECT;
		}
	}

	struct in6_addr a6;
	struct in_addr a4;
	if (inet_pton(AF_INET6, buf, &a6) == 1) {
		if (prefix < 0) prefix = 128;
		struct tun_ip6 *ip6 = malloc(sizeof(*ip6));
		if (!ip6) {
			slog(LOG_CRIT, "Failed to allocate %s memory\n", what);
			return ERROR_REJECT;
		}
		ip6->addr = a6;
		ip6->prefix_len = (int)prefix;
		INIT_LIST_HEAD(&ip6->list);
		list_add(&ip6->list, list6);
		return ERROR_NONE;
	}
	if (inet_pton(AF_INET, buf, &a4) == 1) {
		if (prefix < 0) prefix = 32;
		if (prefix > 32) {
			slog(LOG_CRIT, "Invalid prefix length %ld for IPv4 "
			     "%s on line %d\n", prefix, what, ln);
			return ERROR_REJECT;
		}
		struct tun_ip4 *ip4 = malloc(sizeof(*ip4));
		if (!ip4) {
			slog(LOG_CRIT, "Failed to allocate %s memory\n", what);
			return ERROR_REJECT;
		}
		ip4->addr = a4;
		ip4->prefix_len = (int)prefix;
		INIT_LIST_HEAD(&ip4->list);
		list_add(&ip4->list, list4);
		return ERROR_NONE;
	}
	slog(LOG_CRIT, "Expected an IPv4 or IPv6 address but found \"%s\" on "
		     "line %d\n", arg, ln);
	return ERROR_REJECT;
}

static int config_tun_ip(int ln, int arg_count, char **args)
{
	(void)arg_count;
	return parse_tun_addr(ln, "address", args[0],
			&cfg_target->tun_ip4_list, &cfg_target->tun_ip6_list);
}

static int config_tun_route(int ln, int arg_count, char **args)
{
	(void)arg_count;
	return parse_tun_addr(ln, "route", args[0],
			&cfg_target->tun_rt4_list, &cfg_target->tun_rt6_list);
}


static int config_map(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	struct map_static *m;
	struct map4 *m4;
	struct map6 *m6;

	m = alloc_map_static(ln);
	if(!m) return ERROR_REJECT;

	if (strchr(args[0], '/')) {
		if (parse_prefix(AF_INET, args[0], &m->map4.addr, &m->map4.prefix_len) ||
		    calc_ip4_mask(&m->map4.mask, &m->map4.addr, m->map4.prefix_len)) {
			slog(LOG_CRIT, "Expected a valid IPv4 subnet with zero host bits but found \"%s\" on line %d\n", args[0], ln);
			free(m);
			return ERROR_REJECT;
		}
	} else if (!inet_pton(AF_INET, args[0], &m->map4.addr)) {
		slog(LOG_CRIT, "Expected an IPv4 subnet but found \"%s\" on "
		     "line %d\n", args[0], ln);
		free(m);
		return ERROR_REJECT;
	} else {
		m->map4.prefix_len = 32;
		calc_ip4_mask(&m->map4.mask, &m->map4.addr, 32);
	}

	if (strchr(args[1], '/')) {
		if (parse_prefix(AF_INET6, args[1], &m->map6.addr, &m->map6.prefix_len) ||
		    calc_ip6_mask(&m->map6.mask, &m->map6.addr, m->map6.prefix_len)) {
			slog(LOG_CRIT, "Expected a valid IPv6 subnet with zero host bits but found \"%s\" on line %d\n", args[1], ln);
			free(m);
			return ERROR_REJECT;
		}
	} else if (!inet_pton(AF_INET6, args[1], &m->map6.addr)) {
		slog(LOG_CRIT, "Expected an IPv6 subnet but found \"%s\" on "
				"line %d\n", args[1], ln);
		free(m);
		return ERROR_REJECT;
	} else {
		m->map6.prefix_len = 128;
		calc_ip6_mask(&m->map6.mask, &m->map6.addr, 128);
	}

	if ((32 - m->map4.prefix_len) > (128 - m->map6.prefix_len)) {
		slog(LOG_CRIT, "IPv6 prefix has insufficient space for the IPv4 suffix in"
				" %s and %s on line %d\n", args[0], args[1], ln);
		free(m);
		return ERROR_REJECT;
	}
    int ret = m->map4.prefix_len ? validate_ip4_addr(&m->map4.addr) : ERROR_NONE;
	if (ret == ERROR_LOCAL) {
		slog(LOG_WARNING, "Using link-local address %s in map "
			"directive, use with caution\n", args[0]);
	} else if (ret < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in map "
				"directive, aborting...\n", args[0]);
		free(m);
		return ERROR_REJECT;
	}
	if (m->map6.prefix_len && validate_ip6_addr(&m->map6.addr) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in map "
				"directive, aborting...\n", args[1]);
		free(m);
		return ERROR_REJECT;
	}
	if (insert_map4_to(&cfg_target->map4_list, &m->map4, &m4) < 0) {
		abort_on_conflict4("Error: IPv4 address in map directive",
				ln, m4);
		free(m);
		return ERROR_REJECT;
	}
	if (insert_map6_to(&cfg_target->map6_list, &m->map6, &m6) < 0) {
		abort_on_conflict6("Error: IPv6 address in map directive",
				ln, m6);
		list_del(&m->map4.list);
		free(m);
		return ERROR_REJECT;
	}
	return ERROR_NONE;
}

static int config_dynamic_pool(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	struct dynamic_pool *pool;
	struct map4 *m4;

	if (cfg_target->dynamic_pool) {
		slog(LOG_CRIT, "Error: duplicate dynamic-pool directive on "
				"line %d\n", ln);
		return ERROR_REJECT;
	}

	pool = (struct dynamic_pool *)malloc(sizeof(struct dynamic_pool));
	if (!pool) {
		slog(LOG_CRIT, "Unable to allocate config memory\n");
		return ERROR_REJECT;
	}
	memset(pool, 0, sizeof(struct dynamic_pool));
	INIT_LIST_HEAD(&pool->mapped_list);
	INIT_LIST_HEAD(&pool->dormant_list);
	INIT_LIST_HEAD(&pool->free_list);

	m4 = &pool->map4;
	m4->type = MAP_TYPE_DYNAMIC_POOL;
	INIT_LIST_HEAD(&m4->list);

	if (parse_prefix(AF_INET, args[0], &m4->addr, &m4->prefix_len) ||
			calc_ip4_mask(&m4->mask, &m4->addr, m4->prefix_len)) {
		slog(LOG_CRIT, "Expected an IPv4 prefix but found \"%s\" on "
				"line %d\n", args[0], ln);
		free(pool);
		return ERROR_REJECT;
	}
	int ret = validate_ip4_addr(&m4->addr);
	if (ret == ERROR_LOCAL) {
		slog(LOG_WARNING, "Using link-local address %s in dynamic-pool "
			"directive, use with caution\n", args[0]);
	} else if (ret < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in dynamic-pool "
				"directive, aborting...\n", args[0]);
		free(pool);
		return ERROR_REJECT;
	}
	if (m4->prefix_len > 31) {
		slog(LOG_CRIT, "Cannot use a prefix longer than /31 in "
			       "dynamic-pool directive, aborting...\n");
		free(pool);
		return ERROR_REJECT;
	}
	if (insert_map4_to(&cfg_target->map4_list, &pool->map4, &m4) < 0) {
		abort_on_conflict4("Error: IPv4 prefix in dynamic-pool "
				"directive", ln, m4);
		free(pool);
		return ERROR_REJECT;
	}

	pool->free_head.addr = ntohl(m4->addr.s_addr);
	pool->free_head.count = UINT32_MAX >> m4->prefix_len;
	INIT_LIST_HEAD(&pool->free_head.list);
	list_add(&pool->free_head.list, &pool->free_list);

	cfg_target->dynamic_pool = pool;
	return ERROR_NONE;
}

static int config_icmp_v4_pool(int ln, int arg_count, char **args)
{
	struct in_addr addr, mask;
	int plen = 0;
	int ret;

	(void)arg_count;
	if (cfg_target->icmp_v4_pool_len) {
		slog(LOG_CRIT, "Error: duplicate icmp-v4-pool directive on line %d\n", ln);
		return ERROR_REJECT;
	}
	if (parse_prefix(AF_INET, args[0], &addr, &plen) ||
			calc_ip4_mask(&mask, &addr, plen) || plen < 1 || plen > 32) {
		slog(LOG_CRIT, "Expected an IPv4 prefix (/1../32) in icmp-v4-pool on line %d\n", ln);
		return ERROR_REJECT;
	}
	ret = validate_ip4_addr(&addr);
	if (ret == ERROR_LOCAL) {
		slog(LOG_WARNING, "Using link-local address %s in icmp-v4-pool, use with caution\n", args[0]);
	} else if (ret < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in icmp-v4-pool on line %d\n", args[0], ln);
		return ERROR_REJECT;
	}
	cfg_target->icmp_v4_pool_addr = addr;
	cfg_target->icmp_v4_pool_mask = mask;
	cfg_target->icmp_v4_pool_len = plen;
	return ERROR_NONE;
}

static int config_data_dir(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (cfg_target->data_dir[0]) {
		slog(LOG_CRIT, "Error: duplicate data-dir directive on line "
				"%d\n", ln);
		return ERROR_REJECT;
	}
	if (args[0][0] != '/') {
		slog(LOG_CRIT, "Error: data-dir must be an absolute path\n");
		return ERROR_REJECT;
	}
	strcpy(cfg_target->data_dir, args[0]);
	return ERROR_NONE;
}

static int config_map_file(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	if (cfg_target->map_file[0]) {
		slog(LOG_CRIT, "Error: duplicate map-file directive on line "
				"%d\n", ln);
		return ERROR_REJECT;
	}
	strcpy(cfg_target->map_file, args[0]);
	return ERROR_NONE;
}

static int config_strict_fh(int ln, int arg_count, char **args)
{
	//unused
	(void)arg_count;
	(void)args;
	 
	slog(LOG_WARNING,"Warning: strict-frag-hdr deprecated on line %d\n",ln);
	return ERROR_NONE;
}

static int config_log(int ln, int arg_count, char **args)
{
	if(cfg_target->log_opts) {
		slog(LOG_CRIT, "Error: duplicate log directive on line "
				"%d\n", ln);
		return ERROR_REJECT;
	}
	/* Set this flag to detect duplicate entries */
	cfg_target->log_opts |= LOG_OPT_CONFIG;
	/* For each arg we have */
	for(int i = 0; i < arg_count; i++)
	{
		/* Check if this arg matches one of these keys, and enable that key */
		if(!strcasecmp(args[i],"drop")) cfg_target->log_opts |= LOG_OPT_DROP;
		else if(!strcasecmp(args[i],"reject")) cfg_target->log_opts |= LOG_OPT_REJECT;
		else if(!strcasecmp(args[i],"icmp")) cfg_target->log_opts |= LOG_OPT_ICMP;
		else if(!strcasecmp(args[i],"self")) cfg_target->log_opts |= LOG_OPT_SELF;
		else if(!strcasecmp(args[i],"dyn")) cfg_target->log_opts |= LOG_OPT_DYN;
		else {
			slog(LOG_CRIT, "Error: invalid value for log on line %d\n",ln);
			return ERROR_REJECT;
		}
	}
	return ERROR_NONE;
}

static int config_offlink_mtu(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;
	
	/* Offlink MTU already set? */
	if (cfg_target->ipv6_offlink_mtu) {
		slog(LOG_CRIT, "Error: duplicate offlink-mtu directive on "
				"line %d\n", ln);
		return ERROR_REJECT;
	}
	/* Try to convert the argument to an integer */
	char *endptr;
	long int mtu = strtol(args[0], &endptr, 10);
	if (*endptr != '\0') {
		slog(LOG_CRIT, "Error: unable to parse offlink-mtu on line %d\n", ln);
		return ERROR_REJECT;
	} else if(mtu < MTU_MIN) {
		slog(LOG_CRIT, "Error: invalid value for offlink-mtu on line (must be"
			" at least %d) on line %d\n", MTU_MIN, ln);
		return ERROR_REJECT;

	} else if(mtu > UINT16_MAX) {
		slog(LOG_CRIT, "Error: invalid value for offlink-mtu on line (must be"
			" at most %d) on line %d\n", UINT16_MAX, ln);
		return ERROR_REJECT;
	}
	/* Set the offlink MTU */
	cfg_target->ipv6_offlink_mtu = mtu;
	return ERROR_NONE;
}

static int config_workers(int ln, int arg_count, char **args)
{
	//arg_count unused
	(void)arg_count;

	/* If we are not configured for workers, print a warning */
#if MAX_WORKERS > 0
	char *endptr;
	long int workers;
	
	/* Offlink MTU already set? */
	if (cfg_target->workers != -1) {
		slog(LOG_CRIT, "Error: duplicate workers directive on "
				"line %d\n", ln);
		return ERROR_REJECT;
	}
	/* Try to convert the argument to an integer */
	workers = strtol(args[0], &endptr, 10);
	if (*endptr != '\0') {
		slog(LOG_CRIT, "Error: unable to parse workers on line %d\n", ln);
		return ERROR_REJECT;
	} else if(workers < 0) {
		slog(LOG_CRIT, "Error: invalid value for workers on line (must be"
			" at least zero) on line %d\n", ln);
		return ERROR_REJECT;

	} else if(workers > MAX_WORKERS) {
		slog(LOG_CRIT, "Error: invalid value for workers on line (must be"
			" at most %d) on line %d\n", MAX_WORKERS, ln);
		return ERROR_REJECT;
	}
	/* Set the offlink MTU */
	cfg_target->workers = workers;
	return ERROR_NONE;
#else
	//args unused
	(void)args;
	slog(LOG_CRIT,"Error: `workers` (line %d) not supported on this platform",ln);
	return ERROR_REJECT;
#endif
}


static int config_tun_offload(int ln, int arg_count, char **args)
{
	(void)arg_count;
	if (strcasecmp(args[0], "off") == 0) {
		cfg_target->tun_offload = TUN_OFFLOAD_OFF;
	} else if (strcasecmp(args[0], "tcp") == 0) {
		cfg_target->tun_offload = TUN_OFFLOAD_TCP;
	} else if (strcasecmp(args[0], "auto") == 0) {
		cfg_target->tun_offload = TUN_OFFLOAD_AUTO;
	} else if (strcasecmp(args[0], "udp") == 0) {
		cfg_target->tun_offload = TUN_OFFLOAD_UDP;
	} else {
		slog(LOG_CRIT, "Error: invalid value for tun-offload on line %d (must be off, tcp, udp, or auto)\n", ln);
		return ERROR_REJECT;
	}
	return 0;
}

static int config_tun_steering(int ln, int arg_count, char **args)
{
	(void)arg_count;
	if (strcasecmp(args[0], "kernel") == 0) {
		cfg_target->tun_steering_flows = 0;
	} else if (strcasecmp(args[0], "flows") == 0) {
		cfg_target->tun_steering_flows = 1;
	} else {
		slog(LOG_CRIT, "Error: invalid value for tun-steering on line %d (must be kernel or flows)\n", ln);
		return ERROR_REJECT;
	}
	return 0;
}

static int config_runtime_dir(int ln, int argc, char **argv)
{
	(void)argc;
	if (cfg_target->runtime_dir_configured || argv[0][0] != '/' || strlen(argv[0]) >= sizeof(cfg_target->runtime_dir)) {
		slog(LOG_CRIT, "Invalid runtime-dir on line %d\n", ln);
		return ERROR_REJECT;
	}
	strcpy(cfg_target->runtime_dir, argv[0]);
	cfg_target->runtime_dir_configured = 1;
	return 0;
}

struct {
	/* Long name */
	char *name;
	/* Parser function */
	int (*config_func)(int ln, int arg_count, char **args);
	/* Required args (more are allowed) */
	int need_args;
} config_directives[] = {
	{ "ipv4-addr", 		config_ipv4_addr, 		1 },
	{ "ipv6-addr", 		config_ipv6_addr, 		1 },
	{ "prefix", 		config_prefix, 			1 },
	{ "wkpf-strict", 	config_wkpf_strict, 	1 },
	{ "icmp-rate-limit", 	config_icmp_rate_limit, 	1 },
	{ "hash-bits", 		config_hash_bits, 		1 },
	{ "cache-size", 		config_cache_size, 		1 },
	{ "udp-cksum-mode", config_udp_cksum_mode, 	1 },
	{ "flow-label", 			config_flow_label, 		   1 },
	{ "worker-affinity", 		config_worker_affinity, 	   1 },
	{ "tun-up", 		config_tun_up, 			1 },
	{ "tun-ip", 		config_tun_ip, 			1 },
	{ "tun-route", 		config_tun_route, 		1 },
	{ "tun-device", 	config_tun_device, 		1 },
	{ "map", 			config_map, 			2 },
	{ "dynamic-pool", 	config_dynamic_pool,	1 },
	{ "icmp-v4-pool",	config_icmp_v4_pool,	1 },
	{ "runtime-dir", config_runtime_dir, 1 },
	{ "data-dir", 		config_data_dir, 		1 },
	{ "map-file", 		config_map_file, 		1 },
	{ "strict-frag-hdr",config_strict_fh, 		1 },
	{ "log"	,			config_log, 		   -1 },
	{ "offlink-mtu"	,  	config_offlink_mtu,		1 },
	{ "workers"	,  		config_workers,			1 },
	{ "tun-offload"	,	config_tun_offload,		1 },
	{ "tun-steering",	config_tun_steering,	1 },
	{ NULL, NULL, 0 }
};

void config_free(void)
{
	struct list_head *entry, *next;

	if (cfg_target == &gcfg)
		addrmap_free_index();

	if (cfg_target->map4_list.next && cfg_target->map4_list.next != &cfg_target->map4_list) {
		list_for_each_safe(entry, next, &cfg_target->map4_list) {
			struct map4 *m = list_entry(entry, struct map4, list);
			if (m->type == MAP_TYPE_STATIC || m->type == MAP_TYPE_RFC6052) {
				struct map_static *s = container_of(m, struct map_static, map4);
				list_del(&s->map4.list);
				list_del(&s->map6.list);
				free(s);
			} else {
				list_del(&m->list);
			}
		}
	}
	if (cfg_target->map6_list.next && cfg_target->map6_list.next != &cfg_target->map6_list) {
		list_for_each_safe(entry, next, &cfg_target->map6_list) {
			struct map6 *m = list_entry(entry, struct map6, list);
			if (m->type == MAP_TYPE_STATIC || m->type == MAP_TYPE_RFC6052) {
				struct map_static *s = container_of(m, struct map_static, map6);
				list_del(&s->map6.list);
				free(s);
			} else {
				list_del(&m->list);
			}
		}
	}
	if (cfg_target->dynamic_pool) {
		free(cfg_target->dynamic_pool);
		cfg_target->dynamic_pool = NULL;
	}
	if (cfg_target->tun_ip4_list.next && cfg_target->tun_ip4_list.next != &cfg_target->tun_ip4_list) {
		list_for_each_safe(entry, next, &cfg_target->tun_ip4_list) {
			struct tun_ip4 *ip4 = list_entry(entry, struct tun_ip4, list);
			list_del(&ip4->list);
			free(ip4);
		}
	}
	if (cfg_target->tun_ip6_list.next && cfg_target->tun_ip6_list.next != &cfg_target->tun_ip6_list) {
		list_for_each_safe(entry, next, &cfg_target->tun_ip6_list) {
			struct tun_ip6 *ip6 = list_entry(entry, struct tun_ip6, list);
			list_del(&ip6->list);
			free(ip6);
		}
	}
	if (cfg_target->tun_rt4_list.next && cfg_target->tun_rt4_list.next != &cfg_target->tun_rt4_list) {
		list_for_each_safe(entry, next, &cfg_target->tun_rt4_list) {
			struct tun_ip4 *ip4 = list_entry(entry, struct tun_ip4, list);
			list_del(&ip4->list);
			free(ip4);
		}
	}
	if (cfg_target->tun_rt6_list.next && cfg_target->tun_rt6_list.next != &cfg_target->tun_rt6_list) {
		list_for_each_safe(entry, next, &cfg_target->tun_rt6_list) {
			struct tun_ip6 *ip6 = list_entry(entry, struct tun_ip6, list);
			list_del(&ip6->list);
			free(ip6);
		}
	}
}

int config_init(void)
{
	/* Initialize configuration structure to defaults */
	memset(cfg_target, 0, sizeof(struct config));
	strcpy(cfg_target->runtime_dir, "/run");
	INIT_LIST_HEAD(&cfg_target->map4_list);
	INIT_LIST_HEAD(&cfg_target->map6_list);
	cfg_target->dyn_min_lease = 7200 + 4 * 60; /* just over two hours */
	cfg_target->dyn_max_lease = 14 * 86400;
	cfg_target->max_commit_delay = cfg_target->dyn_max_lease / 4;
	cfg_target->hash_bits = 14;
	hash_bits_explicit = 0;
	cfg_target->cache_size = 8192;
	INIT_LIST_HEAD(&cfg_target->cache_pool);
	INIT_LIST_HEAD(&cfg_target->cache_active);
	cfg_target->wkpf_strict = 1;
	cfg_target->udp_cksum_mode = UDP_CKSUM_DROP;
	cfg_target->workers = -1;
	cfg_target->tun_offload = TUN_OFFLOAD_AUTO;
	cfg_target->vnet_hdr_sz = 0;
	INIT_LIST_HEAD(&cfg_target->tun_ip4_list);
	INIT_LIST_HEAD(&cfg_target->tun_ip6_list);
	INIT_LIST_HEAD(&cfg_target->tun_rt4_list);
	INIT_LIST_HEAD(&cfg_target->tun_rt6_list);
	cfg_target->tun_up = 0;
	return ERROR_NONE;
}

int config_read(char *conffile)
{
	FILE *in;
	int ln = 0;
	char line[512];
	char *c, *tokptr;
	char *args[MAX_ARGS];
	int arg_count;
	int i;

	/* Has conf file failed validation, should we exit? */
	int willexit = 0;

	/* Reject an absent path before calling libc: fopen(NULL, ...) is undefined. */
	if (!conffile) {
		slog(LOG_CRIT, "No configuration file path supplied\n");
		return ERROR_REJECT;
	}

	/* Read in conf file */
	in = fopen(conffile, "r");
	if (!in) {
		slog(LOG_CRIT, "unable to open %s, aborting: %s\n", conffile,
				strerror(errno));
		return ERROR_REJECT;
	}
	/* Parse each line of conf file */
	while (fgets(line, sizeof(line), in)) {
		++ln;
		if (strlen(line) + 1 == sizeof(line)) {
			slog(LOG_CRIT, "Line %d of %s is too long\n", ln, conffile);
			willexit = 1;
			continue;
		}
		arg_count = 0;
		for (;;) {
			c = strtok_r(arg_count ? NULL : line, DELIM, &tokptr);
			if (!c || *c == '#')
				break;
			if (arg_count == MAX_ARGS) {
				slog(LOG_CRIT, "Line %d of %s has too many tokens, "
					"aborting\n", ln, conffile);
				willexit = 1;
				break;
			}
			args[arg_count++] = c;
		}
		if (arg_count == 0)
			continue;
		for (i = 0; config_directives[i].name; ++i)
			if (!strcasecmp(args[0], config_directives[i].name))
				break;
		if (!config_directives[i].name) {
			slog(LOG_CRIT, "Unknown directive \"%s\" on line %d of "
					"%s\n", args[0],
					ln, conffile);
			willexit = 1;
			continue;
		}
		--arg_count;
		if (config_directives[i].need_args >= 0 &&
				arg_count != config_directives[i].need_args) {
			slog(LOG_CRIT, "Incorrect number of arguments on "
					"line %d\n", ln);
			willexit = 1;
			continue;
		}
		willexit |= config_directives[i].config_func(ln, arg_count, &args[1]);
	}
	fclose(in);

	/* At this point, exit if we had parsing errors */
	if(willexit) return ERROR_REJECT;
	return ERROR_NONE;
}

static int config_validate_internal(int build_index)
{
	struct map_static *m;
	struct map4 *m4;
	struct map6 *m6;
	char addrbuf[128];

	/* Now, validate the inputs */
	if (list_empty(&cfg_target->map6_list)) {
		slog(LOG_CRIT, "Error: no translation maps or NAT64 prefix "
				"configured\n");
		return ERROR_REJECT;
	}

	/* Check if the env var STATE_DIRECTORY exists to use as data_dir
	 * This env var is set by systemd
	 * And it can still be overridden by the conf file
	 */
	char * sd = getenv("STATE_DIRECTORY");
	if(sd && !cfg_target->data_dir[0]) {
		if (sd[0] != '/') {
			slog(LOG_CRIT, "Error: STATE_DIRECTORY must be an "
				"absolute path\n");
			return ERROR_REJECT;
		}
		/* Copy env var into data_dir */
		if(strlen(sd) + 1 > sizeof(cfg_target->data_dir)) {
			slog(LOG_CRIT, "Error: STATE_DIRECTORY is too long, "
					"aborting...\n");
			return ERROR_REJECT;
		}
		/* Copy state directory */
		strcpy(cfg_target->data_dir, sd);
		/* Check for a : which signifies that we have multiple dirs */
		for(int i = 0; cfg_target->data_dir[i]; i++) {
			if(cfg_target->data_dir[i] == ':') {
				slog(LOG_WARNING, "STATE_DIRECTORY env var contains "
						"multiple directories, using first one\n");
				cfg_target->data_dir[i] = 0;
				break;
			}
		}
	}

	m4 = list_entry(cfg_target->map4_list.next, struct map4, list);
	m6 = list_entry(cfg_target->map6_list.next, struct map6, list);

	/*
	 * A configuration without a dynamic pool or a reloadable map file has a
	 * small, immutable static map set.  The cache adds a global mutex, hash
	 * lookup and per-packet timestamp write but cannot make those maps change.
	 */
	cfg_target->maps_immutable = !cfg_target->dynamic_pool && !cfg_target->map_file[0];
	if (cfg_target->maps_immutable) {
		slog(LOG_DEBUG,"Disabling cache for immutable static maps\n");
		cfg_target->cache_size = 0;
	}
	/* Size the bucket arrays for the cache actually configured: about two
	 * buckets per entry, between 128 and 16384 buckets, unless hash-bits is set. */
	if (!hash_bits_explicit && cfg_target->cache_size > 0) {
		int bits = 7;
		while (bits < 14 && (1 << (bits - 1)) < cfg_target->cache_size)
			bits++;
		cfg_target->hash_bits = bits;
	}

	if (!cfg_target->local_addr4.s_addr) {
		slog(LOG_CRIT, "Error: no ipv4-addr directive found\n");
		return ERROR_REJECT;
	}

	m = alloc_map_static(0);
	if(!m) return ERROR_REJECT;
	m->map4.addr = cfg_target->local_addr4;
	m->origin = MAP_ORIGIN_SELF;
	if (insert_map4_to(&cfg_target->map4_list, &m->map4, &m4) < 0) {
		abort_on_conflict4("Error: ipv4-addr", 0, m4);
		free(m);
		return ERROR_REJECT;
	}

	/* ipv6-addr is configured and is within the well known prefix */
	if (cfg_target->local_addr6.s6_addr32[0] == WKPF &&
		cfg_target->local_addr6.s6_addr32[1] == 0 &&
		cfg_target->local_addr6.s6_addr32[2] == 0 &&
		cfg_target->wkpf_strict)
	{
		slog(LOG_CRIT, "Error: ipv6-addr directive cannot contain an "
				"address in the Well-Known Prefix "
				"(64:ff9b::/96)\n");
		list_del(&m->map4.list);
		free(m);
		return ERROR_REJECT;
	/* ipv6-addr is configured but not within the well known prefix */
	} else if (cfg_target->local_addr6.s6_addr32[0]) {
		m->map6.addr = cfg_target->local_addr6;
		if (insert_map6_to(&cfg_target->map6_list, &m->map6, &m6) < 0) {
			if (m6->type == MAP_TYPE_RFC6052) {
				inet_ntop(AF_INET6, &m6->addr,
						addrbuf, sizeof(addrbuf));
				slog(LOG_CRIT, "Error: ipv6-addr cannot reside "
						"within configured prefix "
						"%s/%d\n", addrbuf,
						m6->prefix_len);
			} else {
				abort_on_conflict6("Error: ipv6-addr", 0, m6);
			}
			list_del(&m->map4.list);
			free(m);
			return ERROR_REJECT;
		}
	/* ipv6-addr is zero (not set), generate from ipv4-addr and prefix */
	} else {
		m6 = list_entry(cfg_target->map6_list.prev, struct map6, list);
		if (m6->type != MAP_TYPE_RFC6052) {
			slog(LOG_CRIT, "Error: ipv6-addr directive must be "
					"specified if no NAT64 prefix is "
					"configured\n");
			list_del(&m->map4.list);
			free(m);
			return ERROR_REJECT;
		}
		if (append_to_prefix(&cfg_target->local_addr6, &cfg_target->local_addr4,
					&m6->addr, m6->prefix_len)) {
			if(cfg_target->wkpf_strict)
			{
				slog(LOG_CRIT, "Error: ipv6-addr directive must be "
						"specified if prefix is 64:ff9b::/96 "
						"and ipv4-addr is a non-global "
						"(RFC 1918) address\n");
				list_del(&m->map4.list);
				free(m);
				return ERROR_REJECT;
			}
		}
		m->map6.addr = cfg_target->local_addr6;
	}

	/* Offlink MTU defaults to 1280 if not set */
	if (cfg_target->ipv6_offlink_mtu <= MTU_MIN) cfg_target->ipv6_offlink_mtu = MTU_MIN;

	/* Tundev must be provided */
	if(strlen(cfg_target->tundev) < 1) {
		slog(LOG_CRIT, "Error: no tun-device directive found\n");
		return ERROR_REJECT;
	}

	/* Immutable tables with many entries get a flat per-length prefix index. */
	if (build_index && cfg_target->maps_immutable)
		addrmap_build_index();

	/* Guess there are no errors? */
	return ERROR_NONE;
}

int config_validate(void)
{
	return config_validate_internal(1);
}

static void move_list_entries(struct list_head *dst, struct list_head *src)
{
	struct list_head *entry, *next;

	list_for_each_safe(entry, next, src) {
		list_del(entry);
		list_add_tail(entry, dst);
	}
}

int config_reload(const char *conffile)
{
	struct config staged;
	struct list_head old_map4, old_map6;
	struct list_head *entry, *next;
	struct dynamic_pool *old_pool_to_free = NULL;
	int saved_hash_bits_explicit = hash_bits_explicit;

	if (!conffile || !*conffile)
		return ERROR_REJECT;

	cfg_target = &staged;
	config_init();
	staged.log_out = gcfg.log_out;
	staged.tun_offload = gcfg.tun_offload;
	staged.dispatch_mode = gcfg.dispatch_mode;
	staged.async_tun = gcfg.async_tun;
	staged.tun_steering_flows = gcfg.tun_steering_flows;

	if (config_read((char *)conffile) != ERROR_NONE ||
	    config_validate_internal(0) != ERROR_NONE) {
		config_free();
		cfg_target = &gcfg;
		hash_bits_explicit = saved_hash_bits_explicit;
		slog(LOG_ERR, "Config reload failed for %s; retaining active configuration\n", conffile);
		return ERROR_REJECT;
	}
	cfg_target = &gcfg;
	hash_bits_explicit = saved_hash_bits_explicit;

	if (staged.maps_immutable != gcfg.maps_immutable) {
		slog(LOG_WARNING, "SIGHUP reload cannot switch between immutable static maps and dynamic/map-file mode; restart required\n");
		cfg_target = &staged;
		config_free();
		cfg_target = &gcfg;
		return ERROR_REJECT;
	}
	if (strcmp(staged.tundev, gcfg.tundev) != 0)
		slog(LOG_WARNING, "SIGHUP: tun-device change (%s -> %s) requires restart; keeping %s\n",
		     gcfg.tundev, staged.tundev, gcfg.tundev);
	if (strcmp(staged.data_dir, gcfg.data_dir) != 0)
		slog(LOG_WARNING, "SIGHUP: data-dir change requires restart; keeping %s\n", gcfg.data_dir);
	if (staged.workers > 0 && staged.workers != gcfg.workers)
		slog(LOG_WARNING, "SIGHUP: workers change (%d -> %d) requires restart; keeping %d\n",
		     gcfg.workers, staged.workers, gcfg.workers);

	INIT_LIST_HEAD(&old_map4);
	INIT_LIST_HEAD(&old_map6);

	pthread_mutex_lock(&gcfg.map_mutex);
	pthread_mutex_lock(&gcfg.cache_mutex);

	move_list_entries(&old_map4, &gcfg.map4_list);
	move_list_entries(&old_map6, &gcfg.map6_list);

	int keep_pool = 0;
	if (gcfg.dynamic_pool && staged.dynamic_pool &&
	    gcfg.dynamic_pool->map4.addr.s_addr == staged.dynamic_pool->map4.addr.s_addr &&
	    gcfg.dynamic_pool->map4.prefix_len == staged.dynamic_pool->map4.prefix_len) {
		/* Keep existing dynamic pool and its active leases. */
		keep_pool = 1;
		list_del(&staged.dynamic_pool->map4.list);
		free(staged.dynamic_pool);
		staged.dynamic_pool = NULL;
		list_del(&gcfg.dynamic_pool->map4.list);
		insert_map4_to(&staged.map4_list, &gcfg.dynamic_pool->map4, NULL);
	} else if (gcfg.dynamic_pool != staged.dynamic_pool) {
		if (gcfg.dynamic_pool) {
			list_del(&gcfg.dynamic_pool->map4.list);
			old_pool_to_free = gcfg.dynamic_pool;
		}
		gcfg.dynamic_pool = staged.dynamic_pool;
		staged.dynamic_pool = NULL;
	}

	move_list_entries(&gcfg.map4_list, &staged.map4_list);
	move_list_entries(&gcfg.map6_list, &staged.map6_list);
	if (keep_pool) {
		list_for_each_safe(entry, next, &old_map4) {
			struct map4 *m = list_entry(entry, struct map4, list);
			if (m->type == MAP_TYPE_DYNAMIC_HOST) {
				list_del(entry);
				insert_map4_to(&gcfg.map4_list, m, NULL);
			}
		}
		list_for_each_safe(entry, next, &old_map6) {
			struct map6 *m = list_entry(entry, struct map6, list);
			if (m->type == MAP_TYPE_DYNAMIC_HOST) {
				list_del(entry);
				insert_map6_to(&gcfg.map6_list, m, NULL);
			}
		}
	}

	gcfg.local_addr4 = staged.local_addr4;
	gcfg.local_addr6 = staged.local_addr6;
	gcfg.icmp_v4_pool_addr = staged.icmp_v4_pool_addr;
	gcfg.icmp_v4_pool_mask = staged.icmp_v4_pool_mask;
	gcfg.icmp_v4_pool_len = staged.icmp_v4_pool_len;
	gcfg.wkpf_strict = staged.wkpf_strict;
	gcfg.ipv6_offlink_mtu = staged.ipv6_offlink_mtu;
	gcfg.icmp_rate_limit = staged.icmp_rate_limit;
	gcfg.flow_label_mode = staged.flow_label_mode;
	gcfg.udp_cksum_mode = staged.udp_cksum_mode;
	gcfg.log_opts = staged.log_opts;
	gcfg.dyn_min_lease = staged.dyn_min_lease;
	gcfg.dyn_max_lease = staged.dyn_max_lease;
	gcfg.max_commit_delay = staged.max_commit_delay;
	memcpy(gcfg.map_file, staged.map_file, sizeof(gcfg.map_file));

	list_for_each_safe(entry, next, &gcfg.cache_active) {
		struct cache_entry *c = list_entry(entry, struct cache_entry, list);
		list_del(&c->hash4);
		list_del(&c->hash6);
		list_add(&c->list, &gcfg.cache_pool);
	}
	addrmap_invalidate_front();
	if (gcfg.maps_immutable)
		addrmap_build_index();

	pthread_mutex_unlock(&gcfg.cache_mutex);
	pthread_mutex_unlock(&gcfg.map_mutex);

	/* Free old static/rfc6052 map entries and unused staging lists */
	list_for_each_safe(entry, next, &old_map4) {
		struct map4 *m = list_entry(entry, struct map4, list);
		if (m->type == MAP_TYPE_STATIC || m->type == MAP_TYPE_RFC6052) {
			struct map_static *s = container_of(m, struct map_static, map4);
			list_del(&s->map4.list);
			list_del(&s->map6.list);
			free(s);
		} else {
			list_del(&m->list);
		}
	}
	list_for_each_safe(entry, next, &old_map6) {
		struct map6 *m = list_entry(entry, struct map6, list);
		if (m->type == MAP_TYPE_STATIC || m->type == MAP_TYPE_RFC6052) {
			struct map_static *s = container_of(m, struct map_static, map6);
			list_del(&s->map6.list);
			free(s);
		} else {
			list_del(&m->list);
		}
	}
	free(old_pool_to_free);
	cfg_target = &staged;
	config_free();
	cfg_target = &gcfg;

	if (gcfg.map_file[0])
		addrmap_reload();

	return ERROR_NONE;
}
