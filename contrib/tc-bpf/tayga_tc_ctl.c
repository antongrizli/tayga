/*
 *  tayga_tc_ctl.c -- control-plane helper for tayga tc-bpf fast-path maps
 *
 *  Parses tayga.conf (prefix /96 + static map directives) into pinned BPF map
 *  records, formats tc-bpf telemetry counters (Prometheus/JSON), and provides
 *  a root-free --self-test validation mode.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tayga_tc_maps.h"

static int parse_cidr4(const char *arg, uint32_t *addr_be, int *plen)
{
	char buf[64];
	if (strlen(arg) >= sizeof(buf))
		return -1;
	strcpy(buf, arg);
	char *slash = strchr(buf, '/');
	int len = 32;
	if (slash) {
		*slash++ = '\0';
		char *end = NULL;
		long v = strtol(slash, &end, 10);
		if (!*slash || *end || v < 0 || v > 32)
			return -1;
		len = (int)v;
	}
	struct in_addr a4;
	if (inet_pton(AF_INET, buf, &a4) != 1)
		return -1;
	*addr_be = a4.s_addr;
	*plen = len;
	return 0;
}

static int parse_cidr6(const char *arg, uint32_t words_be[4], int *plen)
{
	char buf[128];
	if (strlen(arg) >= sizeof(buf))
		return -1;
	strcpy(buf, arg);
	char *slash = strchr(buf, '/');
	int len = 128;
	if (slash) {
		*slash++ = '\0';
		char *end = NULL;
		long v = strtol(slash, &end, 10);
		if (!*slash || *end || v < 0 || v > 128)
			return -1;
		len = (int)v;
	}
	struct in6_addr a6;
	if (inet_pton(AF_INET6, buf, &a6) != 1)
		return -1;
	memcpy(words_be, a6.s6_addr, 16);
	*plen = len;
	return 0;
}

int parse_tayga_conf_for_bpf(const char *conf_path,
			      struct tayga_bpf_cfg *cfg_out,
			      struct tayga_lpm4_key *k4, struct tayga_eam_val *v4,
			      struct tayga_lpm6_key *k6, struct tayga_eam_val *v6,
			      size_t max_eam, size_t *eam_count_out)
{
	FILE *f = fopen(conf_path, "r");
	if (!f)
		return -1;

	memset(cfg_out, 0, sizeof(*cfg_out));
	*eam_count_out = 0;

	char line[512];
	int have_prefix = 0;
	while (fgets(line, sizeof(line), f)) {
		char *save = NULL;
		char *tok0 = strtok_r(line, " \t\r\n", &save);
		if (!tok0 || tok0[0] == '#')
			continue;

		if (strcasecmp(tok0, "prefix") == 0) {
			char *tok1 = strtok_r(NULL, " \t\r\n", &save);
			uint32_t w[4];
			int plen = 0;
			if (!tok1 || parse_cidr6(tok1, w, &plen) != 0 || plen != 96) {
				fclose(f);
				return -1;
			}
			cfg_out->pref64_words[0] = w[0];
			cfg_out->pref64_words[1] = w[1];
			cfg_out->pref64_words[2] = w[2];
			cfg_out->enabled = 1;
			have_prefix = 1;
		} else if (strcasecmp(tok0, "map") == 0) {
			char *tok1 = strtok_r(NULL, " \t\r\n", &save);
			char *tok2 = strtok_r(NULL, " \t\r\n", &save);
			if (!tok1 || !tok2 || *eam_count_out >= max_eam) {
				fclose(f);
				return -1;
			}
			uint32_t a4 = 0, a6[4] = {0};
			int l4 = 0, l6 = 0;
			if (parse_cidr4(tok1, &a4, &l4) != 0 ||
			    parse_cidr6(tok2, a6, &l6) != 0) {
				fclose(f);
				return -1;
			}
			size_t idx = (*eam_count_out)++;
			memset(&k4[idx], 0, sizeof(k4[idx]));
			memset(&v4[idx], 0, sizeof(v4[idx]));
			k4[idx].prefixlen = (__u32)l4;
			k4[idx].addr = a4;
			memcpy(v4[idx].prefix, a6, 16);
			v4[idx].prefix_len = (__u8)l6;

			memset(&k6[idx], 0, sizeof(k6[idx]));
			memset(&v6[idx], 0, sizeof(v6[idx]));
			k6[idx].prefixlen = (__u32)l6;
			memcpy(k6[idx].addr, a6, 16);
			v6[idx].prefix[0] = a4;
			v6[idx].prefix_len = (__u8)l4;
		}
	}

	fclose(f);
	return have_prefix ? 0 : -1;
}

void format_tc_stats_prometheus(FILE *out, const struct tayga_bpf_stats *st)
{
	fprintf(out,
		"# HELP tayga_tc_fastpath_packets_total Packets processed by tc-bpf fast-path\n"
		"# TYPE tayga_tc_fastpath_packets_total counter\n"
		"tayga_tc_fastpath_packets_total{dir=\"4to6\"} %llu\n"
		"tayga_tc_fastpath_packets_total{dir=\"6to4\"} %llu\n"
		"tayga_tc_fastpath_packets_total{dir=\"slow_fallback\"} %llu\n",
		(unsigned long long)st->fast_4to6,
		(unsigned long long)st->fast_6to4,
		(unsigned long long)st->slow_fallback);
}

void format_tc_stats_json(FILE *out, const struct tayga_bpf_stats *st)
{
	fprintf(out,
		"{\n"
		"  \"fast_4to6\": %llu,\n"
		"  \"fast_6to4\": %llu,\n"
		"  \"slow_fallback\": %llu\n"
		"}\n",
		(unsigned long long)st->fast_4to6,
		(unsigned long long)st->fast_6to4,
		(unsigned long long)st->slow_fallback);
}

static int run_self_test(void)
{
	char tmpl[] = "/tmp/tayga_tc_ctl_XXXXXX";
	int fd = mkstemp(tmpl);
	assert(fd >= 0);
	const char *sample =
		"# Sample config\n"
		"tun-device nat64\n"
		"prefix 64:ff9b::/96\n"
		"map 192.0.2.1 2001:db8::1\n"
		"map 198.51.100.0/24 2001:db8:100::/56\n";
	size_t n = strlen(sample);
	assert(write(fd, sample, n) == (ssize_t)n);
	close(fd);

	struct tayga_bpf_cfg cfg;
	struct tayga_lpm4_key k4[8];
	struct tayga_lpm6_key k6[8];
	struct tayga_eam_val v4[8], v6[8];
	size_t eam_count = 0;

	assert(parse_tayga_conf_for_bpf(tmpl, &cfg, k4, v4, k6, v6, 8, &eam_count) == 0);
	unlink(tmpl);

	assert(cfg.enabled == 1);
	struct in6_addr exp_pref;
	assert(inet_pton(AF_INET6, "64:ff9b::", &exp_pref) == 1);
	assert(memcmp(cfg.pref64_words, exp_pref.s6_addr, 12) == 0);

	assert(eam_count == 2);
	assert(k4[0].prefixlen == 32 && v4[0].prefix_len == 128);
	assert(k4[1].prefixlen == 24 && v4[1].prefix_len == 56);
	assert(k6[1].prefixlen == 56 && v6[1].prefix_len == 24);

	struct tayga_bpf_stats st = { .fast_4to6 = 123, .fast_6to4 = 456, .slow_fallback = 7 };
	FILE *mem = tmpfile();
	assert(mem != NULL);
	format_tc_stats_prometheus(mem, &st);
	rewind(mem);
	char buf[512] = "";
	size_t r = fread(buf, 1, sizeof(buf) - 1, mem);
	fclose(mem);
	buf[r] = '\0';
	assert(strstr(buf, "tayga_tc_fastpath_packets_total{dir=\"4to6\"} 123") != NULL);
	assert(strstr(buf, "tayga_tc_fastpath_packets_total{dir=\"slow_fallback\"} 7") != NULL);

	printf("PASS: tayga-tc-ctl self-test (BPF map config parsing + stats formatting)\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "--self-test") == 0)
		return run_self_test();

	if (argc >= 3 && strcmp(argv[1], "--dump-config") == 0) {
		struct tayga_bpf_cfg cfg;
		struct tayga_lpm4_key k4[TAYGA_TC_MAX_EAM];
		struct tayga_lpm6_key k6[TAYGA_TC_MAX_EAM];
		struct tayga_eam_val v4[TAYGA_TC_MAX_EAM], v6[TAYGA_TC_MAX_EAM];
		size_t eam_count = 0;
		if (parse_tayga_conf_for_bpf(argv[2], &cfg, k4, v4, k6, v6,
					      TAYGA_TC_MAX_EAM, &eam_count) != 0) {
			fprintf(stderr, "Error parsing %s (requires /96 prefix)\n", argv[2]);
			return 1;
		}
		printf("enabled=%u eam_entries=%zu\n", cfg.enabled, eam_count);
		return 0;
	}

	fprintf(stderr, "Usage: %s --self-test | --dump-config <tayga.conf>\n", argv[0]);
	return 1;
}
