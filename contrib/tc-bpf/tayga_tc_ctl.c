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
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/bpf.h>
#include <sys/syscall.h>
#endif

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

static int parse_eam_pair(const char *tok1, const char *tok2,
			  struct tayga_lpm4_key *k4, struct tayga_eam_val *v4,
			  struct tayga_lpm6_key *k6, struct tayga_eam_val *v6,
			  size_t max_eam, size_t *eam_count_out)
{
	if (!tok1 || !tok2 || *eam_count_out >= max_eam)
		return -1;
	uint32_t a4 = 0, a6[4] = {0};
	int l4 = 0, l6 = 0;
	if (parse_cidr4(tok1, &a4, &l4) != 0 ||
	    parse_cidr6(tok2, a6, &l6) != 0)
		return -1;

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
	return 0;
}

static int parse_map_file_for_bpf(const char *map_path,
				  struct tayga_lpm4_key *k4, struct tayga_eam_val *v4,
				  struct tayga_lpm6_key *k6, struct tayga_eam_val *v6,
				  size_t max_eam, size_t *eam_count_out)
{
	FILE *f = fopen(map_path, "r");
	if (!f)
		return -1;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		char *save = NULL;
		char *tok0 = strtok_r(line, " \t\r\n", &save);
		if (!tok0 || tok0[0] == '#')
			continue;
		if (strcasecmp(tok0, "map") != 0) {
			fclose(f);
			return -1;
		}
		char *tok1 = strtok_r(NULL, " \t\r\n", &save);
		char *tok2 = strtok_r(NULL, " \t\r\n", &save);
		if (parse_eam_pair(tok1, tok2, k4, v4, k6, v6,
				   max_eam, eam_count_out) != 0) {
			fclose(f);
			return -1;
		}
	}

	fclose(f);
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
			if (parse_eam_pair(tok1, tok2, k4, v4, k6, v6,
					   max_eam, eam_count_out) != 0) {
				fclose(f);
				return -1;
			}
		} else if (strcasecmp(tok0, "map-file") == 0) {
			char *tok1 = strtok_r(NULL, " \t\r\n", &save);
			if (!tok1 || parse_map_file_for_bpf(tok1, k4, v4, k6, v6,
							    max_eam, eam_count_out) != 0) {
				fclose(f);
				return -1;
			}
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

#ifdef __linux__
static int bpf_syscall(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_obj_get(const char *path)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.pathname = (uint64_t)(uintptr_t)path;
	return bpf_syscall(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (__u32)fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = flags;
	return bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (__u32)fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	return bpf_syscall(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static long bpf_possible_cpus(void)
{
	FILE *f = fopen("/sys/devices/system/cpu/possible", "r");
	if (f) {
		char buf[128] = "";
		if (fgets(buf, sizeof(buf), f)) {
			long max_cpu = 0;
			const char *p = buf;
			while (*p) {
				if (isdigit((unsigned char)*p)) {
					char *end = NULL;
					long v = strtol(p, &end, 10);
					if (v > max_cpu)
						max_cpu = v;
					p = end;
				} else {
					p++;
				}
			}
			fclose(f);
			if (max_cpu >= 0)
				return max_cpu + 1;
		} else {
			fclose(f);
		}
	}
	long n = sysconf(_SC_NPROCESSORS_CONF);
	return n > 0 ? n : 1;
}

static int open_pinned_map(const char *pin_dir, const char *name)
{
	char path[PATH_MAX];
	int n = snprintf(path, sizeof(path), "%s/%s", pin_dir, name);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	int fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "Error opening pinned BPF map %s: %s\n", path, strerror(errno));
	return fd;
}

static int sync_pinned_maps(const char *conf_path, const char *pin_dir)
{
	struct tayga_bpf_cfg cfg;
	struct tayga_lpm4_key *k4 = calloc(TAYGA_TC_MAX_EAM, sizeof(*k4));
	struct tayga_lpm6_key *k6 = calloc(TAYGA_TC_MAX_EAM, sizeof(*k6));
	struct tayga_eam_val *v4 = calloc(TAYGA_TC_MAX_EAM, sizeof(*v4));
	struct tayga_eam_val *v6 = calloc(TAYGA_TC_MAX_EAM, sizeof(*v6));
	if (!k4 || !k6 || !v4 || !v6) {
		free(k4); free(k6); free(v4); free(v6);
		return 1;
	}

	size_t eam_count = 0;
	if (parse_tayga_conf_for_bpf(conf_path, &cfg, k4, v4, k6, v6,
				      TAYGA_TC_MAX_EAM, &eam_count) != 0) {
		fprintf(stderr, "Error parsing %s (requires /96 prefix)\n", conf_path);
		free(k4); free(k6); free(v4); free(v6);
		return 1;
	}

	int cfg_fd = open_pinned_map(pin_dir, "tayga_cfg_map");
	int eam4_fd = open_pinned_map(pin_dir, "tayga_eam4_map");
	int eam6_fd = open_pinned_map(pin_dir, "tayga_eam6_map");
	if (cfg_fd < 0 || eam4_fd < 0 || eam6_fd < 0) {
		if (cfg_fd >= 0) close(cfg_fd);
		if (eam4_fd >= 0) close(eam4_fd);
		if (eam6_fd >= 0) close(eam6_fd);
		free(k4); free(k6); free(v4); free(v6);
		return 1;
	}

	int rc = 0;
	__u32 zero = 0;
	if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY) != 0) {
		fprintf(stderr, "Error updating tayga_cfg_map: %s\n", strerror(errno));
		rc = 1;
	}
	for (size_t i = 0; rc == 0 && i < eam_count; i++) {
		if (bpf_map_update_elem(eam4_fd, &k4[i], &v4[i], BPF_ANY) != 0 ||
		    bpf_map_update_elem(eam6_fd, &k6[i], &v6[i], BPF_ANY) != 0) {
			fprintf(stderr, "Error updating EAM entry %zu: %s\n", i, strerror(errno));
			rc = 1;
		}
	}

	close(cfg_fd);
	close(eam4_fd);
	close(eam6_fd);
	free(k4); free(k6); free(v4); free(v6);
	if (rc == 0)
		printf("synced enabled=%u eam_entries=%zu\n", cfg.enabled, eam_count);
	return rc;
}

static int read_pinned_stats(const char *pin_dir, int json_fmt)
{
	int fd = open_pinned_map(pin_dir, "tayga_stats_map");
	if (fd < 0)
		return 1;

	long ncpus = bpf_possible_cpus();
	struct tayga_bpf_stats *vals = calloc((size_t)ncpus, sizeof(*vals));
	if (!vals) {
		close(fd);
		return 1;
	}

	__u32 zero = 0;
	int rc = 0;
	if (bpf_map_lookup_elem(fd, &zero, vals) != 0) {
		fprintf(stderr, "Error reading tayga_stats_map: %s\n", strerror(errno));
		rc = 1;
	} else {
		struct tayga_bpf_stats total = {0};
		for (long i = 0; i < ncpus; i++) {
			total.fast_4to6 += vals[i].fast_4to6;
			total.fast_6to4 += vals[i].fast_6to4;
			total.slow_fallback += vals[i].slow_fallback;
		}
		if (json_fmt)
			format_tc_stats_json(stdout, &total);
		else
			format_tc_stats_prometheus(stdout, &total);
	}

	free(vals);
	close(fd);
	return rc;
}
#else
static int sync_pinned_maps(const char *conf_path, const char *pin_dir)
{
	(void)conf_path;
	(void)pin_dir;
	fprintf(stderr, "--sync-maps is supported on Linux only\n");
	return 1;
}

static int read_pinned_stats(const char *pin_dir, int json_fmt)
{
	(void)pin_dir;
	(void)json_fmt;
	fprintf(stderr, "--read-stats is supported on Linux only\n");
	return 1;
}
#endif

static int run_self_test(void)
{
	char map_tmpl[] = "/tmp/tayga_tc_map_XXXXXX";
	int mfd = mkstemp(map_tmpl);
	assert(mfd >= 0);
	const char *map_sample =
		"# Dynamic map-file entries\n"
		"map 203.0.113.10/32 2001:db8:200::10/128\n";
	size_t mn = strlen(map_sample);
	assert(write(mfd, map_sample, mn) == (ssize_t)mn);
	close(mfd);

	char tmpl[] = "/tmp/tayga_tc_ctl_XXXXXX";
	int fd = mkstemp(tmpl);
	assert(fd >= 0);
	char sample[512];
	int sn = snprintf(sample, sizeof(sample),
			  "# Sample config\n"
			  "tun-device nat64\n"
			  "prefix 64:ff9b::/96\n"
			  "map 192.0.2.1 2001:db8::1\n"
			  "map 198.51.100.0/24 2001:db8:100::/56\n"
			  "map-file %s\n",
			  map_tmpl);
	assert(sn > 0 && (size_t)sn < sizeof(sample));
	assert(write(fd, sample, (size_t)sn) == (ssize_t)sn);
	close(fd);

	struct tayga_bpf_cfg cfg;
	struct tayga_lpm4_key k4[8];
	struct tayga_lpm6_key k6[8];
	struct tayga_eam_val v4[8], v6[8];
	size_t eam_count = 0;

	assert(parse_tayga_conf_for_bpf(tmpl, &cfg, k4, v4, k6, v6, 8, &eam_count) == 0);
	unlink(tmpl);
	unlink(map_tmpl);

	assert(cfg.enabled == 1);
	struct in6_addr exp_pref;
	assert(inet_pton(AF_INET6, "64:ff9b::", &exp_pref) == 1);
	assert(memcmp(cfg.pref64_words, exp_pref.s6_addr, 12) == 0);

	assert(eam_count == 3);
	assert(k4[0].prefixlen == 32 && v4[0].prefix_len == 128);
	assert(k4[1].prefixlen == 24 && v4[1].prefix_len == 56);
	assert(k6[1].prefixlen == 56 && v6[1].prefix_len == 24);
	assert(k4[2].prefixlen == 32 && v4[2].prefix_len == 128);

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

	printf("PASS: tayga-tc-ctl self-test (BPF map config + map-file parsing + stats formatting)\n");
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

	if (argc >= 4 && strcmp(argv[1], "--sync-maps") == 0)
		return sync_pinned_maps(argv[2], argv[3]);

	if (argc >= 3 && strcmp(argv[1], "--read-stats") == 0) {
		int json_fmt = (argc >= 4 && strcmp(argv[3], "--json") == 0);
		return read_pinned_stats(argv[2], json_fmt);
	}

	fprintf(stderr,
		"Usage: %s --self-test | --dump-config <tayga.conf> | "
		"--sync-maps <tayga.conf> <pin_dir> | --read-stats <pin_dir> [--json]\n",
		argv[0]);
	return 1;
}
