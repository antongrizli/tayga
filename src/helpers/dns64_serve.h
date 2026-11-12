/*
 *  dns64_serve.h -- Embedded DNS64 server and RFC 6052 synthesis used by
 *  pref64-discover.
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef DNS64_SERVE_H
#define DNS64_SERVE_H

#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

/* Optional hosts-file override for --serve-dns64 (set only via --hosts-file). */
extern const char *g_hosts_file;

/* Stop flag shared by every long-running mode (DNS64 server, TUN echo,
 * RA supervisor) and the SIGTERM/SIGINT handler that sets it. */
extern volatile sig_atomic_t dns64_stop;
void handle_dns64_sig(int sig);

int synthesize_pref64(const struct in6_addr *prefix, int prefix_len, const uint8_t ipv4[4], struct in6_addr *out);
size_t lookup_hosts_v4(const char *hosts_path, const char *qname,
                       uint8_t v4_list[][4], size_t max_v4);
int serve_dns64(const char *listen_spec, const char *prefix_spec, const char *upstream_spec);

#endif
