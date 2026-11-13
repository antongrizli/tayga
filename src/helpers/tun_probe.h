/*
 *  tun_probe.h -- Linux TUN echo/client fixtures used by the system tests.
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TUN_PROBE_H
#define TUN_PROBE_H

#ifdef __linux__
int tun_echo6(const char *dev);
int tun_client4(const char *dev, const char *src_str, const char *dst_str);
int tun_client6(const char *dev, const char *src_str, const char *dst_str);
#endif

#endif
