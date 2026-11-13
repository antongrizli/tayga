/*
 *  tun_probe.c -- Linux TUN echo/client fixtures used by the system tests
 *  (--tun-echo6, --tun-client4, --tun-client6).
 *
 *  Copyright (C) 2026 Anton Grizli / TAYGA Contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "dns64_serve.h"
#include "tun_probe.h"
#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifdef __linux__
static uint16_t inet_cksum(const void *buf, size_t len, uint32_t init_sum)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t sum = init_sum;
    while (len > 1) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint32_t)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

static uint16_t icmp6_cksum(const uint8_t src6[16], const uint8_t dst6[16],
                            const uint8_t *icmp, size_t icmp_len)
{
    uint8_t pseudo[40];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, src6, 16);
    memcpy(pseudo + 16, dst6, 16);
    pseudo[34] = (uint8_t)(icmp_len >> 8);
    pseudo[35] = (uint8_t)(icmp_len & 0xff);
    pseudo[39] = 58;
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(pseudo); i += 2)
        sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
    return inet_cksum(icmp, icmp_len, sum);
}

static int open_tun_dev(const char *dev)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
#ifdef IFF_MULTI_QUEUE
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
#else
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#endif
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

int tun_echo6(const char *dev)
{
    for (int cfd = 3; cfd <= 4096; cfd++)
        close(cfd);
    int fd = open_tun_dev(dev);
    if (fd < 0) return 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_dns64_sig;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    while (!dns64_stop) {
        uint8_t pkt[1500];
        ssize_t n = read(fd, pkt, sizeof(pkt));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n >= 48 && (pkt[0] >> 4) == 6 && pkt[6] == 58 && pkt[40] == 128) {
            uint8_t tmp[16];
            memcpy(tmp, pkt + 8, 16);
            memcpy(pkt + 8, pkt + 24, 16);
            memcpy(pkt + 24, tmp, 16);
            pkt[40] = 129;
            pkt[42] = pkt[43] = 0;
            uint16_t ck = icmp6_cksum(pkt + 8, pkt + 24, pkt + 40, (size_t)n - 40);
            pkt[42] = (uint8_t)(ck >> 8);
            pkt[43] = (uint8_t)(ck & 0xff);
            if (write(fd, pkt, (size_t)n) < 0)
                break;
        }
    }
    close(fd);
    return 0;
}

int tun_client4(const char *dev, const char *src_str, const char *dst_str)
{
    struct in_addr src4, dst4;
    if (inet_pton(AF_INET, src_str, &src4) != 1 || inet_pton(AF_INET, dst_str, &dst4) != 1)
        return 1;
    int fd = open_tun_dev(dev);
    if (fd < 0) return 1;
    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[3] = 28;
    pkt[4] = 0x12; pkt[5] = 0x34;
    pkt[8] = 64;
    pkt[9] = 1;
    memcpy(pkt + 12, &src4.s_addr, 4);
    memcpy(pkt + 16, &dst4.s_addr, 4);
    uint16_t ip_ck = inet_cksum(pkt, 20, 0);
    pkt[10] = (uint8_t)(ip_ck >> 8);
    pkt[11] = (uint8_t)(ip_ck & 0xff);
    pkt[20] = 8;
    pkt[24] = 0x54; pkt[25] = 0x47;
    pkt[26] = 0x00; pkt[27] = 0x01;
    uint16_t ic_ck = inet_cksum(pkt + 20, 8, 0);
    pkt[22] = (uint8_t)(ic_ck >> 8);
    pkt[23] = (uint8_t)(ic_ck & 0xff);
    if (write(fd, pkt, sizeof(pkt)) != (ssize_t)sizeof(pkt)) {
        close(fd);
        return 1;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    for (int i = 0; i < 30; i++) {
        if ((i == 10 || i == 20) && write(fd, pkt, sizeof(pkt)) < 0) break;
        if (poll(&pfd, 1, 100) <= 0) continue;
        uint8_t rx[1500];
        ssize_t n = read(fd, rx, sizeof(rx));
        if (n >= 28 && (rx[0] >> 4) == 4 && rx[9] == 1 &&
            memcmp(rx + 12, &dst4.s_addr, 4) == 0 &&
            memcmp(rx + 16, &src4.s_addr, 4) == 0 && rx[20] == 0) {
            close(fd);
            return 0;
        }
    }
    close(fd);
    return 1;
}

int tun_client6(const char *dev, const char *src_str, const char *dst_str)
{
    struct in6_addr src6, dst6;
    if (inet_pton(AF_INET6, src_str, &src6) != 1 || inet_pton(AF_INET6, dst_str, &dst6) != 1)
        return 1;
    int fd = open_tun_dev(dev);
    if (fd < 0) return 1;
    uint8_t pkt[48];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    pkt[5] = 8;
    pkt[6] = 58;
    pkt[7] = 64;
    memcpy(pkt + 8, src6.s6_addr, 16);
    memcpy(pkt + 24, dst6.s6_addr, 16);
    pkt[40] = 128;
    pkt[44] = 0x54; pkt[45] = 0x47;
    pkt[46] = 0x00; pkt[47] = 0x01;
    uint16_t ck = icmp6_cksum(src6.s6_addr, dst6.s6_addr, pkt + 40, 8);
    pkt[42] = (uint8_t)(ck >> 8);
    pkt[43] = (uint8_t)(ck & 0xff);
    if (write(fd, pkt, sizeof(pkt)) != (ssize_t)sizeof(pkt)) {
        close(fd);
        return 1;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    for (int i = 0; i < 30; i++) {
        if ((i == 10 || i == 20) && write(fd, pkt, sizeof(pkt)) < 0) break;
        if (poll(&pfd, 1, 100) <= 0) continue;
        uint8_t rx[1500];
        ssize_t n = read(fd, rx, sizeof(rx));
        if (n >= 48 && (rx[0] >> 4) == 6 && rx[6] == 58 &&
            memcmp(rx + 8, dst6.s6_addr, 16) == 0 &&
            memcmp(rx + 24, src6.s6_addr, 16) == 0 && rx[40] == 129) {
            close(fd);
            return 0;
        }
    }
    close(fd);
    return 1;
}
#endif
