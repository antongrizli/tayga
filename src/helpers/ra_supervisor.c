/*
 *  ra_supervisor.c -- RFC 8781 Router Advertisement socket, one-shot RA
 *  discovery and the --supervise-ra translator supervisor.
 *
 *  Copyright (C) 2026 Anton Grizli / TAYGA Contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <net/if.h>
#include "pref64_ra.h"
#include "pref64_util.h"
#include "dns64_serve.h"
#include "ra_supervisor.h"

#ifdef PREF64_NO_MAIN
#define RA_TESTABLE
#else
#define RA_TESTABLE __attribute__((unused)) static
#endif

#if defined(__linux__) || defined(__FreeBSD__)
/*
 * Solicit a Router Advertisement on ifname and read PREF64 from it.
 * Needs CAP_NET_RAW; returns -2 when the socket cannot be opened so the
 * caller can fall back to RFC 7050 silently.  RAs are only accepted from
 * link-local sources with Hop Limit 255 (RFC 4861 6.1.2) on that interface.
 */
static int send_rs(int fd, unsigned ifindex);
static int open_ra_socket(const char *ifname)
{
    unsigned ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -1;
    int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
    if (fd < 0)
        return -2;

    struct icmp6_filter filt;
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
    int on = 1, hops = 255;
    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0) {
        close(fd);
        return -1;
    }

    struct ipv6_mreq mr;
    memset(&mr, 0, sizeof(mr));
    inet_pton(AF_INET6, "ff02::1", &mr.ipv6mr_multiaddr);
    mr.ipv6mr_interface = ifindex;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr, sizeof(mr));
    if (send_rs(fd, ifindex) < 0)
        { close(fd); return -1; }

    return fd;
}

/* Router Solicitation to ff02::2 (RFC 4861 6.3.7). */
static int send_rs(int fd, unsigned ifindex)
{
    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "ff02::2", &dst.sin6_addr);
    dst.sin6_scope_id = ifindex;
    struct nd_router_solicit rs;
    memset(&rs, 0, sizeof(rs));
    rs.nd_rs_type = ND_ROUTER_SOLICIT;
    return sendto(fd, &rs, sizeof(rs), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0 ? -1 : 0;
}

static long mono_ms_since(const struct timespec *t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)((now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000);
}

/*
 * Receive one acceptable RA: link-local source, Hop Limit 255, expected
 * interface (RFC 4861 6.1.2).  Returns its length (the source router in
 * *router), or -1 when the timeout elapses first.
 */
static ssize_t receive_ra(int fd, unsigned ifindex, long timeout_ms,
                          uint8_t *buf, size_t bufsz, struct in6_addr *router)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        long left = timeout_ms - mono_ms_since(&t0);
        if (left <= 0)
            return -1;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, (int)left) <= 0)
            return -1;
        uint8_t cbuf[256];
        struct sockaddr_in6 from;
        struct iovec iov = { buf, bufsz };
        struct msghdr mh = { .msg_name = &from, .msg_namelen = sizeof(from),
                             .msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
        ssize_t n = recvmsg(fd, &mh, 0);
        if (n < 16 || (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            !IN6_IS_ADDR_LINKLOCAL(&from.sin6_addr))
            continue;
        int hl = -1;
        unsigned idx = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level != IPPROTO_IPV6)
                continue;
            if (c->cmsg_type == IPV6_HOPLIMIT && c->cmsg_len >= CMSG_LEN(sizeof(int)))
                memcpy(&hl, CMSG_DATA(c), sizeof(int));
            else if (c->cmsg_type == IPV6_PKTINFO && c->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
                struct in6_pktinfo pi;
                memcpy(&pi, CMSG_DATA(c), sizeof(pi));
                idx = pi.ipi6_ifindex;
            }
        }
        if (hl != 255 || idx != ifindex)
            continue;
        *router = from.sin6_addr;
        return n;
    }
}

static int receive_ra_pref64(int fd, unsigned ifindex, int timeout_sec,
                              struct in6_addr *out, int *plen, uint32_t *lifetime,
                              const struct in6_addr *active, int active_len)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        long left = (long)timeout_sec * 1000 - mono_ms_since(&t0);
        if (left <= 0)
            break;
        uint8_t buf[1500];
        struct in6_addr router;
        ssize_t n = receive_ra(fd, ifindex, left, buf, sizeof(buf), &router);
        if (n < 0)
            break;
        if (parse_ra_pref64_update(buf, (size_t)n, out, plen, lifetime, active, active_len) == 0)
            return 0;
    }
    return -1;
}
int discover_ra_pref64(const char *ifname, int timeout_sec, struct in6_addr *out,
                       int *plen, uint32_t *lifetime)
{
    int fd = open_ra_socket(ifname);
    if (fd < 0) return fd;
    int result = receive_ra_pref64(fd, if_nametoindex(ifname), timeout_sec, out, plen, lifetime, NULL, 0);
    close(fd);
    return result;
}

#endif

static volatile sig_atomic_t supervisor_hup, supervisor_usr1, supervisor_usr2;
static void supervisor_signal(int sig)
{
    if (sig == SIGHUP) supervisor_hup = 1;
    else if (sig == SIGUSR1) supervisor_usr1 = 1;
    else if (sig == SIGUSR2) supervisor_usr2 = 1;
    else dns64_stop = 1;
}

#if defined(__linux__) || defined(__FreeBSD__)
/* The controller owns journalled network mutations. Run it only while the
 * translator is stopped, in its own process group, with a bounded lifetime. */
static int ra_network_action(const char *controller, const char *action, const char *config)
{
    if (dns64_stop) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) {
        if (setpgid(0, 0) < 0) _exit(126);
        unsetenv("NOTIFY_SOCKET");
        execl(controller, controller, action, config, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    struct timespec started, current;
    clock_gettime(CLOCK_MONOTONIC, &started);
    int stopping = 0, status;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0 && !stopping ? 0 : -1;
        if (done < 0 && errno != EINTR) return -1;
        clock_gettime(CLOCK_MONOTONIC, &current);
        if (!stopping && (dns64_stop || current.tv_sec - started.tv_sec >= 30)) {
            kill(-pid, SIGTERM);
            started = current;
            stopping = 1;
        }
        if (stopping && current.tv_sec - started.tv_sec >= 5) {
            kill(-pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return -1;
        }
        (void)poll(NULL, 0, 50);
    }
}

static void stop_ra_child(pid_t child)
{
    /* Keep the PID reserved until the child is reaped. ECHILD means there
     * is no owned process left to signal, including after an earlier reap. */
    int status;
    pid_t done = waitpid(child, &status, WNOHANG);
    if (done == child || (done < 0 && errno == ECHILD)) return;
    kill(child, SIGTERM);
    for (int i = 0; i < 50; i++) {
        done = waitpid(child, &status, WNOHANG);
        if (done == child || (done < 0 && errno == ECHILD)) return;
        usleep(100000);
    }
    kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
}
#endif

RA_TESTABLE void active_prefix_path(const char *dir, char *out, size_t size)
{
    snprintf(out, size, "%s/active-prefix", dir);
}

/* Publish the prefix the translator really runs, so status and verification
 * scripts do not read the (unchanged) installed profile. */
RA_TESTABLE void publish_active_prefix(const char *dir, const struct in6_addr *prefix, int plen)
{
    if (!dir)
        return;
    char path[1024], tmp[1040], text[INET6_ADDRSTRLEN];
    active_prefix_path(dir, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (!inet_ntop(AF_INET6, prefix, text, sizeof(text)))
        return;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    int failed = dprintf(fd, "%s/%d rfc8781\n", text, plen) < 0;
    if (close(fd))
        failed = 1;
    if (failed || rename(tmp, path))
        unlink(tmp);
}

RA_TESTABLE void retract_active_prefix(const char *dir)
{
    if (!dir)
        return;
    char path[1024];
    active_prefix_path(dir, path, sizeof(path));
    unlink(path);
}

__attribute__((unused)) static time_t mono_seconds_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

/* Snapshots "<config>.ra.XXXXXX" survive a SIGKILL or power cut of an earlier
 * supervisor; one supervisor runs per profile, so every match is stale. */
RA_TESTABLE void remove_stale_snapshots(const char *config)
{
    char dir[1024], prefix[300];
    const char *slash = strrchr(config, '/');
    size_t dl = slash == config ? 1 : (size_t)(slash - config);
    if (dl >= sizeof(dir) || snprintf(prefix, sizeof(prefix), "%s.ra.", slash + 1) >= (int)sizeof(prefix))
        return;
    memcpy(dir, config, dl);
    dir[dl] = '\0';
    DIR *d = opendir(dir);
    if (!d)
        return;
    int dfd = dirfd(d);
    if (dfd < 0) {
        closedir(d);
        return;
    }
    struct dirent *e;
    size_t plen = strlen(prefix);
    while ((e = readdir(d)))
        if (!strncmp(e->d_name, prefix, plen) && strlen(e->d_name) == plen + 6)
            (void)unlinkat(dfd, e->d_name, 0);
    closedir(d);
}

/* RFC 4861 6.3.7: three solicitations, four seconds apart, before giving up
 * on the first start.  After that the supervisor stays resident and asks
 * again with exponential back-off (RFC 7559), capped at one hour. */
#define RA_INITIAL_ATTEMPTS 3
#define RA_SOLICIT_INTERVAL 4
#define RA_SOLICIT_CAP 3600

/* Control-plane supervisor. The configured file stays unchanged; each child
 * reads a private snapshot with the currently advertised translation prefix.
 *   --supervise-ra CONFIG [--network-controller PATH] [--runtime-dir DIR]
 *                  [--initial-prefix PFX/LEN --initial-lifetime SEC] -- COMMAND... */
int supervise_ra(int argc, char **argv)
{
    const char *controller = NULL, *runtime_dir = NULL, *initial_prefix = NULL;
    long initial_lifetime = 0;
    int command = 0;
    if (argc < 5)
        return 2;
    const char *config = argv[2];
    if (config[0] != '/')
        return 2;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--")) {
            command = i + 1;
            break;
        }
        if (i + 1 >= argc)
            return 2;
        if (!strcmp(argv[i], "--network-controller")) controller = argv[++i];
        else if (!strcmp(argv[i], "--runtime-dir")) runtime_dir = argv[++i];
        else if (!strcmp(argv[i], "--initial-prefix")) initial_prefix = argv[++i];
        else if (!strcmp(argv[i], "--initial-lifetime")) initial_lifetime = atol(argv[++i]);
        else return 2;
    }
    if (!command || command >= argc)
        return 2;
    if ((controller && controller[0] != '/') || (runtime_dir && runtime_dir[0] != '/'))
        return 2;
    FILE *in = fopen(config, "r");
    if (!in) return 1;
    char line[1024], iface[IF_NAMESIZE] = "", configured[INET6_ADDRSTRLEN + 8] = "";
    int nat66 = 0;
    while (fgets(line, sizeof(line), in)) {
        char value[IF_NAMESIZE];
        if (sscanf(line, "# installer-pref64-interface %15s", value) == 1)
            snprintf(iface, sizeof(iface), "%s", value);
        if (sscanf(line, "# installer-clat-address-mode %15s", value) == 1 && !strcmp(value, "nat66")) nat66 = 1;
        (void)sscanf(line, "prefix %53s", configured);
    }
    int read_failed = ferror(in);
    fclose(in);
    if (read_failed) return 1;
    if (!iface[0]) { execvp(argv[command], argv + command); return 1; }
#if defined(__linux__) || defined(__FreeBSD__)
    int ra_fd = open_ra_socket(iface);
    if (ra_fd < 0) {
        fprintf(stderr, "Cannot use %s for Router Advertisements%s\n", iface,
                ra_fd == -2 ? " (raw ICMPv6 socket: CAP_NET_RAW required)"
                            : " (unknown interface, or no usable link-local address)");
        return 1;
    }
    unsigned ifindex = if_nametoindex(iface);
    char snapshot[1024];
    if (snprintf(snapshot, sizeof(snapshot), "%s.ra.XXXXXX", config) >= (int)sizeof(snapshot)) { close(ra_fd); return 1; }
    remove_stale_snapshots(config);
    int fd = mkstemp(snapshot);
    if (fd < 0) { close(ra_fd); return 1; }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) { close(fd); close(ra_fd); unlink(snapshot); return 1; }
    int config_arg = 0;
    for (int i = command; i < argc; i++) if (!strcmp(argv[i], config)) config_arg = 1;
    if (!config_arg) { close(fd); close(ra_fd); unlink(snapshot); return 2; }
    for (int i = command; i < argc; i++) if (!strcmp(argv[i], config)) argv[i] = snapshot;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL); sigaction(SIGUSR1, &sa, NULL); sigaction(SIGUSR2, &sa, NULL);

    struct ra_table table;
    ra_table_init(&table);
    time_t started = mono_seconds_now();
    if (initial_prefix && initial_lifetime > 0) {
        struct in6_addr p;
        int pl;
        if (parse_prefix_spec(initial_prefix, &p, &pl) == 0 && is_valid_pref64_prefix(&p, pl))
            ra_table_add_provisional(&table, &p, pl, (uint32_t)initial_lifetime, started);
    }
    /* The prefix the host network (NAT66 firewall) was built for. */
    struct in6_addr net_prefix;
    int net_len = 0;
    memset(&net_prefix, 0, sizeof(net_prefix));
    if (parse_prefix_spec(configured, &net_prefix, &net_len))
        net_len = 0;

    pid_t child = -1;
    struct in6_addr active;
    memset(&active, 0, sizeof(active));
    int active_len = 0, result = 1, ever_started = 0, rs_sent = 1;
    time_t next_rs = started + RA_SOLICIT_INTERVAL;
    long rs_interval = RA_SOLICIT_INTERVAL;
    while (!dns64_stop) {
        if (child > 0) {
            int status;
            pid_t done = waitpid(child, &status, WNOHANG);
            /* The translator died on its own: let the service manager apply
             * its restart policy. */
            if (done == child || (done < 0 && errno == ECHILD)) {
                if (done == child && WIFEXITED(status))
                    fprintf(stderr, "Translator exited with status %d\n", WEXITSTATUS(status));
                else if (done == child && WIFSIGNALED(status))
                    fprintf(stderr, "Translator killed by signal %d\n", WTERMSIG(status));
                child = -1;
                break;
            }
            if (supervisor_hup) { supervisor_hup = 0; kill(child, SIGHUP); }
            if (supervisor_usr1) { supervisor_usr1 = 0; kill(child, SIGUSR1); }
            if (supervisor_usr2) { supervisor_usr2 = 0; kill(child, SIGUSR2); }
        }

        uint8_t ra[1500];
        struct in6_addr router;
        ssize_t ra_len = receive_ra(ra_fd, ifindex, 500, ra, sizeof(ra), &router);
        time_t now = mono_seconds_now();
        if (ra_len > 0) {
            struct ra_option opts[RA_MAX_OPTIONS];
            int count = parse_ra_pref64_all(ra, (size_t)ra_len, opts, RA_MAX_OPTIONS);
            if (count > 0) {
                ra_table_apply(&table, &router, opts, count, now);
                rs_interval = RA_SOLICIT_INTERVAL;
                next_rs = now + (long)RA_SOLICIT_INTERVAL;
            }
        }
        ra_table_expire(&table, now);

        struct in6_addr pick;
        int pick_len = 0;
        time_t pick_deadline = 0;
        uint32_t pick_life = 0;
        int have = ra_table_pick(&table, child > 0 ? &active : NULL, active_len, now,
                                 &pick, &pick_len, &pick_deadline, &pick_life) == 0;

        if (child > 0 && (!have || pick_len != active_len || memcmp(&pick, &active, sizeof(pick)))) {
            /* Active prefix withdrawn or expired everywhere. */
            stop_ra_child(child);
            child = -1;
            active_len = 0;
            retract_active_prefix(runtime_dir);
            if (!have) {
                fprintf(stderr, "PREF64 withdrawn or expired; translator stopped, soliciting a new RA\n");
                rs_interval = RA_SOLICIT_INTERVAL;
                next_rs = now;
            }
        }
        if (dns64_stop) break;

        if (child < 0 && have) {
            /* A prefix-dependent firewall must change while no translator runs. */
            int change_network = 0;
            if (nat66) {
                change_network = net_len != pick_len || memcmp(&net_prefix, &pick, sizeof(pick));
                if (change_network && !controller) {
                    fprintf(stderr, "RA prefix changed: a network controller is required for NAT66\n");
                    break;
                }
            }
            in = fopen(config, "r");
            if (ftruncate(fd, 0) || lseek(fd, 0, SEEK_SET) < 0) { if (in) fclose(in); break; }
            int copy_fd = dup(fd);
            FILE *out = copy_fd >= 0 ? fdopen(copy_fd, "w") : NULL;
            if (!out && copy_fd >= 0) close(copy_fd);
            if (!in || !out) { if (in) fclose(in); if (out) fclose(out); break; }
            char text[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &pick, text, sizeof(text));
            int replaced = 0;
            while (fgets(line, sizeof(line), in)) {
                char key[64];
                if (sscanf(line, "%63s", key) == 1 && !strcmp(key, "prefix")) {
                    fprintf(out, "prefix %s/%d\n", text, pick_len); replaced++;
                } else fputs(line, out);
            }
            int failed = ferror(in) || ferror(out);
            if (fclose(in)) failed = 1;
            if (fclose(out)) failed = 1;
            if (failed || replaced != 1) break;
            if (change_network) {
                /* down uses the existing undo journal, including the actual live
                 * prefix. up validates the snapshot and rolls back partial setup.
                 * If replacement fails, restore the saved profile without starting
                 * a translator on an unconfirmed/expired old prefix. */
                if (ra_network_action(controller, "down", config)) {
                    fprintf(stderr, "RA network teardown failed; retaining controller journal for recovery\n");
                    break;
                }
                if (ra_network_action(controller, "up", snapshot)) {
                    fprintf(stderr, "RA network replacement failed; restoring saved profile\n");
                    if (!dns64_stop && ra_network_action(controller, "up", config))
                        fprintf(stderr, "RA network restore failed; service cleanup/recovery is required\n");
                    break;
                }
                net_prefix = pick;
                net_len = pick_len;
            }
            if (dns64_stop || mono_seconds_now() >= pick_deadline) continue;
            child = fork();
            if (child < 0) break;
            if (!child) {
                execvp(argv[command], argv + command);
                fprintf(stderr, "Cannot execute %s: %s\n", argv[command], strerror(errno));
                _exit(127);
            }
            active = pick; active_len = pick_len;
            ever_started = 1;
            publish_active_prefix(runtime_dir, &active, active_len);
            rs_interval = RA_SOLICIT_INTERVAL;
            next_rs = now + (long)RA_SOLICIT_INTERVAL;
            continue;
        }

        /* Solicitations: start-up retries, last-quarter refresh and outage back-off. */
        int need_rs = 0;
        if (child < 0 && !have) {
            if (!ever_started) {
                if (rs_sent >= RA_INITIAL_ATTEMPTS && now >= next_rs) {
                    fprintf(stderr, "No PREF64 router advertisement received on %s\n", iface);
                    break;
                }
                need_rs = now >= next_rs && rs_sent < RA_INITIAL_ATTEMPTS;
            } else {
                need_rs = now >= next_rs;
            }
        } else if (child > 0 && pick_deadline - now < (time_t)(pick_life / 4)) {
            need_rs = now >= next_rs;
        }
        if (need_rs) {
            (void)send_rs(ra_fd, ifindex);
            rs_sent++;
            next_rs = now + rs_interval;
            if (ever_started)
                rs_interval = rs_interval < RA_SOLICIT_CAP / 2 ? rs_interval * 2 : RA_SOLICIT_CAP;
        }
    }
    if (child > 0) stop_ra_child(child);
    if (dns64_stop) result = 0;
    retract_active_prefix(runtime_dir);
    close(fd);
    close(ra_fd);
    unlink(snapshot);
    return result;
#else
    (void)configured; (void)nat66; (void)supervisor_signal; (void)controller;
    (void)runtime_dir; (void)initial_prefix; (void)initial_lifetime;
    return 1;
#endif
}
