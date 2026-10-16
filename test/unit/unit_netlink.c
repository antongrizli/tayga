#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#ifdef __linux__
#include "netlink_io.h"
int main(void)
{
    struct { struct nlmsghdr n; struct nlmsgerr e; } ack = {
        .n = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr)), .nlmsg_type = NLMSG_ERROR, .nlmsg_seq = 7}
    };
    assert(rtnl_ack(&ack, sizeof(ack), 7) == 0);
    assert(rtnl_ack(&ack, sizeof(ack)+4, 7) < 0 && errno == EPROTO);
    ack.e.error = -EPERM; assert(rtnl_ack(&ack, sizeof(ack), 7) < 0 && errno == EPERM);
    ack.e.error = INT_MIN; assert(rtnl_ack(&ack, sizeof(ack), 7) < 0 && errno == EPROTO);
    ack.e.error = 0; assert(rtnl_ack(&ack, sizeof(ack), 8) < 0 && errno == EPROTO);
    for (size_t len = 0; len < sizeof(ack); len++) assert(rtnl_ack(&ack, len, 7) < 0);
    ack.n.nlmsg_len = NLMSG_LENGTH(0); assert(rtnl_ack(&ack, sizeof(ack), 7) < 0);
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); assert(fd >= 0);
    _Alignas(struct nlmsghdr) char buf[128];
    int64_t start = rtnl_milliseconds();
    assert(rtnl_receive(fd, buf, sizeof(buf), 7, start+30) < 0 && errno == ETIMEDOUT);
    assert(rtnl_milliseconds()-start < 500); assert(fcntl(fd, F_GETFD) >= 0); close(fd);
    puts("PASS: truncated/wrong-sequence/invalid ACK, bounded timeout, descriptor ownership");
    return 0;
}
#else
int main(void) { puts("SKIP: rtnetlink requires Linux"); return 0; }
#endif
