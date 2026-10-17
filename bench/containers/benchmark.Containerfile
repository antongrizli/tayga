FROM alpine:3.24
RUN apk add --no-cache build-base linux-headers iproute2 iperf3 nftables procps ethtool python3 py3-scapy py3-pyroute2 socat unbound tini
WORKDIR /src
COPY . .
ARG TAYGA_VERSION=local
ARG TAYGA_BRANCH=local
ARG TAYGA_COMMIT=unknown
RUN make all bench-tools benchmark-script VERSION="$TAYGA_VERSION" BRANCH="$TAYGA_BRANCH" COMMIT="$TAYGA_COMMIT" LDFLAGS='' \
 && install -Dm0755 build/tayga /usr/sbin/tayga \
 && install -Dm0755 container/rootfs/usr/local/sbin/clat-start.sh /usr/local/sbin/clat-start.sh \
 && install -Dm0755 build/benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh \
 && install -Dm0755 bench/clat/benchmark-matrix.sh /usr/local/sbin/benchmark-matrix.sh \
 && install -d /usr/local/lib/tayga-perf /usr/local/libexec/tayga-perf \
 && cp build/shims/*.so /usr/local/lib/tayga-perf/ \
 && cp build/shims/*control /usr/local/libexec/tayga-perf/
ENTRYPOINT ["/usr/local/sbin/benchmark-clat.sh"]
