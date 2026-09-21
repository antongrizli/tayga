FROM alpine:3.20

RUN apk add --no-cache \
    build-base \
    linux-headers \
    iproute2 \
    iperf3 \
    nftables \
    procps \
    python3 \
    py3-pip \
    socat \
    ethtool \
    tini

WORKDIR /src
COPY . /src/

RUN make clean \
 && make CC=gcc CFLAGS='-O2 -flto' LDFLAGS='-flto' \
 && install -Dm0755 tayga /usr/local/sbin/tayga \
 && ln -sf /usr/local/sbin/tayga /usr/sbin/tayga \
 && install -Dm0755 scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh \
 && install -Dm0755 benchmark-clat.sh /usr/local/sbin/benchmark-clat.sh \
 && install -Dm0755 benchmark-matrix.sh /usr/local/sbin/benchmark-matrix.sh \
 && chmod 0755 /usr/local/sbin/*.sh

ENTRYPOINT ["/bin/sh"]
