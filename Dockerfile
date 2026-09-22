# Stage 1: Build environment
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS build-env

ARG TAYGA_VERSION=""
ARG TAYGA_COMMIT=""
ARG TAYGA_BRANCH=""

# Install build tools
RUN apk add --no-cache gcc make musl-dev linux-headers git binutils

# Set working directory
WORKDIR /app

# Copy source code into the container
COPY ./ ./

# Build tayga and helper statically and strip
RUN make clean && make static pref64-discover VERSION="${TAYGA_VERSION}" COMMIT="${TAYGA_COMMIT}" BRANCH="${TAYGA_BRANCH}" && strip tayga pref64-discover

# Stage 2: Unified Minimal Production Base Image
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS production

ARG TAYGA_VERSION="unknown"
ARG TAYGA_COMMIT="unknown"

LABEL org.opencontainers.image.title="TAYGA Unified 464XLAT & NAT64" \
      org.opencontainers.image.description="High-performance stateless NAT64 / CLAT (RFC 6877 / RFC 6146) for MikroTik RouterOS 7 and Linux" \
      org.opencontainers.image.version="${TAYGA_VERSION}" \
      org.opencontainers.image.revision="${TAYGA_COMMIT}" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

# Install minimal runtime dependencies and record manifest
RUN apk add --no-cache \
    iproute2 \
    ethtool \
    tini \
    unbound \
    ca-certificates \
    && apk list -I > /etc/tayga-build-manifest.txt \
    && rm -rf /var/cache/apk/*

# Install binaries
COPY --from=build-env /app/tayga /usr/sbin/tayga
COPY --from=build-env /app/pref64-discover /usr/local/sbin/pref64-discover

# Install container scripts and templates
COPY scripts/container/entrypoint.sh /usr/local/sbin/entrypoint.sh
COPY scripts/container/clat-start.sh /usr/local/sbin/clat-start.sh
COPY scripts/container/nat64-start.sh /usr/local/sbin/nat64-start.sh
COPY scripts/container/diagnose.sh /usr/local/sbin/diagnose.sh
COPY scripts/container/tayga-status.sh /usr/local/sbin/tayga-status
COPY scripts/container/config/unbound.conf.template /etc/unbound/unbound.conf.template

# Ensure executable permissions and create backward-compatibility links
RUN chmod +x /usr/sbin/tayga /usr/local/sbin/pref64-discover /usr/local/sbin/*.sh /usr/local/sbin/tayga-status \
    && mkdir -p /app /run /var/lib/tayga \
    && ln -s /usr/sbin/tayga /app/tayga \
    && ln -s /usr/local/sbin/entrypoint.sh /app/launch.sh \
    && ln -s /usr/local/sbin/clat-start.sh /app/launch-clat.sh \
    && ln -s /usr/local/sbin/nat64-start.sh /app/launch-nat64.sh \
    && ln -s /usr/local/sbin/tayga-status /app/status.sh \
    && ln -s /usr/local/sbin/tayga-status /usr/local/sbin/tayga-status.sh

ENV MODE=clat

WORKDIR /

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/sbin/entrypoint.sh"]

# Target clat: Explicit CLAT profile
FROM production AS clat
ENV MODE=clat

# Target nat64: Explicit NAT64 profile with Unbound DNS64
FROM production AS nat64
ENV MODE=nat64