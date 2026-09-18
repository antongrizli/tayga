# Stage 1: Build environment
FROM alpine:3.20 AS build-env

# Install build tools
RUN apk add --no-cache gcc make musl-dev linux-headers git binutils

# Set working directory
WORKDIR /app

# Copy source code into the container
COPY ./ ./

# Build the code statically and strip
RUN make clean && make static && strip tayga

# Stage 2a: Final image (nat64)
FROM alpine:3.20 AS final-nat64

WORKDIR /app
COPY --from=build-env /app/tayga /app/tayga
COPY scripts/launch-nat64.sh /app/launch-nat64.sh
RUN chmod +x /app/launch-nat64.sh

ENTRYPOINT ["/bin/sh","/app/launch-nat64.sh"]

# Stage 2b: Final Image (clat)
FROM alpine:3.20 AS final-clat
RUN apk add --no-cache iproute2
WORKDIR /app
COPY --from=build-env /app/tayga /app/tayga
COPY scripts/launch-clat.sh /app/launch-clat.sh
COPY scripts/clat-start.sh /app/clat-start.sh
RUN chmod +x /app/launch-clat.sh /app/clat-start.sh

ENTRYPOINT ["/bin/sh","/app/launch-clat.sh"]

# Stage 2c: Final Image (No Config / Bring Your Own)
FROM alpine:3.20 AS final
RUN apk add --no-cache iproute2
WORKDIR /app
COPY --from=build-env /app/tayga /app/tayga
COPY scripts/launch.sh /app/launch.sh
RUN chmod +x /app/launch.sh

ENTRYPOINT ["/bin/sh","/app/launch.sh"]