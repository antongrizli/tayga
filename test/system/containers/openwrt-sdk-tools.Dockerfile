FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential gawk rsync unzip zstd file libncurses-dev libssl-dev zlib1g-dev python3 ca-certificates wget git patch time && rm -rf /var/lib/apt/lists/*
RUN useradd -m builder
