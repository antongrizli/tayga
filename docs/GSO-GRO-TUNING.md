# TAYGA CLAT Hardware Offloads: GSO & GRO Tuning Guide

This document describes the high-performance GSO (Generic Segmentation Offload) and GRO (Generic Receive Offload) architecture implemented in TAYGA, configuration options, runtime preflight detection, and tuning guidelines.

---

## 1. Overview and Architecture

Traditional userspace NAT64 translators process network traffic packet-by-packet (MTU 1500 or 1280 bytes). For a 300 Mbps TCP stream, this requires approximately **62,000 system calls per second** (`read` + `write`), consuming significant CPU both in userspace and in kernel softirq processing.

With **GSO/GRO Offload**, TAYGA interacts with the Linux kernel TUN driver using VirtIO network headers (`IFF_VNET_HDR`):
- **GSO (Transmit / Forwarding)**: The kernel delivers aggregated TCP super-packets (up to 64 KB) to TAYGA in a single `read()`. TAYGA translates the headers in-place (updating TCP/IP pseudo-checksum seeds) and forwards them back into the TUN device via a single vectored `writev()` system call with `VIRTIO_NET_HDR_GSO_TCPV4` or `VIRTIO_NET_HDR_GSO_TCPV6`.
- **GRO (Receive-Side)**: When enabled on ingress interfaces (`ethtool -K <iface> gro on`), the kernel coalesces incoming TCP packets of the same flow before delivering them to TUN.
- **RFC 7915 Safety Fallback**: For segments requiring unique IPv4 Identification (e.g. tail fragments ≤ 1260 bytes with DF=0), TAYGA automatically performs software segmentation with unique atomic IDs.

### Measured Performance Gains (Lima VM ARM64, 300 Mbps fixed load)
- **System Calls**: Reduced from 62,000/s to 2,800/s (**−95.5% reduction**).
- **TAYGA CPU**: Reduced from 0.27–0.31 cores to 0.06–0.07 cores (**4.1× reduction**).
- **Kernel Softirq**: Reduced by **67–68%**.
- **TUN Drops**: Completely eliminated (0 drops across all tested workloads).

---

## 2. Configuration Options

### 2.1. `tayga.conf` Directives

```conf
# tun-offload: Controls hardware/kernel offload support
# Options:
#   off  - Standard packet-by-packet operation (safe default, legacy compatible)
#   tcp  - Enforce TCP GSO/CSUM offloads (requires IFF_VNET_HDR support)
#   auto - Probe kernel capabilities at startup; enable if supported, fallback to off
tun-offload auto
```

### 2.2. Command-Line Arguments

```sh
# Start with explicit offload mode
tayga --tun-offload auto -c /etc/tayga.conf

# Check kernel and TUN driver offload capabilities without starting daemon
tayga --check-offload
```

### 2.3. Environment Variables (Container & CLAT startup scripts)

```sh
# Set CLAT_OFFLOAD environment variable before starting clat-start.sh:
export CLAT_OFFLOAD=auto   # Recommended for automatic safe offload
# export CLAT_OFFLOAD=tcp  # Enforce offload
# export CLAT_OFFLOAD=off  # Explicitly disable offload
```

---

## 3. Preflight Self-Test and Runtime Detection

### 3.1. Standalone Preflight Check

You can verify whether the host kernel and `/dev/net/tun` support full offload before deploying TAYGA:

```sh
tayga --check-offload
```

Output on supported systems:
```text
OFFLOAD_CHECK: OK (IFF_VNET_HDR supported, vnet_hdr_sz=10, TSO4|TSO6|CSUM available)
```

Output on unsupported systems:
```text
OFFLOAD_CHECK: FAIL (IFF_VNET_HDR ioctl failed: Invalid argument)
```

### 3.2. Automatic Runtime Fallback (`tun-offload auto`)

When configured with `tun-offload auto`:
1. `tayga` requests `IFF_VNET_HDR` and queries the header size (`TUNGETVNETHDRSZ`).
2. `tayga` attempts to enable `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6` via `TUNSETOFFLOAD`.
3. If any ioctl fails, `tayga` logs a warning and automatically re-opens a clean TUN device in standard `offload=off` mode.
4. Traffic is processed without interruptions or packet corruption regardless of host capabilities.

---

## 4. MikroTik RouterOS / Container Recommendations

When running TAYGA in a Container on MikroTik RouterOS (e.g. CCR2004, CCR2116, RB5009, CHR):

1. **Recommended Setting**: Use `CLAT_OFFLOAD=auto` (or `tun-offload auto` in `tayga.conf`).
2. **Container Privileges**: Ensure the RouterOS container has access to `/dev/net/tun` (`tun` device permitted).
3. **Ingress Interface GRO**: Inside the container environment, ensure GRO is enabled on the virtual ethernet interface:
   ```sh
   ethtool -K eth0 gro on 2>/dev/null || true
   ```
4. **Verification**: Check container logs on startup:
   - `TUN offload active: vnet_hdr_sz=10, TSO4|TSO6|CSUM` indicates offloads are engaged.
   - `Unable to attach tun with IFF_VNET_HDR (...), falling back to offload=off` indicates safe fallback.

---

## 5. Verification Test Suite

The repository provides automated validation scripts in the `test/` directory:

| Test Script | Scope |
|---|---|
| [`test/test_correctness.py`](file:///Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/test_correctness.py) | ICMP ping, 20 MB TCP upload/download SHA-256 integrity, UDP datagrams |
| [`test/test_pmtud.py`](file:///Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/test_pmtud.py) | End-to-end PMTUD & ICMPv6 Packet Too Big (1280 → 1260) translation |
| [`test/test_preflight.py`](file:///Users/antongrizli/Documents/MikroTik/tayga-clat-perf/test/test_preflight.py) | CLI `--check-offload`, mode startups (`auto`, `tcp`, `off`), and data path |

Run the complete test suite:
```sh
sudo python3 test/test_correctness.py
sudo python3 test/test_pmtud.py
sudo python3 test/test_preflight.py
```
