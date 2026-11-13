# `tc-bpf` Fast-Path Specification and Prototype (Linux / OpenWrt)

## 1. Motivation

Even with multi-queue TUN, `TUN_VNET_HDR` GSO/USO, and per-worker counters, every packet in userspace TAYGA crosses the kernel/userspace boundary twice (`read()` from TUN + `write()` to TUN). On Linux and OpenWrt routers (kernel >= 5.10), steady-state stateless CLAT / SIIT / NAT64 data packets (unfragmented TCP and UDP with `TTL/HopLimit > 1` and no IP options/extension headers) can be translated in-kernel via `tc-bpf` (`cls_bpf` + `bpf_skb_change_proto`) while falling back (`TC_ACT_OK`) to userspace TAYGA for control-plane and complex packets.

## 2. Why `tc-bpf` (`cls_bpf`) Instead of XDP or Kernel Modules

- **`bpf_skb_change_proto()`**: Resizes `sk_buff` headroom cleanly between 20-byte IPv4 and 40-byte IPv6 headers and updates `skb->protocol` without custom kernel patches.
- **GSO / Checksum Preservation**: Unlike XDP, `tc-bpf` operates on `sk_buff`, preserving kernel GRO/GSO metadata and incremental pseudo-header checksum updates via `bpf_l4_csum_replace(..., BPF_F_PSEUDO_HDR)`.
- **Virtual Interface Compatibility**: Works on TUN, `veth`, bridges, VLANs, and PPPoE interfaces common on OpenWrt, where native XDP driver support is often unavailable.
- **Zero-Risk Fallback**: Any packet that requires dynamic pool allocation, ICMP error translation (RFC 7915 §4.2 / §5.2), PTB generation, IPv4 option stripping, IPv6 extension header walking, or fragmentation simply returns `TC_ACT_OK` and is handled identically by userspace TAYGA.

## 3. Architecture: Fast-Path vs Slow-Path Split

```
Ingress packet on WAN / LAN
  │
  ▼
[tc-bpf cls_bpf hook]
  ├─ Static EAM / RFC 6052 /96 match + TCP/UDP + unfragmented + TTL/HL > 1
  │    └─► bpf_skb_change_proto() + L3/L4 csum update ─► Fast-Path Forward
  └─ Everything else (ICMP errors, fragments, options, dynamic-pool miss, TTL <= 1)
       └─► TC_ACT_OK ─► Kernel routing ─► TAYGA TUN (Userspace Slow-Path)
```

### Control Plane Integration

Userspace TAYGA owns configuration parsing (`conffile.c`), validation, `SIGHUP` hot-reload (`config_reload()`), and dynamic lease management. When `tc-bpf` offload is enabled in a future phase:

1. TAYGA pins BPF maps under `/sys/fs/bpf/tayga/`:
   - `tayga_cfg_map` (`BPF_MAP_TYPE_ARRAY`, 1 entry): `nat64_prefix` (`/96` in network byte order), `wkpf_strict`, `flags`.
   - `tayga_eam4_map` (`BPF_MAP_TYPE_LPM_TRIE`): IPv4 CIDR -> IPv6 prefix + `prefix_len`.
   - `tayga_eam6_map` (`BPF_MAP_TYPE_LPM_TRIE`): IPv6 CIDR -> IPv4 prefix + `prefix_len`.
   - `tayga_stats_map` (`BPF_MAP_TYPE_PERCPU_ARRAY`): `fast_4to6`, `fast_6to4`, `slow_fallback` counters exported alongside userspace metrics in `stats_exporter.c`.
2. On `SIGHUP`, `config_reload()` atomically updates the pinned BPF maps after `config_validate()` succeeds.

## 4. OpenWrt and Platform Notes

- **OpenWrt**: Requires `kmod-sched-bpf` and `tc-tiny` (or `bpftool`) on Linux 5.10+.
- **MikroTik RouterOS**: Standard RouterOS environments do not expose `CAP_BPF` / `tc-bpf` hooks to user containers; MikroTik deployments continue to rely on TAYGA's userspace multi-queue TUN + GSO/USO path.

## 5. Prototype

A minimal, verifier-oriented `tc-bpf` prototype is provided in [tayga_tc_fastpath.c](../../contrib/tc-bpf/tayga_tc_fastpath.c) with a standalone build target in [Makefile](../../contrib/tc-bpf/Makefile):

```sh
make -C contrib/tc-bpf
```
