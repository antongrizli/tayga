# TAYGA Unified Container for MikroTik RouterOS (Chateau 5G ax)

High-performance, minimal single-image container deployment of TAYGA with Atomic-1 and GSO/GRO segmentation offload for MikroTik Chateau 5G ax (ARM64) and RouterOS 7.x.

Supports two operational modes in a single container image:
- **`MODE=clat` (Default)**: 464XLAT Customer-Side Translator (RFC 6877) with native RFC 7050 PREF64 discovery. Primary mode for IPv6-only LTE/5G uplinks (e.g., Deutsche Telekom).
- **`MODE=nat64`**: Server-Side NAT64 (RFC 6146) bundled with Unbound DNS64 (RFC 6147) and dynamic mapping pool.

---

## 1. Prerequisites

- **Router**: MikroTik Chateau 5G ax (or any ARM64 / aarch64 RouterOS 7.x device).
- **RouterOS Version**: 7.12+ (tested on 7.24.3).
- **Container Feature**: Installed `container` package and enabled `/system/device-mode container=yes`.
- **External Storage**: USB flash drive / SSD formatted as `ext4`, mounted as `usb1`.
- **WAN Connectivity**: Native IPv6 connectivity on WAN (e.g. `lte1`) with active default route (`::/0`).

---

## 2. Directory Structure on Router USB (`usb1`)

Before importing configuration, create the directory structure on the USB drive:

```routeros
/file/add name="usb1/telekom-xlat" type=directory
/file/add name="usb1/telekom-xlat/images" type=directory
/file/add name="usb1/telekom-xlat/rootfs" type=directory
/file/add name="usb1/telekom-xlat/scripts" type=directory
/file/add name="usb1/telekom-xlat/state" type=directory
```

---

## 3. Build & Upload Container Image

### On your build workstation / laptop:

```bash
# Build ARM64 single-platform image and export archive:
./scripts/build-arm64.sh

# Upload TAR archive and scripts to MikroTik router (replace router IP):
scp dist/tayga-arm64.tar admin@192.168.88.1:usb1/telekom-xlat/images/
scp scripts/mikrotik/*.rsc admin@192.168.88.1:usb1/telekom-xlat/scripts/
```

Alternatively, you can pull the multi-arch image directly from GitHub Container Registry:
```text
ghcr.io/antongrizli/tayga:latest
```

---

## 4. Deployment Lifecycle Scripts

All scripts are idempotent and tag created objects with `comment="[tayga-unified:...]"` for clean tracking and removal. Foreign or unowned objects are never modified or deleted.

### Step 1: Preflight Audit
Run the read-only preflight check to verify CPU architecture (ARM64), free RAM, ext4 USB storage, free disk space (>100MB), `device-mode container=yes`, and active IPv6 upstream:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-preflight.rsc
```

### Step 2: Install CLAT (Primary Profile)
Deploys the container in CLAT mode, configures bridge/VETH, sets up NAT44, IPv6 firewall forward transit, and mandatory LTE WAN IPv6 masquerade, starts the container, validates end-to-end connectivity via probe ping `/32`, and safely enables the default route:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-install-clat.rsc
```

### Step 3: Verify Health & Diagnostics
Inspect container state, link status, probe route latency, active routes, and container logs:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-verify.rsc
```

### Step 4: Dual-Slot (A/B) Upgrade with Auto-Rollback
Safely upgrades the container to a new TAR image version using dual-slot (`rootfs/clat-a` <-> `rootfs/clat-b`) rotation. If the probe test fails on the new version, RouterOS **automatically executes a self-healing rollback** to the preserved previous working slot and restores routing:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-upgrade.rsc
```

### Step 5: Temporarily Disable Service
Withdraws traffic steering routes and stops the container while keeping all configurations intact:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-disable.rsc
```

### Step 6: Emergency Rollback
Actively restores the container from the previous working rootfs slot, verifies connectivity, and re-enables routes:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-rollback.rsc
```

### Step 7: Clean Removal
Completely removes all bridges, VETH interfaces, IP addresses, NAT rules, and containers tagged with `[tayga-unified]`:

```routeros
/import file-name=usb1/telekom-xlat/scripts/routeros-remove.rsc
```

---

## 5. Environment Variable Contract

| Variable | Default | Allowed Values | Description |
|---|---|---|---|
| `MODE` | `clat` | `clat`, `nat64`, `diagnose` | Operational mode dispatcher |
| `TAYGA_WORKERS` | `3` | `0` .. `63` | Worker thread count (alias: `CLAT_WORKERS`) |
| `TAYGA_OFFLOAD` | `off` | `off`, `tcp`, `auto` | TUN segmentation offload (alias: `CLAT_OFFLOAD`) |
| `TAYGA_OFFLINK_MTU` | `1280` | `1280` .. `1500` | Offlink IPv6 MTU (alias: `CLAT_OFFLINK_MTU`) |
| `PREF64` | `auto` | `auto` or `/32,/40,/48,/56,/64,/96` | NAT64 prefix (auto discovers via RFC 7050) |
| `ROUTER4` | `172.31.64.1` | IPv4 address | RouterOS IPv4 gateway on transport bridge |
| `CLAT_V4_CLIENT` | `192.0.0.1` | IPv4 address | Virtual IPv4 mapped client |
| `CLAT_V4_TAYGA` | `192.0.0.2` | IPv4 address | Virtual IPv4 address for TAYGA daemon |
| `CLAT_V4_HOST` | `192.0.0.3` | IPv4 address | Container host IPv4 address |
| `CLAT_V6_CLIENT` | `fd9b:64:1:ff::10` | IPv6 address | Virtual IPv6 mapped client |
| `CLAT_V6_TAYGA` | `fd9b:64:1:ff::11` | IPv6 address | Virtual IPv6 address for TAYGA daemon |
| `CLAT_V6_HOST` | `fd9b:64:1:ff::12` | IPv6 address | Container host IPv6 address |

---

## 6. Troubleshooting & Inspection

### View container status:
```routeros
/container/print detail
```

### View container live logs:
```routeros
/log/print follow where topics~"container"
```

### Run in-container diagnostics:
```routeros
/container/shell [find where comment~"tayga-unified"]
# Inside container shell:
/usr/local/sbin/diagnose.sh
```
