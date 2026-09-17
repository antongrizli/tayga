# TAYGA on MikroTik RouterOS 7

This guide describes how to run **TAYGA** (Stateless NAT64 and CLAT) in a container on **MikroTik RouterOS 7**.

TAYGA is executed as a lightweight container using RouterOS's native `/container` feature, using virtual ethernet (`veth`) interfaces connected to a bridge on the router.

---

## Hardware & Architecture Compatibility

- **Supported RouterOS Version**: RouterOS **v7.4** or newer (RouterOS v7 is required for container support).
- **Supported CPU Architectures**:
  - `arm64` (e.g., CCR2004, CCR2116, RB5009, hAP ax series, Chateau series)
  - `arm` (armhf / armv7, e.g., hAP ac², RB3011, RB4011)
  - `x86_64` / `x86` (CHR - Cloud Hosted Router, x86 PC hardware)
- **Unsupported Hardware**: `arm32v5` (older ARM hardware without v7 instruction set support) and `mipsbe`/`tile` platforms.

---

## Prerequisites & RouterOS Container Setup

### 1. Install the Container Package
Ensure the `container` package (`container.npk`) is installed on your RouterOS device. You can verify installed packages by running:

```routeros
/system/package/print
```

If it is not present, download the Extra Packages bundle matching your RouterOS version and architecture from the [MikroTik Download Page](https://mikrotik.com/download), upload `container.npk` to the router's disk, and reboot.

### 2. Enable Container Mode on Hardware Devices
For security reasons, RouterOS requires explicit permission to enable container execution mode:

```routeros
/system/device-mode/update container=yes
```

> [!IMPORTANT]
> Executing this command requires **physical authorization**:
> - **Ethernet/Serial**: Power cycle (cold reboot) the router or press the physical Reset button when prompted on the console within 5 minutes.
> - **Virtual Machines (CHR)**: Container mode is enabled immediately without requiring a physical reboot prompt.

---

## Storage & Registry Configuration

Before pulling container images, configure registry settings and ensure adequate storage (USB drive, NVMe, or external disk recommended for physical routers to preserve internal flash memory):

```routeros
# Configure container RAM and registry options
/container/config/set tmpdir=disk1/tmp registry-url=https://ghcr.io
```

*(Replace `disk1` with your target storage location if using external media).*

---

## Automated Deployment Scripts

Two RouterOS configuration scripts are provided in this directory:

- [`nat64-setup.rsc`](nat64-setup.rsc) — Quick setup script for TAYGA NAT64.
- [`clat-setup.rsc`](clat-setup.rsc) — Quick setup script for TAYGA CLAT.

You can upload these scripts to your router and import them:

```routeros
/import file-name=nat64-setup.rsc
```

---

## Detailed Installation Steps

### Option A: TAYGA NAT64 Setup

NAT64 translates IPv6-only client requests to IPv4 destinations.

#### Network Addressing Scheme (Defaults):
- **VETH Router OS Gateway (IPv4)**: `192.168.239.1/30`
- **VETH Container (IPv4)**: `192.168.239.2/30`
- **VETH Router OS Gateway (IPv6)**: `fc64::1/126`
- **VETH Container (IPv6)**: `fc64::2/126`
- **NAT64 Well-Known Prefix (WKP)**: `64:ff9b::/96`
- **Dynamic IPv4 Pool**: `192.168.240.0/20`

#### Step-by-Step Commands:

```routeros
# 1. Create a dedicated bridge for the NAT64 container
/interface/bridge add name=nat64 comment="TAYGA NAT64 Bridge"

# 2. Assign IP addresses to the bridge for RouterOS gateway side
/ip/address add address=192.168.239.1/30 interface=nat64 comment="NAT64 container IPv4 gateway"
/ipv6/address add address=fc64::1/126 interface=nat64 advertise=no comment="NAT64 container IPv6 gateway"

# 3. Create virtual ethernet (VETH) setup for the container
/interface/veth add name=veth-nat64 address=192.168.239.2/30,fc64::2/126 gateway=192.168.239.1 gateway6=fc64::1 dhcp=no comment="NAT64 container VETH"
/interface/bridge/port add bridge=nat64 interface=veth-nat64

# 4. Add routes to direct traffic through TAYGA VETH
/ip/route add dst-address=192.168.240.0/20 gateway=192.168.239.2 comment="NAT64 dynamic IPv4 pool route"
/ipv6/route add dst-address=64:ff9b::/96 gateway=fc64::2%nat64 comment="NAT64 translation prefix route"

# 5. Add bridge to LAN interface list
/interface/list/member add interface=nat64 list=LAN

# 6. Configure IPv4 Masquerade (NAT44) for outbound IPv4 traffic from the TAYGA dynamic pool
/ip/firewall/nat add chain=srcnat action=masquerade src-address=192.168.240.0/20 comment="NAT64 dynamic pool masquerade"

# 7. Add TAYGA NAT64 container
/container/add remote-image="ghcr.io/apalrd/tayga-nat64:latest" interface=veth-nat64 name=tayga-nat64 workdir=/app logging=yes
```

---

### Option B: TAYGA CLAT Setup (464XLAT Customer-Side)

CLAT translates local IPv4-only application traffic into IPv6 packets destined for a provider PLAT / NAT64 gateway.

#### Network Addressing Scheme (Defaults):
- **VETH Subnet (IPv4)**: `192.168.238.0/30` (`192.168.238.1` on RouterOS, `192.168.238.2` on container)
- **VETH Subnet (IPv6)**: `fc68::/126` (`fc68::1` on RouterOS, `fc68::2` on container)
- **PLAT / NAT64 Prefix**: `64:ff9b::/96`

#### Step-by-Step Commands:

```routeros
# 1. Create bridge interface for CLAT container
/interface/bridge add name=clat comment="TAYGA CLAT Bridge"

# 2. Configure gateway IP addresses on the bridge
/ip/address add address=192.168.238.1/30 interface=clat comment="CLAT IPv4 gateway"
/ipv6/address add address=fc68::1/126 interface=clat advertise=no comment="CLAT IPv6 gateway"

# 3. Create virtual ethernet (VETH) setup
/interface/veth add name=veth-clat address=192.168.238.2/30,fc68::2/126 gateway=192.168.238.1 gateway6=fc68::1 dhcp=no comment="CLAT VETH"
/interface/bridge/port add bridge=clat interface=veth-clat

# 4. Route default IPv4 traffic via CLAT container
/ip/route add dst-address=0.0.0.0/0 gateway=192.168.238.2 distance=10 comment="IPv4 default route via CLAT"

# 5. Add TAYGA CLAT container
/container/add remote-image="ghcr.io/apalrd/tayga-clat:latest" interface=veth-clat name=tayga-clat workdir=/app logging=yes
```

---

## Container Environment Variables

TAYGA container images support customization using RouterOS container environment variables (`/container/envs`).

To define custom environment variables:

```routeros
/container/envs add key=TAYGA_POOL4 name=tayga-env value="192.168.240.0/20"
/container/envs add key=TAYGA_PREF64 name=tayga-env value="64:ff9b::/96"
/container/envs add key=TAYGA_ADDR4 name=tayga-env value="192.168.240.1"
/container/envs add key=TAYGA_LOG name=tayga-env value="drop reject icmp self dyn"
```

Then attach the env list when adding the container:

```routeros
/container/add remote-image="ghcr.io/apalrd/tayga-nat64:latest" interface=veth-nat64 name=tayga-nat64 envlist=tayga-env workdir=/app logging=yes
```

### Supported Environment Variables:

| Variable | Default Value | Description |
|---|---|---|
| `TAYGA_POOL4` | `192.168.240.0/20` | IPv4 address pool used for dynamic NAT64 mapping (CIDR format). |
| `TAYGA_PREF64` | `64:ff9b::/96` | IPv6 prefix used for NAT64 translation (CIDR format). |
| `TAYGA_ADDR4` | `192.168.240.1` | Tayga internal IPv4 address used for ICMP packet responses. |
| `TAYGA_WKPF_STRICT` | `no` | Strict compliance with RFC 6052 well-known prefix restrictions. |
| `TAYGA_LOG` | `drop reject icmp self dyn` | Logging features to enable. Options include `drop`, `reject`, `icmp`, `self`, `dyn`. |

---

## Managing & Verifying the Container

### Start / Stop Container
```routeros
# Start container
/container/start [find name=tayga-nat64]

# Stop container
/container/stop [find name=tayga-nat64]
```

### Check Container Status
```routeros
/container/print
```
Look for status `running`.

### View Logs
```routeros
/log/print where topics~"container"
```

---

## Troubleshooting & Best Practices

1. **MSS Clamping / MTU Configuration**:
   IPv6 headers add 20 bytes of overhead compared to IPv4. To prevent fragmentation, configure TCP MSS clamping in RouterOS firewall:
   ```routeros
   /ip/firewall/mangle add chain=forward protocol=tcp tcp-flags=syn action=change-mss new-mss=clamp-to-pmtu passthrough=yes comment="Clamp IPv4 MSS for NAT64"
   ```

2. **Container Fails to Start (`error` state)**:
   - Check if container mode is enabled (`/system/device-mode/print`).
   - Ensure the architecture of the container matches your router hardware (`arm64`, `arm`, `x86_64`).
   - Check available disk space (`/system/resource/print`).

3. **IPv6 Forwarding & Firewall**:
   Ensure IPv6 forwarding is enabled and that your IPv6 firewall permits traffic forwarded through the NAT64 prefix:
   ```routeros
   /ipv6/firewall/filter add chain=forward dst-address=64:ff9b::/96 action=accept comment="Allow NAT64 translation prefix"
   ```
