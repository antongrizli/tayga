# TAYGA on MikroTik RouterOS

Using TAYGA on MikroTik RouterOS 7 is supported for both NAT64 and CLAT using native RouterOS containers.

For complete step-by-step setup guides, environment variable references, and downloadable RouterOS configuration scripts (`.rsc`), see:

👉 **[MikroTik RouterOS TAYGA Setup Guide & Scripts](../../scripts/mikrotik/README.md)**

## Quick Overview

### Automated Setup Scripts
- **[NAT64 Setup Script](../../scripts/mikrotik/nat64-setup.rsc)** (`nat64-setup.rsc`)
- **[CLAT Setup Script](../../scripts/mikrotik/clat-setup.rsc)** (`clat-setup.rsc`)

### Speedrun NAT64 Container

Assumptions used in this guide:

- Bridge `nat64` is created only to route packets to/from `tayga`
- You are using `64:ff9b::/96` as your translation prefix
- `192.168.240.0/20` is used for dynamic clients (max 4093 clients)
- `192.168.239.0/30` is used for `tayga` VETH IPv4 subnet
- `fc64::/126` is used for `tayga` VETH IPv6 subnet
- You must ensure masquerade srcnat is configured for `192.168.240.0/20`

```routeros
# Create a bridge for nat64 container
/interface/bridge add name=nat64
# Addresses on nat64 bridge for routeros
/ip/address add address=192.168.239.1/30 interface=nat64
/ipv6/address add address=fc64::1/126 advertise=no comment="nat64 loopback" interface=nat64
# Create veth setup for nat64
/interface/veth add name=veth-nat64 address=192.168.239.2/30,fc64::2/126 comment="nat64 veth" dhcp=no gateway=192.168.239.1 gateway6=fc64::1
/interface/bridge port add bridge=nat64 interface=veth-nat64
# Add routes to tayga via veth
/ip/route add dst-address=192.168.240.0/20 gateway=192.168.239.2 comment="nat64 dynamic pool"
/ipv6/route add dst-address=64:ff9b::/96 gateway=fc64::2%nat64 comment="nat64 translation prefix"
# Add our dynamic pool to interface list
/interface/list/member add interface=nat64 list=LAN
# Create tayga container
/container/add remote-image=ghcr.io/antongrizli/tayga-nat64 interface=veth-nat64 name=tayga-nat64 workdir=/app logging=yes
# Start the container
/container/start [find name=tayga-nat64]
```

