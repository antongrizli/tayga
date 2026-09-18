# MikroTik RouterOS 7 Configuration Script for TAYGA NAT64
#
# Assumptions and Defaults:
# - IPv4 Dynamic Pool: 192.168.240.0/20 (allocated for NAT64 translated IPv6 clients)
# - NAT64 Translation Prefix: 64:ff9b::/96
# - RouterOS Container VETH IPv4 Subnet: 192.168.239.0/30 (RouterOS: 192.168.239.1, Tayga: 192.168.239.2)
# - RouterOS Container VETH IPv6 Subnet: fc64::/126 (RouterOS: fc64::1, Tayga: fc64::2)

# 1. Create bridge interface for NAT64 container
/interface bridge add name=nat64 comment="TAYGA NAT64 Bridge"

# 2. Configure IP addresses on the bridge interface for RouterOS gateway side
/ip address add address=192.168.239.1/30 interface=nat64 comment="NAT64 container IPv4 gateway"
/ipv6 address add address=fc64::1/126 interface=nat64 advertise=no comment="NAT64 container IPv6 gateway"

# 3. Create virtual ethernet (VETH) interface for the TAYGA container
/interface veth add name=veth-nat64 address=192.168.239.2/30,fc64::2/126 gateway=192.168.239.1 gateway6=fc64::1 dhcp=no comment="TAYGA NAT64 VETH"

# 4. Attach VETH interface to the nat64 bridge
/interface bridge port add bridge=nat64 interface=veth-nat64

# 5. Add routes towards TAYGA container via VETH interface
/ip route add dst-address=192.168.240.0/20 gateway=192.168.239.2 comment="Route IPv4 pool to TAYGA NAT64"
/ipv6 route add dst-address=64:ff9b::/96 gateway=fc64::2%nat64 comment="Route NAT64 prefix to TAYGA"

# 6. Add NAT64 bridge to LAN interface list for local access
/interface list member add interface=nat64 list=LAN

# 7. Enable IPv4 Masquerade for the TAYGA dynamic pool on WAN
/ip firewall nat add chain=srcnat action=masquerade src-address=192.168.240.0/20 comment="NAT64 outbound IPv4 masquerade"

# 8. Add TAYGA NAT64 container (fetches image from GitHub Container Registry)
/container add remote-image="ghcr.io/antongrizli/tayga-nat64:latest" interface=veth-nat64 name=tayga-nat64 workdir=/app logging=yes comment="TAYGA NAT64 Container"
