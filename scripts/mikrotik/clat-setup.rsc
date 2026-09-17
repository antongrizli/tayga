# MikroTik RouterOS 7 Configuration Script for TAYGA CLAT (Customer-Side Translator)
#
# Assumptions and Defaults:
# - CLAT Local IPv4 Gateway Subnet: 192.168.238.0/30 (RouterOS: 192.168.238.1, Tayga: 192.168.238.2)
# - CLAT VETH IPv6 Subnet: fc68::/126 (RouterOS: fc68::1, Tayga: fc68::2)
# - PLAT / NAT64 Prefix: 64:ff9b::/96

# 1. Create bridge interface for CLAT container
/interface bridge add name=clat comment="TAYGA CLAT Bridge"

# 2. Configure IP addresses on the bridge interface for RouterOS gateway side
/ip address add address=192.168.238.1/30 interface=clat comment="CLAT container IPv4 gateway"
/ipv6 address add address=fc68::1/126 interface=clat advertise=no comment="CLAT container IPv6 gateway"

# 3. Create virtual ethernet (VETH) interface for the TAYGA CLAT container
/interface veth add name=veth-clat address=192.168.238.2/30,fc68::2/126 gateway=192.168.238.1 gateway6=fc68::1 dhcp=no comment="TAYGA CLAT VETH"

# 4. Attach VETH interface to the clat bridge
/interface bridge port add bridge=clat interface=veth-clat

# 5. Route IPv4 traffic needing translation to the CLAT container gateway
/ip route add dst-address=0.0.0.0/0 gateway=192.168.238.2 distance=10 comment="Route IPv4 default via TAYGA CLAT"

# 6. Add TAYGA CLAT container (fetches image from GitHub Container Registry)
/container add remote-image="ghcr.io/apalrd/tayga-clat:latest" interface=veth-clat name=tayga-clat workdir=/app logging=yes comment="TAYGA CLAT Container"
