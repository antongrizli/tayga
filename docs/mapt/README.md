# Mapping of Address and Port using Translation (MAP-T)

**Status: not implemented in TAYGA.** This page records what TAYGA does and
does not provide so that MAP-T and stateful NAT64 designs can be planned
correctly. It is not a configuration guide.

## What TAYGA is

TAYGA is a *stateless* IP/ICMP translator (RFC 7915). Every packet is
translated independently, using only the address mappings configured with
`prefix`, `map`, `map-file` and `dynamic-pool`. It keeps no per-flow state
and never rewrites transport ports.

## MAP-T (RFC 7599) versus TAYGA

MAP-T gives each customer a *port set* of a shared public IPv4 address. The
translator must therefore:

* derive the IPv6 address from the IPv4 address **and** the transport port
  (the Embedded Address bits plus the PSID of RFC 7597), and
* reject or forward packets by port set.

TAYGA's EAM support (RFC 7757) maps whole IPv4 prefixes or hosts; it has no
port-set (PSID) awareness. TAYGA therefore cannot act as a MAP-T BR or CE
by itself.

## Stateful NAT64 (RFC 6146) versus TAYGA

A stateful NAT64 shares one IPv4 address between many IPv6 clients by
translating ports (NAPT). TAYGA does not do this itself. The supported
deployment is to let the operating system perform NAPT44 on the IPv4 side of
the `tayga` tunnel interface:

* `tayga` with `dynamic-pool` gives each IPv6 client a private IPv4 address
  from the pool (a 1:1, stateless mapping), and
* `nftables`/`iptables` masquerade (or `pf` NAT on BSD) translates that pool
  to the public address.

The `container/` image and the installer's `nat64` mode are built this way.
See `docs/nat64/` for the maintained configuration examples.

## Related supported modes

* **SIIT / SIIT-DC** (RFC 7915, RFC 7757): `docs/siit/`
* **464XLAT CLAT** (RFC 6877): `docs/clat/`
* **NAT64 with dynamic pool**: `docs/nat64/`

## Out of scope

Implementing MAP-T would require port-set (PSID) mapping rules in the address
mapper and a per-rule BMR/DMR configuration model. This is not currently
planned.
