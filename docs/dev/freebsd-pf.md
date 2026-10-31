# FreeBSD PF ownership

Managed FreeBSD profiles load only their child anchor `tayga_sfx/<tun-device>`.
The administrator must provision both root calls before activating a profile:

```pf
# In the translation section, before filter rules:
nat-anchor "tayga_sfx/*"

# In the filter section, at the intended policy evaluation position:
anchor "tayga_sfx/*"
```

Merge these calls into the complete authoritative PF configuration. Validate it
with `pfctl -nf /etc/pf.conf` and apply it through the existing firewall management
procedure. The installer does not edit or reload that root configuration.
Missing either call makes activation fail and roll back its network changes.

Do not reconstruct a root configuration from `pfctl -sn` and `pfctl -sr`: these
commands omit global configuration. A real FreeBSD test showed that loading this
reconstructed output reset the configured state limit. Root reloads have therefore
been removed from the controller, including rollback. Existing root calls remain
in place after stop; only the managed child's rules are flushed.

Run the destructive ownership fixture only in a separate disposable VM:

```sh
python3 test/system/run-freebsd-pf-vm.py \
  --vm tayga-installer-freebsd-pf --output build/freebsd-pf/ownership
```

The VM must already be created from a pinned FreeBSD Lima image; Lima reuses its
download cache. The runner builds TAYGA in the guest and tests missing, partial
and complete root calls. It compares foreign rules, a persistent table, edits to
that table while TAYGA runs, nested anchor rules, and global limits. Missing calls
must be rejected without changing those snapshots. With both calls configured,
activation and cleanup must preserve them. Reports record source hashes and the
actual guest version, which may differ from the base image after first-boot OS
updates. The VM is stopped and evidence retained on failure.

## CLAT NAT66 and Proxy NDP traffic gate

`test/system/installer-freebsd-ipv6-smoke.sh` is destructive and requires an
isolated FreeBSD VM with a clean PF root, `curl`, `python3`, and a freshly built
`tayga` in PATH. It creates a VNET jail and epair upstream with IPv6 HTTP target
`fd64:100::101:101` (IPv4 `1.1.1.1` through `fd64:100::/96`). No public endpoint
is used. It temporarily changes the guest IPv6 default and restores it on exit.

```sh
sudo env TAYGA_ISOLATED_TEST=yes PATH="/path/to/source:$PATH" \
  sh test/system/installer-freebsd-ipv6-smoke.sh \
  /path/to/source /var/tmp/tayga-ipv6-evidence
```

For a host-driven run with source hashes, SCP evidence collection and VM stop:

```sh
python3 test/system/run-freebsd-pf-vm.py --gate ipv6 \
  --vm tayga-installer-freebsd-pf --output build/freebsd-ipv6/new-run
```

The fixture tests NAT66 and Proxy NDP sequentially using HTTP, a byte-compared
1 MiB response and ICMP echo. It retains uplink/TUN packet captures and checks
that stop removes the TUN, owned proxy entry and daemon alias. On FreeBSD the
translated CLAT address uses `ndp -s ADDRESS MAC proxy`, while the daemon
identity is an uplink alias. Assigning both addresses as uplink aliases conflicts
with TUN addressing/routing. IPv6 must remain enabled on the TUN even when its
daemon identity is assigned to the uplink.

The gate passed on FreeBSD 15.1-RELEASE-p6 arm64. It exposed two translator bugs:
a missing BSD TUN output family on ordinary IPv6-to-IPv4 data packets, and byte
order detection using undefined macros (silently selecting big endian). C tests
now check the data-output family and ICMP echo checksum round trip.

This gate does not certify UDP wire traffic, explicit PMTU/fragmentation cases,
PF reload lifecycle, other FreeBSD releases/architectures, or provider address
policies. Unit tests exercise UDP translation but do not replace those wire gates.
