# Firewalld CLAT adaptation gate

`test/system/installer-firewalld-adaptation-smoke.sh` checks NAT66 and Linux Proxy
NDP against a real firewalld daemon. Run only as root in a dedicated disposable
Linux VM; the controller temporarily adds IPv4 half-default routes. Use the
existing pinned Fedora Lima base image cache rather than downloading a new image
for each run.

Install firewalld, iptables-nft, iproute, Python 3, curl and ping in the guest.
Start firewalld and put a tested Linux TAYGA binary on PATH. Copy the current
installer sources and fixture to a guest source directory, then run:

```sh
sudo env TAYGA_ISOLATED_TEST=yes PATH="/path/to/binaries:$PATH" \
  sh test/system/installer-firewalld-adaptation-smoke.sh \
  /path/to/source /var/tmp/tayga-firewalld-evidence
```

The fixture requires no preexisting IPv6 default route and reserves the `fwtest0`
and `clat` interfaces plus the `tayga-fw-upstream` namespace. It provides an
IPv6-only upstream with an HTTP endpoint corresponding to IPv4 `1.1.1.1` through
Pref64. For both address modes it verifies a proof response, a 1 MiB TCP transfer,
ICMP replies and the expected IPv6 source in the HTTP server's log. It compares
direct rules, zone configuration and forwarding/NDP sysctls before and after,
and requires removal of the owned proxy entries. Existing unrelated runtime
rules may be added before invoking the fixture to test their preservation.

Evidence stays in the supplied directory. The fixture removes its namespace,
veth pair and processes; the host should copy evidence and stop the VM afterward.
These checks certify traffic and cleanup on the tested firewalld version. They
do not certify arbitrary concurrent firewall edits or automatic reapplication
after `firewall-cmd --reload`; those are separate lifecycle scenarios.
