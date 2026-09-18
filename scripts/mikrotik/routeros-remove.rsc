# ==============================================================================
# RouterOS 7 Removal Script: Complete Clean De-installation of TAYGA
# ==============================================================================
# Strictly removes ONLY objects created and owned by this project (tagged [tayga-unified]).
# Will NEVER delete foreign interfaces, unowned bridges, or untagged NAT/route rules.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-remove.rsc
# ==============================================================================

:put "============================================================"
:put " Removing TAYGA Unified Installation..."
:put "============================================================"

# 1. Remove Routes owned by this project
:put "--> Removing TAYGA routes..."
/ip/route/remove [find where comment~"^\\[tayga-unified"]
/ipv6/route/remove [find where comment~"^\\[tayga-unified"]
:do {
    /routing/rule/remove [find where comment~"^\\[tayga-unified"]
    /ip/route/remove [find where routing-table="wan-direct"]
    /routing/table/remove [find where name="wan-direct"]
} on-error={}

# 2. Remove Firewall NAT & Filter Rules owned by this project
:put "--> Removing TAYGA firewall rules..."
/ip/firewall/nat/remove [find where comment~"^\\[tayga-unified"]
:do {
    /ipv6/firewall/nat/remove [find where comment~"^\\[tayga-unified"]
} on-error={}
:do {
    /ipv6/firewall/filter/remove [find where comment~"^\\[tayga-unified"]
} on-error={}

# 3. Stop and Remove Containers owned by this project
:put "--> Stopping and removing TAYGA containers..."
:local conts [/container/find where comment~"^\\[tayga-unified"]
:foreach c in=$conts do={
    :put "--> Stopping container..."
    /container/stop $c
    :local waits 0
    :while (([/container/get $c stopped] != true) && ($waits < 30)) do={
        :delay 1s
        :set waits ($waits + 1)
    }
    :if ([/container/get $c stopped] != true) do={
        :error "Aborted: Container did not stop within 30s. Halting removal to prevent broken network state."
    }
    /container/remove $c
}

# 4. Remove Container Environment Lists owned by this project
:put "--> Removing TAYGA container environment lists..."
/container/envs/remove [find where comment~"^\\[tayga-unified"]
/container/envs/remove [find where list="tayga-clat-envs"]
/container/envs/remove [find where list="tayga-nat64-envs"]

# 5. Remove Bridge Ports and VETH Interfaces owned by this project
:put "--> Removing bridge ports and VETH interfaces..."
/interface/bridge/port/remove [find where comment~"^\\[tayga-unified"]
/interface/veth/remove [find where comment~"^\\[tayga-unified"]

# 6. Remove IP Addresses on transport bridges owned by this project
:put "--> Removing IP addresses on transport bridges..."
/ip/address/remove [find where comment~"^\\[tayga-unified"]
/ipv6/address/remove [find where comment~"^\\[tayga-unified"]

# 7. Remove Bridges owned by this project
:put "--> Removing transport bridges..."
/interface/bridge/remove [find where comment~"^\\[tayga-unified"]

:put "============================================================"
:put " TAYGA Unified components cleanly removed!"
:put " Unowned interfaces and user configurations preserved."
:put "============================================================"
