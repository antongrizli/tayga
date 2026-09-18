# ==============================================================================
# RouterOS 7 Removal Script: Complete Clean De-installation of TAYGA
# ==============================================================================
# Strictly removes ONLY objects created and owned by this project (tagged [tayga-unified]).
# Will NEVER delete foreign interfaces, unowned bridges, or untagged NAT/route rules.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-remove.rsc
# ==============================================================================

:global TAYGA_LOCK_OWNER
:global TAYGA_LOCK_TIME
:global TAYGA_STATE
:global TAYGA_PARKED_ROUTE_IDS

:put "============================================================"
:put " Removing TAYGA Unified Installation..."
:put "============================================================"

# 0. Acquire Unified Lock with 20s wait
:local waitCount 0
:while ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "remove" and $waitCount < 20) do={
    :put ("--> System locked by " . $TAYGA_LOCK_OWNER . "; waiting for lock release (" . $waitCount . "/20s)...")
    :delay 1s
    :set waitCount ($waitCount + 1)
}
:if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "remove") do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting remove."
    :error "Aborted: lock busy"
}
:set TAYGA_LOCK_OWNER "remove"
:set TAYGA_LOCK_TIME [/system/resource/get uptime]

:do {
    # 1. Restore specifically parked direct WAN default routes if any
    :put "--> Restoring parked direct WAN routes..."
    :if ([:len $TAYGA_PARKED_ROUTE_IDS] > 0) do={
        :foreach pid in=$TAYGA_PARKED_ROUTE_IDS do={
            :do {
                :if ([:len [/ip/route/find where .id=$pid]] > 0) do={
                    :put ("--> Re-enabling route: " . $pid)
                    /ip/route/enable $pid
                }
            } on-error={}
        }
        :set TAYGA_PARKED_ROUTE_IDS [:toarray ""]
    }

    # Also restore any legacy tagged orig-wan-default routes
    :local origRoutes [/ip/route/find where comment~"^\\[tayga-unified:orig-wan-default\\]"]
    :foreach r in=$origRoutes do={
        /ip/route/set $r disabled=no comment="[orig-wan-default]"
    }

    # 2. Remove Scheduler & Routes owned by this project
    :put "--> Removing TAYGA scheduler and routes..."
    :do {
        /system/scheduler/remove [find where name="tayga-controller"]
        /system/scheduler/remove [find where comment~"^\\[tayga-unified"]
    } on-error={}

    # Remove project routes in main table (including legacy /32 probe route)
    /ip/route/remove [find where comment~"^\\[tayga-unified"]
    /ipv6/route/remove [find where comment~"^\\[tayga-unified"]
    :do {
        /routing/rule/remove [find where comment~"^\\[tayga-unified"]
    } on-error={}

    # Remove routes in project tables and safe table removal
    :local wanTable [/routing/table/find where name="wan-direct"]
    :if ([:len $wanTable] > 0) do={
        :local tComm [/routing/table/get ($wanTable->0) comment]
        /ip/route/remove [find where routing-table="wan-direct" and comment~"^\\[tayga-unified"]
        :local remainingRoutes [/ip/route/find where routing-table="wan-direct"]
        :if ([:len $remainingRoutes] = 0 and ($tComm ~ "^\\[tayga-unified")) do={
            /routing/table/remove ($wanTable->0)
        } else={
            :put "--> Table 'wan-direct' contains foreign routes or was not created by this project (retaining table)."
        }
    }

    :local clatTable [/routing/table/find where name="tayga-probe-clat"]
    :if ([:len $clatTable] > 0) do={
        :local cComm [/routing/table/get ($clatTable->0) comment]
        /ip/route/remove [find where routing-table="tayga-probe-clat" and comment~"^\\[tayga-unified"]
        :local remainingClatRoutes [/ip/route/find where routing-table="tayga-probe-clat"]
        :if ([:len $remainingClatRoutes] = 0 and ($cComm ~ "^\\[tayga-unified")) do={
            /routing/table/remove ($clatTable->0)
        } else={
            :put "--> Table 'tayga-probe-clat' contains foreign routes or was not created by this project (retaining table)."
        }
    }

    # 3. Remove Firewall NAT & Filter Rules owned by this project
    :put "--> Removing TAYGA firewall rules..."
    /ip/firewall/nat/remove [find where comment~"^\\[tayga-unified"]
    :do {
        /ipv6/firewall/nat/remove [find where comment~"^\\[tayga-unified"]
    } on-error={}
    :do {
        /ipv6/firewall/filter/remove [find where comment~"^\\[tayga-unified"]
    } on-error={}

    # 4. Stop and Remove Containers owned by this project
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

    # 5. Remove Container Environment Lists owned by this project
    :put "--> Removing TAYGA container environment lists..."
    /container/envs/remove [find where comment~"^\\[tayga-unified"]
    /container/envs/remove [find where list="tayga-clat-envs"]
    /container/envs/remove [find where list="tayga-nat64-envs"]

    # 6. Remove Bridge Ports and VETH Interfaces owned by this project
    :put "--> Removing bridge ports and VETH interfaces..."
    /interface/bridge/port/remove [find where comment~"^\\[tayga-unified"]
    /interface/veth/remove [find where comment~"^\\[tayga-unified"]

    # 7. Remove IP Addresses on transport bridges owned by this project
    :put "--> Removing IP addresses on transport bridges..."
    /ip/address/remove [find where comment~"^\\[tayga-unified"]
    /ipv6/address/remove [find where comment~"^\\[tayga-unified"]

    # 8. Remove Bridges owned by this project
    :put "--> Removing transport bridges..."
    /interface/bridge/remove [find where comment~"^\\[tayga-unified"]

    # 9. Clear global variables
    :set TAYGA_STATE ""
    :set TAYGA_PARKED_ROUTE_IDS [:toarray ""]

    :put "============================================================"
    :put " TAYGA Unified components cleanly removed!"
    :put " Unowned interfaces and user configurations preserved."
    :put "============================================================"
} on-error={
    :put " [ERROR] An unexpected error occurred during removal."
}

# Release Unified Lock strictly by owner
:if ($TAYGA_LOCK_OWNER = "remove") do={
    :set TAYGA_LOCK_OWNER "none"
}
