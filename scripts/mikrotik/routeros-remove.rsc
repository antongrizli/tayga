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
:global TAYGA_LOCK_TOKEN
:global TAYGA_LOCK_TIME
:global TAYGA_STATE
:global TAYGA_PARKED_ROUTE_IDS

:put "============================================================"
:put " Removing TAYGA Unified Installation..."
:put "============================================================"

# 0. Acquire Unified Lock with 20s wait
:local myToken ("remove-" . [:tostr [/system/clock/get time]] . "-" . [:rndnum from=1000 to=9999])
:local waitCount 0
:local acquired false

:while ($acquired = false and $waitCount < 20) do={
    :local curUp [/system/resource/get uptime]
    :local busy false
    :if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none") do={
        :local age 0s
        :local ageValid false
        :do {
            :set age ($curUp - $TAYGA_LOCK_TIME)
            :set ageValid true
        } on-error={ :set ageValid false }
        :if ($ageValid = true and $age >= 300s) do={
            :local jobRunning false
            :do {
                :if ($TAYGA_LOCK_OWNER = "controller") do={
                    :if ([:len [/system/script/job find where script="tayga-controller"]] > 0) do={
                        :set jobRunning true
                    }
                }
            } on-error={}
            :if ($jobRunning = false) do={
                :put ("--> Overriding stale lock held by " . $TAYGA_LOCK_OWNER . " (age=" . [:tostr $age] . ")...")
            } else={
                :set busy true
            }
        } else={
            :set busy true
        }
    }
    :if ($busy = false) do={
        :set TAYGA_LOCK_OWNER "remove"
        :set TAYGA_LOCK_TOKEN $myToken
        :set TAYGA_LOCK_TIME $curUp
        :set acquired true
    } else={
        :put ("--> System locked by " . $TAYGA_LOCK_OWNER . "; waiting for lock release (" . $waitCount . "/20s)...")
        :delay 1s
        :set waitCount ($waitCount + 1)
    }
}

:if ($acquired = false) do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting remove."
    :error "Aborted: lock busy"
}

:do {
    # Verify lock ownership was maintained before making network state changes
    :if ($TAYGA_LOCK_TOKEN != $myToken or $TAYGA_LOCK_OWNER != "remove") do={
        :put " [FAIL] Lock was lost before remove operations could start."
        :error "Aborted: lock lost"
    }
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

    :local nat64Table [/routing/table/find where name="tayga-probe-nat64"]
    :if ([:len $nat64Table] > 0) do={
        :local nComm [/routing/table/get ($nat64Table->0) comment]
        /ipv6/route/remove [find where routing-table="tayga-probe-nat64" and comment~"^\\[tayga-unified"]
        :local remainingNat64Routes [/ipv6/route/find where routing-table="tayga-probe-nat64"]
        :if ([:len $remainingNat64Routes] = 0 and ($nComm ~ "^\\[tayga-unified")) do={
            /routing/table/remove ($nat64Table->0)
        } else={
            :put "--> Table 'tayga-probe-nat64' contains foreign routes or was not created by this project (retaining table)."
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
    /container/envs/remove [find where list="tayga-policy-envs"]

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

# Release Unified Lock strictly by token match
:if ($TAYGA_LOCK_TOKEN = $myToken) do={
    :set TAYGA_LOCK_OWNER "none"
    :set TAYGA_LOCK_TOKEN ""
}
