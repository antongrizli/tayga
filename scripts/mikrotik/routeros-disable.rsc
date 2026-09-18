# ==============================================================================
# RouterOS 7 Script: Safely Disable TAYGA Service & Controller
# ==============================================================================
# 1. Acquires Unified Lock (owner=disable) and disables scheduler
# 2. Waits for any active controller run to finish (with strict 20s timeout)
# 3. Sets persistent TAYGA_STATE to DISABLED
# 4. Disables CLAT default route and re-enables parked direct WAN default routes
# 5. Cleanly stops running TAYGA CLAT and NAT64 containers
# 6. Releases Unified Lock
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-disable.rsc
# ==============================================================================

:global TAYGA_LOCK_OWNER
:global TAYGA_LOCK_TOKEN
:global TAYGA_LOCK_TIME
:global TAYGA_STATE
:global TAYGA_PARKED_ROUTE_IDS

:put "============================================================"
:put " Disabling TAYGA Service & Network State Controller..."
:put "============================================================"

# 1. Acquire Unified Lock with 20s wait
:local myToken ("disable-" . [:tostr [/system/clock/get time]] . "-" . [:rndnum from=1000 to=9999])
:local waitCount 0
:local acquired false

:while ($acquired = false and $waitCount < 20) do={
    :local curUp [/system/resource/get uptime]
    :local busy false
    :if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none") do={
        :local age 0s
        :do { :set age ($curUp - $TAYGA_LOCK_TIME) } on-error={ :set age 999s }
        :if ($age < 120s) do={
            :set busy true
        } else={
            :put ("--> Overriding stale lock held by " . $TAYGA_LOCK_OWNER . "...")
        }
    }
    :if ($busy = false) do={
        :set TAYGA_LOCK_OWNER "disable"
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
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting disable."
    :error "Aborted: lock busy"
}

:do {
    # 2. Disable Controller Scheduler
    :put "--> Disabling /system/scheduler tayga-controller..."
    /system/scheduler/disable [find where name="tayga-controller"]

    # 3. Set persistent state to DISABLED
    :set TAYGA_STATE "DISABLED"

    # 4. Disable CLAT default route in main table
    :put "--> Withdrawing CLAT default route..."
    /ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

    # 5. Disable NAT64 prefix route if active
    :put "--> Withdrawing NAT64 prefix route..."
    /ipv6/route/disable [find where comment~"^\\[tayga-unified:nat64(:prefix)?\\]"]

    # 6. Restore specifically parked direct WAN default routes
    :put "--> Restoring parked direct WAN default routes..."
    :if ([:len $TAYGA_PARKED_ROUTE_IDS] > 0) do={
        :local remainingParked [:toarray ""]
        :foreach pid in=$TAYGA_PARKED_ROUTE_IDS do={
            :local restored false
            :do {
                :if ([:len [/ip/route/find where .id=$pid]] > 0) do={
                    :put ("--> Re-enabling route: " . $pid)
                    /ip/route/enable $pid
                    :if ([/ip/route/get $pid disabled] = false) do={ :set restored true }
                } else={
                    :set restored true
                }
            } on-error={}
            :if ($restored = false) do={
                :set remainingParked ($remainingParked, $pid)
            }
        }
        :set TAYGA_PARKED_ROUTE_IDS $remainingParked
    }

    # 7. Stop running containers cleanly
    :put "--> Stopping TAYGA containers..."
    :local conts [/container/find where comment~"^\\[tayga-unified"]
    :foreach c in=$conts do={
        :do {
            /container/stop $c
        } on-error={}
    }

    :put "============================================================"
    :put " TAYGA service disabled safely. Direct WAN routes restored."
    :put " To re-enable, run routeros-enable.rsc."
    :put "============================================================"
} on-error={
    :put " [ERROR] An unexpected error occurred while disabling service."
}

# Release Unified Lock strictly by token match
:if ($TAYGA_LOCK_TOKEN = $myToken) do={
    :set TAYGA_LOCK_OWNER "none"
    :set TAYGA_LOCK_TOKEN ""
}
