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
:global TAYGA_LOCK_TIME
:global TAYGA_STATE
:global TAYGA_PARKED_ROUTE_IDS

:put "============================================================"
:put " Disabling TAYGA Service & Network State Controller..."
:put "============================================================"

# 1. Acquire Unified Lock with 20s wait
:local waitCount 0
:while ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "disable" and $waitCount < 20) do={
    :put ("--> System locked by " . $TAYGA_LOCK_OWNER . "; waiting for lock release (" . $waitCount . "/20s)...")
    :delay 1s
    :set waitCount ($waitCount + 1)
}
:if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "disable") do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting disable."
    :error "Aborted: lock busy"
}
:set TAYGA_LOCK_OWNER "disable"
:set TAYGA_LOCK_TIME [/system/resource/get uptime]

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
    /ipv6/route/disable [find where comment~"^\\[tayga-unified:nat64:prefix\\]"]

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

# Release Unified Lock strictly by owner
:if ($TAYGA_LOCK_OWNER = "disable") do={
    :set TAYGA_LOCK_OWNER "none"
}
