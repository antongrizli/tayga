# ==============================================================================
# RouterOS 7 Script: Safely Disable TAYGA Service & Controller
# ==============================================================================
# 1. Acquires maintenance lock and disables scheduler
# 2. Waits for any active controller run to finish (with strict timeout)
# 3. Sets persistent TAYGA_STATE to DISABLED
# 4. Disables CLAT default route and re-enables parked direct WAN default routes
# 5. Cleanly stops running TAYGA containers
# 6. Releases maintenance lock
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-disable.rsc
# ==============================================================================

:global TAYGA_MAINTENANCE_LOCK true
:global TAYGA_CONTROLLER_BUSY
:global TAYGA_STATE
:global TAYGA_PARKED_ROUTE_IDS

:put "============================================================"
:put " Disabling TAYGA Service & Network State Controller..."
:put "============================================================"

# 1. Disable Controller Scheduler
:put "--> Disabling /system/scheduler tayga-controller..."
/system/scheduler/disable [find where name="tayga-controller"]

# 2. Wait for active controller cycle to complete (with 20s timeout)
:local waitCtrl 0
:while ($TAYGA_CONTROLLER_BUSY = true and $waitCtrl < 20) do={
    :put "--> Waiting for active controller cycle to finish before disabling..."
    :delay 1s
    :set waitCtrl ($waitCtrl + 1)
}
:if ($TAYGA_CONTROLLER_BUSY = true) do={
    :put " [FAIL] Active controller run did not finish within 20s timeout. Aborting disable."
    :set TAYGA_MAINTENANCE_LOCK false
    :error "Aborted: controller busy timeout"
}

:do {
    # 3. Set persistent state to DISABLED
    :set TAYGA_STATE "DISABLED"

    # 4. Disable CLAT default route in main table
    :put "--> Withdrawing CLAT default route..."
    /ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

    # 5. Restore specifically parked direct WAN default routes
    :put "--> Restoring parked direct WAN default routes..."
    :if ([:len $TAYGA_PARKED_ROUTE_IDS] > 0) do={
        :foreach pid in=$TAYGA_PARKED_ROUTE_IDS do={
            :do {
                :put ("--> Re-enabling route: " . $pid)
                /ip/route/enable $pid
            } on-error={}
        }
        :set TAYGA_PARKED_ROUTE_IDS [:toarray ""]
    }

    # 6. Stop running containers cleanly
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

:set TAYGA_MAINTENANCE_LOCK false
