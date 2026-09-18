# ==============================================================================
# RouterOS 7 Script: Safely Disable TAYGA Service & Controller
# ==============================================================================
# 1. Disables Network State Controller scheduler
# 2. Sets persistent TAYGA_STATE to DISABLED
# 3. Disables CLAT default route and re-enables parked direct WAN default routes
# 4. Cleanly stops running TAYGA containers
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-disable.rsc
# ==============================================================================

:global TAYGA_STATE "DISABLED"
:global TAYGA_CONTROLLER_BUSY false

:put "============================================================"
:put " Disabling TAYGA Service & Network State Controller..."
:put "============================================================"

# 1. Disable Controller Scheduler
:put "--> Disabling /system/scheduler tayga-controller..."
/system/scheduler/disable [find where name="tayga-controller"]

# 2. Disable CLAT default route and restore original WAN default route
:put "--> Withdrawing CLAT default route..."
/ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

:put "--> Restoring parked direct WAN default routes if any..."
:local origRoutes [/ip/route/find where comment~"^\\[tayga-unified:orig-wan-default\\]"]
:foreach r in=$origRoutes do={
    /ip/route/set $r disabled=no comment="[orig-wan-default]"
}

# 3. Stop running containers cleanly
:put "--> Stopping TAYGA containers..."
:local conts [/container/find where comment~"^\\[tayga-unified"]
:foreach c in=$conts do={
    :do {
        /container/stop $c
    } on-error={}
}

:put "============================================================"
:put " TAYGA service disabled. Direct WAN default routes restored."
:put " To re-enable, run routeros-enable.rsc."
:put "============================================================"
